package inspect

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
)

func TestParseLoad(t *testing.T) {
	loads, cpus, err := parseLoad("1.50 0.80 0.60\n8\n")
	if err != nil {
		t.Fatal(err)
	}
	if loads[0] != 1.5 || cpus != 8 {
		t.Fatalf("解析错误: %v %d", loads, cpus)
	}
	if _, _, err := parseLoad("bad\n"); err == nil {
		t.Fatal("异常输入应报错")
	}
}

func TestParseFreeM(t *testing.T) {
	out := "              total        used        free      shared  buff/cache   available\n" +
		"Mem:           7900        1234        2000         100        4666        6000\n" +
		"Swap:          2047           0        2047\n"
	total, used, avail, err := parseFreeM(out)
	if err != nil {
		t.Fatal(err)
	}
	if total != 7900 || used != 1234 || avail != 6000 {
		t.Fatalf("解析错误: %d %d %d", total, used, avail)
	}
}

func TestParseDfAndThresholds(t *testing.T) {
	out := "Filesystem     1024-blocks    Used Available Capacity Mounted on\n" +
		"/dev/vda1         80000000 78000000   2000000      98% /\n" +
		"/dev/vdb1         50000000 10000000  40000000      20% /egova\n"
	rows, err := parseDf(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Pct != 98 || rows[1].Mount != "/egova" {
		t.Fatalf("解析错误: %+v", rows)
	}

	c := checkByName(t, "disk")
	_, fs, err := c.Evaluate(Env{}, out)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Severity != SevCritical {
		t.Fatalf("98%% 应判 critical: %+v", fs)
	}
}

func TestMemoryThreshold(t *testing.T) {
	c := checkByName(t, "memory")
	// 95% → 预警
	_, fs, err := c.Evaluate(Env{}, "Mem:  1000  950  10  0  40  20\n")
	if err != nil || len(fs) != 1 || fs[0].Severity != SevWarn {
		t.Fatalf("95%% 使用率应判 warn: %+v %v", fs, err)
	}
	// 98% → 严重
	_, fs, _ = c.Evaluate(Env{}, "Mem:  1000  980  5  0  15  20\n")
	if len(fs) != 1 || fs[0].Severity != SevCritical {
		t.Fatalf("98%% 使用率应判 critical: %+v", fs)
	}
}

func TestSshPolicy(t *testing.T) {
	kv := parseSshd("PermitRootLogin yes\n# PasswordAuthentication no\nPasswordAuthentication yes\n")
	if kv["PermitRootLogin"] != "yes" || kv["PasswordAuthentication"] != "yes" {
		t.Fatalf("sshd 解析错误: %v", kv)
	}
	c := checkByName(t, "ssh-policy")
	_, fs, _ := c.Evaluate(Env{}, "PermitRootLogin yes\nPasswordAuthentication yes\n")
	if len(fs) != 2 {
		t.Fatalf("应报 2 条（root 登录 + 口令登录）: %+v", fs)
	}
}

func TestRiskyPorts(t *testing.T) {
	out := "0.0.0.0:3306\n127.0.0.1:6379\n[::]:9200\n0.0.0.0:8080\n:::5432\n"
	got := exposedRiskyPorts(out)
	ports := map[string]bool{}
	for _, p := range got {
		ports[p.port] = true
	}
	if !ports["3306"] || !ports["9200"] || !ports["5432"] {
		t.Fatalf("应识别 3306/9200/5432 暴露: %+v", got)
	}
	if ports["6379"] {
		t.Fatalf("127.0.0.1 不应算暴露")
	}
	if portOf("0.0.0.0:8080") != "8080" || portOf("garbage") != "" {
		t.Fatal("portOf 解析错误")
	}
}

func TestAppPortCheck(t *testing.T) {
	c := checkByName(t, "app-port")
	env := Env{Target: Target{App: "eurbanpro", Host: config.Host{Host: "10.0.0.1", ServicePort: 8080}}}
	_, fs, err := c.Evaluate(env, "0.0.0.0:8080\n0.0.0.0:22\n")
	if err != nil || len(fs) != 0 {
		t.Fatalf("端口在监听不应报错: %+v %v", fs, err)
	}
	_, fs, _ = c.Evaluate(env, "0.0.0.0:22\n")
	if len(fs) != 1 || fs[0].Severity != SevError {
		t.Fatalf("端口未监听应报 error: %+v", fs)
	}
}

func TestMysqlServiceCheck(t *testing.T) {
	c := checkByName(t, "mysql-service")
	env := Env{Target: Target{SupportKind: "mysql", Host: config.Host{Host: "10.0.0.3"}}}
	_, fs, _ := c.Evaluate(env, "PROCESS=DOWN\nPORT=0\n")
	if len(fs) != 2 {
		t.Fatalf("进程与端口都异常应报 2 条: %+v", fs)
	}
	_, fs, _ = c.Evaluate(env, "PROCESS=RUNNING\nPORT=1\n")
	if len(fs) != 0 {
		t.Fatalf("正常不应报错: %+v", fs)
	}
}

func TestRegistrySanity(t *testing.T) {
	checks := Checks()
	if len(checks) < 12 {
		t.Fatalf("内置检查项过少: %d", len(checks))
	}
	seen := map[string]bool{}
	for _, c := range checks {
		if c.Name == "" || c.Description == "" || c.Command == nil || c.Evaluate == nil {
			t.Fatalf("检查项定义不完整: %+v", c)
		}
		if seen[c.Name] {
			t.Fatalf("检查项重名: %s", c.Name)
		}
		seen[c.Name] = true
	}
	for _, d := range []Dimension{DimOS, DimSecurity, DimMiddleware} {
		if len(FilterChecks([]Dimension{d})) == 0 {
			t.Fatalf("维度 %s 没有检查项", d)
		}
	}
}

// fakeConn 按命令返回预置输出。
type fakeConn struct{ byCmd map[string]string }

func (f fakeConn) Run(cmd string) (string, error) { return f.byCmd[cmd], nil }

func TestRunnerAggregatesAndSorts(t *testing.T) {
	// 只跑 os-info，命令固定，输出固定
	var infoCmd string
	for _, c := range Checks() {
		if c.Name == "os-info" {
			infoCmd, _ = c.Command(Env{})
		}
	}
	conn := fakeConn{byCmd: map[string]string{infoCmd: "Kylin V10\n4.19.90\nup 3 days\n"}}
	r := Runner{
		Dial:     func(config.Host) (Conn, error) { return conn, nil },
		Parallel: 2,
	}
	targets := []Target{
		{Host: config.Host{Host: "10.0.0.2"}, App: "b"},
		{Host: config.Host{Host: "10.0.0.1"}, App: "a"},
	}
	only := []Check{checkByName(t, "os-info")}
	res := r.Run(&config.Config{}, targets, only)
	if len(res) != len(targets) {
		t.Fatalf("结果数不符: %d", len(res))
	}
	if res[0].Host != "10.0.0.1" {
		t.Fatalf("结果应按主机排序: %s", res[0].Host)
	}
	for _, x := range res {
		if x.Err != "" {
			t.Fatalf("不应有执行错误: %+v", x)
		}
	}
}

func TestTargetsDedup(t *testing.T) {
	cfg := &config.Config{
		Webs: []config.App{{
			Web: "a", MiddleType: "jar",
			Master: []config.Host{{Host: "10.0.0.1", ServicePort: 8080}},
			Update: []config.Host{{Host: "10.0.0.1", ServicePort: 8080}},
		}},
		Supports: []config.Support{{Kind: "mysql", Hosts: []config.Host{{Host: "10.0.0.1"}}}},
	}
	ts := Targets(cfg)
	if len(ts) != 2 {
		t.Fatalf("同主机应用+mysql 应 2 个目标（应用去重），实际 %d: %+v", len(ts), ts)
	}
}

func TestReportTextAndJSON(t *testing.T) {
	now := time.Date(2026, 11, 6, 14, 0, 0, 0, time.UTC)
	results := []Result{
		{Host: "10.0.0.1", Target: "a@10.0.0.1", Check: "disk", Dimension: "os",
			Findings: []Finding{{Host: "10.0.0.1", Target: "a@10.0.0.1", Check: "disk", Dimension: "os",
				Severity: SevWarn, Message: "挂载点 / 使用率 90%"}}},
		{Host: "10.0.0.2", Target: "b@10.0.0.2", Check: "load", Dimension: "os"},
		{Host: "10.0.0.3", Check: "load", Dimension: "os", Err: "SSH 连接失败"},
	}
	rep := BuildReport(results, now)
	if rep.Hosts != 3 || rep.Checks != 2 {
		t.Fatalf("报告统计错误: %+v", rep)
	}
	if len(rep.Findings) != 1 || rep.Summary["warn"] != 1 {
		t.Fatalf("异常统计错误: %+v", rep.Summary)
	}
	if len(rep.ExecErrors) != 1 {
		t.Fatalf("执行失败统计错误: %+v", rep.ExecErrors)
	}
	if Worst(rep.Findings) != SevWarn {
		t.Fatalf("最高级别应为 warn")
	}
	var buf bytes.Buffer
	rep.Text(&buf)
	out := buf.String()
	if !strings.Contains(out, "10.0.0.1") || !strings.Contains(out, "预警") ||
		!strings.Contains(out, "未发现异常") || !strings.Contains(out, "执行失败 1") {
		t.Fatalf("文本报告缺少要素:\n%s", out)
	}
	b, err := rep.JSON()
	if err != nil || !strings.Contains(string(b), "\"findings\"") {
		t.Fatalf("JSON 输出异常: %v %s", err, b)
	}
}

func checkByName(t *testing.T, name string) Check {
	t.Helper()
	for _, c := range Checks() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("检查项不存在: %s", name)
	return Check{}
}
