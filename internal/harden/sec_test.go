package harden

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// captureStdout 捕获标准输出（fix dry-run 打印计划验证用）。
func captureStdout(fn func()) string {
	old := os.Stdout
	rp, wp, _ := os.Pipe()
	os.Stdout = wp
	fn()
	wp.Close()
	os.Stdout = old
	b, _ := io.ReadAll(rp)
	return string(b)
}

// fakeSecRunner 固定输出的远端（sec 系列 check 的纯函数验证）。
type fakeSecRunner struct {
	byFrag map[string]string // 命令片段 → 输出（Contains 匹配）
	defOut string
}

func (f fakeSecRunner) Run(cmd string) (string, error) {
	for frag, out := range f.byFrag {
		if strings.Contains(cmd, frag) {
			return out, nil
		}
	}
	return f.defOut, nil
}
func (f fakeSecRunner) RunWithStdin(cmd string, in []byte) (string, error) {
	return f.Run(cmd)
}

func withFakeHost(t *testing.T, host string, fr SecRunner) {
	t.Helper()
	oldHost, oldFn := currentHostValue, secRunner
	SetCurrentHost(host, func(string) (SecRunner, error) { return fr, nil })
	t.Cleanup(func() {
		currentHostValue, secRunner = oldHost, oldFn
	})
}

func TestParseListeningPorts(t *testing.T) {
	ports := parseListeningPorts("22\n8080\n8080\n3306\n0\n")
	// 字符串序排序（与实现一致）："22" < "3306" < "8080"
	if len(ports) != 3 || ports[0] != "22" || ports[1] != "3306" || ports[2] != "8080" {
		t.Fatalf("端口解析/去重/排序错误: %v", ports)
	}
}

func TestExposureDictAndProtected(t *testing.T) {
	fr := fakeSecRunner{
		byFrag: map[string]string{
			"ipset list": "",
			"ss -lntH":   "22\n6379\n3306\n8848\n",
			"docker ps":  "",
			"PING":       "unauth\n", // Redis 探测（远端 shell 判定结果）
			"curl":       "auth\n",   // HTTP 探测（8848 Nacos 等）
		},
	}
	SetCurrentHost("10.0.0.1", func(string) (SecRunner, error) { return fr, nil })
	defer func() { SetCurrentHost("", nil) }()

	r := NewSecReport("test", []string{"10.0.0.1"}, testNow())
	RunExposureCheck("10.0.0.1", r)

	high := 0
	for _, f := range r.Findings {
		if f.Category == "暴露面" && f.Level == SecHigh {
			high++
		}
	}
	if high != 3 {
		t.Fatalf("6379/3306/8848 应各报 1 条高危，实际 %d: %+v", high, r.Findings)
	}
	// Redis 探测结论存在（unauth → critical）
	foundRedis := false
	for _, f := range r.Findings {
		if f.Category == "未授权访问" && strings.Contains(f.Item, "Redis") {
			foundRedis = true
			if f.Level != SecCritical {
				t.Fatalf("Redis 未授权应为 critical: %+v", f)
			}
		}
	}
	// NOAUTH → auth（信息级）；关键是有探测结论
	if !foundRedis {
		t.Fatal("缺少 Redis 探测结论")
	}
}

func TestExposureProtectedPortSkipped(t *testing.T) {
	fr := fakeSecRunner{
		byFrag: map[string]string{
			"egova-expose-ports": "6379",
			"ss -lntH":           "6379\n",
			"redis":              "+PONG",
			"docker ps":          "",
			"egova-vpc-nets":     "1\n1",
		},
	}
	SetCurrentHost("10.0.0.2", func(string) (SecRunner, error) { return fr, nil })
	defer func() { SetCurrentHost("", nil) }()

	r := NewSecReport("test", []string{"10.0.0.2"}, testNow())
	RunExposureCheck("10.0.0.2", r)
	for _, f := range r.Findings {
		if f.Category == "暴露面" && f.Level == SecHigh {
			t.Fatalf("白名单端口不应报高危: %+v", f)
		}
	}
}

func TestProbeRedisVerdicts(t *testing.T) {
	// probeRedis 的判定逻辑在远端 shell（case $out），fake 直接回判定结果；
	// "PING" 片段命中保证远端命令构造正确。
	fr := fakeSecRunner{byFrag: map[string]string{
		"PING": "unauth\n",
	}}
	SetCurrentHost("h", func(string) (SecRunner, error) { return fr, nil })
	defer func() { SetCurrentHost("", nil) }()
	if got := probeRedis(6379); got != "unauth" {
		t.Fatalf("应回 unauth: %q", got)
	}
	fr2 := fakeSecRunner{byFrag: map[string]string{
		"PING": "auth\n",
	}}
	SetCurrentHost("h", func(string) (SecRunner, error) { return fr2, nil })
	if got := probeRedis(6379); got != "auth" {
		t.Fatalf("应回 auth: %q", got)
	}
}

func TestOSCheckFindings(t *testing.T) {
	fr := fakeSecRunner{byFrag: map[string]string{
		"/etc/shadow":      "backupuser",
		"/etc/passwd":      "hacker",
		"pwquality":        "",
		"PASS_MAX_DAYS":    "99999",
		"pam_faillock":     "",
		"PermitRootLogin":  "yes",
		"PasswordAuth":     "yes",
		"PermitEmpty":      "no",
		"MaxAuthTries":     "6",
		"TMOUT":            "",
		"limits.conf":      "",
		"is-active telnet": "active",
		"auditd":           "inactive",
		"stat -c":          "/etc/shadow 0644",
	}}
	SetCurrentHost("10.0.0.3", func(string) (SecRunner, error) { return fr, nil })
	defer func() { SetCurrentHost("", nil) }()

	r := NewSecReport("test", []string{"10.0.0.3"}, testNow())
	RunOSCheck("10.0.0.3", r)
	critical := 0
	for _, f := range r.Findings {
		if f.Level == SecCritical {
			critical++
		}
	}
	if critical < 1 {
		t.Fatalf("空口令账号应 critical: %+v", r.Findings)
	}
	// 分类齐全
	cats := map[string]bool{}
	for _, f := range r.Findings {
		cats[f.Category] = true
	}
	for _, want := range []string{"账号口令", "SSH", "会话", "服务", "审计", "权限"} {
		if !cats[want] {
			t.Fatalf("缺少分类 %s: %v", want, cats)
		}
	}
}

func TestOSFixSSHRedLine(t *testing.T) {
	fr := fakeSecRunner{byFrag: map[string]string{
		"authorized_keys": "no",
	}}
	SetCurrentHost("10.0.0.4", func(string) (SecRunner, error) { return fr, nil })
	defer func() { SetCurrentHost("", nil) }()

	r := NewSecReport("test", []string{"10.0.0.4"}, testNow())
	err := RunOSFix("10.0.0.4", r, true, true)
	if err == nil || !strings.Contains(err.Error(), "红线") {
		t.Fatalf("无密钥时 fixSSH 必须被红线拦截: %v", err)
	}
}

func TestSSHFixCmdShape(t *testing.T) {
	cmd := SSHFixCmd(true)
	for _, want := range []string{"PermitRootLogin prohibit-password", "PermitEmptyPasswords no", "PasswordAuthentication no", "sshd -t"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("SSH 修复命令缺少 %q", want)
		}
	}
}

func TestNetworkBanIPFiltering(t *testing.T) {
	fr := fakeSecRunner{byFrag: map[string]string{
		"access*.log":   "520 203.0.113.99\n30 198.51.100.7\n25 172.21.133.5\n",
		"Failed pass":   "",
		"ipset create":  "ENSURED",
		"is_private_ip": "no\nno\nyes\n",
	}}
	SetCurrentHost("10.0.0.5", func(string) (SecRunner, error) { return fr, nil })
	defer func() { SetCurrentHost("", nil) }()

	r := NewSecReport("test", []string{"10.0.0.5"}, testNow())
	// dry-run
	if err := RunNetworkBan("10.0.0.5", r, false, false); err != nil {
		t.Fatal(err)
	}
	// 私网 172.21.x 应被豁免（在计划里体现）
	out := captureStdout(func() { _ = RunNetworkBan("10.0.0.5", r, false, false) })
	if strings.Contains(out, "ban 172.21.133.5") {
		t.Fatal("私网 IP 不应进入封禁计划")
	}
	if !strings.Contains(out, "ban 203.0.113.99") {
		t.Fatalf("公网 IP 应在计划中: %s", out)
	}
}

func TestRollbackCommandShape(t *testing.T) {
	cmd, err := RollbackCommand([]BackupEntry{
		{Origin: "/etc/nginx/nginx.conf", Backup: "/egova/eops-sec-backup/10.0.0.1/20261112/etc/nginx/nginx.conf"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, "cp -a '/egova/eops-sec-backup/10.0.0.1/20261112/etc/nginx/nginx.conf' '/etc/nginx/nginx.conf'") {
		t.Fatalf("回滚命令形态错误: %s", cmd)
	}
	if _, err := RollbackCommand(nil); err == nil {
		t.Fatal("空清单应报错")
	}
	if _, err := RollbackCommand([]BackupEntry{{Origin: "/a;b", Backup: "/b"}}); err == nil {
		t.Fatal("非法路径应拒绝")
	}
}

func TestSecReportTSVAndText(t *testing.T) {
	r := NewSecReport("test", []string{"h1"}, testNow())
	r.Add(SecFinding{Host: "h1", Category: "未授权访问", Item: "Redis(6379)",
		Result: "PING 返回 PONG", Level: SecCritical, Advice: "设 requirepass", Fixable: "yes"})
	r.Add(SecFinding{Host: "h1", Category: "Nginx", Item: "server_tokens",
		Result: "未关闭", Level: SecMedium, Advice: "off", Fixable: "yes"})
	tsv := r.TSV()
	if !strings.Contains(tsv, "高危\t未授权访问\tRedis(6379)") {
		t.Fatalf("TSV 应含高危行: %s", tsv)
	}
	if strings.Count(tsv, "\n") != 3 {
		t.Fatalf("TSV 行数错误: %d", strings.Count(tsv, "\n"))
	}
	c, m, low := r.CountBy("all")
	if c != 1 || m != 1 || low != 0 {
		t.Fatalf("计数错误: %d/%d/%d", c, m, low)
	}
	if !r.HasBlocking() {
		t.Fatal("含高危应 HasBlocking")
	}
	var b strings.Builder
	r.Text(&b)
	if !strings.Contains(b.String(), "Redis(6379)") || !strings.Contains(b.String(), "高危 1 / 中危 1") {
		t.Fatalf("Text 输出缺要素:\n%s", b.String())
	}
}

func TestOriginOfBackupPath(t *testing.T) {
	got := originOf("/egova/eops-sec-backup/10.0.0.1/20261112-150405/etc/nginx/nginx.conf")
	if got != "/etc/nginx/nginx.conf" {
		t.Fatalf("originOf 还原错误: %q", got)
	}
}

func testNow() time.Time { return time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC) }
