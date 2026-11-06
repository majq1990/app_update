package monitor

import (
	"strings"
	"testing"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/inspect"
)

func TestParseAgentConf(t *testing.T) {
	kv := ParseAgentConf("# comment\nServer=zabbix.egaca.com.cn\nHostname=proj01\n  Include=/etc/zabbix/zabbix_agentd.d/*.conf\n")
	if kv["Server"] != "zabbix.egaca.com.cn" || kv["Hostname"] != "proj01" || kv["Include"] == "" {
		t.Fatalf("配置解析错误: %v", kv)
	}
	if _, ok := kv["# comment"]; ok {
		t.Fatal("注释行不应解析为键")
	}
}

func TestPortListed(t *testing.T) {
	out := "0.0.0.0:9000\n127.0.0.1:10050\n[::]:9001\n"
	if !portListed(out, 9000) || !portListed(out, 9001) {
		t.Fatal("应识别 9000/9001")
	}
	if portListed(out, 9009) {
		t.Fatal("9009 不应命中")
	}
	if portListed("0.0.0.0:19000", 9000) {
		t.Fatal("19000 不应被当成 9000")
	}
}

func TestTargetsRoles(t *testing.T) {
	cfg := &config.Config{
		Webs: []config.App{{
			Web: "a", MiddleType: "jar",
			Master: []config.Host{{Host: "10.0.0.1", ServicePort: 8080}},
		}},
		Supports: []config.Support{{Kind: "mysql", Hosts: []config.Host{{Host: "10.0.0.2"}}}},
		Monitor: &config.Monitor{
			ProxyHosts: []config.Host{{Host: "10.0.0.9"}},
		},
	}
	ts := Targets(cfg)
	roles := map[string]Role{}
	for _, x := range ts {
		roles[x.Host.Host] = x.Role
	}
	if roles["10.0.0.9"] != RoleProxy {
		t.Fatalf("主控机角色错误: %+v", roles)
	}
	if roles["10.0.0.1"] != RoleAgent || roles["10.0.0.2"] != RoleAgent {
		t.Fatalf("受控机应来自 webs+supports: %+v", roles)
	}

	// 配了 agent_hosts 就只认它
	cfg.Monitor.AgentHosts = []config.Host{{Host: "10.0.0.5"}}
	ts = Targets(cfg)
	for _, x := range ts {
		if x.Role == RoleAgent && x.Host.Host != "10.0.0.5" {
			t.Fatalf("agent_hosts 已配置时不应回落到 webs: %+v", x)
		}
	}
}

func TestAgentServiceEval(t *testing.T) {
	c := check(t, "agent-service")
	fs, _ := c.Evaluate(Env{}, "service=failed\nPROCESS=DOWN\n")
	if len(fs) != 1 || fs[0].Severity != inspect.SevError {
		t.Fatalf("服务与进程都异常应 error: %+v", fs)
	}
	fs, _ = c.Evaluate(Env{}, "service=active\nPROCESS=RUNNING\n")
	if len(fs) != 0 {
		t.Fatalf("正常不应报: %+v", fs)
	}
	fs, _ = c.Evaluate(Env{}, "service=active\nPROCESS=DOWN\n")
	if len(fs) != 1 || fs[0].Severity != inspect.SevWarn {
		t.Fatalf("active 但无进程应 warn: %+v", fs)
	}
}

func TestAgentConfEval(t *testing.T) {
	c := check(t, "agent-conf")
	cfg := &config.Config{Monitor: &config.Monitor{}}
	env := Env{Cfg: cfg}

	fs, _ := c.Evaluate(env, "MISSING\n")
	if len(fs) != 1 || fs[0].Severity != inspect.SevError {
		t.Fatalf("配置缺失应 error: %+v", fs)
	}
	fs, _ = c.Evaluate(env, "Server=1.2.3.4\nHostname=proj\nInclude=/etc/zabbix/zabbix_agentd.d/*.conf\n")
	if len(fs) != 0 {
		t.Fatalf("完整配置不应报: %+v", fs)
	}
	fs, _ = c.Evaluate(env, "Server=1.2.3.4\n")
	if len(fs) != 2 {
		t.Fatalf("缺 Hostname/Include 应报 2 条: %+v", fs)
	}
}

func TestPSKEval(t *testing.T) {
	c := check(t, "psk")
	fs, _ := c.Evaluate(Env{}, "psk=absent\n")
	if len(fs) != 1 || fs[0].Severity != inspect.SevInfo {
		t.Fatalf("未启用 PSK 应 info: %+v", fs)
	}
	fs, _ = c.Evaluate(Env{}, "psk=present\nmode=644\n")
	if len(fs) != 1 || fs[0].Severity != inspect.SevError {
		t.Fatalf("PSK 权限非 600 应 error: %+v", fs)
	}
	fs, _ = c.Evaluate(Env{}, "psk=present\nmode=600\n")
	if len(fs) != 0 {
		t.Fatalf("PSK 正常不应报: %+v", fs)
	}
}

func TestBackupDirsEval(t *testing.T) {
	c := check(t, "backup-dirs")
	fs, _ := c.Evaluate(Env{}, "present=0\n")
	if len(fs) != 1 || fs[0].Severity != inspect.SevWarn {
		t.Fatalf("清单缺失应 warn: %+v", fs)
	}
	fs, _ = c.Evaluate(Env{}, "present=1\nlines=0\n")
	if len(fs) != 1 {
		t.Fatalf("清单为空应 warn: %+v", fs)
	}
	fs, _ = c.Evaluate(Env{}, "present=1\nlines=3\n")
	if len(fs) != 0 {
		t.Fatalf("正常不应报: %+v", fs)
	}
}

func TestProxyAndCloudChecks(t *testing.T) {
	c := check(t, "proxy-service")
	fs, _ := c.Evaluate(Env{}, "service=inactive\nPROCESS=DOWN\n")
	if len(fs) != 1 || fs[0].Severity != inspect.SevError {
		t.Fatalf("proxy 未运行应 error: %+v", fs)
	}

	cc := check(t, "cloud-connectivity")
	cfg := &config.Config{Monitor: &config.Monitor{Server: "zabbix.example.com", ServerPort: 7001}}
	env := Env{Cfg: cfg}
	fs, _ = cc.Evaluate(env, "CONNECT=FAIL\n")
	if len(fs) != 1 || fs[0].Severity != inspect.SevError {
		t.Fatalf("云中心连不通应 error: %+v", fs)
	}
	fs, _ = cc.Evaluate(env, "CONNECT=OK\n")
	if len(fs) != 0 {
		t.Fatalf("连通不应报: %+v", fs)
	}
	cmd, err := cc.Command(env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, "zabbix.example.com") || !strings.Contains(cmd, "7001") {
		t.Fatalf("连通性命令参数错误: %s", cmd)
	}
}

func TestFixPlanAndWhitelist(t *testing.T) {
	results := []inspect.Result{
		{Host: "10.0.0.1", Findings: []inspect.Finding{
			{Host: "10.0.0.1", Check: "agent-service", Severity: inspect.SevError, Message: "agent 未运行"},
			{Host: "10.0.0.1", Check: "agent-port", Severity: inspect.SevError, Message: "端口未监听"},
		}},
		{Host: "10.0.0.9", Findings: []inspect.Finding{
			{Host: "10.0.0.9", Check: "proxy-service", Severity: inspect.SevError, Message: "proxy 未运行"},
		}},
	}
	plan := FixPlan(results)
	if len(plan) != 2 {
		t.Fatalf("应生成 2 条修复动作: %+v", plan)
	}
	for _, a := range plan {
		cmd, err := FixCommand(a)
		if err != nil {
			t.Fatalf("白名单动作应通过: %v", err)
		}
		if !strings.HasPrefix(cmd, "systemctl restart zabbix-") {
			t.Fatalf("修复命令异常: %s", cmd)
		}
	}
	if _, err := FixCommand(FixAction{Host: config.Host{Host: "10.0.0.1"}, Cmd: "rm -rf /"}); err == nil {
		t.Fatal("白名单外动作必须拒绝")
	}
	if _, err := FixCommand(FixAction{Host: config.Host{Host: "10.0.0.1;ls"}, Cmd: "systemctl start zabbix-agent"}); err == nil {
		t.Fatal("非法主机地址必须拒绝")
	}
}

func TestResultsWithFakeConn(t *testing.T) {
	// 只跑 agent-service：命令固定，输出按需返回
	c := check(t, "agent-service")
	cmd, _ := c.Command(Env{})
	conn := fakeConn{byCmd: map[string]string{cmd: "service=active\nPROCESS=RUNNING\n"}}
	cfg := &config.Config{}
	targets := []Target{{Host: config.Host{Host: "10.0.0.1"}, Role: RoleAgent}}
	out := Results(cfg, targets, func(config.Host) (inspect.Conn, error) { return conn, nil })
	agentChecks := 0
	for _, c := range Checks() {
		if c.ForRole == RoleAgent {
			agentChecks++
		}
	}
	if len(out) != agentChecks {
		t.Fatalf("结果数应为全部 agent 检查项 %d，实际 %d", agentChecks, len(out))
	}
	if out[0].Host != "10.0.0.1" {
		t.Fatalf("主机归属错误: %+v", out[0])
	}
}

type fakeConn struct{ byCmd map[string]string }

func (f fakeConn) Run(cmd string) (string, error) { return f.byCmd[cmd], nil }

func check(t *testing.T, name string) Check {
	t.Helper()
	for _, c := range Checks() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("诊断项不存在: %s", name)
	return Check{}
}
