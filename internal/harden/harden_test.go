package harden

import (
	"strings"
	"testing"
	"time"

	"github.com/majq1990/app-updater-go/internal/inspect"
)

func finding(host, check string, sev inspect.Severity, msg string) inspect.Finding {
	return inspect.Finding{Host: host, Target: "a@" + host, Check: check,
		Dimension: "security", Severity: sev, Message: msg}
}

func TestBuildMapsSecurityFindings(t *testing.T) {
	now := time.Date(2026, 11, 6, 15, 0, 0, 0, time.UTC)
	results := []inspect.Result{
		{Host: "10.0.0.1", Findings: []inspect.Finding{
			finding("10.0.0.1", "ssh-policy", inspect.SevWarn, "sshd 允许 root 直接登录"),
			finding("10.0.0.1", "account-empty-password", inspect.SevCritical, "存在空口令账户：test"),
			finding("10.0.0.1", "app-port", inspect.SevError, "这不是加固项"),
		}},
		{Host: "10.0.0.1", Findings: []inspect.Finding{
			finding("10.0.0.1", "ssh-policy", inspect.SevWarn, "重复项应去重"),
		}},
	}
	rep := Build(results, now)
	if rep.Summary.Total != 2 {
		t.Fatalf("应映射 2 项（去重 + 排除非加固项），实际 %d: %+v", rep.Summary.Total, rep.Items)
	}
	if rep.Summary.High != 1 || rep.Summary.Medium != 1 {
		t.Fatalf("风险分布错误: %+v", rep.Summary)
	}
	if rep.Summary.Autoable != 0 {
		t.Fatalf("首期不应有可自动执行项: %+v", rep.Summary)
	}
	if rep.Items[0].Risk != RiskHigh {
		t.Fatalf("高危项应排在最前: %+v", rep.Items[0])
	}
	for _, it := range rep.Items {
		if it.Action == "" || it.Title == "" || it.Evidence == "" {
			t.Fatalf("加固项缺少要素: %+v", it)
		}
	}
}

func TestSnippetsDedupAndContent(t *testing.T) {
	res := []inspect.Result{{Host: "10.0.0.1", Findings: []inspect.Finding{
		finding("10.0.0.1", "ssh-policy", inspect.SevWarn, "root 登录"),
		finding("10.0.0.1", "kernel-network-params", inspect.SevWarn, "syncookies=0"),
		finding("10.0.0.1", "ports-exposure", inspect.SevWarn, "3306 暴露"),
	}}}
	rep := Build(res, time.Now())
	sn := rep.Snippets()
	if len(sn) != 3 {
		t.Fatalf("应有 3 组片段: %+v", sn)
	}
	joined := ""
	for _, s := range sn {
		joined += s.Snippet
	}
	for _, want := range []string{"PermitRootLogin", "tcp_syncookies", "firewall-cmd"} {
		if !strings.Contains(joined, want) {
			t.Errorf("片段缺少 %q\n%s", want, joined)
		}
	}
}

func TestReportTextAndJSON(t *testing.T) {
	var empty strings.Builder
	Build(nil, time.Now()).Text(&empty)
	if !strings.Contains(empty.String(), "未发现需要加固的项") {
		t.Fatalf("空报告文案错误: %s", empty.String())
	}

	res := []inspect.Result{{Host: "10.0.0.1", Findings: []inspect.Finding{
		finding("10.0.0.1", "ssh-policy", inspect.SevWarn, "root 登录"),
	}}}
	rep := Build(res, time.Now())
	var b strings.Builder
	rep.Text(&b)
	out := b.String()
	for _, want := range []string{"10.0.0.1", "SSH 登录策略加固", "现象：", "建议：", "不自动修改"} {
		if !strings.Contains(out, want) {
			t.Errorf("文本报告缺少 %q\n%s", want, out)
		}
	}
	if !strings.Contains(out, "可能影响当前 SSH 连接") {
		t.Errorf("SSH 加固项应提示连接风险:\n%s", out)
	}
	js, err := rep.JSON()
	if err != nil || !strings.Contains(string(js), "\"items\"") {
		t.Fatalf("JSON 输出异常: %v %s", err, js)
	}
}
