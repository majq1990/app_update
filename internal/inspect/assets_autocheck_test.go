package inspect

// assets_autocheck_test.go —— 资产检查接入测试：
// 注册完整性 / manifest / 三类解析器 / stdin 下发链路。

import (
	"strings"
	"testing"

	"github.com/majq1990/app-updater-go/internal/config"
)

func TestAssetChecksRegistered(t *testing.T) {
	man, err := LoadAutocheckManifest()
	if err != nil {
		t.Fatalf("manifest 解析失败: %v", err)
	}
	if man.Commit == "" || len(man.Files) < 6 {
		t.Fatalf("manifest 不完整: %+v", man)
	}
	for _, spec := range assetChecks() {
		c := checkByName(t, spec.name)
		if c.Asset != spec.file {
			t.Fatalf("%s 资产文件不符: %q", spec.name, c.Asset)
		}
		script, ok := assetScript(c.Asset)
		if !ok || len(script) < 200 {
			t.Fatalf("%s 嵌入脚本缺失/过小: %d bytes", c.Asset, len(script))
		}
	}
}

func TestKernelCveParser(t *testing.T) {
	sample := `[2026-11-12 10:00:00] 检测中...` + "\n" + `{
	  "hostname": "node1",
	  "kernel": "4.19.90-52.22.v2207.ky10.x86_64",
	  "kernel_numeric": "4.19.90",
	  "distro_id": "kylin",
	  "distro_ver": "V10",
	  "cve": "CVE-2026-31431,CVE-2025-39964",
	  "cve_count": 6,
	  "vulnerable_count": 1,
	  "vulnerable_cves": "CVE-2026-31431",
	  "kernel_vuln_status": "VULNERABLE",
	  "pkg_check": "found",
	  "pkg_ver": "4.19.90-52.22.v2207.ky10.1",
	  "mitigated": true,
	  "mitigation_reliable": false,
	  "mitigation_note": "已安装修复包但未重启",
	  "verdict": "VULNERABLE",
	  "results": []
	}`
	ms, fs, err := parseKernelCveJSON("10.0.0.1", DimSecurity, []byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Severity != SevError {
		t.Fatalf("VULNERABLE 应报 error: %+v", fs)
	}
	if !strings.Contains(fs[0].Message, "CVE-2026-31431") || !strings.Contains(fs[0].Message, "缓解措施不可靠") {
		t.Fatalf("错误消息缺要素: %s", fs[0].Message)
	}
	if len(ms) != 3 {
		t.Fatalf("指标数错误: %+v", ms)
	}

	// 已修复 → 不报
	sampleOK := strings.Replace(sample, `"kernel_vuln_status": "VULNERABLE"`, `"kernel_vuln_status": "PATCHED"`, 1)
	sampleOK = strings.Replace(sampleOK, `"vulnerable_count": 1,`, `"vulnerable_count": 0,`, 1)
	sampleOK = strings.Replace(sampleOK, `"verdict": "VULNERABLE"`, `"verdict": "PATCHED"`, 1)
	_, fs2, err := parseKernelCveJSON("10.0.0.1", DimSecurity, []byte(sampleOK))
	if err != nil || len(fs2) != 0 {
		t.Fatalf("已修复不应报: %+v %v", fs2, err)
	}

	// UNKNOWN → warn
	sampleUn := strings.Replace(sample, `"kernel_vuln_status": "VULNERABLE"`, `"kernel_vuln_status": "UNKNOWN"`, 1)
	sampleUn = strings.Replace(sampleUn, `"verdict": "VULNERABLE"`, `"verdict": "UNKNOWN"`, 1)
	sampleUn = strings.Replace(sampleUn, `"vulnerable_count": 1,`, `"vulnerable_count": 0,`, 1)
	_, fs3, _ := parseKernelCveJSON("10.0.0.1", DimSecurity, []byte(sampleUn))
	if len(fs3) != 1 || fs3[0].Severity != SevWarn {
		t.Fatalf("UNKNOWN 应报 warn: %+v", fs3)
	}
}

func TestVulnJarParser(t *testing.T) {
	out := "开始扫描漏洞jar包...\n扫描目录: /egova/apps/basic/eurbanpro\n" +
		"扫描完成，发现 3 个漏洞\n" +
		"  {\n" +
		"    \"vulnerable_jar_check\": {\n" +
		"      \"scan_summary\": {\"total_vulnerabilities\": 3, \"scan_processes\": 2}\n" +
		"    },\n" +
		"    \"scan_time\": \"2026-11-12 10:00:00\"\n" +
		"  }"
	ms, fs, err := parseVulnJarJSON("10.0.0.1", DimSecurity, []byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Severity != SevError {
		t.Fatalf("3 个漏洞应报 error: %+v", fs)
	}
	if len(ms) != 2 || ms[0].Value != "3" {
		t.Fatalf("指标错误: %+v", ms)
	}

	zero := strings.Replace(out, `"total_vulnerabilities": 3`, `"total_vulnerabilities": 0`, 1)
	_, fs2, _ := parseVulnJarJSON("10.0.0.1", DimSecurity, []byte(zero))
	if len(fs2) != 0 {
		t.Fatalf("0 漏洞不应报: %+v", fs2)
	}
}

// stdin 下发链路：fakeConn 实现 RunWithStdin，验证资产执行→解析→结果归属
type stdinFakeConn struct {
	script   string
	stdinRun int
	out      string
}

func (c *stdinFakeConn) Run(cmd string) (string, error) { return c.out, nil }
func (c *stdinFakeConn) RunWithStdin(cmd string, in []byte) (string, error) {
	c.stdinRun++
	c.script = string(in)
	return c.out, nil
}

func TestAssetCheckEndToEndViaStdin(t *testing.T) {
	c := checkByName(t, "ac-security-agent")
	if c.Asset == "" {
		t.Fatal("ac-security-agent 应是资产检查")
	}
	cmd, err := c.Command(Env{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, "cat > \"$f\"") || !strings.Contains(cmd, `bash "$f"`) {
		t.Fatalf("命令形态错误（应落临时文件后执行，避免子进程抢 stdin）: %s", cmd)
	}
	conn := &stdinFakeConn{out: `{"basic":{},"topics":{"01:java_process_count":[{"01:count::DATA_eq_0:#17730": 0}],"02:processes":[]}}`}
	res := runOneScoped(conn, Env{Target: Target{Host: config.Host{Host: "10.0.0.1"}, SupportKind: "security"}}, c, true)
	if res.Err != "" {
		t.Fatalf("不应有错误: %+v", res)
	}
	if conn.stdinRun != 1 {
		t.Fatalf("应经 stdin 下发一次: %d", conn.stdinRun)
	}
	if !strings.Contains(conn.script, "get_top_failed") && !strings.Contains(conn.script, "main") {
		t.Fatalf("下发的不是资产脚本内容: %.80s", conn.script)
	}
	// DSL 语义：表达式为真 = 告警。security-agent 的告警条件是 count==0（无安全 agent 进程）
	if len(res.Findings) != 1 || res.Findings[0].Severity != SevWarn {
		t.Fatalf("count=0（无 agent 进程）应报 1 条 warn: %+v", res.Findings)
	}

	// 触发场景
	conn2 := &stdinFakeConn{out: `{"basic":{},"topics":{"01:java_process_count":[{"01:count::DATA_eq_0:#17730": 3}],"02:processes":[]}}`}
	res2 := runOneScoped(conn2, Env{Target: Target{Host: config.Host{Host: "10.0.0.2"}, SupportKind: "security"}}, c, true)
	if len(res2.Findings) != 0 {
		t.Fatalf("count=3（agent 在跑）不应报: %+v", res2.Findings)
	}
}

// vulnjar 的 Applies/Command：按应用、扫描目录来自 web_path、参数带白名单引用
func TestVulnJarAppliesAndArgs(t *testing.T) {
	c := checkByName(t, "ac-vulnerable-jar")
	if c.HostScoped {
		t.Fatal("vulnjar 是按应用检查，不应 HostScoped")
	}
	env := Env{Target: Target{App: "eurbanpro", Host: config.Host{Host: "10.0.0.1", WebPath: "/egova/apps/basic/eurbanpro"}}}
	if !c.Applies(env) {
		t.Fatal("应用目标应命中 Applies")
	}
	if c.Applies(Env{Target: Target{SupportKind: "mysql", Host: config.Host{Host: "10.0.0.3"}}}) {
		t.Fatal("支持软件目标不应命中")
	}
	cmd, err := c.Command(env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, `python3 "$f"`) ||
		!strings.Contains(cmd, `--scan-dirs '/egova/apps/basic/eurbanpro'`) ||
		!strings.Contains(cmd, "--no-containers") {
		t.Fatalf("扫描命令不合规: %s", cmd)
	}
}
