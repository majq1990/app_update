package inspect

// assets_autocheck.go —— auto-check 检查资产的接入（第一轮：安全 6 项）。
//
// 资产来源与同步：tools/sync-autocheck-assets.sh
//   gitlab.egova.com.cn:devops/auto-check @ origin/master → assets/autocheck/
//   脚本内容经 stdin 下发（bash -s / python3 -），零目标机依赖、零注入面。
// 输出解析分三类：
//   legacy    —— {"basic","topics"} key-DSL（parseLegacyTopics，语义随上游
//                internal/result/normalize.go 同步，见 legacy.go 头注）
//   kernelcve —— check-kernel-cve.sh --json 的扁平 schema
//   vulnjar   —— check_vulnerable_jar.py 的扫描汇总 schema

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

//go:embed assets/autocheck/manifest.json
var autocheckManifestJSON []byte

//go:embed assets/autocheck/security-port.sh
var assetSecurityPort []byte

//go:embed assets/autocheck/security-login.sh
var assetSecurityLogin []byte

//go:embed assets/autocheck/security-agent.sh
var assetSecurityAgent []byte

//go:embed assets/autocheck/interface-interception.sh
var assetInterfaceInterception []byte

//go:embed assets/autocheck/kernel-cve.sh
var assetKernelCve []byte

//go:embed assets/autocheck/vulnerable-jar.py
var assetVulnerableJar []byte

// assetScripts 资产名 → 脚本内容。
var assetScripts = map[string][]byte{
	"security-port.sh":          assetSecurityPort,
	"security-login.sh":         assetSecurityLogin,
	"security-agent.sh":         assetSecurityAgent,
	"interface-interception.sh": assetInterfaceInterception,
	"kernel-cve.sh":             assetKernelCve,
	"vulnerable-jar.py":         assetVulnerableJar,
}

func assetScript(file string) ([]byte, bool) {
	b, ok := assetScripts[file]
	return b, ok
}

// AutocheckManifest 供文档/CLI 展示资产同步状态。
type AutocheckManifest struct {
	Source   string                     `json:"source"`
	Commit   string                     `json:"commit"`
	SyncedAt string                     `json:"synced_at"`
	Files    map[string]json.RawMessage `json:"files"`
}

// LoadAutocheckManifest 解析嵌入的 manifest。
func LoadAutocheckManifest() (AutocheckManifest, error) {
	var m AutocheckManifest
	err := json.Unmarshal(autocheckManifestJSON, &m)
	return m, err
}

// acQ 单引号强引用（资产命令参数；路径已过配置白名单，这里防嵌套引号）。
func acQ(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// assetSpec 一项资产检查的定义。
type assetSpec struct {
	name    string // 检查名（ac- 前缀）
	file    string // 资产文件名
	desc    string
	kind    string // legacy | kernelcve | vulnjar
	applies func(Env) bool
	args    func(Env) (string, error) // 解释器后的参数（可含配置派生路径）
}

func assetChecks() []assetSpec {
	return []assetSpec{
		{
			name: "ac-security-port", file: "security-port.sh", kind: "legacy",
			desc: "端口加固检查：ipset/vpc 白名单/默认丢弃策略（auto-check security-port）",
		},
		{
			name: "ac-security-login", file: "security-login.sh", kind: "legacy",
			desc: "近 30 天登录失败 TOP 来源 IP 与用户名（auto-check check_security_login）",
		},
		{
			name: "ac-security-agent", file: "security-agent.sh", kind: "legacy",
			desc: "安全 agent 进程存在性（auto-check check_security_agent）",
		},
		{
			name: "ac-interface-interception", file: "interface-interception.sh", kind: "legacy",
			desc: "nginx 接口拦截抽测（auto-check check-interface_interception）",
		},
		{
			name: "ac-kernel-cve", file: "kernel-cve.sh", kind: "kernelcve",
			desc: "内核高危 CVE 检查（缓解感知：CVE-2026-31431 等 6 项）",
			args: func(Env) (string, error) { return "--json", nil },
		},
		{
			name: "ac-vulnerable-jar", file: "vulnerable-jar.py", kind: "vulnjar",
			desc: "漏洞 jar 扫描（log4j 等；按应用部署目录）",
			applies: func(e Env) bool {
				return e.Target.App != "" && strings.TrimSpace(e.Target.Host.WebPath) != ""
			},
			args: func(e Env) (string, error) {
				wp := strings.TrimRight(strings.TrimSpace(e.Target.Host.WebPath), "/")
				if wp == "" || strings.ContainsAny(wp, "\x00\n\r'\"`$;&|<>(){}") {
					return "", fmt.Errorf("web_path 含非法字符: %q", e.Target.Host.WebPath)
				}
				return "--scan-dirs " + acQ(wp) + " --no-containers", nil
			},
		},
	}
}

func init() {
	for _, spec := range assetChecks() {
		spec := spec
		register(Check{
			Name:        spec.name,
			Dimension:   DimSecurity,
			Description: spec.desc,
			Asset:       spec.file,
			Applies:     spec.applies,
			Command: func(e Env) (string, error) {
				interp := "bash"
				if strings.HasSuffix(spec.file, ".py") {
					interp = "python3"
				}
				args := ""
				if spec.args != nil {
					a, err := spec.args(e)
					if err != nil {
						return "", err
					}
					args = a
				}
				if args != "" {
					return interp + " -s " + spec.file + " " + args, nil
				}
				return interp + " -s " + spec.file, nil
			},
			Evaluate: func(e Env, out string) ([]Metric, []Finding, error) {
				switch spec.kind {
				case "kernelcve":
					return parseKernelCveJSON(e.Target.Host.Host, []byte(out))
				case "vulnjar":
					return parseVulnJarJSON(e.Target.Host.Host, []byte(out))
				default:
					return parseLegacyTopics(e.Target.Host.Host, spec.name, []byte(out))
				}
			},
		})
	}
}

// parseKernelCveJSON 解析 check-kernel-cve.sh --json 的扁平 schema。
func parseKernelCveJSON(host string, data []byte) ([]Metric, []Finding, error) {
	payload := extractJSON(data)
	if payload == nil {
		return nil, nil, fmt.Errorf("未找到 JSON 结果")
	}
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, nil, fmt.Errorf("JSON 解析失败: %v", err)
	}
	verdict, _ := doc["kernel_vuln_status"].(string)
	vcount, _ := doc["vulnerable_count"].(float64)
	kernel, _ := doc["kernel"].(string)
	vulnList, _ := doc["vulnerable_cves"].(string)
	note, _ := doc["mitigation_note"].(string)

	ms := []Metric{
		{Name: "kernel", Value: kernel},
		{Name: "vulnerable_count", Value: strconv.Itoa(int(vcount))},
		{Name: "verdict", Value: verdict},
	}
	mk := func(sev Severity, msg string) []Finding {
		return []Finding{{Host: host, Target: host, Check: "ac-kernel-cve",
			Dimension: string(DimSecurity), Severity: sev, Metric: "kernel_vulnerable",
			Value:   fmt.Sprintf("%d/%d", int(vcount), len(strings.Split(doc["cve"].(string), ","))),
			Message: msg}}
	}
	switch verdict {
	case "VULNERABLE":
		extra := ""
		if !boolOf(doc["mitigation_reliable"]) {
			extra = "；缓解措施不可靠"
		}
		return ms, mk(SevError, fmt.Sprintf("内核存在未缓解高危漏洞（%s）：%s%s",
			kernel, vulnList, extra)), nil
	case "UNKNOWN":
		return ms, mk(SevWarn, fmt.Sprintf("内核漏洞状态无法判定：%s", note)), nil
	}
	return ms, nil, nil
}

func boolOf(v any) bool {
	b, _ := v.(bool)
	return b
}

// parseVulnJarJSON 解析 check_vulnerable_jar.py 的扫描汇总。
// 脚本 stdout 前若干行为进度文本，最后一个 JSON 对象才是结果。
func parseVulnJarJSON(host string, data []byte) ([]Metric, []Finding, error) {
	payload := extractJSON(data)
	if payload == nil {
		return nil, nil, fmt.Errorf("未找到 JSON 结果")
	}
	var doc struct {
		VulnerableJarCheck struct {
			ScanSummary struct {
				TotalVulnerabilities int `json:"total_vulnerabilities"`
				ScanProcesses        int `json:"scan_processes,omitempty"`
			} `json:"scan_summary"`
		} `json:"vulnerable_jar_check"`
		ScanTime string `json:"scan_time"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, nil, fmt.Errorf("JSON 解析失败: %v", err)
	}
	total := doc.VulnerableJarCheck.ScanSummary.TotalVulnerabilities
	ms := []Metric{
		{Name: "vulnerable_jars", Value: strconv.Itoa(total)},
		{Name: "scan_time", Value: doc.ScanTime},
	}
	if total > 0 {
		return ms, []Finding{{Host: host, Target: host, Check: "ac-vulnerable-jar",
			Dimension: string(DimSecurity), Severity: SevError, Metric: "vulnerable_jars",
			Value:   strconv.Itoa(total),
			Message: fmt.Sprintf("发现 %d 个漏洞 jar（明细见完整 JSON 报告）", total)}}, nil
	}
	return ms, nil, nil
}
