package inspect

// 巡检报告：终端摘要 + JSON（供上传/留档/AI 分析）。
// 报告只呈现事实与分级，不做自动修复建议的承诺（修复动作在硬加固/监控域单独设计）。

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Report 一轮巡检的完整结果。
type Report struct {
	GeneratedAt string         `json:"generated_at"`
	Hosts       int            `json:"hosts"`
	Checks      int            `json:"checks"`
	Results     []Result       `json:"results"`
	Findings    []Finding      `json:"findings"`
	Summary     map[string]int `json:"summary"`
	ExecErrors  []string       `json:"exec_errors,omitempty"`
}

// BuildReport 组装报告。
func BuildReport(results []Result, now time.Time) Report {
	hosts := map[string]bool{}
	checks := map[string]bool{}
	for _, r := range results {
		hosts[r.Host] = true
		checks[r.Check] = true
	}
	fs := Findings(results)
	rep := Report{
		GeneratedAt: now.Format(time.RFC3339),
		Hosts:       len(hosts),
		Checks:      len(checks),
		Results:     results,
		Findings:    fs,
		Summary:     map[string]int{},
	}
	for sev, n := range Counts(fs) {
		rep.Summary[string(sev)] = n
	}
	for _, r := range Errors(results) {
		rep.ExecErrors = append(rep.ExecErrors, fmt.Sprintf("%s %s: %s", r.Host, r.Check, r.Err))
	}
	sort.Strings(rep.ExecErrors)
	return rep
}

// JSON 序列化（两空格缩进）。
func (r Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// Text 终端报告：按主机分组，异常按级别排序；末尾统计。
func (r Report) Text(w io.Writer) {
	t, _ := time.Parse(time.RFC3339, r.GeneratedAt)
	fmt.Fprintf(w, "\n========== 巡检报告 %s ==========\n", t.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "主机 %d 台 / 检查项 %d 个\n", r.Hosts, r.Checks)

	// 按主机归集
	byHost := map[string][]Finding{}
	var hosts []string
	for _, f := range r.Findings {
		if _, ok := byHost[f.Host]; !ok {
			hosts = append(hosts, f.Host)
		}
		byHost[f.Host] = append(byHost[f.Host], f)
	}
	sort.Strings(hosts)

	// 无异常的主机也列出（用结果计数）
	hostResults := map[string]int{}
	for _, res := range r.Results {
		hostResults[res.Host]++
	}
	var clean []string
	for h := range hostResults {
		if _, ok := byHost[h]; !ok {
			clean = append(clean, h)
		}
	}
	sort.Strings(clean)

	for _, h := range hosts {
		fmt.Fprintf(w, "\n主机 %s：\n", h)
		for _, f := range byHost[h] {
			label := severityLabel(f.Severity)
			msg := f.Message
			if f.Target != "" && !strings.HasPrefix(f.Target, f.Host) {
				msg = "（" + f.Target + "）" + msg
			}
			fmt.Fprintf(w, "  %s %-22s %s\n", label, f.Check, msg)
		}
	}
	for _, h := range clean {
		fmt.Fprintf(w, "\n主机 %s：未发现异常（%d 项检查）\n", h, hostResults[h])
	}
	if len(r.ExecErrors) > 0 {
		fmt.Fprintln(w, "\n执行失败：")
		for _, e := range r.ExecErrors {
			fmt.Fprintln(w, "  ⚠️", e)
		}
	}

	sevCount := func(s Severity) int { return r.Summary[string(s)] }
	fmt.Fprintf(w, "\n汇总：严重 %d / 错误 %d / 预警 %d / 提示 %d；执行失败 %d\n",
		sevCount(SevCritical), sevCount(SevError), sevCount(SevWarn), sevCount(SevInfo), len(r.ExecErrors))
}

func severityLabel(s Severity) string {
	switch s {
	case SevCritical:
		return "❗严重"
	case SevError:
		return "❌错误"
	case SevWarn:
		return "⚠️预警"
	case SevInfo:
		return "ℹ️提示"
	default:
		return "✅正常"
	}
}

// Highest 最高级别文案（CLI 退出码用）。
func (r Report) Highest() Severity {
	return Worst(r.Findings)
}
