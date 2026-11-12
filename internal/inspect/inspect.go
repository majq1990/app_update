// Package inspect 实现「项目巡检」：以 SSH 直连在目标主机执行检查命令，
// 回收结构化指标与异常项，输出终端摘要 / JSON 报告。
//
// 定位（与规划一致）：把 auto-check 的检查资产迁进来的执行内核——
// 不依赖 Ansible、不往目标机下发二进制；检查项在 Go 侧定义「命令 + 解析 + 阈值」，
// 解析函数是纯函数，便于单测与两工具结果比对。
//
// 只读原则：所有检查命令仅做读取（cat/ss/df/ps/grep/awk），
// 不含任何变更操作；需要变更的修复动作一律不在本包实现。
package inspect

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
)

// Dimension 检查维度。
type Dimension string

const (
	DimOS         Dimension = "os"
	DimSecurity   Dimension = "security"
	DimMiddleware Dimension = "middleware"
)

// Severity 严重级别（字符串便于 JSON 与人工核对）。
type Severity string

const (
	SevOK       Severity = "ok"
	SevInfo     Severity = "info"
	SevWarn     Severity = "warn"
	SevError    Severity = "error"
	SevCritical Severity = "critical"
)

// rank 级别排序：越高越严重。
func rank(s Severity) int {
	switch s {
	case SevCritical:
		return 4
	case SevError:
		return 3
	case SevWarn:
		return 2
	case SevInfo:
		return 1
	default:
		return 0
	}
}

// Target 一台巡检目标（同一 IP 可能因应用与支持软件出现多次）。
type Target struct {
	Host        config.Host
	App         string // 应用名（应用目标）
	MiddleType  string // tomcat | jar
	SupportKind string // 支持软件 kind（支持软件目标）
}

// Label 目标显示名。
func (t Target) Label() string {
	if t.App != "" {
		return t.App + "@" + t.Host.Host
	}
	return t.SupportKind + "@" + t.Host.Host
}

// Targets 从配置展开巡检目标（应用主机 + 支持软件主机，按主机+角色去重）。
func Targets(c *config.Config) []Target {
	var out []Target
	seen := map[string]bool{}
	push := func(key string, t Target) {
		if t.Host.Host == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, t)
	}
	for i := range c.Webs {
		app := &c.Webs[i]
		for _, g := range []string{config.GroupMaster, config.GroupUpdate, config.GroupStatic} {
			for _, h := range app.GroupHosts(g) {
				push(h.Host+"\x00app\x00"+app.Web, Target{
					Host: h, App: app.Web, MiddleType: app.MiddleType,
				})
			}
		}
	}
	for i := range c.Supports {
		s := &c.Supports[i]
		for _, h := range s.Hosts {
			push(h.Host+"\x00sup\x00"+s.Kind, Target{
				Host: h, SupportKind: s.Kind,
			})
		}
	}
	return out
}

// Metric 一条采集指标（不一定异常）。
type Metric struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Unit  string `json:"unit,omitempty"`
}

// Finding 一条异常项。
type Finding struct {
	Host      string   `json:"host"`
	Target    string   `json:"target,omitempty"`
	Check     string   `json:"check"`
	Dimension string   `json:"dimension"`
	Severity  Severity `json:"severity"`
	Metric    string   `json:"metric,omitempty"`
	Value     string   `json:"value,omitempty"`
	Threshold string   `json:"threshold,omitempty"`
	Message   string   `json:"message"`
	Ref       string   `json:"ref,omitempty"`
}

// Result 单主机单检查的执行结果。
type Result struct {
	Host       string    `json:"host"`
	Target     string    `json:"target,omitempty"`
	Check      string    `json:"check"`
	Dimension  string    `json:"dimension"`
	Metrics    []Metric  `json:"metrics,omitempty"`
	Findings   []Finding `json:"findings,omitempty"`
	Err        string    `json:"error,omitempty"`
	DurationMs int64     `json:"duration_ms"`
}

// Env 检查执行上下文。
type Env struct {
	Target Target
	Cfg    *config.Config
}

// Check 一个检查项。
//   - Applies 决定该目标是否需要跑本检查；
//   - HostScoped 表示主机级检查（OS/安全）：同一主机只跑一次，
//     不随应用目标重复（实弹发现：7 个应用会各自报一遍 sshd/sudoers）；
//   - Asset 非空表示资产脚本检查：脚本内容经 stdin 下发（bash -s / python3 -），
//     不进 shell 解释；Command 返回完整远端命令（含解释器与参数）；
//   - Applies 返回 false 表示该目标不跑本检查；带 Applies 的检查不强制 HostScoped
//     （如按应用扫描漏洞 jar 的资产检查）；
//   - Command 返回只读远端命令；
//   - Evaluate 解析输出，产出指标与异常（纯函数，便于单测）。
type Check struct {
	Name        string
	Dimension   Dimension
	Description string
	HostScoped  bool
	Asset       string // internal/inspect/assets/autocheck/ 下的资产文件名（空=内置命令检查）
	Applies     func(Env) bool
	Command     func(Env) (string, error)
	Evaluate    func(Env, string) ([]Metric, []Finding, error)
}

// registry 全部内置检查项。
var registry []Check

// register 由各 checks_*.go 在 init 中登记。
// 规则：os / security 维度天然是主机级检查，统一标记 HostScoped，
// 由 Runner 按主机去重（实弹教训：18 个应用会把 sshd/sudoers 重复报 18 遍）；
// 带 Applies 的检查（按应用/按条件筛选）不强制。
func register(c Check) {
	if (c.Dimension == DimOS || c.Dimension == DimSecurity) && c.Applies == nil {
		c.HostScoped = true
	}
	registry = append(registry, c)
}

// StdinRunner 支持脚本下发的连接（sshx.Client 实现）。
type StdinRunner interface {
	RunWithStdin(cmd string, stdin []byte) (string, error)
}

// Checks 返回全部检查项（按维度、名称排序）。
func Checks() []Check {
	out := append([]Check{}, registry...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dimension != out[j].Dimension {
			return out[i].Dimension < out[j].Dimension
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// FilterChecks 按维度集合筛选（空 = 全部）。
func FilterChecks(dims []Dimension) []Check {
	if len(dims) == 0 {
		return Checks()
	}
	want := map[Dimension]bool{}
	for _, d := range dims {
		want[d] = true
	}
	var out []Check
	for _, c := range Checks() {
		if want[c.Dimension] {
			out = append(out, c)
		}
	}
	return out
}

// ParseDims 解析 --dim 参数（os,security,middleware）。
func ParseDims(s string) ([]Dimension, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []Dimension
	for _, p := range strings.Split(s, ",") {
		d := Dimension(strings.TrimSpace(p))
		switch d {
		case DimOS, DimSecurity, DimMiddleware:
			out = append(out, d)
		case "all", "":
			// all/空 = 不筛选
		default:
			return nil, fmt.Errorf("未知维度 %q（可用 os/security/middleware/all）", p)
		}
	}
	return out, nil
}

// Conn 远端执行接口（sshx.Client 直接满足）。
type Conn interface {
	Run(cmd string) (string, error)
}

// Runner 并发执行器。
type Runner struct {
	Dial     func(config.Host) (Conn, error)
	Parallel int
}

// Run 对每个目标执行适用的检查，返回按 主机→检查 排序的结果。
func (r Runner) Run(cfg *config.Config, targets []Target, checks []Check) []Result {
	par := r.Parallel
	if par < 1 {
		par = 4
	}
	type job struct {
		t          Target
		c          Check
		hostScoped bool
	}
	var jobs []job
	seenHostCheck := map[string]bool{}
	for _, t := range targets {
		env := Env{Target: t, Cfg: cfg}
		for _, c := range checks {
			if c.Applies != nil && !c.Applies(env) {
				continue
			}
			hostScoped := c.HostScoped
			if hostScoped {
				// 主机级检查（OS/安全）同主机只跑一次，避免按应用重复报告
				key := t.Host.Host + "\x00" + c.Name
				if seenHostCheck[key] {
					continue
				}
				seenHostCheck[key] = true
			}
			jobs = append(jobs, job{t: t, c: c, hostScoped: hostScoped})
		}
	}

	// 每台主机一个连接，连接内串行；主机间并发。
	byHost := map[string][]job{}
	var hostOrder []string
	for _, j := range jobs {
		h := j.t.Host.Host
		if _, ok := byHost[h]; !ok {
			hostOrder = append(hostOrder, h)
		}
		byHost[h] = append(byHost[h], j)
	}

	var mu sync.Mutex
	var results []Result
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	for _, h := range hostOrder {
		js := byHost[h]
		wg.Add(1)
		go func(host string, js []job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var local []Result
			conn, err := r.Dial(js[0].t.Host)
			if err != nil {
				// 一台主机只报一条连接失败，避免同一错误按检查项重复刷屏
				local = append(local, Result{
					Host: host, Target: js[0].t.Label(), Check: "connection",
					Dimension: "connection", Err: "SSH 连接失败: " + err.Error(),
				})
			} else {
				for _, j := range js {
					local = append(local, runOneScoped(conn, Env{Target: j.t, Cfg: cfg}, j.c, j.hostScoped))
				}
			}
			mu.Lock()
			results = append(results, local...)
			mu.Unlock()
		}(h, js)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].Host != results[j].Host {
			return results[i].Host < results[j].Host
		}
		if results[i].Dimension != results[j].Dimension {
			return results[i].Dimension < results[j].Dimension
		}
		return results[i].Check < results[j].Check
	})
	return results
}

// runOneScoped 执行单个检查（命令构建失败/执行失败都转成 Err，不中断整轮）。
// hostScoped=true 时结果归属到主机（Target 显示为 IP），不挂某个应用标签。
func runOneScoped(conn Conn, env Env, c Check, hostScoped bool) Result {
	target := env.Target.Label()
	if hostScoped {
		target = env.Target.Host.Host
	}
	res := Result{
		Host: env.Target.Host.Host, Target: target,
		Check: c.Name, Dimension: string(c.Dimension),
	}
	if c.Command == nil || c.Evaluate == nil {
		res.Err = "检查项未完整实现（缺 Command/Evaluate）"
		return res
	}
	cmdStr, err := c.Command(env)
	if err != nil {
		res.Err = "构建命令失败: " + err.Error()
		return res
	}
	start := time.Now()
	var out string
	if c.Asset != "" {
		// 资产脚本：内容经 stdin 下发（bash -s / python3 -），不进 shell 解释
		script, ok := assetScript(c.Asset)
		if !ok {
			res.Err = "资产脚本不存在: " + c.Asset
			return res
		}
		sr, ok := conn.(StdinRunner)
		if !ok {
			res.Err = "连接不支持脚本下发（缺 RunWithStdin）"
			return res
		}
		out, err = sr.RunWithStdin(cmdStr, script)
	} else {
		out, err = conn.Run(cmdStr)
	}
	res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		res.Err = "执行失败: " + err.Error()
		return res
	}
	metrics, findings, perr := c.Evaluate(env, out)
	if perr != nil {
		res.Err = "解析失败: " + perr.Error()
		return res
	}
	res.Metrics = metrics
	for i := range findings {
		findings[i].Host = env.Target.Host.Host
		findings[i].Target = target
		findings[i].Check = c.Name
		findings[i].Dimension = string(c.Dimension)
		if findings[i].Severity == "" {
			findings[i].Severity = SevInfo
		}
	}
	res.Findings = findings
	return res
}

// Findings 汇总所有异常项。
func Findings(results []Result) []Finding {
	var out []Finding
	for _, r := range results {
		out = append(out, r.Findings...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rank(out[i].Severity) != rank(out[j].Severity) {
			return rank(out[i].Severity) > rank(out[j].Severity)
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Check < out[j].Check
	})
	return out
}

// Counts 各级别计数。
func Counts(fs []Finding) map[Severity]int {
	m := map[Severity]int{}
	for _, f := range fs {
		m[f.Severity]++
	}
	return m
}

// Worst 最高级别（无异常返回 ok）。
func Worst(fs []Finding) Severity {
	worst := SevOK
	for _, f := range fs {
		if rank(f.Severity) > rank(worst) {
			worst = f.Severity
		}
	}
	return worst
}

// Errors 执行失败的结果（区别于异常项）。
func Errors(results []Result) []Result {
	var out []Result
	for _, r := range results {
		if r.Err != "" {
			out = append(out, r)
		}
	}
	return out
}
