package main

// 巡检子命令：inspect list / run / security。
// 只读：巡检命令全部是读取类（cat/ss/df/ps/grep/awk），不做任何变更。
// 执行内核在 internal/inspect（Go 直连 SSH，不依赖 Ansible）。

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/inspect"
)

func cmdInspect(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: app-updater inspect list|run|security -c config.yaml [选项]")
	}
	switch args[0] {
	case "list":
		return cmdInspectList(args[1:])
	case "run":
		return cmdInspectRun(args[1:], nil)
	case "security":
		dims := []inspect.Dimension{inspect.DimSecurity}
		return cmdInspectRun(args[1:], dims)
	default:
		return fmt.Errorf("未知 inspect 子命令: %s（可用 list|run|security）", args[0])
	}
}

func cmdInspectList(args []string) error {
	fs := flag.NewFlagSet("inspect list", flag.ExitOnError)
	dim := fs.String("dim", "", "只列某维度（os/security/middleware）")
	fs.Parse(args)
	dims, err := inspect.ParseDims(*dim)
	if err != nil {
		return err
	}
	checks := inspect.FilterChecks(dims)
	fmt.Printf("内置巡检项 %d 个：\n\n", len(checks))
	lastDim := ""
	for _, c := range checks {
		if string(c.Dimension) != lastDim {
			lastDim = string(c.Dimension)
			fmt.Printf("[%s]\n", lastDim)
		}
		fmt.Printf("  %-24s %s\n", c.Name, c.Description)
	}
	return nil
}

// cmdInspectRun 执行巡检。presetDims 非空时强制维度（inspect security 快捷入口）。
func cmdInspectRun(args []string, presetDims []inspect.Dimension) error {
	fs := flag.NewFlagSet("inspect run", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	dim := fs.String("dim", "", "维度：os,security,middleware（空=全部；逗号分隔）")
	host := fs.String("host", "all", "主机过滤：IP / all / 逗号分隔")
	jsonOut := fs.String("json", "", "JSON 报告输出路径")
	parallel := fs.Int("parallel", 4, "并发主机数")
	failOn := fs.String("fail-on", "error", "达到该级别返回非零退出码：warn|error|critical|none")
	fs.Parse(args)

	dims := presetDims
	if len(dims) == 0 {
		var err error
		dims, err = inspect.ParseDims(*dim)
		if err != nil {
			return err
		}
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := gateValidation(cfg, false); err != nil {
		return err
	}

	targets := filterInspectTargets(inspect.Targets(cfg), *host)
	if len(targets) == 0 {
		fmt.Println("没有匹配的巡检目标")
		return nil
	}
	checks := inspect.FilterChecks(dims)
	if len(checks) == 0 {
		return fmt.Errorf("没有匹配的检查项")
	}

	fmt.Printf("巡检 %d 个目标 / %d 个检查项（并发 %d）...\n", len(targets), len(checks), *parallel)
	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()

	runner := inspect.Runner{
		Dial:     func(h config.Host) (inspect.Conn, error) { return dial.Dial(h) },
		Parallel: *parallel,
	}
	start := time.Now()
	results := runner.Run(cfg, targets, checks)
	rep := inspect.BuildReport(results, time.Now())
	rep.Text(os.Stdout)
	fmt.Printf("耗时 %s\n", time.Since(start).Round(time.Second))

	if *jsonOut != "" {
		b, jerr := rep.JSON()
		if jerr != nil {
			return jerr
		}
		if werr := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); werr != nil {
			return werr
		}
		fmt.Printf("JSON 报告: %s\n", *jsonOut)
	}

	// 退出码：达到 --fail-on 阈值即失败，便于流水线/批量脚本判定
	switch strings.ToLower(*failOn) {
	case "none", "":
		return nil
	case "warn":
		if rankAtLeast(rep.Findings, inspect.SevWarn) {
			return fmt.Errorf("巡检发现达到 warn 级别的问题")
		}
	case "critical":
		if rankAtLeast(rep.Findings, inspect.SevCritical) {
			return fmt.Errorf("巡检发现 critical 级别问题")
		}
	default: // error
		if rankAtLeast(rep.Findings, inspect.SevError) {
			return fmt.Errorf("巡检发现 error 及以上问题")
		}
	}
	return nil
}

// rankAtLeast 是否存在 >= 给定级别的异常。
func rankAtLeast(fs []inspect.Finding, sev inspect.Severity) bool {
	order := map[inspect.Severity]int{
		inspect.SevOK: 0, inspect.SevInfo: 1, inspect.SevWarn: 2,
		inspect.SevError: 3, inspect.SevCritical: 4,
	}
	for _, f := range fs {
		if order[f.Severity] >= order[sev] {
			return true
		}
	}
	return false
}

// filterInspectTargets 按 --host 过滤（all / IP / 逗号分隔）。
func filterInspectTargets(ts []inspect.Target, hostSel string) []inspect.Target {
	want := parseSet(hostSel)
	if want["all"] {
		return ts
	}
	var out []inspect.Target
	for _, t := range ts {
		if want[t.Host.Host] {
			out = append(out, t)
		}
	}
	return out
}
