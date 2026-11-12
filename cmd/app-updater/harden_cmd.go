package main

// 加固子命令：harden check / snippets / report。
// 只读：harden 首期不执行任何变更，只把安全巡检发现映射成加固建议与片段。

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/harden"
	"github.com/majq1990/app-updater-go/internal/inspect"
)

func cmdHarden(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: eops harden check|snippets|report|sec -c config.yaml [选项]")
	}
	switch args[0] {
	case "check":
		return cmdHardenCheck(args[1:], false)
	case "snippets":
		return cmdHardenCheck(args[1:], true)
	case "report":
		return cmdHardenReport(args[1:])
	case "sec":
		return cmdHardenSec(args[1:])
	default:
		return fmt.Errorf("未知 harden 子命令: %s（可用 check|snippets|report|sec）", args[0])
	}
}

// hardenResults 跑安全巡检并产出加固项。
func hardenResults(cfgPath, hostSel string) (harden.Report, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return harden.Report{}, err
	}
	if err := gateValidation(cfg, false); err != nil {
		return harden.Report{}, err
	}
	targets := filterInspectTargets(inspect.Targets(cfg), hostSel)
	if len(targets) == 0 {
		return harden.Report{}, fmt.Errorf("没有匹配的加固目标")
	}
	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()
	runner := inspect.Runner{
		Dial:     func(h config.Host) (inspect.Conn, error) { return dial.Dial(h) },
		Parallel: 4,
	}
	results := runner.Run(cfg, targets, inspect.FilterChecks([]inspect.Dimension{inspect.DimSecurity}))
	for _, r := range inspect.Errors(results) {
		fmt.Fprintf(os.Stderr, "  [警告] %s %s: %s\n", r.Host, r.Check, r.Err)
	}
	// 全部主机都连不上时不能报"未发现需要加固的项"
	if len(inspect.Errors(results)) > 0 && len(results) == len(inspect.Errors(results)) {
		return harden.Report{}, fmt.Errorf("全部 %d 个目标巡检失败，无法产出加固清单", len(targets))
	}
	return harden.Build(results, time.Now()), nil
}

func cmdHardenCheck(args []string, snippets bool) error {
	fs := flag.NewFlagSet("harden check", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	host := fs.String("host", "all", "主机过滤：IP / all / 逗号分隔")
	fs.Parse(args)

	rep, err := hardenResults(*cfgPath, *host)
	if err != nil {
		return err
	}
	if snippets {
		sn := rep.Snippets()
		if len(sn) == 0 {
			fmt.Println("无需给出的加固片段（未发现问题）。")
			return nil
		}
		fmt.Printf("加固建议片段 %d 组（人工确认后执行）：\n", len(sn))
		for _, s := range sn {
			fmt.Printf("\n--- %s（%s）---\n%s\n", s.Title, s.Check, s.Snippet)
		}
		return nil
	}
	var b strings.Builder
	rep.Text(&b)
	fmt.Print(b.String())
	return nil
}

func cmdHardenReport(args []string) error {
	fs := flag.NewFlagSet("harden report", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	host := fs.String("host", "all", "主机过滤：IP / all / 逗号分隔")
	out := fs.String("out", "", "输出文件（默认 stdout）")
	fs.Parse(args)

	rep, err := hardenResults(*cfgPath, *host)
	if err != nil {
		return err
	}
	b, err := rep.JSON()
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Println(string(b))
		return nil
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("加固台账已写入 %s（%d 项）\n", *out, rep.Summary.Total)
	return nil
}
