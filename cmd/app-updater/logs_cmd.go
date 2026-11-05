package main

// 日志运维子命令：logs clean（清理）/ logs gather（汇聚）。
// 覆盖应用日志（webs[].log_dir）与支持软件日志（supports[]：mysql/redis/nginx/dm 等）。

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/logs"
	"github.com/majq1990/app-updater-go/internal/sshx"
	"github.com/majq1990/app-updater-go/internal/syncx"
)

// sshOverride CLI/环境变量层面的 SSH 覆盖（与 newRunner 同语义）。
func sshOverride() sshx.Auth {
	return sshx.Auth{
		Password: firstStr(os.Getenv("APP_UPDATER_SSH_PASS"), ""),
	}
}

// sshRunner 适配 logs.Runner：用 execDialer 的单连接执行远端 awk/tail。
type sshRunner struct {
	dial *execDialer
	h    config.Host
}

func (r sshRunner) ExtractLines(abs string, from, to time.Time) (string, error) {
	c, err := r.dial.Dial(r.h)
	if err != nil {
		return "", err
	}
	script := logs.BuildAwkScript(from, to)
	out, err := c.Run(fmt.Sprintf("%s %s 2>/dev/null", script, shellQuoteArg(abs)))
	return out, err
}

func (r sshRunner) ReadTail(abs string, n int) (string, error) {
	c, err := r.dial.Dial(r.h)
	if err != nil {
		return "", err
	}
	out, err := c.Run(fmt.Sprintf("tail -n %d %s 2>/dev/null", n, shellQuoteArg(abs)))
	return out, err
}

func (r sshRunner) FileSize(abs string) (int64, error) {
	c, err := r.dial.Dial(r.h)
	if err != nil {
		return 0, err
	}
	out, err := c.Run(fmt.Sprintf("stat -c %%s %s 2>/dev/null || wc -c < %s", shellQuoteArg(abs), shellQuoteArg(abs)))
	if err != nil {
		return 0, err
	}
	var n int64
	fmt.Sscanf(strings.TrimSpace(out), "%d", &n)
	return n, nil
}

func shellQuoteArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// cmdLogsClean logs clean -c config.yaml [--app 名称|all] [--support kind|all]
// [--dry-run] [--yes]：白名单扫描 → 计划 → 确认 → 执行 → 汇报释放空间。
func cmdLogsClean(args []string) error {
	fs := flag.NewFlagSet("logs clean", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	app := fs.String("app", "all", "应用名（all=全部应用）")
	support := fs.String("support", "all", "支持软件 kind（all=全部支持软件）")
	dryRun := fs.Bool("dry-run", false, "只出计划不删除")
	yes := fs.Bool("yes", false, "确认执行删除")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := gateValidation(cfg, *yes); err != nil {
		return err
	}
	targets := filterTargets(logs.Targets(cfg), *app, *support)
	if len(targets) == 0 {
		fmt.Println("没有匹配的日志目标（应用没配 log_dir、支持软件段为空，或筛选条件不命中）")
		return nil
	}
	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()

	fmt.Printf("扫描 %d 个日志目标（应用 + 支持软件）...\n", len(targets))
	now := time.Now()
	plan := &logs.Plan{}
	for _, t := range targets {
		c, err := dial.Dial(t.Host)
		if err != nil {
			plan.Errs = append(plan.Errs, fmt.Errorf("%s(%s) SSH 连接失败: %w", t.Name, t.Host.Host, err))
			continue
		}
		sub := logs.BuildPlan(c, []logs.Target{t}, now)
		plan.Items = append(plan.Items, sub.Items...)
		plan.TotalSize += sub.TotalSize
		plan.FreeSize += sub.FreeSize
		plan.Errs = append(plan.Errs, sub.Errs...)
	}
	plan.Sort()

	fmt.Println(plan.Summarize())
	for _, it := range plan.Items {
		if it.Expired {
			fmt.Printf("  [过期] %s %s(%s) %s  %s\n",
				sized(it.File.Size), it.Target.Name, it.Target.Host.Host, it.File.Rel, it.File.Mtime.Format("2006-01-02"))
		}
	}
	for _, e := range plan.Errs {
		fmt.Println("  [警告]", e)
	}

	dry := *dryRun || !*yes
	if dry {
		fmt.Println("\n（dry-run，未实际删除；确认后加 --yes 执行）")
		return nil
	}

	// 执行：逐目标用各自连接删除（与计划同源同白名单）
	var deleted, freed int64
	for _, t := range targets {
		c, err := dial.Dial(t.Host)
		if err != nil {
			continue
		}
		sub := &logs.Plan{}
		for _, it := range plan.Items {
			if it.Target.Name == t.Name && it.Target.Host.Host == t.Host.Host {
				sub.Items = append(sub.Items, it)
			}
		}
		n, f, err := logs.Apply(c, sub)
		if err != nil {
			fmt.Println("  [失败]", err)
			continue
		}
		deleted += int64(n)
		freed += f
	}
	fmt.Printf("\n✅ 已删除 %d 个过期日志文件，释放 %s\n", deleted, humanSizeStr(freed))
	return nil
}

// cmdLogsGather logs gather -c config.yaml [--app 名称|all] [--support kind|all]
// [--window 1h|4h|24h] [--out logs-gather]：时间窗过滤拉取 + ERROR 计数。
func cmdLogsGather(args []string) error {
	fs := flag.NewFlagSet("logs gather", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	app := fs.String("app", "all", "应用名（all=全部应用）")
	support := fs.String("support", "all", "支持软件 kind（all=全部支持软件）")
	windowS := fs.String("window", "4h", "时间窗（如 1h/4h/24h）")
	out := fs.String("out", "", "本地落地目录（默认 logs-gather/<时间戳>）")
	fs.Parse(args)

	win, err := parseWindow(*windowS)
	if err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := gateValidation(cfg, false); err != nil {
		return err
	}
	targets := filterTargets(logs.Targets(cfg), *app, *support)
	if len(targets) == 0 {
		fmt.Println("没有匹配的日志目标")
		return nil
	}
	outDir := *out
	if outDir == "" {
		outDir = filepath.Join("logs-gather", time.Now().Format("20060102-150405"))
	}

	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()

	now := time.Now()
	res := &logs.GatherResult{}
	for _, t := range targets {
		c, err := dial.Dial(t.Host)
		if err != nil {
			res.Errs = append(res.Errs, fmt.Errorf("%s(%s) SSH 连接失败: %w", t.Name, t.Host.Host, err))
			continue
		}
		// 文件清单：复用 syncx.Walk（SFTP 遍历）
		var files []logs.LogFile
		for _, dir := range t.LogDirs {
			_ = c.Walk(dir, func(e syncx.Entry) error {
				files = append(files, logs.LogFile{
					Abs: joinSlash(dir, e.Rel), Dir: dir, Rel: e.Rel,
					Size: e.Size, Mtime: e.Mtime, IsDir: e.IsDir,
				})
				return nil
			})
		}
		sub := logs.GatherFiles(sshRunner{dial: dial, h: t.Host}, files, []logs.Target{t},
			logs.GatherOptions{Window: win, OutDir: outDir, MaxBytes: 16 << 20}, now)
		res.Files = append(res.Files, sub.Files...)
		res.Errs = append(res.Errs, sub.Errs...)
		res.TotalErrors += sub.TotalErrors
	}

	fmt.Println(res.Summarize())
	fmt.Printf("落地目录: %s\n", outDir)
	for _, line := range res.TopErrors(10) {
		fmt.Println(line)
	}
	for _, e := range res.Errs {
		fmt.Println("  [警告]", e)
	}
	return nil
}

// filterTargets 按名称筛选（all / 精确名 / 逗号分隔多个）。
func filterTargets(ts []logs.Target, app, support string) []logs.Target {
	wantApp := parseSet(app)
	wantSup := parseSet(support)
	var out []logs.Target
	for _, t := range ts {
		if t.Kind == logs.KindApp {
			if wantApp["all"] || wantApp[t.Name] {
				out = append(out, t)
			}
		} else {
			if wantSup["all"] || wantSup[t.KindRaw] || wantSup[t.Name] {
				out = append(out, t)
			}
		}
	}
	return out
}

func parseSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			m[p] = true
		}
	}
	return m
}

func parseWindow(s string) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("时间窗格式错误 %q（如 1h/4h/24h）", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("时间窗必须为正: %q", s)
	}
	return d, nil
}

func sized(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%6.2fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%6.2fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%6.1fK", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%6dB", n)
	}
}

func humanSizeStr(n int64) string {
	return sized(n)
}

func joinSlash(dir, rel string) string {
	if rel == "" {
		return dir
	}
	return strings.TrimSuffix(dir, "/") + "/" + rel
}
