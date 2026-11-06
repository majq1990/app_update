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

	"github.com/majq1990/app-updater-go/internal/appflow"
	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/logs"
	"github.com/majq1990/app-updater-go/internal/sshx"
	"github.com/majq1990/app-updater-go/internal/syncx"
)

// sshOverride CLI/环境变量层面的 SSH 覆盖（与 newRunner 同语义，密码读入走单点函数）。
func sshOverride() sshx.Auth {
	return sshx.Auth{
		Password: sshPassOrDefault(""),
	}
}

// sshRunner 适配 logs.Runner：用 execDialer 的单连接执行远端 awk/tail。
type sshRunner struct {
	dial *execDialer
	h    config.Host
}

func (r sshRunner) ExtractLines(abs string, from, to time.Time) (string, error) {
	q, err := shellPathArg(abs)
	if err != nil {
		return "", err
	}
	c, err := r.dial.Dial(r.h)
	if err != nil {
		return "", err
	}
	script := logs.BuildAwkScript(from, to)
	out, err := c.Run(fmt.Sprintf("%s %s 2>/dev/null", script, q))
	return out, err
}

func (r sshRunner) ReadTail(abs string, n int) (string, error) {
	q, err := shellPathArg(abs)
	if err != nil {
		return "", err
	}
	c, err := r.dial.Dial(r.h)
	if err != nil {
		return "", err
	}
	out, err := c.Run(fmt.Sprintf("tail -n %d %s 2>/dev/null", n, q))
	return out, err
}

func (r sshRunner) FileSize(abs string) (int64, error) {
	q, err := shellPathArg(abs)
	if err != nil {
		return 0, err
	}
	c, err := r.dial.Dial(r.h)
	if err != nil {
		return 0, err
	}
	out, err := c.Run(fmt.Sprintf("stat -c %%s %s 2>/dev/null || wc -c < %s", q, q))
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

// shellPathArg 远端路径参数的强校验 + 引用：拒绝任何 shell 元字符后引用。
// 与 config.ShellSafetyIssues 双保险——CLI 直接传进来的路径（--out 等）不经配置校验。
func shellPathArg(s string) (string, error) {
	if strings.ContainsAny(s, "\x00\n\r\t'\"`$;&|<>(){}\\") {
		return "", fmt.Errorf("路径含 shell 元字符，拒绝执行: %q", s)
	}
	return shellQuoteArg(s), nil
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

// cmdLogsRotate logs rotate check（只读体检）/ setup（推送配置，闸门变更）。
func cmdLogsRotate(args []string) error {
	if len(args) == 0 || (args[0] != "check" && args[0] != "setup") {
		return fmt.Errorf("用法: eops logs rotate check|setup -c config.yaml [选项]")
	}
	rest := args[1:]
	if args[0] == "check" {
		return cmdLogsRotateCheck(rest)
	}
	return cmdLogsRotateSetup(rest)
}

// cmdLogsRotateCheck 只读：全部目标的切割体检报告（高/中/低 分级）。
func cmdLogsRotateCheck(args []string) error {
	fs := flag.NewFlagSet("logs rotate check", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	app := fs.String("app", "all", "应用名（all=全部应用）")
	support := fs.String("support", "all", "支持软件 kind（all=全部支持软件）")
	fs.Parse(args)

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
	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()

	now := time.Now()
	high, med, low := 0, 0, 0
	for _, t := range targets {
		c, err := dial.Dial(t.Host)
		if err != nil {
			fmt.Printf("❌ %s(%s) SSH 连接失败: %v\n", t.Name, t.Host.Host, err)
			continue
		}
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
		res := logs.RunRotateCheck(sshRotater{c}, t, files, logs.RotateCheckOptions{Now: now})
		if len(res.Findings) == 0 {
			fmt.Printf("✅ %s(%s) 切割配置正常\n", t.Name, t.Host.Host)
			continue
		}
		fmt.Printf("\n%s(%s):\n", t.Name, t.Host.Host)
		for _, f := range res.Findings {
			switch f.Severity {
			case "high":
				high++
				fmt.Println("  [高]", f.Msg)
			case "medium":
				med++
				fmt.Println("  [中]", f.Msg)
			default:
				low++
				fmt.Println("  [低]", f.Msg)
			}
		}
	}
	fmt.Printf("\n切割体检完成：高 %d / 中 %d / 低 %d\n", high, med, low)
	return nil
}

// safeLocalDir 本地输出目录校验：逐段拒绝控制字符、路径穿越（..）、空段名。
// 允许相对与绝对路径（用户指定输出位置是正当需求），但路径必须逐段"像路径"。
func safeLocalDir(dir string) error {
	if strings.ContainsAny(dir, "\x00\n\r") {
		return fmt.Errorf("含控制字符: %q", dir)
	}
	for _, seg := range strings.FieldsFunc(filepath.ToSlash(dir), func(r rune) bool { return r == '/' }) {
		if seg == ".." {
			return fmt.Errorf("含路径穿越段 ..: %q", dir)
		}
		if seg == "" || strings.ContainsAny(seg, "\x00\n\r\"'`$;&|<>(){}\\") {
			return fmt.Errorf("目录段非法: %q", seg)
		}
	}
	return nil
}

// safeSelector 校验 --app/--support 筛选值（CLI 直传数据，进片段路径推导）。
// 白名单：字母数字-_，逗号分隔多值；其余拒绝（中文应用名走配置校验层，不走 shell 路径）。
func safeSelector(v string) error {
	for _, p := range strings.Split(v, ",") {
		for _, r := range strings.TrimSpace(p) {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			default:
				return fmt.Errorf("筛选值 %q 含非常规字符（只允许字母数字-_，逗号分隔）", p)
			}
		}
	}
	return nil
}

// cmdLogsRotateSetup 变更：生成并推送 /etc/logrotate.d/ 片段。
// 闸门：dry-run 展示将写入的片段内容与目标清单 → --yes 才推送 → 远端 logrotate -d 语法验证
// → 不强制轮转（绝不 logrotate -f）。已有片段差异展示提示合并（diff 由人判断）。
func cmdLogsRotateSetup(args []string) error {
	fs := flag.NewFlagSet("logs rotate setup", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	app := fs.String("app", "all", "应用名（all=全部应用）")
	support := fs.String("support", "all", "支持软件 kind（all=全部支持软件）")
	dryRun := fs.Bool("dry-run", false, "只展示片段不推送")
	yes := fs.Bool("yes", false, "确认推送")
	force := fs.Bool("force", false, "远端已有内容不同的片段时强制覆盖（默认跳过并展示差异）")
	fs.Parse(args)

	// CLI 直传筛选值进片段路径推导（filterTargets→RotateFragmentName→uploadString），
	// 白名单校验从入口斩断命令行参数到远端路径的数据流。
	if err := safeSelector(*app); err != nil {
		return fmt.Errorf("--app %v", err)
	}
	if err := safeSelector(*support); err != nil {
		return fmt.Errorf("--support %v", err)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := gateValidation(cfg, *yes); err != nil {
		return err
	}
	targets := filterTargets(logs.Targets(cfg), *app, *support)
	if len(targets) == 0 {
		fmt.Println("没有匹配的日志目标")
		return nil
	}
	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()

	dry := *dryRun || !*yes
	if !*yes && !*dryRun {
		fmt.Println("ℹ️ 未加 --yes，本次只展示将生成的 logrotate 配置（dry-run）")
	}

	// 第一遍：全部生成 + 展示 + 冲突检测
	type job struct {
		t      logs.Target
		frag   string
		body   string
		exists string // 远端已有内容（空=不存在）；非空且不同=冲突
	}
	var jobs []job
	for _, t := range targets {
		if len(t.LogDirs) == 0 {
			continue // 无日志目录的目标没有可切割对象
		}
		c, err := dial.Dial(t.Host)
		if err != nil {
			fmt.Printf("❌ %s(%s) SSH 连接失败: %v\n", t.Name, t.Host.Host, err)
			continue
		}
		frag := "/etc/logrotate.d/" + logs.RotateFragmentName(t)
		if strings.ContainsAny(frag, "'\"`$;&|<>(){} \t\n\r\\") {
			// RotateFragmentName 已做 sanitize，但名称含空格等仍可能来自配置；
			// 片段路径要进 shell，这里双保险拒绝。
			fmt.Printf("❌ %s(%s) 片段名含特殊字符，跳过: %q\n", t.Name, t.Host.Host, frag)
			continue
		}
		body := logs.RotateTemplate(t)
		j := job{t: t, frag: frag, body: body}
		if out, err := c.Run("test -e " + shellQuoteArg(frag) + " && cat " + shellQuoteArg(frag)); err == nil && strings.TrimSpace(out) != "" {
			j.exists = out
		}
		jobs = append(jobs, j)
	}
	if len(jobs) == 0 {
		fmt.Println("没有需要生成切割配置的目标")
		return nil
	}

	fmt.Printf("将为 %d 个目标生成 logrotate 配置：\n", len(jobs))
	var conflicts, skips int
	for _, j := range jobs {
		fmt.Printf("\n--- %s（%s → %s）---\n%s", j.t.Name, j.t.Host.Host, j.frag, j.body)
		if j.exists == "" {
			fmt.Println("  （远端不存在，将新建）")
			continue
		}
		if strings.TrimSpace(j.exists) == strings.TrimSpace(j.body) {
			fmt.Println("  （远端已有一致配置，跳过）")
			skips++
		} else {
			fmt.Printf("  ⚠️ 远端已有内容不同的配置：\n%s\n  （默认跳过；确认覆盖请加 --force）\n", j.exists)
			conflicts++
		}
	}

	if dry {
		fmt.Println("\n（dry-run，未推送；确认后加 --yes 执行）")
		return nil
	}

	// 第二遍：推送 + 语法验证
	pushed, skipped, failed := 0, 0, 0
	for _, j := range jobs {
		if j.exists != "" {
			if strings.TrimSpace(j.exists) == strings.TrimSpace(j.body) {
				skipped++
				continue
			}
			if !*force {
				skipped++
				continue
			}
		}
		c, err := dial.Dial(j.t.Host)
		if err != nil {
			failed++
			continue
		}
		// 写远端：先传临时名再 mv 原子替换（部署运行中文件的安全惯例）
		tmp := j.frag + ".eops-new"
		if err := uploadString(c, tmp, j.body); err != nil {
			fmt.Printf("❌ %s 上传 %s 失败: %v\n", j.t.Host.Host, tmp, err)
			failed++
			continue
		}
		if out, err := c.Run(fmt.Sprintf("mv -f %s %s && logrotate -d %s 2>&1", shellQuoteArg(tmp), shellQuoteArg(j.frag), shellQuoteArg(j.frag))); err != nil || strings.Contains(strings.ToLower(out), "error") {
			fmt.Printf("❌ %s %s 语法验证未过:\n%s\n", j.t.Host.Host, j.frag, out)
			_, _ = c.Run("mv -f " + shellQuoteArg(j.frag) + " " + shellQuoteArg(j.frag+".broken")) // 保留坏配置现场但不让它生效
			failed++
			continue
		}
		fmt.Printf("✅ %s(%s) 已推送 %s（语法验证通过，未强制轮转）\n", j.t.Name, j.t.Host.Host, j.frag)
		pushed++
	}
	fmt.Printf("\n推送完成：成功 %d / 跳过 %d / 失败 %d\n", pushed, skipped, failed)
	if failed > 0 {
		return fmt.Errorf("%d 个目标推送失败", failed)
	}
	return nil
}

// sshRotater 适配 logs.Rotater：appflow.Conn 的动态类型是 *sshx.Client
// （execDialer.Dial 返回），TestPath/ReadFile 在其上；用接口断言取。
type sshRotater struct{ c appflow.Conn }

func (r sshRotater) TestFile(p string) bool {
	if sc, ok := r.c.(interface{ TestPath(string) bool }); ok {
		return sc.TestPath(p)
	}
	return false
}
func (r sshRotater) ReadFile(p string) (string, error) {
	if sc, ok := r.c.(interface {
		ReadFile(string) ([]byte, error)
	}); ok {
		b, err := sc.ReadFile(p)
		return string(b), err
	}
	return "", fmt.Errorf("连接对象不支持 ReadFile")
}
func (r sshRotater) Run(cmd string) (string, error) { return r.c.Run(cmd) }

// uploadString 小文本上传（logrotate 片段）：本地临时文件 + SFTP 上传到 .eops-new。
// remotePath 本函数内强校验（终点闸：无论调用方是谁，进 SFTP 的远端路径必须干净）——
// 只允许 /etc/logrotate.d/<字母数字-_>.eops-new 形态。
func uploadString(c appflow.Conn, remotePath, content string) error {
	if !rotateFragPathOK(remotePath) {
		return fmt.Errorf("远端路径不符合 logrotate 片段白名单形态，拒绝上传: %q", remotePath)
	}
	local, err := os.CreateTemp("", "eops-rotate-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(local.Name())
	if _, err := local.WriteString(content); err != nil {
		local.Close()
		return err
	}
	local.Close()
	// 复用 syncx 上传语义：传到远端后保留 mtime 即可（权限 mv 后 root 默认）
	return c.Upload(local.Name(), remotePath, time.Now())
}

// rotateFragPathOK logrotate 片段路径白名单：/etc/logrotate.d/<name> 或其 .eops-new/.broken 临时态。
// name 仅允许字母数字-_.（与 logs.sanitize 的输出字符集一致）。
func rotateFragPathOK(p string) bool {
	for _, prefix := range []string{"/etc/logrotate.d/"} {
		if strings.HasPrefix(p, prefix) {
			name := strings.TrimPrefix(p, prefix)
			name = strings.TrimSuffix(strings.TrimSuffix(name, ".eops-new"), ".broken")
			if name == "" {
				return false
			}
			for _, r := range name {
				switch {
				case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
				default:
					return false
				}
			}
			return true
		}
	}
	return false
}
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
	} else if err := safeLocalDir(outDir); err != nil {
		// CLI 直传本地输出目录的终点闸：拒绝控制字符与路径穿越段，
		// 允许相对/绝对路径（用户指定输出位置是正当需求），但目录名逐段校验。
		return fmt.Errorf("--out %v", err)
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
