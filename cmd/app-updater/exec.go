package main

// 执行链路子命令：setup-ssh / update / rollback。
// 真实 Dialer 在此实现（解析全局/主机级 SSH 参数 → sshx 连接）。

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/appflow"
	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/sshx"
)

// execDialer 实现 appflow.Dialer：按主机解析 SSH 参数并连接（dialCache 已按主机去重，
// 这里每次调用新建连接即可）。
type execDialer struct {
	cfg   *config.Config
	over  sshx.Auth // CLI/环境变量覆盖（空字段不生效）
	conns []*sshx.Client
}

func (d *execDialer) Dial(h config.Host) (appflow.Conn, error) {
	auth := sshx.Auth{
		Host:     h.Host,
		Port:     firstInt(h.SSHPort, d.cfg.AnsibleSSHPort, d.over.Port),
		User:     firstStr(h.SSHUser, d.cfg.AnsibleUser, d.over.User),
		Password: firstStr(h.SSHPass, d.cfg.AnsibleSSHPass, d.over.Password),
		KeyPath:  d.over.KeyPath,
	}
	c, err := sshx.Connect(auth)
	if err != nil {
		return nil, err
	}
	d.conns = append(d.conns, c)
	return c, nil
}

func (d *execDialer) Close() {
	for _, c := range d.conns {
		_ = c.Close()
	}
}

// newRunner 构造执行器（含 --pass/--key 环境变量兜底与 dry-run 提示）。
func newRunner(cfg *config.Config, passFlag, keyFlag string, dryRun, yes bool) *appflow.Runner {
	over := sshx.Auth{
		Password: firstStr(passFlag, os.Getenv("APP_UPDATER_SSH_PASS")),
		KeyPath:  keyFlag,
	}
	dry := dryRun || !yes
	if !yes && !dryRun {
		fmt.Println("ℹ️ 未加 --yes，本次只输出执行计划（dry-run）；确认无误后加 --yes 正式执行")
	}
	lg := getLogger()
	return &appflow.Runner{
		Cfg:        cfg,
		Dial:       &execDialer{cfg: cfg, over: over},
		DryRun:     dry,
		Logf:       lg.Printf,
		DetailLogf: lg.Detailf,
	}
}

// ---- 日志：控制台 + logs/app_updater_YYYYMMDD.log 双写 ----

type appLogger struct {
	f *os.File
}

var appLog *appLogger

// getLogger 懒初始化日志文件（logs/app_updater_<日期>.log）。
func getLogger() *appLogger {
	if appLog != nil {
		return appLog
	}
	appLog = &appLogger{}
	if err := os.MkdirAll("logs", 0o755); err != nil {
		return appLog
	}
	name := filepath.Join("logs", "app_updater_"+time.Now().Format("20060102")+".log")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return appLog
	}
	appLog.f = f
	fmt.Printf("日志: %s\n", name)
	return appLog
}

// Printf 控制台 + 日志文件。
func (l *appLogger) Printf(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	fmt.Println(line)
	if l.f != nil {
		fmt.Fprintf(l.f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), line)
	}
}

// Detailf 只写日志文件（文件传输明细：tomcat/静态页面不刷控制台，jar 更新不受影响——
// 由 Runner.detailFor 决定明细走哪个通道，这里只负责文件侧写入）。
func (l *appLogger) Detailf(format string, args ...interface{}) {
	if l.f != nil {
		fmt.Fprintf(l.f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
	}
}

// parseGroups 解析 --groups（static 别名 static_page_group）。
func parseGroups(s string) []string {
	var out []string
	for _, g := range strings.Split(s, ",") {
		g = strings.TrimSpace(g)
		switch g {
		case "static_page_group":
			g = appflow.GroupStatic
		}
		if g != "" {
			out = append(out, g)
		}
	}
	return out
}

func cmdSetupSSH(args []string) error {
	fs := flag.NewFlagSet("setup-ssh", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "YAML 配置文件")
	appName := fs.String("app", "", "只处理指定应用（默认全部应用）")
	pass := fs.String("pass", "", "SSH 密码（也可用环境变量 APP_UPDATER_SSH_PASS）")
	keyPath := fs.String("key", "", "SSH 私钥路径（默认 ~/.ssh/id_rsa）")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	privPath, pubPath, err := sshx.EnsureKeyPair()
	if err != nil {
		return err
	}
	pubLine, err := sshx.PublicKeyLine(pubPath)
	if err != nil {
		return err
	}
	fmt.Println("本机密钥对:", privPath, "+", pubPath)

	over := sshx.Auth{Password: firstStr(*pass, os.Getenv("APP_UPDATER_SSH_PASS")), KeyPath: *keyPath}
	targets := hostsFor(cfg, *appName)
	if len(targets) == 0 {
		return fmt.Errorf("没有可处理的主机")
	}

	var failed int
	seen := map[string]bool{}
	for _, h := range targets {
		auth := sshx.Auth{
			Host:     h.Host,
			Port:     firstInt(h.SSHPort, cfg.AnsibleSSHPort, over.Port),
			User:     firstStr(h.SSHUser, cfg.AnsibleUser, over.User),
			Password: firstStr(h.SSHPass, cfg.AnsibleSSHPass, over.Password),
			KeyPath:  over.KeyPath,
		}
		key := fmt.Sprintf("%s:%d@%s", auth.Host, auth.Port, auth.User)
		if seen[key] {
			continue
		}
		seen[key] = true

		if sshx.VerifyKeyAuth(auth) == nil {
			fmt.Printf("✅ %s 已免密（跳过推送）\n", key)
			continue
		}
		fmt.Printf("→ %s 推送公钥...", key)
		if err := sshx.PushPubKey(auth, pubLine); err != nil {
			fmt.Printf(" ❌ %v\n", err)
			failed++
			continue
		}
		if err := sshx.VerifyKeyAuth(auth); err != nil {
			fmt.Printf(" ❌ 推送后验证失败: %v\n", err)
			failed++
			continue
		}
		fmt.Println(" ✅ 免密就绪")
	}
	if failed > 0 {
		return fmt.Errorf("%d 台主机免密设置失败", failed)
	}
	return nil
}

// hostsFor 目标主机集合（去重交由调用方）。
func hostsFor(cfg *config.Config, appName string) []config.Host {
	var out []config.Host
	for i := range cfg.Webs {
		if appName != "" && cfg.Webs[i].Web != appName {
			continue
		}
		a := &cfg.Webs[i]
		out = append(out, a.Master...)
		out = append(out, a.Update...)
		out = append(out, a.StaticPageGroup...)
	}
	return out
}

func cmdUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "YAML 配置文件")
	appName := fs.String("app", "", "应用名称")
	groups := fs.String("groups", "", "群组（默认 master,update）")
	staticMode := fs.String("static", "", "静态页面更新: full | partial | jar")
	staticPath := fs.String("static-path", "", "partial 模式：应用内相对路径")
	staticSrc := fs.String("static-src", "", "jar 模式：本地静态文件目录")
	updateDir := fs.String("update-dir", "update", "本地更新包根目录")
	backupDir := fs.String("backup-dir", "backups", "本地备份根目录")
	dryRun := fs.Bool("dry-run", false, "只输出执行计划")
	yes := fs.Bool("yes", false, "正式执行（不带则只出计划）")
	pass := fs.String("pass", "", "SSH 密码兜底（也可用环境变量 APP_UPDATER_SSH_PASS）")
	keyPath := fs.String("key", "", "SSH 私钥路径")
	fs.Parse(args)
	if *appName == "" {
		return fmt.Errorf("必须用 --app 指定应用（可选值见 config.yaml 的 webs）")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	runner := newRunner(cfg, *pass, *keyPath, *dryRun, *yes)
	runner.UpdateDir = *updateDir
	runner.BackupDir = *backupDir

	var sum *appflow.Summary
	switch strings.ToLower(*staticMode) {
	case "":
		sum, err = runner.Update(*appName, parseGroups(*groups))
	case "full":
		sum, err = runner.StaticFullTomcat(*appName)
	case "partial":
		sum, err = runner.StaticPartial(*appName, *staticPath)
	case "jar":
		sum, err = runner.StaticJar(*appName, *staticSrc)
	default:
		return fmt.Errorf("--static 只支持 full | partial | jar")
	}
	if err != nil {
		return err
	}
	return reportSummary(sum)
}

func cmdRollback(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "YAML 配置文件")
	appName := fs.String("app", "", "应用名称")
	version := fs.String("version", "", "备份版本（默认最新）")
	groups := fs.String("groups", "", "群组（默认 master,update,static）")
	list := fs.Bool("list", false, "只列出可回滚版本")
	backupDir := fs.String("backup-dir", "backups", "本地备份根目录")
	dryRun := fs.Bool("dry-run", false, "只输出执行计划")
	yes := fs.Bool("yes", false, "正式执行（不带则只出计划）")
	pass := fs.String("pass", "", "SSH 密码兜底")
	keyPath := fs.String("key", "", "SSH 私钥路径")
	fs.Parse(args)
	if *appName == "" {
		return fmt.Errorf("必须用 --app 指定应用")
	}

	if *list {
		vs, err := appflow.ListVersions(*backupDir, *appName)
		if err != nil {
			return err
		}
		fmt.Printf("应用 %s 可回滚版本（新→旧）:\n", *appName)
		for _, v := range vs {
			fmt.Println("  " + v)
		}
		return nil
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	runner := newRunner(cfg, *pass, *keyPath, *dryRun, *yes)
	runner.BackupDir = *backupDir

	sum, err := runner.Rollback(*appName, *version, parseGroups(*groups))
	if err != nil {
		return err
	}
	return reportSummary(sum)
}

func reportSummary(sum *appflow.Summary) error {
	fmt.Println("---- 结果汇总 ----")
	for _, r := range sum.Results {
		mark := "✅"
		if !r.OK {
			mark = "❌"
		}
		extra := ""
		if r.Detail != "" {
			extra = "（" + r.Detail + "）"
		}
		fmt.Printf("%s [%s] %s%s\n", mark, r.Group, r.Host, extra)
	}
	ok := len(sum.Results) - sum.FailCount()
	fmt.Printf("成功 %d / 失败 %d / 共 %d\n", ok, sum.FailCount(), len(sum.Results))
	if sum.FailCount() > 0 {
		return errors.New("存在失败主机，请核对上方输出")
	}
	return nil
}

// ---- 小工具 ----

func firstStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstInt(vals ...int) int {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}
