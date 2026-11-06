package main

// 备份运维子命令：backup run / list / verify / prune / report。
// 变更类（run/prune）默认 dry-run，--yes 才执行——与工具宪法一致。
// 所有远端命令由 internal/backup 统一构建（值强引用 + 路径/库名白名单），
// 本文件只做编排与展示，不拼接 shell。

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/backup"
	"github.com/majq1990/app-updater-go/internal/config"
)

func cmdBackup(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: eops backup run|list|verify|prune|clean|report -c config.yaml [选项]")
	}
	switch args[0] {
	case "run":
		return cmdBackupRun(args[1:])
	case "list":
		return cmdBackupList(args[1:])
	case "verify":
		return cmdBackupVerify(args[1:])
	case "prune", "clean": // clean 与规划文档命名一致，行为等同 prune
		return cmdBackupPrune(args[1:])
	case "report":
		return cmdBackupReport(args[1:])
	case "restore":
		return cmdBackupRestore(args[1:])
	default:
		return fmt.Errorf("未知 backup 子命令: %s（可用 run|list|verify|prune|clean|report|restore）", args[0])
	}
}

// backupSel 备份目标筛选：--app 应用名（all / 逗号分隔）、--mysql 是否含数据库。
type backupSel struct {
	app   string
	mysql bool
}

func (s backupSel) apply(ts []backup.Target) []backup.Target {
	want := parseSet(s.app)
	var out []backup.Target
	for _, t := range ts {
		switch t.Kind {
		case backup.KindMySQL:
			if s.mysql {
				out = append(out, t)
			}
		default:
			if want["all"] || want[t.Name] {
				out = append(out, t)
			}
		}
	}
	return out
}

func backupCfg(cfgPath string, yes bool) (*config.Config, []backup.Target, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	if err := gateValidation(cfg, yes); err != nil {
		return nil, nil, err
	}
	return cfg, backup.Targets(cfg), nil
}

// cmdBackupRun 执行备份：目录打包 + MySQL 逻辑备份，产物留现场。
func cmdBackupRun(args []string) error {
	fs := flag.NewFlagSet("backup run", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	app := fs.String("app", "all", "备份范围：应用名（all=全部，逗号分隔多个）")
	mysql := fs.Bool("mysql", false, "同时执行数据库逻辑备份（需配置 backup.databases）")
	noReg := fs.Bool("no-register-zabbix", false, "不把备份目录登记进 zabbix 备份目录监控清单")
	dryRun := fs.Bool("dry-run", false, "只出计划不执行")
	yes := fs.Bool("yes", false, "确认执行备份")
	fs.Parse(args)

	cfg, all, err := backupCfg(*cfgPath, *yes)
	if err != nil {
		return err
	}
	targets := backupSel{app: *app, mysql: *mysql}.apply(all)
	if len(targets) == 0 {
		fmt.Println("没有匹配的备份目标（检查配置的 webs / supports.backup_paths / backup.databases）")
		return nil
	}

	root := cfg.Backup.EffectiveRoot()
	keep := cfg.Backup.EffectiveKeepDays()
	now := time.Now()
	dry := *dryRun || !*yes
	fmt.Printf("备份根目录: %s（保留 %d 天）\n", root, keep)
	fmt.Printf("本次 %d 个目标：\n", len(targets))

	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()

	okCount, failCount := 0, 0
	var totalBytes int64
	registered := map[string]bool{}
	for _, t := range targets {
		dest := backup.ArchivePath(root, t, now)
		cmdStr, err := backupCommand(cfg, t, dest)
		if err != nil {
			fmt.Printf("❌ %s(%s) 构建备份命令失败: %v\n", t.Name, t.Host.Host, err)
			failCount++
			continue
		}
		if dry {
			fmt.Printf("  [将备份] %s @%s → %s\n", t.Name, t.Host.Host, dest)
			continue
		}
		c, err := dial.Dial(t.Host)
		if err != nil {
			fmt.Printf("❌ %s(%s) SSH 连接失败: %v\n", t.Name, t.Host.Host, err)
			failCount++
			continue
		}
		out, err := c.Run(cmdStr)
		if err != nil {
			fmt.Printf("❌ %s(%s) 备份失败: %v\n%s\n", t.Name, t.Host.Host, err, indent(out, "    "))
			failCount++
			continue
		}
		res := backup.ParseVerify(dest, out)
		if !res.OK {
			fmt.Printf("⚠️ %s(%s) 已产出但校验信息不完整: %s\n", t.Name, t.Host.Host, res.Err)
			failCount++
			continue
		}
		totalBytes += res.Bytes
		fmt.Printf("✅ %s@%s  %s  sha256=%s…  %s\n",
			t.Name, t.Host.Host, backup.HumanBytes(res.Bytes), shortHash(res.SHA256), dest)
		okCount++

		// 备份目录登记进 zabbix 备份目录监控清单（每主机一次，agent 未装则跳过）
		if !*noReg && !registered[t.Host.Host] {
			registered[t.Host.Host] = true
			if regCmd, rerr := backup.RegisterBackupDirCommand(root); rerr == nil {
				if rout, rerr := c.Run(regCmd); rerr == nil && backup.ParseRegisterResult(rout) {
					fmt.Printf("   ↳ 已登记 %s 到 zabbix 备份目录监控清单\n", root)
				}
			}
		}
	}

	if dry {
		fmt.Println("\n（dry-run，未执行备份；确认后加 --yes 执行）")
		return nil
	}
	fmt.Printf("\n备份完成：成功 %d / 失败 %d，合计 %s\n", okCount, failCount, backup.HumanBytes(totalBytes))
	if failCount > 0 {
		return fmt.Errorf("%d 个目标备份失败", failCount)
	}
	return nil
}

// backupCommand 按目标类型构建远端命令。
func backupCommand(cfg *config.Config, t backup.Target, dest string) (string, error) {
	if t.Kind == backup.KindMySQL {
		b := cfg.Backup
		return backup.DumpCommand(dest, t.Bases, b.EffectiveDumpUser(), b.DumpDefaultsFile)
	}
	return backup.TarCommand(dest, t.Path, t.Exclude)
}

// gatherStored 逐主机拉取现场备份清单。返回 host→文件，以及按主机归集的错误。
// hosts 保留目标准确的 config.Host（含 ssh_port/ssh_user/ssh_pass 覆盖），不要退化成裸 IP。
func gatherStored(cfg *config.Config, hosts []config.Host, root string, dial *execDialer) (map[string][]backup.StoredFile, []error) {
	byHost := map[string][]backup.StoredFile{}
	var errs []error
	cmdStr, err := backup.ListCommand(root)
	if err != nil {
		return byHost, []error{err}
	}
	for _, h := range hosts {
		c, err := dial.Dial(h)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s SSH 连接失败: %w", h.Host, err))
			continue
		}
		out, err := c.Run(cmdStr)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s 列取备份失败: %w", h.Host, err))
			continue
		}
		byHost[h.Host] = backup.ParseList(out)
	}
	return byHost, errs
}

// backupHosts 涉及备份的主机集合（按 IP 去重，保留首个目标的 Host 覆盖参数）。
func backupHosts(targets []backup.Target) []config.Host {
	seen := map[string]bool{}
	var hosts []config.Host
	for _, t := range targets {
		if t.Host.Host == "" || seen[t.Host.Host] {
			continue
		}
		seen[t.Host.Host] = true
		hosts = append(hosts, t.Host)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	return hosts
}

// cmdBackupList 列出现场已有备份。
func cmdBackupList(args []string) error {
	fs := flag.NewFlagSet("backup list", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	app := fs.String("app", "all", "应用名筛选（all=全部）")
	mysql := fs.Bool("mysql", false, "是否包含数据库备份")
	jsonOut := fs.Bool("json", false, "输出 JSON 台账（含基本信息，不含校验）")
	fs.Parse(args)

	cfg, all, err := backupCfg(*cfgPath, false)
	if err != nil {
		return err
	}
	targets := backupSel{app: *app, mysql: *mysql}.apply(all)
	root := cfg.Backup.EffectiveRoot()
	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()

	hosts := backupHosts(targets)
	byHost, errs := gatherStored(cfg, hosts, root, dial)
	if len(byHost) == 0 && len(hosts) > 0 {
		// 全部主机连不上时不能报"暂无备份"——那会被误读成现场没备份
		return fmt.Errorf("全部 %d 台主机连接失败，无法读取备份清单", len(hosts))
	}
	if *jsonOut {
		led := mergeLedgers(root, cfg.Backup.EffectiveKeepDays(), targets, byHost, nil, time.Now())
		b, err := led.JSON()
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	total, count := 0, 0
	for _, host := range sortedKeys(byHost) {
		files := byHost[host]
		if len(files) == 0 {
			fmt.Printf("%s: 暂无备份\n", host)
			continue
		}
		fmt.Printf("\n%s（%d 份）:\n", host, len(files))
		for _, f := range files {
			fmt.Printf("  %s  %10s  %s\n", f.ModTime.Format("2006-01-02 15:04"), backup.HumanBytes(f.Bytes), f.Path)
			total += int(f.Bytes)
			count++
		}
	}
	for _, e := range errs {
		fmt.Println("  [警告]", e)
	}
	fmt.Printf("\n合计 %d 份 / %s（根目录 %s）\n", count, backup.HumanBytes(int64(total)), root)
	return nil
}

// cmdBackupVerify 校验现场备份完整性（gzip/tar/sha256/大小）。
func cmdBackupVerify(args []string) error {
	fs := flag.NewFlagSet("backup verify", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	app := fs.String("app", "all", "应用名筛选（all=全部）")
	mysql := fs.Bool("mysql", false, "是否包含数据库备份")
	fs.Parse(args)

	cfg, all, err := backupCfg(*cfgPath, false)
	if err != nil {
		return err
	}
	targets := backupSel{app: *app, mysql: *mysql}.apply(all)
	root := cfg.Backup.EffectiveRoot()
	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()

	hosts := backupHosts(targets)
	byHost, errs := gatherStored(cfg, hosts, root, dial)
	if len(byHost) == 0 && len(hosts) > 0 {
		return fmt.Errorf("全部 %d 台主机连接失败，无法校验备份", len(hosts))
	}
	okCount, failCount := 0, 0
	for _, host := range sortedKeys(byHost) {
		files := byHost[host]
		if len(files) == 0 {
			continue
		}
		c, derr := dial.Dial(hostByIP(hosts)[host])
		if derr != nil {
			errs = append(errs, fmt.Errorf("%s SSH 连接失败: %w", host, derr))
			continue
		}
		fmt.Printf("\n%s:\n", host)
		for _, f := range files {
			cmdStr, cerr := backup.VerifyCommand(f.Path)
			if cerr != nil {
				fmt.Printf("  ❌ %v\n", cerr)
				failCount++
				continue
			}
			out, rerr := c.Run(cmdStr)
			res := backup.ParseVerify(f.Path, out)
			if rerr != nil || !res.OK {
				msg := res.Err
				if rerr != nil {
					msg = rerr.Error()
				}
				fmt.Printf("  ❌ %s —— %s\n", f.Path, oneLine(msg))
				failCount++
				continue
			}
			fmt.Printf("  ✅ %s  %s  sha256=%s…\n", f.Path, backup.HumanBytes(res.Bytes), shortHash(res.SHA256))
			okCount++
		}
	}
	for _, e := range errs {
		fmt.Println("  [警告]", e)
	}
	fmt.Printf("\n校验完成：通过 %d / 失败 %d\n", okCount, failCount)
	if failCount > 0 {
		return fmt.Errorf("%d 份备份校验失败", failCount)
	}
	return nil
}

// cmdBackupPrune 清理超过保留期的备份（只删本工具 eops- 产物）。
func cmdBackupPrune(args []string) error {
	fs := flag.NewFlagSet("backup prune", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	app := fs.String("app", "all", "应用名筛选（all=全部）")
	mysql := fs.Bool("mysql", false, "是否包含数据库备份")
	keepDays := fs.Int("keep-days", 0, "保留天数（0=用配置 backup.keep_days）")
	dryRun := fs.Bool("dry-run", false, "只列出不删除")
	yes := fs.Bool("yes", false, "确认删除")
	fs.Parse(args)

	cfg, all, err := backupCfg(*cfgPath, *yes)
	if err != nil {
		return err
	}
	targets := backupSel{app: *app, mysql: *mysql}.apply(all)
	root := cfg.Backup.EffectiveRoot()
	keep := *keepDays
	if keep == 0 {
		keep = cfg.Backup.EffectiveKeepDays()
	}
	if keep < 1 {
		return fmt.Errorf("保留天数必须 >= 1（当前 %d）", keep)
	}
	cmdStr, err := backup.PruneListCommand(root, keep)
	if err != nil {
		return err
	}
	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()

	dry := *dryRun || !*yes
	type pending struct {
		host config.Host
		file string
	}
	var items []pending
	hosts := backupHosts(targets)
	okHosts := 0
	for _, h := range hosts {
		c, derr := dial.Dial(h)
		if derr != nil {
			fmt.Printf("❌ %s SSH 连接失败: %v\n", h.Host, derr)
			continue
		}
		okHosts++
		out, rerr := c.Run(cmdStr)
		if rerr != nil {
			fmt.Printf("⚠️ %s 查询过期备份失败: %v\n", h.Host, rerr)
			continue
		}
		for _, p := range backup.ParseLines(out) {
			items = append(items, pending{host: h, file: p})
		}
	}

	if okHosts == 0 && len(hosts) > 0 {
		// 全部主机连不上时不能报"无需清理"——那会被误读成没有过期备份
		return fmt.Errorf("全部 %d 台主机连接失败，无法查询过期备份", len(hosts))
	}

	fmt.Printf("保留 %d 天，过期备份 %d 份：\n", keep, len(items))
	for _, it := range items {
		fmt.Printf("  [过期] %s  %s\n", it.host.Host, it.file)
	}
	if len(items) == 0 {
		fmt.Println("无需清理")
		return nil
	}
	if dry {
		fmt.Println("\n（dry-run，未删除；确认后加 --yes 执行）")
		return nil
	}

	removed, failed := 0, 0
	for _, it := range items {
		cmdRm, cerr := backup.RemoveCommand(it.file)
		if cerr != nil {
			fmt.Printf("  ❌ %v\n", cerr)
			failed++
			continue
		}
		c, derr := dial.Dial(it.host)
		if derr != nil {
			failed++
			continue
		}
		if _, rerr := c.Run(cmdRm); rerr != nil {
			fmt.Printf("  ❌ 删除失败 %s: %v\n", it.file, rerr)
			failed++
			continue
		}
		removed++
	}
	fmt.Printf("\n清理完成：删除 %d / 失败 %d\n", removed, failed)
	if failed > 0 {
		return fmt.Errorf("%d 份清理失败", failed)
	}
	return nil
}

// cmdBackupReport 导出台账 JSON（默认 stdout；--verify 同时做完整性校验）。
func cmdBackupReport(args []string) error {
	fs := flag.NewFlagSet("backup report", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	out := fs.String("out", "", "输出文件（默认 stdout）")
	app := fs.String("app", "all", "应用名筛选（all=全部）")
	mysql := fs.Bool("mysql", false, "是否包含数据库备份")
	doVerify := fs.Bool("verify", false, "同时校验每份备份（较慢，但台账带 sha256/verified）")
	fs.Parse(args)

	cfg, all, err := backupCfg(*cfgPath, false)
	if err != nil {
		return err
	}
	targets := backupSel{app: *app, mysql: *mysql}.apply(all)
	root := cfg.Backup.EffectiveRoot()
	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()

	hosts := backupHosts(targets)
	byHost, errs := gatherStored(cfg, hosts, root, dial)
	if len(byHost) == 0 && len(hosts) > 0 {
		return fmt.Errorf("全部 %d 台主机连接失败，无法导出台账", len(hosts))
	}
	verified := map[string]backup.VerifyResult{}
	if *doVerify {
		for _, host := range sortedKeys(byHost) {
			files := byHost[host]
			if len(files) == 0 {
				continue
			}
			c, derr := dial.Dial(hostByIP(hosts)[host])
			if derr != nil {
				errs = append(errs, fmt.Errorf("%s SSH 连接失败: %w", host, derr))
				continue
			}
			for _, f := range files {
				cmdStr, cerr := backup.VerifyCommand(f.Path)
				if cerr != nil {
					continue
				}
				res, _ := c.Run(cmdStr)
				verified[f.Path] = backup.ParseVerify(f.Path, res)
			}
		}
	}

	led := mergeLedgers(root, cfg.Backup.EffectiveKeepDays(), targets, byHost, verified, time.Now())
	b, err := led.JSON()
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Println(string(b))
	} else {
		if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("台账已写入 %s（%s）\n", *out, led.Summary())
	}
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "  [警告]", e)
	}
	return nil
}

// cmdBackupRestore 从现场备份包恢复应用：
// 停应用 → 变更前自动备份 → 解压恢复 → 修正属主 → 启动应用 → 健康检查。
// 默认 dry-run，--yes 才执行；任一步失败即停并列出已执行步骤。
func cmdBackupRestore(args []string) error {
	fs := flag.NewFlagSet("backup restore", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	appName := fs.String("app", "", "要恢复的应用名（必须在 webs 中）")
	file := fs.String("file", "", "远端备份包路径（backup.root 下 eops-*.tar.gz）")
	dryRun := fs.Bool("dry-run", false, "只出恢复计划不执行")
	yes := fs.Bool("yes", false, "确认执行恢复")
	fs.Parse(args)

	if strings.TrimSpace(*appName) == "" {
		return fmt.Errorf("必须用 --app 指定应用")
	}
	if strings.TrimSpace(*file) == "" {
		return fmt.Errorf("必须用 --file 指定远端备份包路径")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := gateValidation(cfg, *yes); err != nil {
		return err
	}
	app := cfg.AppByName(*appName)
	if app == nil {
		return fmt.Errorf("应用 %q 不存在于 webs（可用应用见 config.yaml）", *appName)
	}

	root := cfg.Backup.EffectiveRoot()
	t, ok := backup.FindRestoreTarget(backup.Targets(cfg), *appName, *file)
	if !ok {
		return fmt.Errorf("备份包 %s 不属于应用 %s 的任何主机（文件名应为 %s<应用>-<主机>-<时间>.tar.gz）",
			*file, *appName, config.BackupFilePrefix)
	}
	plan, err := backup.BuildRestorePlan(root, t, *file, time.Now())
	if err != nil {
		return err
	}

	fmt.Print(plan.Text())
	dry := *dryRun || !*yes
	if dry {
		fmt.Println("\n（dry-run，未执行恢复；确认后加 --yes 执行）")
		return nil
	}

	budget := restoreHealthBudget(cfg, app)
	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()
	c, err := dial.Dial(t.Host)
	if err != nil {
		return fmt.Errorf("%s SSH 连接失败: %w", t.Host.Host, err)
	}

	var executed []string
	fail := func(name string, cause error) error {
		fmt.Printf("\n❌ 「%s」失败: %v\n", name, cause)
		if len(executed) > 0 {
			fmt.Println("已执行步骤：")
			for i, e := range executed {
				fmt.Printf("  %d. %s\n", i+1, e)
			}
		} else {
			fmt.Println("已执行步骤：无")
		}
		return fmt.Errorf("恢复中断于「%s」", name)
	}

	for _, step := range plan.Steps {
		fmt.Printf("\n→ %s: %s\n", step.Name, step.Command)
		out, rerr := c.Run(step.Command)
		if rerr != nil {
			return fail(step.Name, fmt.Errorf("%v（输出: %s）", rerr, oneLine(out)))
		}
		if step.Key == backup.StepPreBackup {
			res := backup.ParseVerify(plan.PreBackup, out)
			if !res.OK {
				return fail(step.Name, fmt.Errorf("变更前备份校验失败: %s", res.Err))
			}
			fmt.Printf("   ✅ 变更前备份完成 %s  sha256=%s…\n", backup.HumanBytes(res.Bytes), shortHash(res.SHA256))
		}
		executed = append(executed, step.Name)
	}

	if plan.HealthEnabled {
		fmt.Printf("\n→ 健康检查（预算 %s）: %s\n", budget, plan.HealthCommand)
		ok, out := pollRestoreHealth(c, plan.HealthCommand, budget)
		if !ok {
			return fail("健康检查", fmt.Errorf("探测未通过（最后输出: %s）", oneLine(out)))
		}
		fmt.Println("   ✅ 健康检查通过")
	}

	fmt.Printf("\n✅ 恢复完成：%s @%s（备份包 %s）\n", plan.App, plan.Host, plan.Package)
	return nil
}

// restoreCommandRunner 远端命令执行接口（execDialer.Dial 返回的 *sshx.Client 满足）。
type restoreCommandRunner interface {
	Run(string) (string, error)
}

// restoreHealthBudget 健康检查预算：tomcat 读 tomcat_check_minutes（默认 20），
// jar 读 jar_check_minutes（默认 5）。
func restoreHealthBudget(cfg *config.Config, app *config.App) time.Duration {
	if app != nil && app.MiddleType == "tomcat" {
		m := 20
		if cfg.TomcatCheckMinutes > 0 {
			m = cfg.TomcatCheckMinutes
		}
		return time.Duration(m) * time.Minute
	}
	m := 5
	if cfg.JarCheckMinutes > 0 {
		m = cfg.JarCheckMinutes
	}
	return time.Duration(m) * time.Minute
}

// pollRestoreHealth 每 10s 轮询只读健康探测命令，直到通过或预算耗尽。
func pollRestoreHealth(c restoreCommandRunner, cmd string, budget time.Duration) (bool, string) {
	deadline := time.Now().Add(budget)
	var last string
	for {
		out, err := c.Run(cmd)
		last = out
		if err == nil {
			return true, last
		}
		if time.Now().Add(10 * time.Second).After(deadline) {
			return false, last
		}
		time.Sleep(10 * time.Second)
	}
}

// mergeLedgers 按主机分别生成台账后合并（主机归属用实际连接的 host 兜底）。
func mergeLedgers(root string, keep int, targets []backup.Target,
	byHost map[string][]backup.StoredFile, verified map[string]backup.VerifyResult, now time.Time) backup.Ledger {

	merged := backup.Ledger{GeneratedAt: now.Format(time.RFC3339), Root: root, KeepDays: keep}
	for _, host := range sortedKeys(byHost) {
		sub := backup.BuildLedger(root, keep, targets, byHost[host], verified, now)
		for _, e := range sub.Entries {
			if e.Host == "" {
				e.Host = host
			}
			merged.Entries = append(merged.Entries, e)
		}
	}
	sort.Slice(merged.Entries, func(i, j int) bool {
		a, b := merged.Entries[i], merged.Entries[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.File < b.File
	})
	return merged
}

// sortedKeys 稳定顺序遍历 byHost。
func sortedKeys(m map[string][]backup.StoredFile) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// hostByIP 用 IP 反查目标准确的 Host（含 SSH 覆盖参数）。
func hostByIP(hosts []config.Host) map[string]config.Host {
	m := make(map[string]config.Host, len(hosts))
	for _, h := range hosts {
		m[h.Host] = h
	}
	return m
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}
