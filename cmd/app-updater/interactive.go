package main

// 交互模式：对齐旧版工具的菜单式操作（选应用 → 选群组 → 模拟 → 确认执行）。
// 无参数运行 app-updater 即进入；带子命令的参数模式保留给脚本调用。
//
// 配置管理采用「当前配置」模型：识别一键 / 表格导入 都是"载入当前配置"，
// 导出表格 / 导出 YAML 是"把当前配置输出"——识别不代表必须导出，两步解耦。

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/appflow"
	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/maintain"
	"github.com/majq1990/app-updater-go/internal/xlsx"
)

var stdin *bufio.Reader

// curCfgPath 当前会话的工作配置文件（识别/导入会更新它，更新/回滚/导出默认用它）。
var curCfgPath = "config.yaml"

func getInput(prompt, def string) string {
	if def != "" {
		fmt.Printf("%s [默认: %s]: ", prompt, def)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	line, _ := stdin.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func getIntChoice(prompt string, def, max int) int {
	for {
		s := getInput(prompt, strconv.Itoa(def))
		n, err := strconv.Atoi(s)
		if err == nil && n >= 0 && n <= max {
			return n
		}
		fmt.Printf("  ⚠️ 请输入 0-%d 之间的数字\n", max)
	}
}

func confirm(prompt string, def bool) bool {
	suffix := "y/N"
	if def {
		suffix = "Y/n"
	}
	for {
		s := strings.ToLower(getInput(fmt.Sprintf("%s (%s)", prompt, suffix), ""))
		if s == "" {
			return def
		}
		switch s {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
	}
}

func runInteractive() {
	stdin = bufio.NewReader(os.Stdin)
	for {
		fmt.Printf(`
============================================
  Java 应用更新工具 (Go 版) · 交互模式
  %s
  当前配置: %s
============================================
1. 应用更新
2. 应用回滚
3. 配置管理（识别一键 / 表格导入 / 导出当前配置）
4. 免密初始化
0. 退出
`, versionString(), curCfgPath)
		switch getIntChoice("请选择", 0, 4) {
		case 1:
			menuUpdate()
		case 2:
			menuRollback()
		case 3:
			menuConfig()
		case 4:
			menuSetupSSH()
		case 0:
			fmt.Println("再见。")
			return
		}
	}
}

// pickApp 列出配置中的应用并让用户选择（0=取消返回 nil）。
func pickApp(cfg *config.Config) *config.App {
	fmt.Println("\n可用应用:")
	for i := range cfg.Webs {
		a := &cfg.Webs[i]
		fmt.Printf("  %d. %s (%s)  master %d台 / update %d台 / static %d台\n",
			i+1, a.Web, a.MiddleType, len(a.Master), len(a.Update), len(a.StaticPageGroup))
	}
	idx := getIntChoice("请输入应用编号", 1, len(cfg.Webs))
	if idx == 0 {
		return nil
	}
	return &cfg.Webs[idx-1]
}

// askCfgPath 询问配置文件路径（默认当前配置），并把它设为会话当前配置。
func askCfgPath() (string, *config.Config, error) {
	p := getInput("配置文件路径", curCfgPath)
	cfg, err := config.Load(p)
	if err != nil {
		return "", nil, err
	}
	curCfgPath = p
	return p, cfg, nil
}

// saveCurConfig 把配置写入 YAML 并设为当前配置（识别/导入后的落地动作）。
func saveCurConfig(cfg *config.Config, path string) error {
	if len(cfg.GlobalExcludeLogs) == 0 {
		cfg.GlobalExcludeLogs = []string{"*.log", "logs/"}
	}
	if err := cfg.Save(path); err != nil {
		return err
	}
	curCfgPath = path
	return nil
}

// ---- 1. 应用更新 ----

func menuUpdate() {
	_, cfg, err := askCfgPath()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	app := pickApp(cfg)
	if app == nil {
		return
	}
	pass := getInput("SSH 密码（已免密可留空）", "")

	for {
		fmt.Printf("\n--- 更新应用 %s (%s) ---\n", app.Web, app.MiddleType)
		fmt.Printf("1. Master 群组 (%d台)\n", len(app.Master))
		fmt.Printf("2. Update 群组 (%d台)\n", len(app.Update))
		fmt.Println("3. 所有应用群组 (Master + Update)")
		if app.MiddleType == "tomcat" {
			fmt.Println("4. 静态页面部分更新")
			fmt.Println("5. 静态页面全量更新")
			fmt.Println("6. 清理历史更新包（update/）")
			fmt.Println("7. 压缩未压缩的备份包（多线程）")
			fmt.Println("0. 返回")
		} else {
			fmt.Println("4. 静态页面更新 (JAR)")
			fmt.Println("6. 清理历史更新包（update/）")
			fmt.Println("7. 压缩未压缩的备份包（多线程）")
			fmt.Println("0. 返回")
		}
		c := getIntChoice("请选择", 0, 7)
		switch {
		case c == 0:
			return
		case c >= 1 && c <= 3:
			groups := []string{appflow.GroupMaster, appflow.GroupUpdate}
			if c == 1 {
				groups = []string{appflow.GroupMaster}
			} else if c == 2 {
				groups = []string{appflow.GroupUpdate}
			}
			runGroupUpdate(cfg, app.Web, groups, pass)
		case c == 4 && app.MiddleType == "tomcat":
			rel := getInput("应用内相对路径（如 view/css）", "")
			if rel == "" {
				fmt.Println("⚠️ 路径不能为空")
				continue
			}
			runStatic(cfg, app.Web, "partial", rel, "", pass)
		case c == 5 && app.MiddleType == "tomcat":
			if confirm("全量更新前请确认 Master/Update 群组已更新过，继续?", false) {
				runStatic(cfg, app.Web, "full", "", "", pass)
			}
		case c == 4 && app.MiddleType == "jar":
			src := getInput("本地静态文件目录", "")
			if src == "" {
				fmt.Println("⚠️ 目录不能为空")
				continue
			}
			runStatic(cfg, app.Web, "jar", "", src, pass)
		case c == 6:
			maintainCleanUpdate()
		case c == 7:
			maintainCompressBackups()
		}
	}
}

func runGroupUpdate(cfg *config.Config, appName string, groups []string, pass string) {
	pkg := filepath.Join("update", appName)
	if fi, err := os.Stat(pkg); err != nil || !fi.IsDir() {
		fmt.Printf("❌ 更新包目录不存在: %s（请先放置新版包，目录名与应用名一致）\n", pkg)
		return
	}
	fmt.Printf("\n更新包: %s（%d 个顶层条目）\n", pkg, countEntries(pkg))

	fmt.Println("\n--- 第一步：模拟执行（dry-run，不改动服务器）---")
	dry := newRunner(cfg, pass, "", true, true)
	dry.UpdateDir = "update"
	dry.BackupDir = "backups"
	sum, err := dry.Update(appName, groups)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	reportSummary(sum)

	if !confirm("\n确认按上述计划正式执行?", false) {
		fmt.Println("已取消（服务器未做任何改动）。")
		return
	}
	fmt.Println("\n--- 第二步：正式执行 ---")
	real := newRunner(cfg, pass, "", false, true)
	real.UpdateDir = "update"
	real.BackupDir = "backups"
	sum, err = real.Update(appName, groups)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	reportSummary(sum)
}

func runStatic(cfg *config.Config, appName, mode, rel, src, pass string) {
	fmt.Println("\n--- 第一步：模拟执行（dry-run）---")
	dry := newRunner(cfg, pass, "", true, true)
	dry.UpdateDir = "update"
	dry.BackupDir = "backups"
	sum, err := invokeStatic(dry, appName, mode, rel, src)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	reportSummary(sum)
	if !confirm("\n确认按上述计划正式执行?", false) {
		fmt.Println("已取消。")
		return
	}
	fmt.Println("\n--- 第二步：正式执行 ---")
	real := newRunner(cfg, pass, "", false, true)
	real.UpdateDir = "update"
	real.BackupDir = "backups"
	sum, err = invokeStatic(real, appName, mode, rel, src)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	reportSummary(sum)
}

func invokeStatic(r *appflow.Runner, appName, mode, rel, src string) (*appflow.Summary, error) {
	switch mode {
	case "full":
		return r.StaticFullTomcat(appName)
	case "partial":
		return r.StaticPartial(appName, rel)
	default:
		return r.StaticJar(appName, src)
	}
}

// ---- 2. 应用回滚 ----

func menuRollback() {
	_, cfg, err := askCfgPath()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	app := pickApp(cfg)
	if app == nil {
		return
	}

	vs, err := appflow.ListVersions("backups", app.Web)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	fmt.Printf("\n%s 可回滚版本（新→旧）:\n", app.Web)
	for i, v := range vs {
		fmt.Printf("  %d. %s\n", i+1, v)
	}
	idx := getIntChoice("请输入版本编号", 1, len(vs))
	version := vs[idx-1]
	groups := parseGroups(getInput("群组 (master,update,static)", "master,update,static"))
	pass := getInput("SSH 密码（已免密可留空）", "")

	fmt.Println("\n--- 第一步：模拟执行（dry-run）---")
	dry := newRunner(cfg, pass, "", true, true)
	dry.BackupDir = "backups"
	sum, err := dry.Rollback(app.Web, version, groups)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	reportSummary(sum)
	if !confirm("\n确认按上述计划正式回滚?", false) {
		fmt.Println("已取消。")
		return
	}
	fmt.Println("\n--- 第二步：正式执行 ---")
	real := newRunner(cfg, pass, "", false, true)
	real.BackupDir = "backups"
	sum, err = real.Rollback(app.Web, version, groups)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	reportSummary(sum)
}

// ---- 3. 配置管理：识别 / 导入 与 导出 彻底拆分 ----

func menuConfig() {
	for {
		fmt.Printf(`
--- 配置管理（当前配置: %s）---
1. 识别一键部署清单 → 载入当前配置（存 YAML，不导表格）
2. 生成标准配置模板
3. 表格导入 → 载入当前配置
4. 导出当前配置 → 表格
5. 导出当前配置 → YAML
6. 新增应用（人工）
7. 给应用添加主机（人工）
8. 删除应用
9. 删除应用下的某台主机
10. 修改主机配置（端口/健康检查/启停命令等）
0. 返回
`, curCfgPath)
		switch getIntChoice("请选择", 0, 10) {
		case 1:
			configFromOneinstall()
		case 2:
			if err := cmdTemplate([]string{"-o", getInput("模板输出文件", "app_updater_配置模板.xlsx")}); err != nil {
				fmt.Println("❌", err)
			}
		case 3:
			configFromXlsx()
		case 4:
			src := getInput("要导出的配置文件", curCfgPath)
			if err := cmdExport([]string{"-c", src, "-o", getInput("表格输出文件", "app_updater_导出.xlsx")}); err != nil {
				fmt.Println("❌", err)
			}
		case 5:
			src := getInput("要导出的配置文件", curCfgPath)
			cfg, err := config.Load(src)
			if err != nil {
				fmt.Println("❌", err)
				continue
			}
			dst := getInput("YAML 输出路径", "config_copy.yaml")
			if err := cfg.Save(dst); err != nil {
				fmt.Println("❌", err)
				continue
			}
			curCfgPath = dst
			fmt.Printf("✅ 已导出 %s（%d 个应用），并设为当前配置\n", dst, len(cfg.Webs))
		case 6:
			manualAddApp()
		case 7:
			manualAddHost()
		case 8:
			manualDeleteApp()
		case 9:
			manualDeleteHost()
		case 10:
			manualEditHost()
		case 0:
			return
		}
	}
}

// maintainCleanUpdate 清理 update/ 下的历史更新包（先统计再确认）。
func maintainCleanUpdate() {
	updateDir := getInput("更新包目录", "update")
	res, err := maintain.CleanUpdatePackages(updateDir, true)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	if len(res.RemovedApps) == 0 {
		fmt.Printf("ℹ️ %s 下没有可清理的应用包目录\n", updateDir)
		return
	}
	fmt.Printf("\n将清理 %s 下 %d 个应用包目录（共 %d 个文件，%s）：\n",
		updateDir, len(res.RemovedApps), res.RemovedFiles, maintain.HumanBytes(res.FreedBytes))
	for _, a := range res.RemovedApps {
		fmt.Println("  -", a+"/")
	}
	if !confirm("\n确认删除以上更新包?（不可恢复）", false) {
		fmt.Println("已取消。")
		return
	}
	if _, err := maintain.CleanUpdatePackages(updateDir, false); err != nil {
		fmt.Println("❌", err)
		return
	}
	fmt.Printf("✅ 已清理，释放 %s\n", maintain.HumanBytes(res.FreedBytes))
}

// maintainCompressBackups 对未压缩的备份版本目录做多线程压缩。
func maintainCompressBackups() {
	backupDir := getInput("备份目录", "backups")

	// 先预览
	pre, err := maintain.CompressBackups(backupDir, 0, true)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	if len(pre.Archives) == 0 {
		fmt.Printf("ℹ️ %s 下没有需要压缩的备份版本目录\n", backupDir)
		for _, s := range pre.Skipped {
			fmt.Println("  跳过:", s)
		}
		return
	}
	fmt.Printf("\n待压缩 %d 个版本目录，原始体积约 %s\n", len(pre.Archives), maintain.HumanBytes(pre.Bytes))
	for _, s := range pre.Skipped {
		fmt.Println("  跳过:", s)
	}
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	fmt.Printf("\n将使用 %d 线程压缩（每版本一个 tar.gz，压缩成功后删除原目录）\n", workers)
	if !confirm("确认开始压缩?", false) {
		fmt.Println("已取消。")
		return
	}

	fmt.Println("\n压缩中，请稍候...")
	res, err := maintain.CompressBackups(backupDir, workers, false)
	if err != nil {
		fmt.Println("❌", err)
	}
	fmt.Printf("\n✅ 压缩完成：%d 个版本，%s → %s（耗时 %s）\n",
		len(res.Archives), maintain.HumanBytes(res.Bytes), maintain.HumanBytes(res.Packed),
		res.Elapsed.Round(time.Second))
	if maintain.HumanBytes(res.Bytes) != "" && res.Bytes > 0 {
		ratio := float64(res.Packed) / float64(res.Bytes) * 100
		fmt.Printf("   压缩率 %.1f%%\n", ratio)
	}
	for _, a := range res.Archives {
		fmt.Println("  ", a)
	}
}

// pickHost 选应用→群组→主机，返回可修改的 Host 指针。
func pickHost(app *config.App) (*config.Host, string) {
	fmt.Println("1. master  2. update  3. static")
	g := getIntChoice("哪个群组的主机", 1, 3)
	group := []string{appflow.GroupMaster, appflow.GroupUpdate, appflow.GroupStatic}[g-1]
	var hosts []config.Host
	switch group {
	case appflow.GroupMaster:
		hosts = app.Master
	case appflow.GroupUpdate:
		hosts = app.Update
	default:
		hosts = app.StaticPageGroup
	}
	if len(hosts) == 0 {
		fmt.Printf("⚠️ %s 的 %s 群组没有主机\n", app.Web, group)
		return nil, group
	}
	fmt.Printf("\n%s 的 %s 群组主机:\n", app.Web, group)
	for i, h := range hosts {
		fmt.Printf("  %d. %s  %s  uri=%s mode=%s\n", i+1, h.Host, h.WebPath, h.CheckURI, orLocal(h.HealthMode))
	}
	idx := getIntChoice("要修改哪台", 1, len(hosts))
	switch group {
	case appflow.GroupMaster:
		return &app.Master[idx-1], group
	case appflow.GroupUpdate:
		return &app.Update[idx-1], group
	default:
		return &app.StaticPageGroup[idx-1], group
	}
}

func orLocal(m string) string {
	if m == "" {
		return "remote(默认)"
	}
	return m
}

// manualEditHost 逐字段修改主机配置（回车=保持当前值）。
func manualEditHost() {
	cfg, err := loadCurOrEmpty()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	app := pickApp(cfg)
	if app == nil {
		return
	}
	h, group := pickHost(app)
	if h == nil {
		return
	}
	fmt.Println("\n逐项修改（直接回车 = 保持当前值）：")

	h.Host = getInput("主机 IP", h.Host)
	p := getInput("SSH 端口", portOr(h.SSHPort, "22"))
	if n, err := strconv.Atoi(p); err == nil && n > 0 {
		h.SSHPort = n
	}
	h.SSHUser = getInput("SSH 用户（空=跟随全局）", h.SSHUser)
	h.WebPath = getInput("部署路径", h.WebPath)
	p = getInput("服务端口", portOr(h.ServicePort, ""))
	if n, err := strconv.Atoi(p); err == nil {
		h.ServicePort = n
	}
	uri := getInput("健康检查 URI（相对路径；输 - 清空改为TCP端口探测；回车=保持）", h.CheckURI)
	if uri == "-" {
		h.CheckURI = "" // 显式清空 → 更新后按服务端口做 TCP 探测
	} else {
		h.CheckURI = normalizeCheckURI(uri)
	}

	fmt.Printf("  健康检查执行位置（当前: %s）:\n", orLocal(h.HealthMode))
	fmt.Println("    1. remote（目标机本地，默认推荐）  2. local（工具机发起）  3. none（跳过）")
	switch getIntChoice("请选择（回车=保持）", 0, 3) {
	case 1:
		h.HealthMode = "remote"
	case 2:
		h.HealthMode = "local"
	case 3:
		h.HealthMode = "none"
	}

	if group != appflow.GroupStatic {
		h.StartCmd = getInput("启动命令", h.StartCmd)
		h.StopCmd = getInput("停止命令", h.StopCmd)
	}
	h.User = getInput("文件属主用户", h.User)
	h.Group = getInput("文件属主组", h.Group)
	h.Remark = getInput("备注", h.Remark)

	finishEdit(cfg, fmt.Sprintf("%s 修改主机 %s", app.Web, h.Host))
}

func portOr(n int, def string) string {
	if n > 0 {
		return strconv.Itoa(n)
	}
	return def
}

// manualDeleteHost 删除应用下某群组的某台主机。
func manualDeleteHost() {
	cfg, err := loadCurOrEmpty()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	app := pickApp(cfg)
	if app == nil {
		return
	}
	fmt.Println("1. master  2. update  3. static")
	g := getIntChoice("从哪个群组删除", 1, 3)
	group := []string{appflow.GroupMaster, appflow.GroupUpdate, appflow.GroupStatic}[g-1]
	hosts := app.GroupHosts(group)
	if len(hosts) == 0 {
		fmt.Printf("⚠️ %s 的 %s 群组没有主机\n", app.Web, group)
		return
	}
	fmt.Printf("\n%s 的 %s 群组主机:\n", app.Web, group)
	for i, h := range hosts {
		fmt.Printf("  %d. %s  %s  %s\n", i+1, h.Host, h.WebPath, h.Remark)
	}
	idx := getIntChoice("要删除哪台", 1, len(hosts))
	target := hosts[idx-1]
	if !confirm(fmt.Sprintf("确认从 %s 的 %s 群组删除主机 %s?", app.Web, group, target.Host), false) {
		fmt.Println("已取消。")
		return
	}
	switch group {
	case appflow.GroupMaster:
		app.Master = append(app.Master[:idx-1], app.Master[idx:]...)
	case appflow.GroupUpdate:
		app.Update = append(app.Update[:idx-1], app.Update[idx:]...)
	default:
		app.StaticPageGroup = append(app.StaticPageGroup[:idx-1], app.StaticPageGroup[idx:]...)
	}
	finishEdit(cfg, fmt.Sprintf("%s 删除主机 %s", app.Web, target.Host))
}

// loadCurOrEmpty 载入当前配置；文件不存在时允许从空配置开始（人工建表场景）。
func loadCurOrEmpty() (*config.Config, error) {
	if _, err := os.Stat(curCfgPath); err == nil {
		return config.Load(curCfgPath)
	}
	if confirm(fmt.Sprintf("配置文件 %s 不存在，从空配置开始?", curCfgPath), true) {
		return &config.Config{Global: config.Global{AnsibleUser: "root", AnsibleSSHPort: 22}}, nil
	}
	return nil, fmt.Errorf("未加载配置")
}

// printValidation 展示校验结果并返回统计（错误数/警告数）。
func printValidation(issues []config.Issue) (errs, warns int) {
	for _, is := range issues {
		if is.Severity == "error" {
			errs++
		} else {
			warns++
		}
	}
	if len(issues) > 0 {
		fmt.Printf("\n---- 配置校验：%d 个错误 / %d 个警告 ----\n", errs, warns)
		printIssues(issues)
	}
	return errs, warns
}

// finishEdit 人工编辑后的统一收口：完整校验 → 确认 → 落盘当前配置。
// 表格导入、人工增删改应用/主机、识别一键，全部走这一条路径，保证任何配置变更都过一轮有效性验证。
func finishEdit(cfg *config.Config, what string) {
	issues := cfg.Validate()
	errs, warns := printValidation(issues)
	if errs > 0 && !confirm(fmt.Sprintf("配置存在 %d 个错误级问题，仍要保存?", errs), false) {
		fmt.Println("已放弃保存（可用表格导入或重新编辑修正）")
		return
	}
	if err := saveCurConfig(cfg, curCfgPath); err != nil {
		fmt.Println("❌", err)
		return
	}
	status := "✅ 校验通过"
	if errs > 0 {
		status = fmt.Sprintf("⚠️ 已保存但含 %d 个错误", errs)
	} else if warns > 0 {
		status = fmt.Sprintf("✅ 校验通过（%d 个警告）", warns)
	}
	fmt.Printf("%s：已保存%s → %s（%d 个应用）\n", status, what, curCfgPath, len(cfg.Webs))
	if errs == 0 && warns == 0 {
		fmt.Println("   配置完全有效，可直接执行 update/rollback")
	}
}

// askHost 交互录入一台主机。
func askHost(group, appName string) *config.Host {
	h := config.Host{}
	h.Host = getInput("主机 IP", "")
	if strings.TrimSpace(h.Host) == "" {
		return nil
	}
	p := getInput("SSH 端口", "22")
	if n, err := strconv.Atoi(p); err == nil && n > 0 {
		h.SSHPort = n
	}
	h.SSHUser = getInput("SSH 用户（回车=跟随全局）", "")
	h.WebPath = getInput("部署路径（绝对路径）", "")
	defPort := ""
	if group == appflow.GroupStatic {
		defPort = "0"
	}
	h.ServicePort, _ = strconv.Atoi(getInput("服务端口", defPort))
	h.CheckURI = normalizeCheckURI(getInput("健康检查 URI（只填相对路径，如 /eUrbanUMA/main.htm；回车=默认按服务端口做 TCP 探测）", ""))
	if h.CheckURI != "" || h.ServicePort > 0 {
		fmt.Println("  健康检查执行位置:")
		fmt.Println("    1. 目标机本地发起（默认推荐，不受服务器间端口限制）")
		fmt.Println("    2. 工具所在机发起（需工具机可访问应用端口）")
		fmt.Println("    3. 跳过健康检查")
		switch getIntChoice("请选择", 1, 3) {
		case 1:
			h.HealthMode = "remote"
		case 2:
			h.HealthMode = "local"
		case 3:
			h.HealthMode = "none"
		}
	}
	if group != appflow.GroupStatic {
		h.StartCmd = getInput("启动命令（如 systemctl start xxx）", "")
		h.StopCmd = getInput("停止命令（如 systemctl stop xxx）", "")
	}
	h.User = getInput("文件属主用户", "egova")
	h.Group = getInput("文件属主组", "egova")
	h.Remark = getInput("备注", "人工添加")
	return &h
}

// manualAddApp 人工新增应用（含至少一台 master 主机）。
func manualAddApp() {
	cfg, err := loadCurOrEmpty()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	name := getInput("应用名称", "")
	if strings.TrimSpace(name) == "" {
		fmt.Println("⚠️ 应用名称不能为空")
		return
	}
	if cfg.AppByName(name) != nil {
		fmt.Printf("⚠️ 应用 %s 已存在（加主机请用「给应用添加主机」）\n", name)
		return
	}
	var mt string
	for {
		mt = strings.ToLower(getInput("中间件类型 tomcat/jar", "jar"))
		if mt == "tomcat" || mt == "jar" {
			break
		}
		fmt.Println("  ⚠️ 只能填 tomcat 或 jar")
	}
	app := config.App{Web: name, MiddleType: mt}
	if mt == "jar" {
		app.LogDir = "logs/"
		app.RetainedConfigFile = []string{name + ".env", "application.properties"}
	} else {
		app.LogDir = "WEB-INF/logs"
		app.RetainedConfigFile = []string{
			"WEB-INF/classes/jdbc.properties", "WEB-INF/classes/redis.properties",
		}
	}
	if l := getInput("保留配置文件（逗号分隔，回车=上述默认）", ""); l != "" {
		app.RetainedConfigFile = splitList(l)
	}
	if l := getInput("master 专属排除文件（逗号分隔，可回车跳过）", ""); l != "" {
		app.MasterExclusiveFiles = splitList(l)
	}

	fmt.Println("\n添加 Master 主机（至少一台）：")
	for {
		if h := askHost(appflow.GroupMaster, name); h != nil {
			app.Master = append(app.Master, *h)
		} else if len(app.Master) == 0 {
			fmt.Println("⚠️ 至少需要一台 Master 主机")
			continue
		} else {
			break
		}
		if !confirm("继续添加 Master 主机?", false) {
			break
		}
	}
	if len(app.Master) == 0 {
		fmt.Println("❌ 未添加任何 Master 主机，已取消")
		return
	}
	if confirm("添加 Update 群组主机?", false) {
		for {
			if h := askHost(appflow.GroupUpdate, name); h != nil {
				app.Update = append(app.Update, *h)
			}
			if !confirm("继续添加 Update 主机?", false) {
				break
			}
		}
	}
	if confirm("添加 static 静态群组主机?", false) {
		for {
			if h := askHost(appflow.GroupStatic, name); h != nil {
				app.StaticPageGroup = append(app.StaticPageGroup, *h)
			}
			if !confirm("继续添加 static 主机?", false) {
				break
			}
		}
	}

	cfg.Webs = append(cfg.Webs, app)
	finishEdit(cfg, "应用 "+name)
}

// manualAddHost 给已有应用的指定群组添加主机。
func manualAddHost() {
	cfg, err := loadCurOrEmpty()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	app := pickApp(cfg)
	if app == nil {
		return
	}
	fmt.Println("1. master  2. update  3. static")
	g := getIntChoice("添加到哪个群组", 1, 3)
	group := []string{appflow.GroupMaster, appflow.GroupUpdate, appflow.GroupStatic}[g-1]

	added := 0
	for {
		if h := askHost(group, app.Web); h != nil {
			switch group {
			case appflow.GroupMaster:
				app.Master = append(app.Master, *h)
			case appflow.GroupUpdate:
				app.Update = append(app.Update, *h)
			default:
				app.StaticPageGroup = append(app.StaticPageGroup, *h)
			}
			added++
		}
		if !confirm("继续添加?", false) {
			break
		}
	}
	if added > 0 {
		finishEdit(cfg, fmt.Sprintf("%s 的 %d 台 %s 主机", app.Web, added, group))
	}
}

// manualDeleteApp 删除整个应用（含全部群组主机）。
func manualDeleteApp() {
	cfg, err := loadCurOrEmpty()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	app := pickApp(cfg)
	if app == nil {
		return
	}
	if !confirm(fmt.Sprintf("确认删除应用 %s（master %d台 / update %d台 / static %d台 全部移除）?",
		app.Web, len(app.Master), len(app.Update), len(app.StaticPageGroup)), false) {
		fmt.Println("已取消。")
		return
	}
	for i := range cfg.Webs {
		if cfg.Webs[i].Web == app.Web {
			cfg.Webs = append(cfg.Webs[:i], cfg.Webs[i+1:]...)
			break
		}
	}
	finishEdit(cfg, "删除应用 "+app.Web)
}

// splitList 逗号（中英文）/空格分隔的列表。
func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '，' || r == ' ' || r == '\t'
	}) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// normalizeCheckURI 把用户输入纠偏为相对路径（check_uri 只存 "/xxx" 形式）：
//   - 完整 URL（http://host:port/xxx）→ 取 Path(?Query)
//   - host:port/xxx、xxx/yyy 等含 "/" 的输入 → 取第一个 "/" 起
//   - 无 "/" 的裸路径（main.htm）→ 补 "/" 前缀
func normalizeCheckURI(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Path != "" {
			p := u.Path
			if u.RawQuery != "" {
				p += "?" + u.RawQuery
			}
			fmt.Printf("  ℹ️ 已自动转换为相对路径: %s\n", p)
			return p
		}
	}
	if !strings.HasPrefix(s, "/") {
		if i := strings.Index(s, "/"); i >= 0 {
			p := s[i:]
			fmt.Printf("  ℹ️ 已自动转换为相对路径: %s\n", p)
			return p
		}
		p := "/" + s
		fmt.Printf("  ℹ️ 已自动补全为: %s\n", p)
		return p
	}
	return s
}

// configFromOneinstall 识别一键部署 → 只载入/存 YAML（不导表格；需要表格走选项 4）。
func configFromOneinstall() {
	src := genSource{
		SSHHost:           getInput("识别方式（回车=本机自动识别 / 输入服务器IP=远程识别）", ""),
		SSHPort:           22,
		SSHUser:           "root",
		IncludeUndeployed: confirm("包含未部署（undeployed）的应用?", false),
	}
	if src.SSHHost != "" {
		src.SSHPass = getInput("SSH 密码", "")
		p := getInput("SSH 端口", "22")
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			src.SSHPort = n
		}
	}

	cfg, notes, source, err := loadGenConfig(src)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	fmt.Println("识别来源:", source)
	fmt.Printf("识别到 %d 个应用\n", len(cfg.Webs))
	printIssues(notes)

	// 识别后立即做配置校验：有 error 就当场摆出来，避免"看起来成功、实际不能用"
	valIssues := cfg.Validate()
	if len(valIssues) > 0 {
		fmt.Println("\n---- 配置校验 ----")
		printIssues(valIssues)
	}
	if config.HasError(valIssues) {
		fmt.Println("\n❌ 识别出的配置存在错误级问题（常见：v1 部署缺端口，需人工补填）。")
		fmt.Println("   可先保存，然后用「10. 修改主机配置」逐台补端口/健康检查，或「4. 导出当前配置 → 表格」改完再导入。")
		if !confirm("仍要保存这份带错误的配置?", false) {
			fmt.Println("已放弃保存（当前配置未改变）。")
			return
		}
	}

	dst := getInput("保存配置到 YAML", curCfgPath)
	if err := saveCurConfig(cfg, dst); err != nil {
		fmt.Println("❌", err)
		return
	}
	if config.HasError(valIssues) {
		fmt.Printf("⚠️ 已保存 %s（%d 个应用）—— 存在错误，补齐后才能执行 update\n", curCfgPath, len(cfg.Webs))
	} else {
		fmt.Printf("✅ 已载入当前配置: %s（%d 个应用）；需要表格用「导出当前配置 → 表格」\n", curCfgPath, len(cfg.Webs))
	}
}

// configFromXlsx 表格导入 → 载入当前配置（校验不过不落地）。
func configFromXlsx() {
	f := getInput("表格文件路径", "")
	if f == "" {
		fmt.Println("⚠️ 路径不能为空")
		return
	}
	dst := getInput("保存配置到 YAML", curCfgPath)
	cfg, issues, err := xlsx.Import(f)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	issues = append(issues, cfg.Validate()...)
	printIssues(issues)
	if config.HasError(issues) {
		fmt.Println("❌ 校验未通过，未写入", dst)
		return
	}
	if err := saveCurConfig(cfg, dst); err != nil {
		fmt.Println("❌", err)
		return
	}
	fmt.Printf("✅ 已载入当前配置: %s（%d 个应用）\n", curCfgPath, len(cfg.Webs))
}

// ---- 4. 免密初始化 ----

func menuSetupSSH() {
	args := []string{"-c", getInput("配置文件路径", curCfgPath)}
	if app := getInput("仅处理某应用？（回车=全部主机）", ""); app != "" {
		args = append(args, "--app", app)
	}
	if pass := getInput("SSH 密码（未免密主机需要）", ""); pass != "" {
		args = append(args, "--pass", pass)
	}
	if err := cmdSetupSSH(args); err != nil {
		fmt.Println("❌", err)
	}
}

// ---- 小工具 ----

func countEntries(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	return len(entries)
}
