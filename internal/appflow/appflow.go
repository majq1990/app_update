// Package appflow 执行链路：应用更新与回滚。
// 语义对齐旧版 Python 工具（run_update.py / run_rollback.py / utils.py）：
//   - 更新：停 → 备份到本地 → 覆盖式同步（无 --delete）→ chown → 启动 → 健康检查；
//     单台失败不中断（旧版语义），最后汇总报告。
//   - 回滚：停 → 从本地备份全量还原（--delete）→ chown → 启动 → 健康检查。
//   - 健康检查（一键部署标准）：check_uri 有值 → HTTP 200 访问验证；
//     check_uri 留空 → 默认按 service_port 做 TCP 端口连通性探测；health_mode: none → 显式跳过。
//
// 相对旧版的修正：JAR 应用回滚还原完整应用目录（旧版只还原了静态目录）。
package appflow

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/syncx"
)

// Conn 单台主机的远程访问（命令执行 + 文件系统）。
type Conn interface {
	Run(cmd string) (string, error)
	syncx.RemoteFS
}

// Dialer 按主机建立连接（实现在 cmd 层：解析全局/主机级 SSH 参数并连 sshx）。
type Dialer interface {
	Dial(h config.Host) (Conn, error)
	Close()
}

// HealthChecker 健康检查函数（可注入测试替身）。
type HealthChecker func(host string, port int, uri string, budget time.Duration) bool

// Logger 日志函数。
type Logger func(format string, args ...interface{})

// Runner 更新/回滚执行器。
type Runner struct {
	Cfg       *config.Config
	Dial      Dialer
	UpdateDir string // 本地更新包根目录，默认 "update"
	BackupDir string // 本地备份根目录，默认 "backups"
	DryRun    bool
	Logf      Logger
	// DetailLogf 文件传输明细输出（[目录]/[传输]/[删除]/[保留] 逐文件行）。
	// 默认与 Logf 相同；CLI 传入"只写日志文件"实现后生效：
	//   - tomcat 类应用更新/回滚、全部静态页面传输 → 明细只进日志文件（dry-run 也不例外，
	//     控制台只看「备份→/同步完成」汇总行——tomcat 现场动辄上万文件，逐行打印没有价值）；
	//   - jar 类应用更新 → 明细照旧打到控制台（含 dry-run）。
	DetailLogf Logger
	Health     HealthChecker                         // nil → HTTPHealth（local 模式的 HTTP 验证）
	TCPProbe   func(string, int, time.Duration) bool // nil → TCPHealth（local 模式的端口探测）
	Now        func() time.Time                      // 备份版本号时间源（测试可注入）
	Sleep      func(time.Duration)
}

// HostStatus 单台主机的执行结果。
type HostStatus struct {
	App    string
	Group  string
	Host   string
	OK     bool
	Detail string
}

// Summary 一次 update/rollback 的汇总。
type Summary struct {
	App     string
	Version string // 备份版本号（yyyymmddHH）
	Results []HostStatus
}

func (s *Summary) FailCount() int {
	n := 0
	for _, r := range s.Results {
		if !r.OK {
			n++
		}
	}
	return n
}

// 群组常量（沿用旧版命名，static 对应配置中的 static_page_group）。
const (
	GroupMaster = "master"
	GroupUpdate = "update"
	GroupStatic = "static"
)

func (r *Runner) logf(format string, args ...interface{}) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Runner) sleep(d time.Duration) {
	if r.DryRun || r.Sleep == nil {
		return
	}
	r.Sleep(d)
}

// tomcatCheckMinutes 全局 tomcat 健康检查预算（分钟），默认 20。
func (r *Runner) tomcatCheckMinutes() int {
	if r.Cfg != nil && r.Cfg.TomcatCheckMinutes > 0 {
		return r.Cfg.TomcatCheckMinutes
	}
	return 20
}

// jarCheckMinutes 全局 jar 健康检查预算（分钟），默认 5（435MB 级大 jar 启动可能 >1 分钟）。
func (r *Runner) jarCheckMinutes() int {
	if r.Cfg != nil && r.Cfg.JarCheckMinutes > 0 {
		return r.Cfg.JarCheckMinutes
	}
	return 5
}

func (r *Runner) healthFn() HealthChecker {
	if r.Health != nil {
		return r.Health
	}
	return HTTPHealth
}

// detailFor 选择文件传输明细的输出通道：
// tomcat 更新/回滚、静态页面传输 → 仅日志文件（dry-run 也不例外，控制台只看汇总行）；
// jar 更新 → 后端文件（jar/env/libs）打控制台，前端静态文件（webApps 等）只进日志文件。
func (r *Runner) detailFor(app *config.App, static bool) Logger {
	if (static || app.MiddleType == "tomcat") && r.DetailLogf != nil {
		return r.DetailLogf
	}
	if app.MiddleType == "jar" && r.DetailLogf != nil {
		return r.routedDetail()
	}
	return r.Logf
}

// routedDetail jar 应用专用：按路径逐行分流。
// 前端静态文件（webApps/webapp/static/frontend/dist 等目录下的资源）只写日志文件，
// 后端文件（jar、env、jvm 配置等）照常打印+写日志。
func (r *Runner) routedDetail() Logger {
	console := r.Logf // 控制台+文件双写
	fileOnly := r.DetailLogf
	return func(format string, args ...interface{}) {
		line := fmt.Sprintf(format, args...)
		rel := line
		if i := strings.LastIndex(line, "] "); i >= 0 {
			rel = line[i+2:]
		}
		if isFrontendPath(rel) {
			fileOnly("%s", line)
		} else {
			console("%s", line)
		}
	}
}

// isFrontendPath 判断相对路径是否属于前端静态资源目录（jar 应用里的 webApps 等）。
func isFrontendPath(rel string) bool {
	first := strings.SplitN(strings.TrimPrefix(rel, "/"), "/", 2)[0]
	switch strings.ToLower(first) {
	case "webapps", "webapp", "static", "frontend", "front", "dist", "public":
		return true
	}
	return false
}

// checkHealth 健康检查规则（一键部署标准）：
//   - check_uri 有值 → HTTP 200 访问验证；
//   - check_uri 留空（且 service_port>0）→ 默认做 TCP 端口连通性探测；
//   - health_mode: none → 显式跳过；无 URI 且无端口 → 跳过。
//
// 执行位置：local（默认，工具所在机发起）/ remote（经 SSH 通道在目标机本地探测，
// 严格网络隔离场景使用，无需常驻 agent）。
// checkHealth 健康检查规则（一键部署标准）：
//   - check_uri 有值 → HTTP 200 访问验证；留空（且 service_port>0）→ TCP 端口连通性探测；
//   - health_mode: none → 显式跳过；无 URI 且无端口 → 跳过。
//
// 执行位置（默认目标机本地）：
//   - ""（默认）/remote → 经 SSH 通道在目标机本地探测（bash /dev/tcp，无需常驻 agent，
//     不受工具机到应用端口的网络限制影响）；
//   - local → 工具所在机发起 HTTP/TCP 探测（显式选择才用）。
func (r *Runner) checkHealth(conn Conn, h config.Host, budget time.Duration) bool {
	if h.HealthMode == "none" {
		r.logf("      [健康检查] health_mode=none，跳过")
		return true
	}
	useRemote := h.HealthMode != "local"
	if strings.TrimSpace(h.CheckURI) != "" {
		if useRemote {
			r.logf("      [健康检查] 目标机本地探测 http://127.0.0.1:%d%s（预算 %s）", h.ServicePort, h.CheckURI, budget)
			return r.pollRemote(conn, fmt.Sprintf(
				`timeout 10 bash -c 'exec 3<>/dev/tcp/127.0.0.1/%d && printf "GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n" >&3 && head -1 <&3 | grep -q " 200 "'`,
				h.ServicePort, h.CheckURI), budget)
		}
		r.logf("      [健康检查] 工具机探测 http://%s:%d%s（预算 %s）", h.Host, h.ServicePort, h.CheckURI, budget)
		return r.healthFn()(h.Host, h.ServicePort, h.CheckURI, budget)
	}
	if h.ServicePort > 0 {
		if useRemote {
			r.logf("      [健康检查] 目标机本地 TCP 端口探测 127.0.0.1:%d（预算 %s）", h.ServicePort, budget)
			return r.pollRemote(conn, fmt.Sprintf(
				`timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/%d'`, h.ServicePort), budget)
		}
		r.logf("      [健康检查] 工具机 TCP 端口探测 %s:%d（预算 %s）", h.Host, h.ServicePort, budget)
		probe := r.TCPProbe
		if probe == nil {
			probe = TCPHealth
		}
		return probe(h.Host, h.ServicePort, budget)
	}
	r.logf("      [健康检查] 未配置 URI 且无服务端口，跳过")
	return true
}

// pollRemote 在目标机执行探测命令，每 10s 轮询直到预算耗尽。
func (r *Runner) pollRemote(conn Conn, cmd string, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for {
		if _, err := conn.Run(cmd); err == nil {
			return true
		}
		if time.Now().Add(10 * time.Second).After(deadline) {
			return false
		}
		r.sleep(10 * time.Second)
	}
}

// TCPHealth 默认 TCP 端口探测：dial 成功即视为就绪。每 10s 轮询，单次 3s 超时。
func TCPHealth(host string, port int, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 3*time.Second)
		if err == nil {
			_ = conn.Close()
			return true
		}
		if time.Now().Add(10 * time.Second).After(deadline) {
			return false
		}
		time.Sleep(10 * time.Second)
	}
}

func (r *Runner) updateDir() string {
	if r.UpdateDir != "" {
		return r.UpdateDir
	}
	return "update"
}

func (r *Runner) backupDir() string {
	if r.BackupDir != "" {
		return r.BackupDir
	}
	return "backups"
}

// runCmd 执行远端命令。失败只记录不中断（旧版 execute_remote_command 语义）。
func (r *Runner) runCmd(c Conn, cmd, desc string) bool {
	if r.DryRun {
		r.logf("      [dry-run] %s: %s", desc, cmd)
		return true
	}
	r.logf("      %s: %s", desc, cmd)
	out, err := c.Run(cmd)
	if err != nil {
		r.logf("      ⚠️ %s 失败: %v（输出: %s）——继续执行", desc, err, strings.TrimSpace(out))
		return false
	}
	return true
}

// dialCache 连接复用（key = host:port:user）。
type dialCache struct {
	r     *Runner
	conns map[string]Conn
}

func (r *Runner) dialer() *dialCache { return &dialCache{r: r, conns: map[string]Conn{}} }

func (d *dialCache) get(h config.Host) (Conn, error) {
	key := fmt.Sprintf("%s:%d@%s", h.Host, h.SSHPort, h.SSHUser)
	if c, ok := d.conns[key]; ok {
		return c, nil
	}
	c, err := d.r.Dial.Dial(h)
	if err != nil {
		return nil, err
	}
	d.conns[key] = c
	return c, nil
}

func (d *dialCache) close() {
	if d.r.Dial != nil {
		d.r.Dial.Close()
	}
}

// Update 执行应用更新。groups 为空默认 [master, update]（顺序执行：先主后备）。
func (r *Runner) Update(appName string, groups []string) (*Summary, error) {
	app := r.Cfg.AppByName(appName)
	if app == nil {
		return nil, fmt.Errorf("配置中不存在应用 %q", appName)
	}
	if len(groups) == 0 {
		groups = []string{GroupMaster, GroupUpdate}
	}
	for _, g := range groups {
		if g != GroupMaster && g != GroupUpdate {
			return nil, fmt.Errorf("update 不支持群组 %q（可选 master/update）", g)
		}
	}

	ts := r.now().Format("2006010215")
	sum := &Summary{App: appName, Version: ts}
	cache := r.dialer()
	defer cache.close()

	srcDir := path.Join(r.updateDir(), appName)
	r.logf("--- 更新应用 %s（备份版本 %s，源目录 %s）---", appName, ts, srcDir)

	for _, g := range groups {
		hosts := app.GroupHosts(g)
		if len(hosts) == 0 {
			r.logf("  [%s] 群组无主机，跳过", g)
			continue
		}
		r.logf("  [%s] 群组 %d 台主机", g, len(hosts))
		for _, h := range hosts {
			r.logf("  ▶ %s (%s)", h.Host, h.WebPath)
			conn, err := cache.get(h)
			if err != nil {
				r.logf("      ❌ 连接失败: %v", err)
				sum.Results = append(sum.Results, HostStatus{App: appName, Group: g, Host: h.Host, Detail: "连接失败: " + err.Error()})
				continue
			}

			// 1. 停止（失败继续，旧版语义）
			if h.StopCmd != "" {
				r.runCmd(conn, h.StopCmd, "停止应用")
				r.sleep(2 * time.Second)
			}

			// 2. 备份远端 → 本地（排除日志；传输明细按应用类型走 detailFor：tomcat 只进日志文件）
			backupPath := path.Join(r.backupDir(), appName, ts, h.Host, appName)
			if res, err := syncx.Pull(conn, h.WebPath, backupPath, syncx.Options{
				Excludes: append(globalExcludes(r.Cfg), logDirPatterns(app)...),
				DryRun:   r.DryRun,
				Logf:     r.detailFor(app, false),
			}); err != nil {
				r.logf("      ❌ 备份失败: %v ——跳过此主机", err)
				sum.Results = append(sum.Results, HostStatus{App: appName, Group: g, Host: h.Host, Detail: "备份失败: " + err.Error()})
				continue
			} else {
				r.logf("      备份→ %s（%s）", backupPath, res)
			}

			// 3. 覆盖式同步新代码（无 --delete；排除日志/保留配置；tomcat update 群组额外排除 master 专属文件，
			//    并把目标端已存在的 master 专属文件清理掉——如 liquibase jar，备节点跑它有数据库锁冲突风险）
			excludes := append(logDirPatterns(app), app.RetainedConfigFile...)
			pushOpt := syncx.Options{
				Excludes: excludes,
				Retain:   app.RetainedConfigFile,
				DryRun:   r.DryRun,
				Logf:     r.detailFor(app, false),
			}
			if app.MiddleType == "tomcat" && g == GroupUpdate {
				excludes = append(excludes, app.MasterExclusiveFiles...)
				pushOpt.Excludes = excludes
				pushOpt.DeletePatterns = app.MasterExclusiveFiles
			}
			if res, err := syncx.Push(conn, srcDir, h.WebPath, pushOpt); err != nil {
				r.logf("      ❌ 同步失败: %v", err)
				sum.Results = append(sum.Results, HostStatus{App: appName, Group: g, Host: h.Host, Detail: "同步失败: " + err.Error()})
				continue
			} else {
				r.logf("      同步完成（%s）", res)
			}

			// 4. 属主
			r.runCmd(conn, fmt.Sprintf("chown -R %s:%s %s", h.User, h.Group, h.WebPath), "更新属主")

			// 5. 启动 + 健康检查
			if h.StartCmd != "" {
				r.runCmd(conn, h.StartCmd, "启动应用")
			}
			budget := time.Duration(r.jarCheckMinutes()) * time.Minute
			if app.MiddleType == "tomcat" {
				// 预算全局可配：tomcat_check_minutes（默认 20 分钟）/ jar_check_minutes（默认 5 分钟）
				budget = time.Duration(r.tomcatCheckMinutes()) * time.Minute
			}
			if r.DryRun {
				r.logf("      [dry-run] 健康检查 %s:%d%s（预算 %s）", h.Host, h.ServicePort, h.CheckURI, budget)
				sum.Results = append(sum.Results, HostStatus{App: appName, Group: g, Host: h.Host, OK: true, Detail: "dry-run"})
				continue
			}
			if r.checkHealth(conn, h, budget) {
				r.logf("      ✅ 更新成功，健康检查通过")
				sum.Results = append(sum.Results, HostStatus{App: appName, Group: g, Host: h.Host, OK: true})
			} else {
				r.logf("      ❌ 健康检查未通过！可用 rollback 回滚到版本 %s", ts)
				sum.Results = append(sum.Results, HostStatus{App: appName, Group: g, Host: h.Host, Detail: "健康检查失败"})
			}
		}
	}
	return sum, nil
}

// Rollback 回滚到指定备份版本（空 = 最新版本）。
// groups 为空默认 [master, update, static]。
func (r *Runner) Rollback(appName, version string, groups []string) (*Summary, error) {
	app := r.Cfg.AppByName(appName)
	if app == nil {
		return nil, fmt.Errorf("配置中不存在应用 %q", appName)
	}
	if len(groups) == 0 {
		groups = []string{GroupMaster, GroupUpdate, GroupStatic}
	}

	appBackupRoot := path.Join(r.backupDir(), appName)
	if version == "" {
		latest, err := latestVersion(appBackupRoot)
		if err != nil {
			return nil, err
		}
		version = latest
		r.logf("未指定版本，使用最新备份: %s", version)
	}
	if !dirExists(path.Join(appBackupRoot, version)) {
		return nil, fmt.Errorf("备份版本不存在: %s（可用目录: %s）", version, appBackupRoot)
	}

	sum := &Summary{App: appName, Version: version}
	cache := r.dialer()
	defer cache.close()
	r.logf("--- 回滚应用 %s 到版本 %s ---", appName, version)

	for _, g := range groups {
		hosts := app.GroupHosts(g)
		if len(hosts) == 0 {
			r.logf("  [%s] 群组无主机，跳过", g)
			continue
		}
		r.logf("  [%s] 群组 %d 台主机", g, len(hosts))
		for _, h := range hosts {
			r.logf("  ▶ %s (%s)", h.Host, h.WebPath)
			conn, err := cache.get(h)
			if err != nil {
				r.logf("      ❌ 连接失败: %v", err)
				sum.Results = append(sum.Results, HostStatus{App: appName, Group: g, Host: h.Host, Detail: "连接失败: " + err.Error()})
				continue
			}

			// 备份源路径：static 群组用 nginx_deploy，master/update 用应用目录（含 JAR 修正：还原完整应用目录）
			var backupSrc string
			if g == GroupStatic {
				backupSrc = path.Join(r.backupDir(), appName, version, h.Host, "nginx_deploy")
			} else {
				backupSrc = path.Join(r.backupDir(), appName, version, h.Host, appName)
			}
			if !dirExists(backupSrc) {
				r.logf("      ❌ 该主机无此版本备份（%s），跳过", backupSrc)
				sum.Results = append(sum.Results, HostStatus{App: appName, Group: g, Host: h.Host, Detail: "无备份: " + backupSrc})
				continue
			}

			if g != GroupStatic {
				if h.StopCmd != "" {
					r.runCmd(conn, h.StopCmd, "停止应用")
					r.sleep(2 * time.Second)
				}
			}

			// 全量还原（--delete 语义）。日志目录与全局排除项做删除保护：
			// 备份不含日志，若无保护会把备份之后产生的运行期日志清掉（排查问题正需要它们）。
			// 静态群组还原也按"静态传输"处理（明细只进日志文件）。
			if res, err := syncx.Push(conn, backupSrc, h.WebPath, syncx.Options{
				Delete:   true,
				Excludes: append(globalExcludes(r.Cfg), logDirPatterns(app)...),
				DryRun:   r.DryRun,
				Logf:     r.detailFor(app, g == GroupStatic),
			}); err != nil {
				r.logf("      ❌ 还原失败: %v", err)
				sum.Results = append(sum.Results, HostStatus{App: appName, Group: g, Host: h.Host, Detail: "还原失败: " + err.Error()})
				continue
			} else {
				r.logf("      还原完成（%s）", res)
			}

			r.runCmd(conn, fmt.Sprintf("chown -R %s:%s %s", h.User, h.Group, h.WebPath), "更新属主")

			if g == GroupStatic {
				r.logf("      ✅ 静态页面还原完成（无需启停）")
				sum.Results = append(sum.Results, HostStatus{App: appName, Group: g, Host: h.Host, OK: true})
				continue
			}
			if h.StartCmd != "" {
				r.runCmd(conn, h.StartCmd, "启动应用")
				r.sleep(5 * time.Second)
			}
			budget := time.Duration(r.jarCheckMinutes()) * time.Minute
			if app.MiddleType == "tomcat" {
				// 预算全局可配：tomcat_check_minutes（默认 20 分钟）/ jar_check_minutes（默认 5 分钟）
				budget = time.Duration(r.tomcatCheckMinutes()) * time.Minute
			}
			if r.DryRun {
				sum.Results = append(sum.Results, HostStatus{App: appName, Group: g, Host: h.Host, OK: true, Detail: "dry-run"})
				continue
			}
			if r.checkHealth(conn, h, budget) {
				r.logf("      ✅ 回滚成功，健康检查通过")
				sum.Results = append(sum.Results, HostStatus{App: appName, Group: g, Host: h.Host, OK: true})
			} else {
				r.logf("      ❌ 回滚后健康检查仍未通过！请人工检查")
				sum.Results = append(sum.Results, HostStatus{App: appName, Group: g, Host: h.Host, Detail: "回滚后健康检查失败"})
			}
		}
	}
	return sum, nil
}

// ---- 辅助 ----

func globalExcludes(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	return cfg.GlobalExcludeLogs
}

// logDirPatterns 日志目录排除模式（含尾 / 的目录模式，锚定与 basename 两种形式都被匹配器支持）。
func logDirPatterns(app *config.App) []string {
	d := strings.Trim(strings.TrimSpace(app.LogDir), "/")
	if d == "" {
		return nil
	}
	return []string{d + "/"}
}

// ListVersions 列出应用可回滚的备份版本（新→旧）。
func ListVersions(backupDir, appName string) ([]string, error) {
	root := path.Join(backupDir, appName)
	entries, err := osReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("没有找到应用 %q 的备份（%s）", appName, root)
	}
	var vs []string
	for _, e := range entries {
		if e.IsDir() {
			vs = append(vs, e.Name())
		}
	}
	sortReverse(vs)
	return vs, nil
}

// HTTPHealth 默认健康检查：HTTP 200；空 URI 跳过（= 通过）。每 10s 轮询，单次请求 10s 超时。
func HTTPHealth(host string, port int, uri string, budget time.Duration) bool {
	if strings.TrimSpace(uri) == "" {
		return true
	}
	url := fmt.Sprintf("http://%s:%d%s", host, port, uri)
	client := &http.Client{Timeout: 10 * time.Second}
	deadline := time.Now().Add(budget)
	for {
		resp, err := client.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		if time.Now().Add(10 * time.Second).After(deadline) {
			return false
		}
		time.Sleep(10 * time.Second)
	}
}
