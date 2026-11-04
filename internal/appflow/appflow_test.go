package appflow

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/syncx"
)

// ---- 测试替身：命令记录 + 本地目录充当远端文件系统 ----

type fakeConn struct {
	fs   localFSAdapt
	cmds *[]string
	fail map[string]bool // 命令 → 是否失败
}

func (c *fakeConn) Run(cmd string) (string, error) {
	*c.cmds = append(*c.cmds, cmd)
	if c.fail[cmd] {
		return "", fmt.Errorf("模拟失败: %s", cmd)
	}
	return "", nil
}

func (c *fakeConn) Stat(p string) (syncx.Entry, error)              { return c.fs.Stat(p) }
func (c *fakeConn) Walk(p string, fn func(syncx.Entry) error) error { return c.fs.Walk(p, fn) }
func (c *fakeConn) MkdirAll(p string) error                         { return c.fs.MkdirAll(p) }
func (c *fakeConn) Upload(l, p string, m time.Time) error           { return c.fs.Upload(l, p, m) }
func (c *fakeConn) Download(p, l string) (int64, error)             { return c.fs.Download(p, l) }
func (c *fakeConn) RemoveAll(p string) error                        { return c.fs.RemoveAll(p) }

type localFSAdapt struct{}

func (localFSAdapt) Stat(p string) (syncx.Entry, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return syncx.Entry{}, err
	}
	return syncx.Entry{IsDir: fi.IsDir(), Size: fi.Size(), Mtime: fi.ModTime()}, nil
}

func (f localFSAdapt) Walk(p string, fn func(syncx.Entry) error) error {
	return filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == p {
			return nil
		}
		rel, _ := filepath.Rel(p, path)
		e := syncx.Entry{Rel: filepath.ToSlash(rel), IsDir: d.IsDir()}
		if !d.IsDir() {
			fi, err := d.Info()
			if err != nil {
				return err
			}
			e.Size, e.Mtime = fi.Size(), fi.ModTime()
		}
		return fn(e)
	})
}

func (localFSAdapt) MkdirAll(p string) error { return os.MkdirAll(p, 0o755) }

func (localFSAdapt) Upload(localPath, p string, mtime time.Time) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return err
	}
	return os.Chtimes(p, mtime, mtime)
}

func (localFSAdapt) Download(p, localPath string) (int64, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(localPath, data, 0o644); err != nil {
		return 0, err
	}
	if fi, err := os.Stat(p); err == nil {
		_ = os.Chtimes(localPath, fi.ModTime(), fi.ModTime())
	}
	return int64(len(data)), nil
}

func (localFSAdapt) RemoveAll(p string) error { return os.RemoveAll(p) }

type fakeDialer struct {
	cmds *[]string
	fail map[string]bool
}

func (d *fakeDialer) Dial(h config.Host) (Conn, error) {
	return &fakeConn{cmds: d.cmds, fail: d.fail}, nil
}

func (d *fakeDialer) Close() {}

// ---- 夹具 ----

func testConfig() *config.Config {
	return &config.Config{
		Global: config.Global{AnsibleUser: "root", AnsibleSSHPort: 22},
		Webs: []config.App{
			{
				Web:                  "eUrbanMIS",
				MiddleType:           "tomcat",
				LogDir:               "WEB-INF/logs",
				RetainedConfigFile:   []string{"WEB-INF/classes/jdbc.properties"},
				MasterExclusiveFiles: []string{"egova-jobmanager-[0-9]*.jar"},
				Master: []config.Host{{
					Host: "10.0.0.1", ServicePort: 8081, CheckURI: "/eUrbanMIS/main.htm",
					WebPath: "/remote/mis", StartCmd: "systemctl start tomcat-MIS", StopCmd: "systemctl stop tomcat-MIS",
					User: "egova", Group: "egova", HealthMode: "local",
				}},
				Update: []config.Host{{
					Host: "10.0.0.2", ServicePort: 8081, CheckURI: "/eUrbanMIS/main.htm",
					WebPath: "/remote/mis", StartCmd: "systemctl start tomcat-MIS", StopCmd: "systemctl stop tomcat-MIS",
					User: "egova", Group: "egova", HealthMode: "local",
				}},
			},
		},
	}
}

func newTestRunner(t *testing.T, cfg *config.Config, root string) (*Runner, *[]string) {
	t.Helper()
	cmds := &[]string{}
	healthCalls := 0
	health := func(host string, port int, uri string, budget time.Duration) bool {
		healthCalls++
		return true
	}
	r := &Runner{
		Cfg:       cfg,
		Dial:      &fakeDialer{cmds: cmds},
		UpdateDir: filepath.Join(root, "update"),
		BackupDir: filepath.Join(root, "backups"),
		Logf: func(format string, args ...interface{}) {
			t.Logf(format, args...)
		},
		Health: health,
		Now:    func() time.Time { return time.Date(2026, 11, 2, 18, 0, 0, 0, time.Local) },
		Sleep:  func(time.Duration) {},
	}
	_ = healthCalls
	// webPath 真实落地目录：把 /remote/mis 映射到 root/webapps（通过软链不可行，直接改用临时根路径）
	for i := range cfg.Webs {
		for j := range cfg.Webs[i].Master {
			cfg.Webs[i].Master[j].WebPath = filepath.ToSlash(filepath.Join(root, "webapps", "master"))
		}
		for j := range cfg.Webs[i].Update {
			cfg.Webs[i].Update[j].WebPath = filepath.ToSlash(filepath.Join(root, "webapps", "update"))
		}
	}
	return r, cmds
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFileMap(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = string(data)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// ---- 用例 ----

// 更新全流程：停止/属主/启动命令顺序、备份落地、保留配置不动、日志排除、update 群组排除 master 专属。
func TestUpdateFlow(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig()
	r, cmds := newTestRunner(t, cfg, root)

	// 线上现场：保留配置 + 日志 + master 专属文件（update 主机上不该被包覆盖）
	mustWrite(t, filepath.Join(root, "webapps", "update", "WEB-INF", "classes", "jdbc.properties"), "PROD")
	mustWrite(t, filepath.Join(root, "webapps", "update", "WEB-INF", "logs", "app.log"), "runtime")
	mustWrite(t, filepath.Join(root, "webapps", "master", "WEB-INF", "classes", "jdbc.properties"), "PROD")

	// 本地更新包
	upd := filepath.Join(root, "update", "eUrbanMIS")
	mustWrite(t, filepath.Join(upd, "web.xml"), "v2")
	mustWrite(t, filepath.Join(upd, "WEB-INF", "classes", "jdbc.properties"), "PACKAGE")
	mustWrite(t, filepath.Join(upd, "WEB-INF", "logs", "x.log"), "noise")
	mustWrite(t, filepath.Join(upd, "WEB-INF", "lib", "egova-jobmanager-1.0.jar"), "masteronly")

	sum, err := r.Update("eUrbanMIS", nil)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if sum.FailCount() != 0 || len(sum.Results) != 2 {
		t.Fatalf("汇总异常: %+v", sum.Results)
	}

	// 命令顺序：每台主机 stop → chown → start（各一次）
	var stops, starts, chowns int
	for _, c := range *cmds {
		switch {
		case strings.HasPrefix(c, "systemctl stop"):
			stops++
		case strings.HasPrefix(c, "systemctl start"):
			starts++
		case strings.HasPrefix(c, "chown -R egova:egova"):
			chowns++
		}
	}
	if stops != 2 || starts != 2 || chowns != 2 {
		t.Fatalf("命令计数错误 stop=%d start=%d chown=%d（%v）", stops, starts, chowns, *cmds)
	}

	// master：包内容覆盖 + 保留配置不动
	masterFiles := readFileMap(t, filepath.Join(root, "webapps", "master"))
	if masterFiles["web.xml"] != "v2" {
		t.Fatalf("新文件未上传: %+v", masterFiles)
	}
	if masterFiles["WEB-INF/classes/jdbc.properties"] != "PROD" {
		t.Fatalf("保留配置被覆盖: %s", masterFiles["WEB-INF/classes/jdbc.properties"])
	}
	if _, ok := masterFiles["WEB-INF/logs/x.log"]; ok {
		t.Fatalf("日志应被排除")
	}

	// update 群组：master 专属文件被排除（tomcat+update 特有）
	updateFiles := readFileMap(t, filepath.Join(root, "webapps", "update"))
	if _, ok := updateFiles["WEB-INF/lib/egova-jobmanager-1.0.jar"]; ok {
		t.Fatalf("master 专属文件不应进入 update 群组")
	}
	if updateFiles["WEB-INF/classes/jdbc.properties"] != "PROD" {
		t.Fatalf("update 主机保留配置被覆盖")
	}

	// 备份：backups/eUrbanMIS/2026110218/{host}/eUrbanMIS 含原始 jdbc.properties
	backup := readFileMap(t, filepath.Join(root, "backups", "eUrbanMIS", "2026110218", "10.0.0.1", "eUrbanMIS"))
	if backup["WEB-INF/classes/jdbc.properties"] != "PROD" {
		t.Fatalf("备份缺少原始保留配置: %+v", backup)
	}
	if _, ok := backup["WEB-INF/logs/app.log"]; ok {
		t.Fatalf("备份不应含日志")
	}
}

// 回滚：还原备份 + --delete 清掉更新期新增文件；stop→还原→chown→start 顺序。
func TestRollbackFlow(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig()
	r, cmds := newTestRunner(t, cfg, root)

	webPath := filepath.Join(root, "webapps", "master")
	// 预置现场（= 备份将看到的内容）
	mustWrite(t, filepath.Join(webPath, "app.jar"), "v1")
	mustWrite(t, filepath.Join(webPath, "WEB-INF", "classes", "jdbc.properties"), "PROD")

	// 执行一次更新产生备份
	upd := filepath.Join(root, "update", "eUrbanMIS")
	mustWrite(t, filepath.Join(upd, "web.xml"), "v2")
	if _, err := r.Update("eUrbanMIS", []string{"master"}); err != nil {
		t.Fatalf("update: %v", err)
	}

	// 更新后现场出现新增文件（备份中没有），且 app.jar 未被动过
	mustWrite(t, filepath.Join(webPath, "new-bug-file.jar"), "bad")
	mustWrite(t, filepath.Join(webPath, "app.jar"), "corrupted")
	// 运行期日志（备份时排除、备份后才产生）——回滚必须保留
	mustWrite(t, filepath.Join(webPath, "WEB-INF", "logs", "run.log"), "runtime-log")

	*cmds = nil
	if _, err := r.Rollback("eUrbanMIS", "", []string{"master"}); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	files := readFileMap(t, webPath)
	if files["app.jar"] != "v1" {
		t.Fatalf("回滚未还原 app.jar: %s", files["app.jar"])
	}
	if _, ok := files["new-bug-file.jar"]; ok {
		t.Fatalf("回滚应 --delete 清理更新期新增文件")
	}
	if files["WEB-INF/classes/jdbc.properties"] != "PROD" {
		t.Fatalf("回滚后保留配置错误")
	}
	if files["WEB-INF/logs/run.log"] != "runtime-log" {
		t.Fatalf("回滚不应删除运行期日志（排查问题正需要）")
	}

	// 命令：stop → chown → start
	joined := strings.Join(*cmds, "|")
	if !strings.Contains(joined, "systemctl stop tomcat-MIS") ||
		!strings.Contains(joined, "systemctl start tomcat-MIS") ||
		!strings.Contains(joined, "chown -R egova:egova") {
		t.Fatalf("回滚命令序列异常: %v", *cmds)
	}
}

// dry-run：不执行命令、不改文件。
func TestDryRunNoSideEffects(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig()
	r, cmds := newTestRunner(t, cfg, root)
	r.DryRun = true

	upd := filepath.Join(root, "update", "eUrbanMIS")
	mustWrite(t, filepath.Join(upd, "web.xml"), "v2")

	webPath := filepath.Join(root, "webapps", "master")
	mustWrite(t, filepath.Join(webPath, "old.txt"), "keep")

	if _, err := r.Update("eUrbanMIS", []string{"master"}); err != nil {
		t.Fatalf("dry update: %v", err)
	}
	if len(*cmds) != 0 {
		t.Fatalf("dry-run 不应执行任何命令: %v", *cmds)
	}
	files := readFileMap(t, webPath)
	if len(files) != 1 || files["old.txt"] != "keep" {
		t.Fatalf("dry-run 不应修改现场: %+v", files)
	}
}

// JAR 应用回滚修正：还原完整应用目录（旧版只还原静态目录）。
func TestJarRollbackRestoresAppDir(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig()
	cfg.Webs[0].MiddleType = "jar"
	cfg.Webs[0].Master[0].CheckURI = ""
	cfg.Webs[0].Master[0].StartCmd = "systemctl start mis"
	cfg.Webs[0].Master[0].StopCmd = "systemctl stop mis"
	r, _ := newTestRunner(t, cfg, root)
	r.TCPProbe = func(string, int, time.Duration) bool { return true } // 空 URI 走 TCP 探测，测试注入通过

	webPath := filepath.Join(root, "webapps", "master")
	mustWrite(t, filepath.Join(webPath, "mis.jar"), "mis-service-jar-v1")

	upd := filepath.Join(root, "update", "eUrbanMIS")
	mustWrite(t, filepath.Join(upd, "mis.jar"), "mis-service-jar-v2-NEW")
	if _, err := r.Update("eUrbanMIS", []string{"master"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := readFileMap(t, webPath)["mis.jar"]; got != "mis-service-jar-v2-NEW" {
		t.Fatalf("更新未生效: %s", got)
	}

	if _, err := r.Rollback("eUrbanMIS", "", []string{"master"}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := readFileMap(t, webPath)["mis.jar"]; got != "mis-service-jar-v1" {
		t.Fatalf("JAR 回滚应还原完整应用目录（旧版缺陷已修正）: %s", got)
	}
}

// 健康检查失败 → 该主机标记失败但不中断（旧版语义）。
func TestHealthFailMarksHost(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig()
	r, _ := newTestRunner(t, cfg, root)
	r.Health = func(string, int, string, time.Duration) bool { return false }

	upd := filepath.Join(root, "update", "eUrbanMIS")
	mustWrite(t, filepath.Join(upd, "web.xml"), "v2")

	sum, err := r.Update("eUrbanMIS", nil)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if sum.FailCount() != 2 {
		t.Fatalf("两台都应健康检查失败: %+v", sum.Results)
	}
}

// 静态全量更新（tomcat）：解包 jar 资源 + 目录合并 + xml/jsp 清理 + --delete 推送。
func TestStaticFullTomcat(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig()
	cfg.Webs[0].StaticPageGroup = []config.Host{{
		Host: "10.0.0.9", WebPath: filepath.ToSlash(filepath.Join(root, "nginx", "eUrbanMIS")),
		User: "nginx", Group: "nginx",
	}}
	r, cmds := newTestRunner(t, cfg, root)

	upd := filepath.Join(root, "update", "eUrbanMIS")
	mustWrite(t, filepath.Join(upd, "view", "page.htm"), "static-page")
	// 构造一个 egova-*.jar，内含 META-INF/resources/style/main.css
	jarPath := filepath.Join(upd, "WEB-INF", "lib", "egova-ui-1.0.jar")
	if err := os.MkdirAll(filepath.Dir(jarPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := makeTestJar(jarPath, map[string]string{
		"META-INF/resources/style/main.css":   "body{}",
		"META-INF/resources/WEB-INF/evil.xml": "x",
	}); err != nil {
		t.Fatal(err)
	}
	// 预置静态服务器现场：多余文件（应被 --delete 清理）
	mustWrite(t, filepath.Join(root, "nginx", "eUrbanMIS", "stale.htm"), "old")

	sum, err := r.StaticFullTomcat("eUrbanMIS")
	if err != nil {
		t.Fatalf("static full: %v", err)
	}
	if sum.FailCount() != 0 {
		t.Fatalf("静态全量失败: %+v", sum.Results)
	}

	files := readFileMap(t, filepath.Join(root, "nginx", "eUrbanMIS"))
	if files["view/page.htm"] != "static-page" {
		t.Fatalf("view 目录未合并: %+v", files)
	}
	if files["style/main.css"] != "body{}" {
		t.Fatalf("jar 内 META-INF/resources 未解包: %+v", files)
	}
	for rel := range files {
		if strings.HasSuffix(rel, ".xml") || strings.HasSuffix(rel, ".jsp") {
			t.Fatalf("xml/jsp 应被清理: %s", rel)
		}
	}
	if _, ok := files["stale.htm"]; ok {
		t.Fatalf("静态全量应 --delete 清理多余文件")
	}
	if !strings.Contains(strings.Join(*cmds, "|"), "chown -R nginx:nginx") {
		t.Fatalf("静态服务器属主命令缺失: %v", *cmds)
	}
}

// remote 健康检查模式：经 SSH 通道在目标机本地探测，不调用工具机 HTTP。
func TestRemoteHealthMode(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig()
	r, cmds := newTestRunner(t, cfg, root)
	cfg.Webs[0].Master[0].CheckURI = "/mis/main.htm"
	cfg.Webs[0].Master[0].HealthMode = "remote"
	r.Health = func(string, int, string, time.Duration) bool {
		t.Fatalf("remote 模式不应调用工具机本地健康检查")
		return false
	}

	upd := filepath.Join(root, "update", "eUrbanMIS")
	mustWrite(t, filepath.Join(upd, "web.xml"), "v2")
	sum, err := r.Update("eUrbanMIS", []string{"master"})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if sum.FailCount() != 0 {
		t.Fatalf("remote 健康检查应通过: %+v", sum.Results)
	}
	found := false
	for _, c := range *cmds {
		if strings.Contains(c, "/dev/tcp/127.0.0.1/8081") {
			found = true
		}
	}
	if !found {
		t.Fatalf("remote 健康检查未在目标机执行: %v", *cmds)
	}
}

// 空 check_uri 时默认 TCP 端口探测：真实监听端口 → 通过；未监听端口 → 失败。
func TestTCPHealthProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听本地端口: %v", err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	if !TCPHealth("127.0.0.1", port, 2*time.Second) {
		t.Fatalf("监听中的端口 %d 应探测通过", port)
	}
	// 关闭后探测失败（预算极小，避免长时间轮询）
	closedPort := port + 1
	_ = TCPHealth("127.0.0.1", closedPort, 1*time.Second) // 不强制断言，端口可能被占用

	// 探测确实轮询：预算内不通 → false
	if TCPHealth("127.0.0.1", 1, 1*time.Second) {
		t.Fatalf("未监听端口不应通过")
	}
}

// remote 模式 + 空 URI：在目标机本地做 TCP 端口探测（bash /dev/tcp）。
func TestRemoteTCPMode(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig()
	r, cmds := newTestRunner(t, cfg, root)
	cfg.Webs[0].Master[0].CheckURI = ""
	cfg.Webs[0].Master[0].HealthMode = "remote"

	upd := filepath.Join(root, "update", "eUrbanMIS")
	mustWrite(t, filepath.Join(upd, "web.xml"), "v2")
	sum, err := r.Update("eUrbanMIS", []string{"master"})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if sum.FailCount() != 0 {
		t.Fatalf("remote TCP 探测应通过: %+v", sum.Results)
	}
	found := false
	for _, c := range *cmds {
		if strings.Contains(c, "/dev/tcp/127.0.0.1/8081") {
			found = true
		}
	}
	if !found {
		t.Fatalf("remote TCP 探测未在目标机执行: %v", *cmds)
	}
}

// 明细通道选择：tomcat/静态 → 日志文件；jar/dry-run → 控制台。
func TestDetailFor(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig()
	r, _ := newTestRunner(t, cfg, root)
	detailCalled, consoleCalled := false, false
	r.DetailLogf = func(string, ...interface{}) { detailCalled = true }
	r.Logf = func(string, ...interface{}) { consoleCalled = true }

	app := &cfg.Webs[0]
	reset := func() { detailCalled, consoleCalled = false, false }

	r.detailFor(app, false)("x") // tomcat 更新
	if !detailCalled || consoleCalled {
		t.Fatalf("tomcat 更新明细应只进日志文件")
	}
	reset()

	jarApp := *app
	jarApp.MiddleType = "jar"
	r.detailFor(&jarApp, false)("  [传输] %s", "egova-usercenter.jar") // jar 后端文件 → 控制台
	if detailCalled || !consoleCalled {
		t.Fatalf("jar 后端文件明细应进控制台")
	}
	reset()

	r.detailFor(&jarApp, false)("  [传输] %s", "webApps/usercenter/assets/a.js") // jar 前端文件 → 仅日志
	if !detailCalled || consoleCalled {
		t.Fatalf("jar 前端静态文件明细应只进日志文件")
	}
	reset()

	r.detailFor(app, true)("x") // 静态页面
	if !detailCalled || consoleCalled {
		t.Fatalf("静态传输明细应只进日志文件")
	}
	reset()

	r.DryRun = true
	r.detailFor(app, false)("x") // tomcat dry-run：明细同样只进日志文件
	if !detailCalled || consoleCalled {
		t.Fatalf("tomcat dry-run 明细也应只进日志文件（控制台只看汇总）")
	}
	reset()
	jarDry := jarApp
	r.DryRun = true
	r.detailFor(&jarDry, false)("  [传输] %s", "egova-usercenter.jar") // jar dry-run 后端 → 控制台
	if detailCalled || !consoleCalled {
		t.Fatalf("jar dry-run 后端文件明细应进控制台")
	}
}

// 端到端：tomcat 更新控制台不出现逐文件明细，但日志文件里有。
func TestTomcatUpdateHidesDetailOnConsole(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig()
	r, _ := newTestRunner(t, cfg, root)
	var console, file []string
	r.Logf = func(f string, a ...interface{}) { console = append(console, fmt.Sprintf(f, a...)) }
	r.DetailLogf = func(f string, a ...interface{}) { file = append(file, fmt.Sprintf(f, a...)) }

	upd := filepath.Join(root, "update", "eUrbanMIS")
	mustWrite(t, filepath.Join(upd, "web.xml"), "v2")
	if _, err := r.Update("eUrbanMIS", []string{"master"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	hasDetail := func(lines []string) bool {
		for _, l := range lines {
			if strings.Contains(l, "[传输]") || strings.Contains(l, "[目录]") {
				return true
			}
		}
		return false
	}
	if hasDetail(console) {
		t.Fatalf("tomcat 明细不应进控制台: %v", console)
	}
	if !hasDetail(file) {
		t.Fatalf("tomcat 明细应进日志文件: %v", file)
	}
}

// tomcat update 群组：master 专属文件（liquibase）不推且自动清理目标端已有副本。
func TestUpdateGroupCleansExclusive(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig()
	cfg.Webs[0].MasterExclusiveFiles = []string{"egova-liquibase-*.jar", "liquibase-core-*.jar"}
	r, _ := newTestRunner(t, cfg, root)

	upd := filepath.Join(root, "update", "eUrbanMIS")
	mustWrite(t, filepath.Join(upd, "WEB-INF", "web.xml"), "v2-new")
	mustWrite(t, filepath.Join(upd, "WEB-INF", "lib", "egova-liquibase-1.4.9.jar"), "NEW") // 不应推给 update 群组

	// update 主机现场：已有 liquibase jar（应被清理）+ 旧 web.xml
	updHost := filepath.Join(root, "webapps", "update")
	mustWrite(t, filepath.Join(updHost, "WEB-INF", "lib", "egova-liquibase-1.4.9.jar"), "OLD")
	mustWrite(t, filepath.Join(updHost, "WEB-INF", "lib", "liquibase-core-3.5.3.jar"), "OLD")
	mustWrite(t, filepath.Join(updHost, "WEB-INF", "web.xml"), "v1")

	sum, err := r.Update("eUrbanMIS", []string{GroupUpdate})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if sum.FailCount() != 0 {
		t.Fatalf("更新失败: %+v", sum.Results)
	}
	files := readFileMap(t, updHost)
	if v, ok := files["WEB-INF/lib/egova-liquibase-1.4.9.jar"]; ok {
		t.Fatalf("update 群组的 liquibase jar 应被自动清理: %s", v)
	}
	if _, ok := files["WEB-INF/lib/liquibase-core-3.5.3.jar"]; ok {
		t.Fatalf("liquibase-core 应被自动清理")
	}
	if files["WEB-INF/web.xml"] != "v2-new" {
		t.Fatalf("正常文件未更新")
	}
}

// 默认（health_mode 留空）走目标机本地探测，不依赖工具机到应用端口网络。
func TestDefaultHealthModeIsRemote(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig()
	cfg.Webs[0].Master[0].HealthMode = "" // 留空 = 默认
	r, cmds := newTestRunner(t, cfg, root)
	r.Health = func(string, int, string, time.Duration) bool {
		t.Fatalf("默认模式不应调用工具机 HTTP 探测")
		return false
	}

	upd := filepath.Join(root, "update", "eUrbanMIS")
	mustWrite(t, filepath.Join(upd, "WEB-INF", "web.xml"), "v2-new")
	sum, err := r.Update("eUrbanMIS", []string{"master"})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if sum.FailCount() != 0 {
		t.Fatalf("默认远程健康检查应通过: %+v", sum.Results)
	}
	found := false
	for _, c := range *cmds {
		if strings.Contains(c, "/dev/tcp/127.0.0.1/8081") {
			found = true
		}
	}
	if !found {
		t.Fatalf("默认模式应在目标机本地探测: %v", *cmds)
	}
}
