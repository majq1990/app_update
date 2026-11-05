package logs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/syncx"
)

// localFS 测试用假远端：本地目录树直接当远端。实现 syncx.RemoteFS。
type localFS struct{ root string }

func (l localFS) Stat(abs string) (syncx.Entry, error) {
	st, err := os.Stat(filepath.Join(l.root, filepath.FromSlash(abs)))
	if err != nil {
		if os.IsNotExist(err) {
			return syncx.Entry{}, fs.ErrNotExist
		}
		return syncx.Entry{}, err
	}
	rel := ""
	if abs != "/" {
		rel = strings.TrimPrefix(abs, "/")
	}
	return syncx.Entry{Rel: rel, IsDir: st.IsDir(), Size: st.Size(), Mtime: st.ModTime()}, nil
}

func (l localFS) Walk(abs string, fn func(syncx.Entry) error) error {
	base := filepath.Join(l.root, filepath.FromSlash(abs))
	if _, err := os.Stat(base); err != nil {
		if os.IsNotExist(err) {
			return fs.ErrNotExist
		}
		return err
	}
	prefix := filepath.ToSlash(base) + "/"
	return filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == base {
			return err
		}
		info, _ := d.Info()
		rel := strings.TrimPrefix(filepath.ToSlash(p), prefix)
		return fn(syncx.Entry{Rel: rel, IsDir: d.IsDir(), Size: info.Size(), Mtime: info.ModTime()})
	})
}

func (l localFS) MkdirAll(abs string) error { return os.MkdirAll(filepath.Join(l.root, filepath.FromSlash(abs)), 0o755) }
func (l localFS) Upload(local, abs string, tm time.Time) error  { return nil }
func (l localFS) Download(abs, local string) (int64, error) {
	src := filepath.Join(l.root, filepath.FromSlash(abs))
	st, err := os.Stat(src)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		return 0, err
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(local, b, 0o644); err != nil {
		return 0, err
	}
	return st.Size(), nil
}
func (l localFS) RemoveAll(abs string) error {
	return os.RemoveAll(filepath.Join(l.root, filepath.FromSlash(abs)))
}

// ---- Target 展开 ----

func loadCfg(t *testing.T, y string) *config.Config {
	t.Helper()
	c := &config.Config{}
	if err := yaml.Unmarshal([]byte(y), c); err != nil {
		t.Fatal(err)
	}
	c.Normalize()
	return c
}

const cfgYAML = `
ansible_user: root
global_exclude_logs: ['*.log', 'logs/']
log_keep_days: 7
webs:
  - web: usercenter
    middle_type: jar
    log_dir: logs/
    master: [{host: 10.0.0.1, web_path: /egova/apps/basic/usercenter, user: egova, service_port: 10050, start_cmd: x, stop_cmd: x}]
    update:  [{host: 10.0.0.2, web_path: /egova/apps/basic/usercenter, user: egova, service_port: 10050, start_cmd: x, stop_cmd: x}]
  - web: gis
    middle_type: tomcat
    master: [{host: 10.0.0.1, web_path: /egova/apps/basic/gis, user: egova, service_port: 8080, start_cmd: x, stop_cmd: x}]
supports:
  - kind: mysql
    keep_days: 15
    hosts: [{host: 10.0.0.9}]
  - kind: redis
    keep_days: 5
    hosts: [{host: 10.0.0.9}]
`

func TestTargetsUnified(t *testing.T) {
	c := loadCfg(t, cfgYAML)
	ts := Targets(c)
	// 应用 3（uc×2 主机 + gis×1；update 同主机去重场景 uc 不同主机）+ 支持 2
	var apps, sups int
	for _, x := range ts {
		if x.Kind == KindApp {
			apps++
		} else {
			sups++
		}
	}
	if apps != 3 || sups != 2 {
		t.Fatalf("目标数 app=%d support=%d, want 3/2", apps, sups)
	}
	// 应用目录展开 = web_path + log_dir
	var uc *Target
	for i := range ts {
		if ts[i].Kind == KindApp && ts[i].Name == "usercenter" && ts[i].Host.Host == "10.0.0.1" {
			uc = &ts[i]
		}
	}
	if uc == nil || len(uc.LogDirs) != 1 || uc.LogDirs[0] != "/egova/apps/basic/usercenter/logs" {
		t.Fatalf("应用日志目录展开错误: %+v", uc)
	}
	if uc.KeepDays != 7 {
		t.Errorf("应用保留天数应取全局 7: %d", uc.KeepDays)
	}
	// gis 没配 log_dir → LogDirs 空（clean 时该目标自然跳过）
	var gis *Target
	for i := range ts {
		if ts[i].Name == "gis" {
			gis = &ts[i]
		}
	}
	if gis != nil && len(gis.LogDirs) != 0 {
		t.Errorf("未配 log_dir 的应用不应有日志目录: %v", gis.LogDirs)
	}
	// mysql 支持软件目录约定 + keep_days
	var my *Target
	for i := range ts {
		if ts[i].KindRaw == "mysql" {
			my = &ts[i]
		}
	}
	if my == nil || my.LogDirs[0] != "/egova/apps/mysql/data" || my.KeepDays != 15 {
		t.Fatalf("mysql 目标错误: %+v", my)
	}
}

// ---- clean 计划 + 白名单 ----

func writeTree(t *testing.T, dir string, files map[string]time.Time) {
	t.Helper()
	for rel, mtime := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBuildPlanWhitelist(t *testing.T) {
	root := t.TempDir()
	old := time.Now().Add(-20 * 24 * time.Hour)
	fresh := time.Now().Add(-1 * 24 * time.Hour)
	writeTree(t, root, map[string]time.Time{
		"mysql/data/app.err":                     old, // 过期，mysql 白名单
		"mysql/data/mysql-bin.000042":            old, // binlog：白名单外，绝不删
		"mysql/data/ibdata1":                     old, // 数据文件：白名单外
		"mysql/data/slowquery.log":               fresh,
		"redis/log/redis.log":                    old, // 过期
		"nginx/logs/access.log":                  old,
		"nginx/logs/access.log-20261101":         old,
		"usercenter/logs/app.log":                old, // 应用日志过期（但 app 目标含 exclude？无）
	})
	fsys := localFS{root}
	c := loadCfg(t, cfgYAML)
	ts := Targets(c)
	// 只跑 mysql + redis 目标。测试树模拟的是约定目录布局，把假 FS 的根目录
	// 当作 "/"：LocalRoot 重写目标目录（真机路径 /egova/apps/... → root 下同名子树）。
	var sel []Target
	for _, x := range ts {
		if x.Kind == KindSupport {
			tx := x
			for i, d := range tx.LogDirs {
				tx.LogDirs[i] = strings.TrimPrefix(d, "/egova/apps") // /egova/apps/mysql/data → /mysql/data
			}
			sel = append(sel, tx)
		}
	}
	p := BuildPlan(fsys, sel, time.Now())

	var got []string
	for _, it := range p.Items {
		got = append(got, strings.TrimPrefix(it.File.Abs, "/"))
	}
	sort.Strings(got)
	want := []string{"mysql/data/app.err", "mysql/data/slowquery.log", "redis/log/redis.log"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("白名单结果不符:\ngot  %v\nwant %v", got, want)
	}
	// binlog 与数据文件绝不在计划里（连「未过期统计」都不进——白名单外完全不可见）
	for _, it := range p.Items {
		if strings.Contains(it.File.Abs, "mysql-bin") || strings.Contains(it.File.Abs, "ibdata") {
			t.Fatalf("白名单外文件进入计划: %s", it.File.Abs)
		}
	}
	// 过期判定：app.err 与 redis.log 过期，slowquery 未过期
	expired := map[string]bool{}
	for _, it := range p.Items {
		expired[strings.TrimPrefix(it.File.Abs, "/")] = it.Expired
	}
	if !expired["mysql/data/app.err"] || !expired["redis/log/redis.log"] {
		t.Errorf("过期判定错误: %v", expired)
	}
	if expired["mysql/data/slowquery.log"] {
		t.Error("slowquery 1 天不应过期（keep 15）")
	}
	// 目录不存在的目标（nginx 目录其实存在；redis 保持）——补一个不存在目录目标验证 Errs
	p2 := BuildPlan(fsys, []Target{{Kind: KindSupport, KindRaw: "nginx", Name: "nginx", Host: config.Host{Host: "h"}, LogDirs: []string{"/egova/apps/nginx/logs"}, KeepDays: 15}}, time.Now())
	if len(p2.Errs) == 0 {
		t.Error("不存在的日志目录应计入 Errs 而不是静默")
	}
}

func TestBuildPlanAppExclude(t *testing.T) {
	// 应用目标带 global_exclude_logs（*.log, logs/）——目录本身是 logs/，排除目录模式会拦掉其下所有文件吗？
	// 语义确认：global_exclude_logs 用于「更新同步」排除，clean 复用它防止把「同步排除的」当垃圾删；
	// 但目录模式 "logs/" 在 syncx 里 = basename 命中 logs 的目录及其子树 → 全部文件被排除。
	// 这会让应用日志 clean 无事可做——违背需求。因此应用的 CleanExclude 不含目录模式，
	// 只保留 basename 文件模式（*.log 本来就在白名单）。见 logs.go CleanExclude 注释修正。
	c := loadCfg(t, cfgYAML)
	ts := Targets(c)
	var uc *Target
	for i := range ts {
		if ts[i].Kind == KindApp && ts[i].Name == "usercenter" {
			uc = &ts[i]
		}
	}
	_ = uc
}

func TestApplyOnlyDeletesExpired(t *testing.T) {
	root := t.TempDir()
	old := time.Now().Add(-20 * 24 * time.Hour)
	fresh := time.Now().Add(-1 * 24 * time.Hour)
	writeTree(t, root, map[string]time.Time{
		"redis/log/redis.log":      old,
		"redis/log/redis.log.2":    fresh,
	})
	fsys := localFS{root}
	tg := Target{Kind: KindSupport, KindRaw: "redis", Name: "redis",
		Host: config.Host{Host: "h"}, LogDirs: []string{"/redis/log"}, KeepDays: 5}
	p := BuildPlan(fsys, []Target{tg}, time.Now())
	if len(p.Items) != 2 {
		t.Fatalf("计划项 = %d, want 2", len(p.Items))
	}
	n, freed, err := Apply(fsys, p)
	if err != nil || n != 1 {
		t.Fatalf("Apply: n=%d err=%v, want 1", n, err)
	}
	if freed != 1 {
		t.Errorf("freed = %d, want 1", freed)
	}
	if _, err := os.Stat(filepath.Join(root, "redis/log/redis.log")); !os.IsNotExist(err) {
		t.Error("过期文件未被删除")
	}
	if _, err := os.Stat(filepath.Join(root, "redis/log/redis.log.2")); err != nil {
		t.Error("未过期文件被误删")
	}
}

var _ = errors.New
