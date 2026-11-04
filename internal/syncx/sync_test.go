package syncx

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testLog = "logs/app.log" // 通用日志相对路径

// 推送：空目标全量上传 → 二次推送零传输 → 内容变更增量 → --delete 清理多余。
func TestPushIncrementalAndDelete(t *testing.T) {
	fs := localFS{}
	src := t.TempDir()
	dst := t.TempDir()

	write(t, filepath.Join(src, "a.txt"), "hello")
	write(t, filepath.Join(src, testLog), "noise") // 应被排除

	res, err := Push(fs, src, dst, Options{Excludes: []string{"logs/"}})
	if err != nil {
		t.Fatalf("push1: %v", err)
	}
	if len(res.Uploaded) != 1 || res.Uploaded[0] != "a.txt" {
		t.Fatalf("首推应只上传 a.txt: %+v", res.Uploaded)
	}
	got := readAll(t, dst)
	if got["a.txt"] != "hello" || got[testLog] != "" {
		t.Fatalf("目标内容错误: %+v", got)
	}

	// 二次推送：mtime/size 一致 → 零传输
	res2, err := Push(fs, src, dst, Options{Excludes: []string{"logs/"}})
	if err != nil {
		t.Fatalf("push2: %v", err)
	}
	if len(res2.Uploaded) != 0 {
		t.Fatalf("二次推送应零传输: %+v", res2.Uploaded)
	}

	// 修改内容 → 增量 1 个
	time.Sleep(1100 * time.Millisecond) // mtime 秒级判据，需跨秒
	write(t, filepath.Join(src, "a.txt"), "hello world, longer")
	res3, err := Push(fs, src, dst, Options{Excludes: []string{"logs/"}})
	if err != nil {
		t.Fatalf("push3: %v", err)
	}
	if len(res3.Uploaded) != 1 || res3.Uploaded[0] != "a.txt" {
		t.Fatalf("变更后应只传 a.txt: %+v", res3.Uploaded)
	}

	// 源里删掉 a.txt → Delete 清理；默认（无 Delete）保留
	if err := os.Remove(filepath.Join(src, "a.txt")); err != nil {
		t.Fatal(err)
	}
	res4, _ := Push(fs, src, dst, Options{Excludes: []string{"logs/"}})
	if len(res4.Deleted) != 0 {
		t.Fatalf("无 Delete 不应删除: %+v", res4.Deleted)
	}
	if _, err := os.Stat(filepath.Join(dst, "a.txt")); err != nil {
		t.Fatalf("无 Delete 时 a.txt 应还在")
	}
	res5, _ := Push(fs, src, dst, Options{Excludes: []string{"logs/"}, Delete: true})
	if len(res5.Deleted) != 1 || res5.Deleted[0] != "a.txt" {
		t.Fatalf("Delete 应清理 a.txt: %+v", res5.Deleted)
	}
	if _, err := os.Stat(filepath.Join(dst, "a.txt")); !os.IsNotExist(err) {
		t.Fatalf("Delete 后 a.txt 应已删除")
	}
}

// 排除与保留配置：日志目录不传不删；保留文件不被包内同名覆盖、不被 --delete 删除。
func TestPushExcludesRetainDryRun(t *testing.T) {
	fs := localFS{}
	src := t.TempDir()
	dst := t.TempDir()

	write(t, filepath.Join(src, "WEB-INF", "classes", "jdbc.properties"), "new")
	write(t, filepath.Join(src, testLog), "noise")
	write(t, filepath.Join(src, "web.xml"), "app")
	write(t, filepath.Join(dst, "WEB-INF", "classes", "jdbc.properties"), "production")
	write(t, filepath.Join(dst, "WEB-INF", "classes", "redis.properties"), "production")
	write(t, filepath.Join(dst, testLog), "runtime-log")
	write(t, filepath.Join(dst, "stale.jar"), "old")

	excludes := []string{"logs/"}
	retain := []string{"WEB-INF/classes/jdbc.properties", "WEB-INF/classes/redis.properties"}

	// dry-run：不落盘
	res, err := Push(fs, src, dst, Options{Excludes: excludes, Retain: retain, DryRun: true})
	if err != nil {
		t.Fatalf("dryrun push: %v", err)
	}
	if len(res.Uploaded) == 0 {
		t.Fatalf("dry-run 应仍输出计划")
	}
	if got := readAll(t, dst); got["web.xml"] != "" {
		t.Fatalf("dry-run 不应落盘")
	}

	// 正式推送（覆盖式，无 Delete）
	res, err = Push(fs, src, dst, Options{Excludes: excludes, Retain: retain})
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	got := readAll(t, dst)
	if got["WEB-INF/classes/jdbc.properties"] != "production" {
		t.Fatalf("保留配置不应被覆盖: %s", got["WEB-INF/classes/jdbc.properties"])
	}
	if got["web.xml"] != "app" {
		t.Fatalf("新文件应上传")
	}
	if got[testLog] != "runtime-log" {
		t.Fatalf("目标日志不应被触碰")
	}

	// --delete：多余文件清理，保留配置与日志豁免
	res, err = Push(fs, src, dst, Options{Excludes: excludes, Retain: retain, Delete: true})
	if err != nil {
		t.Fatalf("push delete: %v", err)
	}
	got = readAll(t, dst)
	if _, ok := got["stale.jar"]; ok {
		t.Fatalf("--delete 应删除 stale.jar")
	}
	if got["WEB-INF/classes/redis.properties"] != "production" {
		t.Fatalf("保留配置不应被删除")
	}
	if got[testLog] != "runtime-log" {
		t.Fatalf("日志目录不应被删除")
	}
}

// 通配模式（旧版 master_exclusive_files 形如 egova-liquibase-[0-9]*...jar）。
func TestExcludeGlobPatterns(t *testing.T) {
	fs := localFS{}
	src := t.TempDir()
	dst := t.TempDir()

	write(t, filepath.Join(src, "WEB-INF", "lib", "egova-liquibase-1.2.3.jar"), "x")
	write(t, filepath.Join(src, "WEB-INF", "lib", "egova-core-9.9.jar"), "keep")

	res, err := Push(fs, src, dst, Options{
		Excludes: []string{"egova-liquibase-[0-9]*.[0-9]*.[0-9]*.jar"},
	})
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	got := readAll(t, dst)
	if _, ok := got["WEB-INF/lib/egova-liquibase-1.2.3.jar"]; ok {
		t.Fatalf("glob 排除应命中 liquibase jar")
	}
	if _, ok := got["WEB-INF/lib/egova-core-9.9.jar"]; !ok {
		t.Fatalf("不应误伤其它 jar")
	}
	_ = res
}

// Pull：远端 → 本地（备份语义），排除日志。
func TestPullBackup(t *testing.T) {
	fs := localFS{}
	src := t.TempDir() // 充当"远端"应用目录
	dst := t.TempDir()

	write(t, filepath.Join(src, "app.jar"), "binary")
	write(t, filepath.Join(src, testLog), "noise")
	write(t, filepath.Join(src, "conf", "a.properties"), "k=v")

	res, err := Pull(fs, src, filepath.Join(dst, "backup"), Options{Excludes: []string{"logs/"}})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	got := readAll(t, filepath.Join(dst, "backup"))
	if got["app.jar"] != "binary" || got["conf/a.properties"] != "k=v" {
		t.Fatalf("备份内容错误: %+v", got)
	}
	if got[testLog] != "" {
		t.Fatalf("备份不应包含日志")
	}
	if len(res.Uploaded) != 2 {
		t.Fatalf("应下载 2 个文件: %+v", res.Uploaded)
	}
}

// dry-run 不落盘且删除计划可见。
func TestDryRunNoSideEffects(t *testing.T) {
	fs := localFS{}
	src := t.TempDir()
	dst := t.TempDir()
	write(t, filepath.Join(src, "n.txt"), "1")
	write(t, filepath.Join(dst, "old.txt"), "0")

	res, err := Push(fs, src, dst, Options{Delete: true, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Deleted) != 1 || res.Deleted[0] != "old.txt" {
		t.Fatalf("dry-run 应报告删除计划: %+v", res.Deleted)
	}
	if _, err := os.Stat(filepath.Join(dst, "old.txt")); err != nil {
		t.Fatalf("dry-run 不应实际删除")
	}
	if _, err := os.Stat(filepath.Join(dst, "n.txt")); err == nil {
		t.Fatalf("dry-run 不应实际上传")
	}
}

// DeletePatterns 定向清理：目标端匹配模式的文件被删（无论源里有没有），保留配置与无关文件不受影响。
func TestDeletePatterns(t *testing.T) {
	fs := localFS{}
	src := t.TempDir()
	dst := t.TempDir()

	write(t, filepath.Join(src, "WEB-INF", "web.xml"), "v2-new") // 源里有正常文件（与目标长度不同，确保走传输）
	write(t, filepath.Join(dst, "WEB-INF", "lib", "egova-liquibase-1.4.9.jar"), "X")
	write(t, filepath.Join(dst, "WEB-INF", "lib", "liquibase-core-3.5.3.jar"), "X")
	write(t, filepath.Join(dst, "WEB-INF", "web.xml"), "v1")
	write(t, filepath.Join(dst, "WEB-INF", "classes", "jdbc.properties"), "PROD") // 保留配置

	pats := []string{"egova-liquibase-*.jar", "liquibase-core-*.jar"}
	retain := []string{"WEB-INF/classes/jdbc.properties"}

	res, err := Push(fs, src, dst, Options{
		Excludes:       pats, // 不推 liquibase
		Retain:         retain,
		DeletePatterns: pats, // 且清掉目标端已有的
	})
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	got := readAll(t, dst)
	if _, ok := got["WEB-INF/lib/egova-liquibase-1.4.9.jar"]; ok {
		t.Fatalf("清理未删除 egova-liquibase jar: %+v", got)
	}
	if _, ok := got["WEB-INF/lib/liquibase-core-3.5.3.jar"]; ok {
		t.Fatalf("清理未删除 liquibase-core jar")
	}
	if got["WEB-INF/web.xml"] != "v2-new" {
		t.Fatalf("正常文件应被更新")
	}
	if got["WEB-INF/classes/jdbc.properties"] != "PROD" {
		t.Fatalf("保留配置不应被清理")
	}
	if len(res.Deleted) != 2 {
		t.Fatalf("应报告 2 个清理项: %+v", res.Deleted)
	}

	// dry-run：只出计划不落盘
	dst2 := t.TempDir()
	write(t, filepath.Join(dst2, "WEB-INF", "lib", "egova-liquibase-1.4.9.jar"), "X")
	res2, err := Push(localFS{}, src, dst2, Options{DeletePatterns: pats, DryRun: true})
	if err != nil {
		t.Fatalf("dryrun: %v", err)
	}
	if len(res2.Deleted) != 1 {
		t.Fatalf("dry-run 应报告清理计划: %+v", res2.Deleted)
	}
	if _, err := os.Stat(filepath.Join(dst2, "WEB-INF", "lib", "egova-liquibase-1.4.9.jar")); err != nil {
		t.Fatalf("dry-run 不应实际清理")
	}
}
