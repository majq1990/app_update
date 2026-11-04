package maintain

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// 清理更新包：dry-run 不删，正式执行清空应用目录但保留 update/ 本身。
func TestCleanUpdatePackages(t *testing.T) {
	root := t.TempDir()
	upd := filepath.Join(root, "update")
	writeFile(t, filepath.Join(upd, "usercenter", "app.jar"), "jar")
	writeFile(t, filepath.Join(upd, "usercenter", "webApps", "a.js"), "js")
	writeFile(t, filepath.Join(upd, "export", "e.jar"), "jar")

	// dry-run
	res, err := CleanUpdatePackages(upd, true)
	if err != nil {
		t.Fatalf("dry: %v", err)
	}
	if len(res.RemovedApps) != 2 || res.RemovedFiles != 3 {
		t.Fatalf("dry-run 统计错误: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(upd, "usercenter", "app.jar")); err != nil {
		t.Fatalf("dry-run 不应删除")
	}

	// 正式执行
	res, err = CleanUpdatePackages(upd, false)
	if err != nil {
		t.Fatalf("clean: %v", err)
	}
	if len(res.RemovedApps) != 2 {
		t.Fatalf("应清理 2 个应用: %+v", res.RemovedApps)
	}
	if _, err := os.Stat(filepath.Join(upd, "usercenter")); !os.IsNotExist(err) {
		t.Fatalf("应用目录应被删除")
	}
	if _, err := os.Stat(upd); err != nil {
		t.Fatalf("update/ 自身不应删除")
	}

	// 空目录不报错
	res, err = CleanUpdatePackages(upd, false)
	if err != nil || len(res.RemovedApps) != 0 {
		t.Fatalf("空目录应无操作: %+v %v", res, err)
	}
}

// 备份压缩：内容完整、原目录删除、已有压缩包跳过、dry-run 不落盘。
func TestCompressBackups(t *testing.T) {
	root := t.TempDir()
	bk := filepath.Join(root, "backups")
	// 版本 1：待压缩
	writeFile(t, filepath.Join(bk, "usercenter", "2026110412", "172.21.133.222", "app.jar"), "jar-content")
	writeFile(t, filepath.Join(bk, "usercenter", "2026110412", "172.21.133.222", "conf", "a.properties"), "k=v")
	// 版本 2：已有压缩包 → 跳过
	writeFile(t, filepath.Join(bk, "usercenter", "2026110312", "x", "old.jar"), "old")
	writeFile(t, filepath.Join(bk, "usercenter", "2026110312.tar.gz"), "fake-archive")

	// dry-run
	pre, err := CompressBackups(bk, 4, true)
	if err != nil {
		t.Fatalf("dry: %v", err)
	}
	if len(pre.Archives) != 1 {
		t.Fatalf("应只有 1 个待压缩版本: %v", pre.Archives)
	}
	if len(pre.Skipped) != 1 || !strings.Contains(pre.Skipped[0], "已存在压缩包") {
		t.Fatalf("应跳过已有压缩包的版本: %v", pre.Skipped)
	}
	if pre.Bytes == 0 {
		t.Fatalf("dry-run 应统计原始体积")
	}
	if _, err := os.Stat(filepath.Join(bk, "usercenter", "2026110412.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("dry-run 不应生成压缩包")
	}

	// 正式压缩
	res, err := CompressBackups(bk, 4, false)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if len(res.Archives) != 1 {
		t.Fatalf("应压缩 1 个: %v", res.Archives)
	}
	if res.Bytes == 0 || res.Packed == 0 {
		t.Fatalf("应统计体积: %+v", res)
	}
	// 原目录已删除
	if _, err := os.Stat(filepath.Join(bk, "usercenter", "2026110412")); !os.IsNotExist(err) {
		t.Fatalf("压缩成功后原目录应删除")
	}
	// 已有压缩包的版本目录保持不动
	if _, err := os.Stat(filepath.Join(bk, "usercenter", "2026110312", "x", "old.jar")); err != nil {
		t.Fatalf("已存在压缩包的版本目录不应被处理")
	}

	// 校验压缩包内容完整可读
	archive := filepath.Join(bk, "usercenter", "2026110412.tar.gz")
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("读压缩包: %v", err)
		}
		if hdr.Typeflag == tar.TypeReg {
			data, _ := io.ReadAll(tr)
			found[hdr.Name] = string(data)
		}
	}
	want := map[string]string{
		"172.21.133.222/app.jar":           "jar-content",
		"172.21.133.222/conf/a.properties": "k=v",
	}
	for k, v := range want {
		if found[k] != v {
			t.Fatalf("压缩包内容缺失/错误: %s=%q (全部: %v)", k, found[k], found)
		}
	}
}
