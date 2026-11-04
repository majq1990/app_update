package appflow

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

// makeTestJar 构造测试用 JAR（zip）。
func makeTestJar(path string, files map[string]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return err
		}
	}
	return zw.Close()
}

// 静态部分更新（partial）：内容推到各群组根 + rel。
func TestStaticPartial(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig()
	r, _ := newTestRunner(t, cfg, root)

	upd := filepath.Join(root, "update", "eUrbanMIS", "view", "css")
	mustWrite(t, filepath.Join(upd, "common.css"), "v2")

	// master/update webPath 已指向本地目录；tomcat 部分更新目标 = webPath/view/css
	if _, err := r.StaticPartial("eUrbanMIS", "view/css"); err != nil {
		t.Fatalf("partial: %v", err)
	}
	files := readFileMap(t, filepath.Join(root, "webapps", "master"))
	if files["view/css/common.css"] != "v2" {
		t.Fatalf("partial 未落到 master: %+v", files)
	}
	files = readFileMap(t, filepath.Join(root, "webapps", "update"))
	if files["view/css/common.css"] != "v2" {
		t.Fatalf("partial 未落到 update 群组: %+v", files)
	}
	_ = t
}
