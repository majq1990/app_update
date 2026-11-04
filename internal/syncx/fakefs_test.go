package syncx

// 假远端文件系统：直接落在本地临时目录（同步逻辑与传输协议解耦，
// SFTP 真实通道由 internal/sshx 的回环测试覆盖）。

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type localFS struct{}

func (localFS) Stat(abs string) (Entry, error) {
	fi, err := os.Stat(abs)
	if err != nil {
		return Entry{}, fmt.Errorf("%s: %w", abs, fs.ErrNotExist)
	}
	return Entry{IsDir: fi.IsDir(), Size: fi.Size(), Mtime: fi.ModTime()}, nil
}

func (localFS) Walk(abs string, fn func(Entry) error) error {
	return walkDirLocal(abs, "", fn)
}

func walkDirLocal(abs, rel string, fn func(Entry) error) error {
	infos, err := os.ReadDir(abs)
	if err != nil {
		return err
	}
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].IsDir() != infos[j].IsDir() {
			return infos[i].IsDir()
		}
		return infos[i].Name() < infos[j].Name()
	})
	for _, di := range infos {
		childRel := di.Name()
		if rel != "" {
			childRel = rel + "/" + di.Name()
		}
		e := Entry{Rel: childRel, IsDir: di.IsDir()}
		if !di.IsDir() {
			fi, err := di.Info()
			if err != nil {
				return err
			}
			e.Size = fi.Size()
			e.Mtime = fi.ModTime()
		}
		if err := fn(e); err != nil {
			if err == fs.SkipDir && di.IsDir() {
				continue
			}
			return err
		}
		if di.IsDir() {
			if err := walkDirLocal(filepath.Join(abs, di.Name()), childRel, fn); err != nil {
				return err
			}
		}
	}
	return nil
}

func (localFS) MkdirAll(abs string) error { return os.MkdirAll(abs, 0o755) }

func (localFS) Upload(localPath, abs string, mtime time.Time) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(abs, data, 0o644); err != nil {
		return err
	}
	if !mtime.IsZero() {
		return os.Chtimes(abs, mtime, mtime)
	}
	return nil
}

func (localFS) Download(abs, localPath string) (int64, error) {
	data, err := os.ReadFile(abs)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(localPath, data, 0o644); err != nil {
		return 0, err
	}
	if fi, err := os.Stat(abs); err == nil {
		_ = os.Chtimes(localPath, fi.ModTime(), fi.ModTime())
	}
	return int64(len(data)), nil
}

func (localFS) RemoveAll(abs string) error { return os.RemoveAll(abs) }

// ---- 测试辅助 ----

func write(t helper, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

type helper interface {
	Helper()
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
}

func readAll(t helper, root string) map[string]string {
	out := map[string]string{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel := filepath.ToSlash(strings.TrimPrefix(strings.TrimPrefix(p, root), "\\"))
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			t.Fatal(rerr)
		}
		out[rel] = string(data)
		return nil
	})
	return out
}
