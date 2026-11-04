package sshx

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"

	"github.com/majq1990/app-updater-go/internal/syncx"
)

// FS 返回（懒创建、复用的）SFTP 文件系统适配器。
func (c *Client) FS() (*SFTPFS, error) {
	if c.fsCache != nil {
		return c.fsCache, nil
	}
	cli, err := sftp.NewClient(c.cli)
	if err != nil {
		return nil, fmt.Errorf("建立 SFTP: %w", err)
	}
	c.fsCache = &SFTPFS{cli: cli}
	return c.fsCache, nil
}

// SFTPFS 基于 SFTP 的 syncx.RemoteFS 实现。
type SFTPFS struct {
	cli *sftp.Client
}

// Stat 返回路径信息；不存在时错误包装 fs.ErrNotExist。
func (s *SFTPFS) Stat(abs string) (syncx.Entry, error) {
	fi, err := s.cli.Stat(abs)
	if err != nil {
		if isNotExist(err) {
			return syncx.Entry{}, fmt.Errorf("%s: %w", abs, fs.ErrNotExist)
		}
		return syncx.Entry{}, err
	}
	return syncx.Entry{
		Rel:   "", // Stat 不带相对语义，调用方按需填
		IsDir: fi.IsDir(),
		Size:  fi.Size(),
		Mtime: fi.ModTime(),
	}, nil
}

// Walk 先序遍历 abs 子树（不含 abs 自身），Entry.Rel 为相对 abs 的路径。
func (s *SFTPFS) Walk(abs string, fn func(syncx.Entry) error) error {
	return s.walk(abs, "", fn)
}

func (s *SFTPFS) walk(abs, rel string, fn func(syncx.Entry) error) error {
	infos, err := s.cli.ReadDir(abs)
	if err != nil {
		return err
	}
	// 先序：目录排前，路径排序保证确定性
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].IsDir() != infos[j].IsDir() {
			return infos[i].IsDir()
		}
		return infos[i].Name() < infos[j].Name()
	})
	for _, fi := range infos {
		childRel := fi.Name()
		if rel != "" {
			childRel = rel + "/" + fi.Name()
		}
		e := syncx.Entry{Rel: childRel, IsDir: fi.IsDir()}
		if !fi.IsDir() {
			e.Size = fi.Size()
			e.Mtime = fi.ModTime()
		}
		if err := fn(e); err != nil {
			if errors.Is(err, fs.SkipDir) && fi.IsDir() {
				continue
			}
			return err
		}
		if fi.IsDir() {
			if err := s.walk(abs+"/"+fi.Name(), childRel, fn); err != nil {
				return err
			}
		}
	}
	return nil
}

// MkdirAll 逐级创建远端目录。
func (s *SFTPFS) MkdirAll(abs string) error {
	abs = strings.TrimRight(abs, "/")
	if abs == "" {
		return nil
	}
	if _, err := s.cli.Stat(abs); err == nil {
		return nil
	}
	parent := path.Dir(abs)
	if parent != "/" && parent != "." && parent != abs {
		if err := s.MkdirAll(parent); err != nil {
			return err
		}
	}
	if err := s.cli.Mkdir(abs); err != nil {
		// 并发/竞态下目录可能已存在
		if _, serr := s.cli.Stat(abs); serr == nil {
			return nil
		}
		return err
	}
	return nil
}

// Upload 上传本地文件并保留源 mtime 与权限位。
func (s *SFTPFS) Upload(localPath, abs string, mtime time.Time) error {
	src, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := s.cli.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	if !mtime.IsZero() {
		_ = s.cli.Chtimes(abs, mtime, mtime)
	}
	if fi, err := src.Stat(); err == nil {
		_ = s.cli.Chmod(abs, fi.Mode().Perm())
	}
	return nil
}

// Download 下载远端文件到本地并保留源 mtime，返回字节数。
func (s *SFTPFS) Download(abs, localPath string) (int64, error) {
	src, err := s.cli.Open(abs)
	if err != nil {
		return 0, err
	}
	defer src.Close()

	dst, err := os.Create(localPath)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(dst, src)
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, err
	}
	if fi, err := src.Stat(); err == nil {
		mt := fi.ModTime()
		_ = os.Chtimes(localPath, mt, mt)
	}
	return n, nil
}

// RemoveAll 递归删除（SFTP 无 rm -rf，先删文件再自底向上删目录）。
func (s *SFTPFS) RemoveAll(abs string) error {
	fi, err := s.cli.Stat(abs)
	if err != nil {
		if isNotExist(err) {
			return nil // 幂等
		}
		return err
	}
	if !fi.IsDir() {
		return s.cli.Remove(abs)
	}
	infos, err := s.cli.ReadDir(abs)
	if err != nil {
		return err
	}
	for _, info := range infos {
		if err := s.RemoveAll(abs + "/" + info.Name()); err != nil {
			return err
		}
	}
	return s.cli.RemoveDirectory(abs)
}

func isNotExist(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, fs.ErrNotExist) ||
		errors.Is(err, os.ErrNotExist) ||
		strings.Contains(err.Error(), "no such file") ||
		strings.Contains(err.Error(), "NOT_FOUND")
}
