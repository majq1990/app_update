package appflow

// 备份压缩包解压（回滚支持直接从 .tar.gz 还原）。

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractTarGz 把 tar.gz 解压到 dstDir。
// 安全约束：拒绝绝对路径与 ../ 逃逸（防止恶意/损坏的备份包写到目录外）。
func ExtractTarGz(archive, dstDir string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	root, err := filepath.Abs(dstDir)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("读取 tar: %w", err)
		}
		name := hdr.Name
		if name == "" {
			continue
		}
		// 拒绝绝对路径与路径穿越
		if filepath.IsAbs(name) || strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			return fmt.Errorf("备份包含非法路径: %q", name)
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		if !strings.HasPrefix(target, root+string(os.PathSeparator)) && target != root {
			return fmt.Errorf("备份路径越界: %q", name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			// 保留备份内权限位；无权限信息时按 0644（备份内容是应用文件，非敏感凭据）
			mode := os.FileMode(hdr.Mode) & 0o777
			if mode == 0 {
				mode = 0o644
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				_ = out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
			if !hdr.ModTime.IsZero() {
				_ = os.Chtimes(target, hdr.ModTime, hdr.ModTime)
			}
		case tar.TypeSymlink:
			// 备份里不预期有符号链接，保守跳过
			continue
		}
	}
}
