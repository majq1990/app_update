//go:build !windows

package maintain

import (
	"path/filepath"
	"syscall"
)

// freeSpace 返回路径所在文件系统的可用字节数（Unix）。
func freeSpace(dir string) (int64, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return 0, err
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(abs, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
