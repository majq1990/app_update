//go:build windows

package maintain

import (
	"path/filepath"
	"syscall"
	"unsafe"
)

// freeSpace 返回路径所在卷的可用字节数（Windows，GetDiskFreeSpaceExW）。
func freeSpace(dir string) (int64, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return 0, err
	}
	p, err := syscall.UTF16PtrFromString(abs)
	if err != nil {
		return 0, err
	}
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetDiskFreeSpaceExW")
	r1, _, e := proc.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if r1 == 0 {
		return 0, e
	}
	return int64(freeBytesAvailable), nil
}
