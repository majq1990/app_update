// Package maintain 提供本地工作目录维护：清理历史更新包、备份压缩。
package maintain

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CleanUpdateResult 清理更新包结果。
type CleanUpdateResult struct {
	RemovedApps  []string // 清空的更新包目录（update/<应用名>/）
	RemovedFiles int
	FreedBytes   int64
	KeptApps     []string // 无更新包的应用（update/ 下不存在）
}

// CleanUpdatePackages 清理 update/ 下的历史更新包。
// mode: "all"      清空 update/ 下所有应用目录
//
//	"except-noted" 先不实现（预留）
//
// 默认保留 update/ 目录本身，只清其下的应用包目录。
func CleanUpdatePackages(updateDir string, dryRun bool) (*CleanUpdateResult, error) {
	res := &CleanUpdateResult{}
	entries, err := os.ReadDir(updateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return res, nil // 没有 update 目录，无需清理
		}
		return nil, fmt.Errorf("读取 %s: %w", updateDir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(updateDir, e.Name())
		var files int
		var bytes int64
		_ = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			files++
			if fi, err := d.Info(); err == nil {
				bytes += fi.Size()
			}
			return nil
		})
		res.RemovedApps = append(res.RemovedApps, e.Name())
		res.RemovedFiles += files
		res.FreedBytes += bytes
		if !dryRun {
			if err := os.RemoveAll(p); err != nil {
				return res, fmt.Errorf("删除 %s: %w", p, err)
			}
		}
	}
	sort.Strings(res.RemovedApps)
	return res, nil
}

// CompressResult 备份压缩结果。
type CompressResult struct {
	Archives []string // 生成的 .tar.gz 路径
	Bytes    int64    // 压缩前总字节
	Packed   int64    // 压缩后总字节
	Skipped  []string // 已是压缩包 / 空目录 / 空间不足，跳过
	Failed   []string // 压缩失败（原目录保留，数据未丢）
	Elapsed  time.Duration
}

// CompressBackups 对 backups/ 下**未压缩**的备份版本目录做多线程压缩。
//
// 规则：
//   - 只处理 backups/<应用>/<版本>/ 这一层目录；同层若已有 <版本>.tar.gz 则跳过
//   - 每个版本目录打包为备份根目录下的 <应用>/<版本>.tar.gz，压缩成功后删除原目录
//   - 多线程：并发压缩多个版本目录（每版本一条 goroutine）；gzip 内部按 CPU 数并行度已足够
//   - dryRun 只统计不落盘
//
// 返回结果用于汇总展示（压缩前后体积、耗时）。
func CompressBackups(backupDir string, workers int, dryRun bool) (*CompressResult, error) {
	res := &CompressResult{}
	if workers <= 0 {
		workers = runtime.NumCPU()
		if workers > 8 {
			workers = 8 // 压缩是 IO 密集，8 路足够
		}
	}
	start := time.Now()

	apps, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return res, nil
		}
		return nil, fmt.Errorf("读取 %s: %w", backupDir, err)
	}

	// 收集待压缩的版本目录
	type job struct {
		app, version, dir, archive string
	}
	var jobs []job
	for _, app := range apps {
		if !app.IsDir() {
			continue
		}
		appDir := filepath.Join(backupDir, app.Name())
		versions, err := os.ReadDir(appDir)
		if err != nil {
			continue
		}
		for _, v := range versions {
			if !v.IsDir() {
				continue // 已经是 .tar.gz 或其它文件
			}
			dir := filepath.Join(appDir, v.Name())
			archive := filepath.Join(appDir, v.Name()+".tar.gz")
			if _, err := os.Stat(archive); err == nil {
				res.Skipped = append(res.Skipped, dir+"（已存在压缩包）")
				continue
			}
			// 空目录跳过
			hasFile := false
			_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					hasFile = true
					return io.EOF
				}
				return nil
			})
			if !hasFile {
				res.Skipped = append(res.Skipped, dir+"（空目录）")
				continue
			}
			jobs = append(jobs, job{app.Name(), v.Name(), dir, archive})
		}
	}

	if len(jobs) == 0 {
		res.Elapsed = time.Since(start)
		return res, nil
	}

	if dryRun {
		for _, j := range jobs {
			var size int64
			_ = filepath.WalkDir(j.dir, func(p string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					if fi, err := d.Info(); err == nil {
						size += fi.Size()
					}
				}
				return nil
			})
			res.Bytes += size
			res.Archives = append(res.Archives, j.archive+"（dry-run 未生成）")
		}
		res.Elapsed = time.Since(start)
		return res, nil
	}

	// 多线程压缩
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		totalIn  int64
		totalOut int64
		done     int64
	)
	sem := make(chan struct{}, workers)
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()

			// 空间预检：压缩期间原目录与压缩包同时存在，需要约 2 倍原目录空间。
			// 空间不足时跳过该版本（原目录保留，数据不丢），继续处理其他版本。
			var need int64
			_ = filepath.WalkDir(j.dir, func(p string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					if fi, e := d.Info(); e == nil {
						need += fi.Size()
					}
				}
				return nil
			})
			if free, err := freeSpace(filepath.Dir(j.archive)); err == nil && free < need {
				mu.Lock()
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s（空间不足：需 %s，可用 %s）",
					j.dir, HumanBytes(need), HumanBytes(free)))
				mu.Unlock()
				return
			}

			in, out, err := compressDir(j.dir, j.archive)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// 单个版本失败不影响其他版本；原目录保留
				res.Failed = append(res.Failed, fmt.Sprintf("%s: %v", j.dir, err))
				return
			}
			totalIn += in
			totalOut += out
			res.Archives = append(res.Archives, j.archive)
			atomic.AddInt64(&done, 1)
			// 压缩成功后再删除原目录（失败保留原数据，绝不丢备份）
			if err := os.RemoveAll(j.dir); err != nil {
				res.Failed = append(res.Failed, fmt.Sprintf("删除已压缩目录 %s: %v", j.dir, err))
			}
		}(j)
	}
	wg.Wait()
	res.Bytes = totalIn
	res.Packed = totalOut
	res.Elapsed = time.Since(start)
	sort.Strings(res.Archives)
	sort.Strings(res.Skipped)
	if len(res.Failed) > 0 {
		return res, fmt.Errorf("%d 个版本压缩失败（原目录已保留）:\n  %s",
			len(res.Failed), strings.Join(res.Failed, "\n  "))
	}
	return res, nil
}

// compressDir 把目录打包为 tar.gz，返回输入/输出字节数。
// gzip 使用默认压缩级别（时间与体积平衡，GB 级备份不宜用 BestCompression）。
func compressDir(srcDir, dstArchive string) (int64, int64, error) {
	var inBytes int64
	tmp := dstArchive + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		_ = f.Close()
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	walkErr := filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := filepath.Rel(srcDir, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		hdr, herr := tar.FileInfoHeader(info, "")
		if herr != nil {
			return herr
		}
		hdr.Name = filepath.ToSlash(rel)
		if d.IsDir() {
			hdr.Name += "/"
		}
		if werr := tw.WriteHeader(hdr); werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		src, oerr := os.Open(p)
		if oerr != nil {
			return oerr
		}
		n, cerr := io.Copy(tw, src)
		_ = src.Close()
		inBytes += n
		return cerr
	})
	if walkErr != nil {
		err = walkErr
		return inBytes, 0, err
	}
	if err = tw.Close(); err != nil {
		return inBytes, 0, err
	}
	if err = gz.Close(); err != nil {
		return inBytes, 0, err
	}
	if err = f.Close(); err != nil {
		return inBytes, 0, err
	}
	fi, serr := os.Stat(tmp)
	if serr != nil {
		err = serr
		return inBytes, 0, err
	}
	if err = os.Rename(tmp, dstArchive); err != nil {
		return inBytes, 0, err
	}
	return inBytes, fi.Size(), nil
}

// HumanBytes 人类可读体积。
func HumanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// TrimSuffixSlash 去除尾部斜杠。
func TrimSuffixSlash(s string) string { return strings.TrimRight(s, "/") }
