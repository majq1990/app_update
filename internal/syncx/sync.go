// Package syncx 是自研的文件级同步引擎（替代旧版对外部 rsync 的依赖）。
// 增量判据 = 大小 + 修改时间（秒级），语义对齐旧版 rsync 用法：
//   - 应用更新：覆盖式（无 --delete），排除日志目录与保留配置；
//   - 回滚 / 静态页面：全量对齐（--delete）；
//   - 备份：远端→本地拉取，排除日志。
//
// DryRun 只计算计划不落盘。
package syncx

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Entry 远端/本地文件的规范化描述。Rel 恒为斜杠分隔的相对路径。
type Entry struct {
	Rel   string
	IsDir bool
	Size  int64
	Mtime time.Time
}

// RemoteFS 抽象远端（SFTP 实现于 internal/sshx，测试用本地假实现）。
// 所有 abs 参数为绝对路径（远端）或绝对/相对路径（本地假实现均可）。
type RemoteFS interface {
	// Stat 返回路径信息；不存在时返回包装了 fs.ErrNotExist 的错误。
	Stat(abs string) (Entry, error)
	// Walk 先序遍历 abs 子树（不含 abs 自身），按根→叶顺序。
	Walk(abs string, fn func(Entry) error) error
	MkdirAll(abs string) error
	// Upload 上传本地文件到远端并保留源 mtime 与权限。
	Upload(localPath, abs string, mtime time.Time) error
	// Download 下载远端文件到本地并保留源 mtime，返回字节数。
	Download(abs, localPath string) (int64, error)
	RemoveAll(abs string) error
}

// Options 同步选项。
type Options struct {
	Excludes []string // rsync 风格模式：无 / = basename 匹配任意层级；含 / = 锚定相对路径；尾 / = 目录子树
	Delete   bool     // 删除目标端多余的文件（--delete 语义；保留配置与排除项除外）
	DryRun   bool
	// 保留配置路径：永不覆盖上传、永不删除（不配 Delete 时仅影响上传跳过）。
	Retain []string
	// DeletePatterns 推送后删除目标端匹配这些模式的文件（"清理"语义：
	// 用于移除备节点不该存在的文件，如 master_exclusive_files 里的 liquibase jar——
	// 主节点专属文件推给了备节点后，靠它在更新备节点时清掉）。保留配置不受影响。
	DeletePatterns []string
	Logf           func(format string, args ...interface{})
}

// Result 一次同步的结果清单。
type Result struct {
	Uploaded []string
	Deleted  []string
	Skipped  []string // 排除/保留而未动的目标端文件
	Bytes    int64
}

func (r Result) String() string {
	return fmt.Sprintf("上传 %d / 删除 %d / 跳过 %d / %s",
		len(r.Uploaded), len(r.Deleted), len(r.Skipped), humanBytes(r.Bytes))
}

func humanBytes(n int64) string {
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

func (o Options) logf(format string, args ...interface{}) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// Push 本地 srcDir → 远端 dstDir。
// 目标端按全量遍历（不过滤 Excludes），否则被排除的文件（如 master 专属文件）在清理阶段不可见。
func Push(rfs RemoteFS, srcDir, dstDir string, opt Options) (Result, error) {
	src, err := walkLocal(srcDir, opt.Excludes)
	if err != nil {
		return Result{}, err
	}
	dst, err := walkRemote(rfs, dstDir, nil)
	if err != nil {
		return Result{}, err
	}
	return apply(rfs, srcDir, dstDir, src, dst, opt, true, uploadFile)
}

// Pull 远端 srcDir → 本地 dstDir（方向与 Push 相反，判据一致）。
// dstDir 不存在视为空集（首次备份/首次拉取）。
func Pull(rfs RemoteFS, srcDir, dstDir string, opt Options) (Result, error) {
	src, err := walkRemote(rfs, srcDir, opt.Excludes)
	if err != nil {
		return Result{}, err
	}
	dst, err := walkLocalOpt(dstDir, opt.Excludes, false)
	if err != nil {
		return Result{}, err
	}
	return apply(rfs, srcDir, dstDir, src, dst, opt, false, downloadFile)
}

// transfer 抽象单文件搬运动作（Push=上传 / Pull=下载），自行创建父目录。
type transfer func(rfs RemoteFS, fromBase, rel, toBase string, mtime time.Time) (int64, error)

func uploadFile(rfs RemoteFS, fromBase, rel, toBase string, mtime time.Time) (int64, error) {
	var size int64
	if st, err := os.Stat(filepath.Join(fromBase, filepath.FromSlash(rel))); err == nil {
		size = st.Size()
	}
	// 目标父目录无条件确保存在（目标根可能比远端现场更深；MkdirAll 幂等）。
	// 远端路径必须用 path.Dir（POSIX 语义），Windows 的 filepath.Dir 会把 /egova/... 解析为 "."。
	dst := joinAbs(toBase, rel)
	if parent := path.Dir(dst); parent != "." && parent != "/" && parent != dst {
		if err := rfs.MkdirAll(parent); err != nil {
			return size, err
		}
	}
	return size, rfs.Upload(filepath.Join(fromBase, filepath.FromSlash(rel)), dst, mtime)
}

func downloadFile(rfs RemoteFS, fromBase, rel, toBase string, mtime time.Time) (int64, error) {
	local := filepath.Join(toBase, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		return 0, err
	}
	return rfs.Download(joinAbs(fromBase, rel), local)
}

// apply 核心增量逻辑：mkdir → 传输新增/变更 → 删除多余。
// push=true 时目标端是远端（rfs）；push=false 时目标端是本地（os）。
func apply(rfs RemoteFS, srcBase, dstBase string, src, dst map[string]Entry, opt Options, push bool, tf transfer) (Result, error) {
	var res Result

	mkTarget := func(rel string) error {
		if push {
			return rfs.MkdirAll(joinAbs(dstBase, rel))
		}
		return os.MkdirAll(filepath.Join(dstBase, filepath.FromSlash(rel)), 0o755)
	}
	rmTarget := func(rel string) error {
		if push {
			return rfs.RemoveAll(joinAbs(dstBase, rel))
		}
		return os.RemoveAll(filepath.Join(dstBase, filepath.FromSlash(rel)))
	}

	// 1. 建缺失的目录
	for rel, e := range src {
		if !e.IsDir {
			continue
		}
		if _, ok := dst[rel]; ok {
			continue
		}
		opt.logf("  [目录] %s", rel)
		if !opt.DryRun {
			if err := mkTarget(rel); err != nil {
				return res, fmt.Errorf("创建目录 %s: %w", rel, err)
			}
		}
	}

	// 2. 传输新增或变更的文件（保留配置路径跳过上传，绝不覆盖现场）
	srcFiles := make([]string, 0, len(src))
	for rel, e := range src {
		if !e.IsDir {
			srcFiles = append(srcFiles, rel)
		}
	}
	sort.Strings(srcFiles)
	for _, rel := range srcFiles {
		s := src[rel]
		if retainedRel(rel, opt.Retain) {
			res.Skipped = append(res.Skipped, rel)
			opt.logf("  [保留] %s", rel)
			continue
		}
		d, ok := dst[rel]
		switch {
		case !ok:
			// 新文件
		case s.Size != d.Size || s.Mtime.Unix() != d.Mtime.Unix():
			// 内容可能变化
		default:
			res.Skipped = append(res.Skipped, rel) // 未变化（无需传输）
			continue
		}
		res.Uploaded = append(res.Uploaded, rel)
		opt.logf("  [传输] %s", rel)
		if opt.DryRun {
			if st, err := os.Stat(filepath.Join(srcBase, filepath.FromSlash(rel))); err == nil {
				res.Bytes += st.Size()
			}
			continue
		}
		n, err := tf(rfs, srcBase, rel, dstBase, s.Mtime)
		if err != nil {
			return res, fmt.Errorf("传输 %s: %w", rel, err)
		}
		res.Bytes += n
	}

	// 3. 删除目标端多余项（排除项与保留项除外）
	if opt.Delete {
		var doomed []string
		for rel, e := range dst {
			if _, ok := src[rel]; ok {
				continue
			}
			if excludedRel(rel, e.IsDir, opt.Excludes) || retainedRel(rel, opt.Retain) {
				if opt.Delete || len(opt.DeletePatterns) > 0 {
					res.Skipped = append(res.Skipped, rel)
				}
				continue
			}
			doomed = append(doomed, rel)
		}
		// 先深后浅：子项先删，父目录最后（RemoveAll 对已缺失路径幂等）
		sort.Slice(doomed, func(i, j int) bool { return len(doomed[i]) > len(doomed[j]) })
		for _, rel := range doomed {
			res.Deleted = append(res.Deleted, rel)
			opt.logf("  [删除] %s", rel)
			if opt.DryRun {
				continue
			}
			if err := rmTarget(rel); err != nil {
				return res, fmt.Errorf("删除 %s: %w", rel, err)
			}
		}
	}

	// 4. 定向清理：删除目标端匹配 DeletePatterns 的文件（无论源里有没有），
	//    用于移除备节点不该存在的 master 专属文件（如 liquibase jar）。保留配置受保护。
	if len(opt.DeletePatterns) > 0 {
		var doomed []string
		for rel, e := range dst {
			if e.IsDir || retainedRel(rel, opt.Retain) {
				continue
			}
			if !excludedRel(rel, false, opt.DeletePatterns) {
				continue
			}
			doomed = append(doomed, rel)
		}
		sort.Strings(doomed)
		for _, rel := range doomed {
			res.Deleted = append(res.Deleted, rel)
			opt.logf("  [清理] %s", rel)
			if opt.DryRun {
				continue
			}
			if err := rmTarget(rel); err != nil {
				return res, fmt.Errorf("清理 %s: %w", rel, err)
			}
		}
	}
	return res, nil
}

// ---- 本地遍历 ----

func walkLocal(root string, excludes []string) (map[string]Entry, error) {
	return walkLocalOpt(root, excludes, true)
}

// walkLocalOpt 遍历本地目录；mustExist=false 时目录不存在返回空集（作为 Pull 目标）。
func walkLocalOpt(root string, excludes []string, mustExist bool) (map[string]Entry, error) {
	out := map[string]Entry{}
	info, err := os.Stat(root)
	if err != nil {
		if !mustExist && os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("本地目录不可访问: %s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("本地源不是目录: %s", root)
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		isDir := d.IsDir()
		if excludedRel(rel, isDir, excludes) {
			if isDir {
				return filepath.SkipDir
			}
			return nil
		}
		e := Entry{Rel: rel, IsDir: isDir}
		if !isDir {
			fi, err := d.Info()
			if err != nil {
				return err
			}
			e.Size = fi.Size()
			e.Mtime = fi.ModTime()
		}
		out[rel] = e
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("遍历本地 %s: %w", root, err)
	}
	return out, nil
}

// ---- 远端遍历 ----

func walkRemote(rfs RemoteFS, root string, excludes []string) (map[string]Entry, error) {
	out := map[string]Entry{}
	if _, err := rfs.Stat(root); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return out, nil // 目标不存在 = 空集（首次部署）
		}
		return nil, err
	}
	err := rfs.Walk(root, func(e Entry) error {
		if excludedRel(e.Rel, e.IsDir, excludes) {
			if e.IsDir {
				return fs.SkipDir
			}
			return nil
		}
		out[e.Rel] = e
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("遍历远端 %s: %w", root, err)
	}
	return out, nil
}

func joinAbs(base, rel string) string {
	return strings.TrimRight(base, "/") + "/" + rel
}

// ---- rsync 风格模式匹配（务实子集） ----
//
//	p 尾带 "/"            → 目录模式：匹配该名字的目录及其子树（任意层级）
//	p 不含 "/"            → basename 匹配任意层级（文件或目录）
//	p 含 "/"（锚定）       → 匹配相对路径 == p、p 子树，或 path.Match 通配
//	支持 glob：* ? [a-z]
func excludedRel(rel string, isDir bool, patterns []string) bool {
	parts := strings.Split(strings.Trim(rel, "/"), "/")
	for i := 1; i < len(parts); i++ { // 祖先目录命中目录模式 → 子树整体排除
		anc := strings.Join(parts[:i], "/")
		for _, pat := range patterns {
			if strings.HasSuffix(pat, "/") {
				if ok, _ := path.Match(strings.TrimSuffix(pat, "/"), path.Base("/"+anc)); ok {
					return true
				}
			}
		}
	}
	for _, pat := range patterns {
		if matchOne(rel, isDir, pat) {
			return true
		}
	}
	return false
}

// retainedRel 保留配置命中：含 / 锚定精确（含子树），不含 / 按 basename。
func retainedRel(rel string, patterns []string) bool {
	clean := strings.TrimPrefix(rel, "/")
	for _, pat := range patterns {
		p := strings.TrimSuffix(strings.TrimSpace(pat), "/")
		if p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			if clean == p || strings.HasPrefix(clean, p+"/") {
				return true
			}
			continue
		}
		if ok, _ := path.Match(p, path.Base("/"+clean)); ok {
			return true
		}
	}
	return false
}

func matchOne(rel string, isDir bool, pat string) bool {
	dirOnly := strings.HasSuffix(pat, "/")
	p := strings.TrimSuffix(pat, "/")
	if p == "" || rel == "" {
		return false
	}
	clean := strings.TrimPrefix(rel, "/")
	if !strings.Contains(p, "/") {
		base := path.Base("/" + clean)
		if ok, _ := path.Match(p, base); ok {
			if dirOnly && !isDir {
				return false
			}
			return true
		}
		return false
	}
	if clean == p {
		return !dirOnly || isDir
	}
	if strings.HasPrefix(clean, p+"/") {
		return true
	}
	if m, _ := path.Match(p, clean); m {
		return true
	}
	if m, _ := path.Match(p+"/*", clean); m {
		return true
	}
	return false
}
