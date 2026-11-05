package logs

import (
	"fmt"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/syncx"
)

// BuildPlan 扫描全部目标生成清理计划（只读）。now 传 time.Now()（测试可注入）。
// 目录不存在的目标计入 Errs 继续跑其余目标（现场配置漂移是常态，不因单目标阻断）。
func BuildPlan(rfs syncx.RemoteFS, targets []Target, now time.Time) *Plan {
	p := &Plan{}
	for _, t := range targets {
		for _, dir := range t.LogDirs {
			var files []LogFile
			err := rfs.Walk(dir, func(e syncx.Entry) error {
				// Entry.Rel 恒为相对路径（syncx 契约），但防御个别实现回传绝对路径：
				rel := strings.TrimPrefix(e.Rel, "/")
				files = append(files, LogFile{
					Abs: path.Join(dir, rel), Dir: dir, Rel: rel,
					Size: e.Size, Mtime: e.Mtime, IsDir: e.IsDir,
				})
				return nil
			})
			if err != nil {
				if isNotExist(err) {
					p.Errs = append(p.Errs, fmt.Errorf("%s(%s) 日志目录不存在: %s", t.Name, t.Host.Host, dir))
				} else {
					p.Errs = append(p.Errs, fmt.Errorf("%s(%s) 扫描 %s 失败: %w", t.Name, t.Host.Host, dir, err))
				}
				continue
			}
			for _, f := range files {
				if !t.Candidate(f) {
					continue // 白名单外（如 mysql binlog、非日志文件）：一个不碰
				}
				exp := t.Expired(f, now)
				p.Items = append(p.Items, PlanItem{Target: t, File: f, Expired: exp})
				if exp {
					p.FreeSize += f.Size
				}
				p.TotalSize += f.Size
			}
		}
	}
	p.Sort()
	return p
}

// Apply 执行计划：只删 Expired 项。返回实际删除数与释放字节数。
// 计划来自 BuildPlan 的白名单判定，此处不再二次匹配（执行与计划一致性由测试保障）。
func Apply(rfs syncx.RemoteFS, p *Plan) (deleted int, freed int64, err error) {
	for _, it := range p.Items {
		if !it.Expired {
			continue
		}
		if err := rfs.RemoveAll(it.File.Abs); err != nil {
			return deleted, freed, fmt.Errorf("删除 %s: %w", it.File.Abs, err)
		}
		deleted++
		freed += it.File.Size
	}
	return deleted, freed, nil
}

func isNotExist(err error) bool {
	return errorsIs(err, fs.ErrNotExist)
}

// errorsIs 小包装，避免每个文件都引 errors。
func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// Summarize 计划摘要（终端用；明细落日志文件的宪法规则）。
func (p *Plan) Summarize() string {
	expired, kept := 0, 0
	for _, it := range p.Items {
		if it.Expired {
			expired++
		} else {
			kept++
		}
	}
	s := fmt.Sprintf("日志文件 %d 个（过期 %d / 保留 %d），可释放 %s",
		len(p.Items), expired, kept, humanSize(p.FreeSize))
	if n := len(p.Errs); n > 0 {
		s += fmt.Sprintf("，%d 个目标扫描失败", n)
	}
	return s
}

func humanSize(n int64) string {
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

var _ = time.Now // 保持 time 引用（LogFile.Mtime 语义文档化）
