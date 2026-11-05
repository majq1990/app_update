// Package logs 实现「日志运维」：目标归一（应用 + 支持软件）、
// 清理（clean）与汇聚（gather）。
// 应用目标复用 config.App 的 log_dir 约定；支持软件目标走 config.Supports 段。
// 所有变更操作（clean）遵循工具宪法：DryRun 默认、--yes 才执行、白名单外不动。
package logs

import (
	"path"
	"sort"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/syncx"
)

// Kind 目标类别：应用 或 支持软件。
type Kind string

const (
	KindApp     Kind = "app"
	KindSupport Kind = "support"
)

// Target 一个可执行日志运维的主机级目标（应用单主机 / 支持软件单主机）。
// 应用与支持软件在此归一：后续 clean/gather 只面对 Target，不再区分来源。
type Target struct {
	Kind     Kind
	Name     string   // 应用名 / 支持软件名（显示用）
	KindRaw  string   // 支持软件原始 kind（app 时为 middle_type）
	Host     config.Host
	LogDirs  []string // 绝对路径（应用 = web_path + log_dir 展开；支持软件 = log_dirs）
	KeepDays int      // 日志保留天数（app=全局，support=段内覆盖后）
	// CleanExclude clean 时额外排除（rsync 风格）。应用默认含 global_exclude_logs；
	// 支持软件默认为空 + 段内 exclude_patterns。
	CleanExclude []string
}

// Targets 从配置展开全部目标。
func Targets(c *config.Config) []Target {
	var out []Target
	for i := range c.Webs {
		app := &c.Webs[i]
		hostSet := map[string]bool{}
		for _, group := range []string{config.GroupMaster, config.GroupUpdate, config.GroupStatic} {
			for _, h := range app.GroupHosts(group) {
				if h.Host == "" || hostSet[h.Host] {
					continue // 同应用跨群组同主机只出一个目标
				}
				hostSet[h.Host] = true
				var dirs []string
				if ld := strings.TrimSpace(app.LogDir); ld != "" {
					// log_dir 是相对 web_path 的约定（validate 已保证相对路径）
					dirs = append(dirs, path.Join(h.WebPath, ld))
				}
				// 注意：这里不把 global_exclude_logs 传给 CleanExclude——
				// 其中 "logs/" 这类目录子树模式在 syncx 匹配语义下会排除整个日志目录自身，
				// clean 就无事可做了。global_exclude_logs 是给「更新同步」用的排除表，
				// clean 的安全由白名单（Candidate）保证，不需要再叠加应用层排除。
				out = append(out, Target{
					Kind: KindApp, Name: app.Web, KindRaw: app.MiddleType,
					Host: h, LogDirs: dirs, KeepDays: c.LogKeepDays,
				})
			}
		}
	}
	for i := range c.Supports {
		s := &c.Supports[i]
		for _, h := range s.Hosts {
			if h.Host == "" {
				continue
			}
			out = append(out, Target{
				Kind: KindSupport, Name: s.Name, KindRaw: s.Kind,
				Host: h, LogDirs: append([]string{}, s.LogDirs...),
				KeepDays: s.KeepDays,
				CleanExclude: append([]string{}, s.ExcludePatterns...),
			})
		}
	}
	return out
}

// LogFile clean/gather 扫描到的一个日志文件。
type LogFile struct {
	Abs      string    // 远端绝对路径
	Dir      string    // 所属 LogDirs 项
	Rel      string    // 相对 Dir（用于匹配与显示）
	Size     int64
	Mtime    time.Time
	IsDir    bool
}

// cleanPatternsFor 按目标类别返回「只删日志模式」白名单。
// 应用日志目录：*.log *.out 及轮转归档；支持软件按 kind 约定扩展。
// 覆盖《信创第三方软件拉包打包矩阵》日志型软件的文件名形态。
func cleanPatternsFor(t Target) []string {
	pats := []string{"*.log", "*.log.[0-9]*", "*.log-20*", "*.out", "*.out.[0-9]*", "*.gz", "*.xz", "*.zip"}
	switch t.KindRaw {
	case "mysql", "mysql_log", "percona", "mydumper":
		// mysql data 目录：错误日志与慢日志；binlog 默认不删（DBA 域，需显式加 pattern）
		pats = append(pats, "*.err", "*slow.log", "mysql-slow*.log", "slowquery*.log", "mysqld.log*")
	case "dm":
		// 达梦 log 目录：dm_*.log 与归档
		pats = append(pats, "dm_*.log", "DMSERVER*.log")
	case "redis", "redis_log":
		// redis 通常单文件 + 手动轮转
		pats = append(pats, "redis*.log*")
	case "nginx", "nginx_log", "openresty":
		pats = append(pats, "access.log*", "error.log*", "host.access.*")
	case "postgres":
		// pg_log：postgresql-*.log；WAL/数据文件白名单外不碰
		pats = append(pats, "postgresql-*.log*", "pg_log/*.log")
	case "kafka":
		// kafka log_path 下：server/controller/state-change/request 等 .log 与 .log.[0-9] 滚动（已被基础 *.log 覆盖）
		pats = append(pats, "kafka-request.log*", "kafka-authorizer.log*")
	case "elasticsearch":
		pats = append(pats, "*_server.json", "*_index_indexing_slowlog.json", "*_search_slowlog.json",
			"gc.log*", "*.json.[0-9]*")
	case "zookeeper":
		pats = append(pats, "zookeeper-*.log*", "transaction.log*")
	case "tdengine", "tdengine3":
		// taosdlog.0 按序滚动；目录里还有 taosdump 等临时文件不碰
		pats = append(pats, "taosdlog.[0-9]*", "taosdlog", "*.log.[0-9]*")
	case "nacos":
		pats = append(pats, "nacos.log*", "alipay-jraft.log*", "rotated-*.log*")
	case "minio":
		pats = append(pats, "minio*.log*")
	case "docker":
		// json-file 驱动：containers/<id>/<id>-json.log
		pats = append(pats, "*-json.log*")
	case "proxysql":
		pats = append(pats, "proxysql.log*")
	case "cetus":
		pats = append(pats, "cetus*.log*")
	case "onlyoffice":
		pats = append(pats, "*.out", "converterout.log*", "docservice.out*")
	}
	return pats
}

// Candidate 返回 e 是否为 t 的可清理候选（白名单命中且未被排除）。
// 白名单模式集是唯一删除入口：白名单外一律不动（工具宪法 3）。
func (t Target) Candidate(e LogFile) bool {
	if e.IsDir {
		return false
	}
	if !syncx.MatchPatterns(e.Rel, false, cleanPatternsFor(t)) {
		return false
	}
	if syncx.MatchPatterns(e.Rel, false, t.CleanExclude) {
		return false
	}
	return true
}

// Expired 按 t.KeepDays 判定文件是否过期（mtime 距 now 超过天数）。
func (t Target) Expired(e LogFile, now time.Time) bool {
	return now.Sub(e.Mtime) > time.Duration(t.KeepDays)*24*time.Hour
}

// PlanItem clean 计划的一行。
type PlanItem struct {
	Target  Target
	File    LogFile
	Expired bool // 过期将删；未过期仅统计（clean 输出清单时标注保留）
}

// Plan clean 计划：先扫描全部目标生成，DryRun 直接展示，--yes 才执行。
type Plan struct {
	Items       []PlanItem
	TotalSize   int64 // 过期文件可释放空间
	FreeSize    int64
	Errs        []error // 扫描错误（目录不存在等，不阻断其他目标）
}

// Sort 计划按 目标名→主机→路径 排序，输出稳定。
func (p *Plan) Sort() {
	sort.Slice(p.Items, func(i, j int) bool {
		a, b := p.Items[i], p.Items[j]
		if a.Target.Name != b.Target.Name {
			return a.Target.Name < b.Target.Name
		}
		if a.Target.Host.Host != b.Target.Host.Host {
			return a.Target.Host.Host < b.Target.Host.Host
		}
		return a.File.Abs < b.File.Abs
	})
}
