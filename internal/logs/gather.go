package logs

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Runner 远端命令执行器（sshx.Client 满足；测试注入假实现）。
type Runner interface {
	// ExtractLines 在远端抽取文件中 [from,to) 时间窗内的行。
	// 返回抽取内容；文件不存在应返回错误（由实现方保证）。
	ExtractLines(abs string, from, to time.Time) (string, error)
	// ReadTail 远端取文件末尾 n 行（无时间戳文件 fallback）。
	ReadTail(abs string, n int) (string, error)
	// FileSize 远端文件大小。
	FileSize(abs string) (int64, error)
}

// GatherOptions 汇聚选项。
type GatherOptions struct {
	// Window 时间窗：只拉 [now-window, now) 内的日志行。
	Window time.Duration
	// MaxBytes 单文件抽取上限（防失控把 2G catalina.out 全传回来）。达到上限截断并标记 Truncated。
	MaxBytes int64
	// OutDir 本地落地根目录：{OutDir}/{目标名}/{主机}/{文件相对路径}。
	OutDir string
	// ErrorPattern ERROR/Exception 计数正则（nil 用默认）。
	ErrorPattern *regexp.Regexp
	// TailLines 无时间戳文件取末尾行数。0 = 200。
	TailLines int
}

// GatherFile 一个文件的汇聚结果。
type GatherFile struct {
	Target    Target
	Abs       string // 远端绝对路径
	LocalPath string // 本地落地
	Bytes     int64
	Truncated bool
	Errors    int // ERROR/Exception 计数
	NoTS      bool // 文件无标准时间戳（走了 tail fallback）
}

// GatherResult 一次汇聚的总结果。
type GatherResult struct {
	Files []GatherFile
	Errs  []error
	// 汇总：ERROR/Exception 总数（钉钉/终端摘要用）
	TotalErrors int
}

var defaultErrPat = regexp.MustCompile(`ERROR|Exception|OOM|OutOfMemoryError`)

// tsLayouts 常见日志时间戳格式（Java/MySQL/Redis/Nginx）。
var tsLayouts = []string{
	"2006-01-02 15:04:05",  // Java 应用 / MySQL slow / dm
	"2006-01-02 15:04:05.000",
	"2006/01/02 15:04:05",  // nginx error / 部分 Java
	"02/Jan/2006:15:04:05", // nginx access
	"2006-01-02T15:04:05",  // 部分新版框架
}

// tsRe 时间戳形态正则（覆盖 tsLayouts 各格式）：yyyy[-/]MM[-/]dd[ T]HH:mm:ss
var tsRe = regexp.MustCompile(`\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}`)

// tsNginxRe nginx access 格式：02/Nov/2026:08:30:05
var tsNginxRe = regexp.MustCompile(`\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}`)

var nginxMonths = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March,
	"Apr": time.April, "May": time.May, "Jun": time.June,
	"Jul": time.July, "Aug": time.August, "Sep": time.September,
	"Oct": time.October, "Nov": time.November, "Dec": time.December,
}

// LineTime 判断一行日志的时间戳并解析（找不到返回零值）。
// 供 ExtractLines 实现与测试共用：实现方用 shell 时不需要它，本地假实现/校验用。
func LineTime(line string) (time.Time, bool) {
	if m := tsRe.FindString(line); m != "" {
		// 归一化到统一布局（- 分隔 + 空格时分秒）
		norm := strings.Replace(strings.ReplaceAll(m, "/", "-"), "T", " ", 1)
		if ts, err := time.ParseInLocation("2006-01-02 15:04:05", norm, time.Local); err == nil {
			return ts, true
		}
	}
	if m := tsNginxRe.FindString(line); m != "" {
		// 02/Nov/2026:08:30:05
		var d, y, hh, mm, ss int
		var monS string
		if _, err := fmt.Sscanf(m, "%d/%3s/%d:%d:%d:%d", &d, &monS, &y, &hh, &mm, &ss); err == nil {
			if mo, ok := nginxMonths[monS]; ok {
				return time.Date(y, mo, d, hh, mm, ss, 0, time.Local), true
			}
		}
	}
	return time.Time{}, false
}

// BuildAwkScript 生成远端 awk 抽取脚本（时间窗过滤，只传命中段）。
// 逻辑：行首无时间戳 → 跟随上一行归属（堆栈行属于其异常头）；
// 有时间戳 → 落在 [from,to) 才输出，并更新当前归属。
func BuildAwkScript(from, to time.Time) string {
	// awk 用秒级 epoch 比较最稳（mktime 需 GNU awk；现场多为 gawk，CentOS7+ 自带）
	return fmt.Sprintf(`awk -v F=%d -v T=%d '
function mk(ts) { gsub(/[-/T:]/, " ", ts); return mktime(ts) }
{
  line=$0; ts=""
  if (match(line, /[0-9]{4}[-/][0-9]{2}[-/][0-9]{2}[ T][0-9]{2}:[0-9]{2}:[0-9]{2}/)) {
    ts=substr(line, RSTART, RLENGTH)
  }
  if (ts != "") {
    e=mk(ts)
    if (e>=F && e<T) { keep=1 } else { keep=0 }
  }
  if (keep) print line
}'`, from.Unix(), to.Unix())
}

// Gather 对目标列表执行汇聚。只读远端。
// 文件清单由调用方用 syncx.Walk 获取后传 GatherFiles（Runner 接口刻意最小化，
// 避免在 logs 包重复定义远端遍历能力）。
func Gather(r Runner, targets []Target, opt GatherOptions, now time.Time) *GatherResult {
	return &GatherResult{} // 占位：直接用 GatherFiles；保留函数以稳定 API
}

// GatherFiles 对已知的文件清单执行抽取+落盘+计数（Gather 的实质实现）。
func GatherFiles(r Runner, files []LogFile, targets []Target, opt GatherOptions, now time.Time) *GatherResult {
	res := &GatherResult{}
	pat := opt.ErrorPattern
	if pat == nil {
		pat = defaultErrPat
	}
	tailN := opt.TailLines
	if tailN == 0 {
		tailN = 200
	}
	from := now.Add(-opt.Window)

	byTarget := map[string]Target{}
	for _, t := range targets {
		for _, d := range t.LogDirs {
			byTarget[d] = t
		}
	}

	for _, f := range files {
		t := byTarget[f.Dir]
		if t.Name == "" {
			// 调用方没按 Dir 对上目标：跳过（防御，CLI 层不会触发）
			continue
		}
		if !t.Candidate(f) {
			continue // 白名单外（binlog/数据文件）不拉
		}
		gf := GatherFile{Target: t, Abs: f.Abs}

		var content string
		var err error
		noTS := false
		if hasTimestampHeuristic(f.Rel) {
			content, err = r.ExtractLines(f.Abs, from, now)
		} else {
			noTS = true
			content, err = r.ReadTail(f.Abs, tailN)
		}
		if err != nil {
			if os.IsNotExist(err) {
				continue // 文件在扫描与抽取之间被轮转/清理：静默跳过
			}
			res.Errs = append(res.Errs, fmt.Errorf("%s(%s) 抽取 %s: %w", t.Name, t.Host.Host, f.Abs, err))
			continue
		}
		gf.NoTS = noTS
		if opt.MaxBytes > 0 && int64(len(content)) > opt.MaxBytes {
			content = content[:opt.MaxBytes]
			gf.Truncated = true
		}
		gf.Bytes = int64(len(content))
		gf.Errors = len(pat.FindAllString(content, -1))

		// 落地 {OutDir}/{目标}/{主机}/{相对目录树}
		rel := strings.TrimPrefix(f.Abs, strings.TrimSuffix(t.LogDirOf(f.Dir), "/")+"/")
		local := filepath.Join(opt.OutDir, sanitize(t.Name), sanitize(t.Host.Host), filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
			res.Errs = append(res.Errs, fmt.Errorf("创建本地目录 %s: %w", local, err))
			continue
		}
		if err := os.WriteFile(local, []byte(content), 0o644); err != nil {
			res.Errs = append(res.Errs, fmt.Errorf("写入 %s: %w", local, err))
			continue
		}
		gf.LocalPath = local
		res.Files = append(res.Files, gf)
		res.TotalErrors += gf.Errors
	}
	sort.Slice(res.Files, func(i, j int) bool {
		if res.Files[i].Target.Name != res.Files[j].Target.Name {
			return res.Files[i].Target.Name < res.Files[j].Target.Name
		}
		return res.Files[i].Abs < res.Files[j].Abs
	})
	return res
}

// LogDirOf 返回目标中包含 dir 的日志目录（gather 落地路径推导用）。
func (t Target) LogDirOf(dir string) string {
	for _, d := range t.LogDirs {
		if d == dir {
			return d
		}
	}
	return ""
}

// hasTimestampHeuristic 按文件名猜是否有时间戳：catalina.out 等无时间戳走 tail。
var noTimestampFiles = map[string]bool{
	"catalina.out": true,
	"catalina.log": false,
}

func hasTimestampHeuristic(rel string) bool {
	base := rel
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if noTS, ok := noTimestampFiles[base]; ok {
		return !noTS // catalina.out → false（走 tail）
	}
	return true
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '_'
		}
	}, s)
}

// Summarize 汇聚摘要（终端）。
func (g *GatherResult) Summarize() string {
	s := fmt.Sprintf("拉取 %d 个日志文件，ERROR/Exception 命中 %d 处", len(g.Files), g.TotalErrors)
	if n := len(g.Errs); n > 0 {
		s += fmt.Sprintf("，%d 个失败", n)
	}
	return s
}

// TopErrors 按文件列 ERROR 计数 TOP（终端摘要不打明细，宪法 4）。
func (g *GatherResult) TopErrors(n int) []string {
	type kv struct {
		name string
		cnt  int
	}
	var kvs []kv
	for _, f := range g.Files {
		if f.Errors > 0 {
			kvs = append(kvs, kv{f.Target.Name + "@" + f.Target.Host.Host + " " + filepath.Base(f.Abs), f.Errors})
		}
	}
	sort.Slice(kvs, func(i, j int) bool { return kvs[i].cnt > kvs[j].cnt })
	if len(kvs) > n {
		kvs = kvs[:n]
	}
	var out []string
	for _, k := range kvs {
		out = append(out, fmt.Sprintf("  %s: %d", k.name, k.cnt))
	}
	return out
}
