package logs

// rotate check：日志切割检查（只读）。
// 检查项（对齐规划 §3.2）：
//  1. /etc/logrotate.d/ 是否有该目标条目；
//  2. 日志目录下最大未切割文件是否超阈值（默认 1G，catalina.out 高发）；
//  3. 已有 logrotate 配置语法是否正确（远端 logrotate -d 干跑）；
//  4. 近 7 天日志目录增长率（按 mtime 统计新写入量，估算"如果不切割会怎样"）。
// 输出问题清单分 高/中/低；纯只读，不改任何远端状态。

import (
	"fmt"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/syncx"
)

// RotateCheckResult 单个目标的切割检查结果。
type RotateCheckResult struct {
	Target  Target
	Findings []Finding
}

// Finding 一条检查发现。
type Finding struct {
	Severity string // high | medium | low | info
	Msg      string
}

// Rotater 远端探测能力（sshx.Client 满足；测试注入假实现）。
type Rotater interface {
	// TestFile 远端路径是否存在。
	TestFile(path string) bool
	// ReadFile 远端小文件读取（logrotate 片段）。
	ReadFile(path string) (string, error)
	// Run 远端命令（logrotate -d 语法干跑等）。
	Run(cmd string) (string, error)
}

// RotateCheckOptions 检查阈值。
type RotateCheckOptions struct {
	// BigFileBytes 单文件告警阈值。0 = 1GiB。
	BigFileBytes int64
	// GrowthDays 增长统计窗口天数。0 = 7。
	GrowthDays int
	// Now 时间注入（测试）。零值 = time.Now()。
	Now time.Time
}

// RotateFragmentName 目标对应的 logrotate 片段文件名（/etc/logrotate.d/ 下）。
// 应用用应用名；支持软件用 kind——保持现场运维已有的命名直觉。
func RotateFragmentName(t Target) string {
	base := t.Name
	if t.Kind == KindSupport {
		base = t.KindRaw
	}
	return sanitize(base)
}

// RunRotateCheck 对一个目标执行全部检查项。
func RunRotateCheck(rt Rotater, t Target, files []LogFile, opt RotateCheckOptions) RotateCheckResult {
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	big := opt.BigFileBytes
	if big == 0 {
		big = 1 << 30
	}
	growthDays := opt.GrowthDays
	if growthDays == 0 {
		growthDays = 7
	}

	res := RotateCheckResult{Target: t}
	frag := "/etc/logrotate.d/" + RotateFragmentName(t)

	// ---- 1. 片段存在性 ----
	hasFrag := rt.TestFile(frag)
	if !hasFrag {
		// 应用日志目录为空的目标不算问题（没有可切割的东西）
		if len(t.LogDirs) > 0 && hasAnyLog(files, t) {
			res.Findings = append(res.Findings, Finding{"high",
				fmt.Sprintf("无 logrotate 配置（缺 %s），日志只增不切", frag)})
		}
	} else {
		res.Findings = append(res.Findings, Finding{"info",
			fmt.Sprintf("已有 logrotate 配置 %s", frag)})

		// ---- 3. 语法干跑（有片段才检查）----
		out, err := rt.Run("logrotate -d " + frag + " 2>&1")
		if err == nil && isLogrotateError(out) {
			res.Findings = append(res.Findings, Finding{"high",
				fmt.Sprintf("logrotate 配置语法错误: %s", firstErrLine(out))})
		}
		// logrotate -d 输出 error 字样即配置问题；正常情况输出状态行

		// 片段内容里没有覆盖到目标日志目录 → 配置漂移
		if body, rerr := rt.ReadFile(frag); rerr == nil {
			for _, d := range t.LogDirs {
				if !strings.Contains(body, d) {
					res.Findings = append(res.Findings, Finding{"medium",
						fmt.Sprintf("logrotate 配置未覆盖日志目录 %s（配置漂移）", d)})
				}
			}
		}
	}

	// ---- 2. 大文件未切割 ----
	for _, f := range files {
		if f.IsDir || !t.Candidate(f) {
			continue
		}
		if f.Size >= big {
			res.Findings = append(res.Findings, Finding{"high",
				fmt.Sprintf("未切割大文件 %s（%s）超过阈值 %s",
					f.Rel, humanSize(f.Size), humanSize(big))})
		} else if f.Size >= big/10 {
			res.Findings = append(res.Findings, Finding{"low",
				fmt.Sprintf("大文件预警 %s（%s）已达阈值 1/10", f.Rel, humanSize(f.Size))})
		}
	}

	// ---- 4. 近 N 天增长率 ----
	var grown int64
	for _, f := range files {
		if f.IsDir {
			continue
		}
		if now.Sub(f.Mtime) <= time.Duration(growthDays)*24*time.Hour {
			grown += f.Size
		}
	}
	if grown > 0 {
		perDay := int64(float64(grown) / float64(growthDays))
		if perDay >= big/30 { // 按当前增速 ~30 天就会顶到 1G
			res.Findings = append(res.Findings, Finding{"medium",
				fmt.Sprintf("近 %d 天新增 %s（约 %s/天），无切割约 %d 天后超阈值",
					growthDays, humanSize(grown), humanSize(perDay), 30)})
		}
	}
	return res
}

// hasAnyLog 文件清单里是否有该目标的日志类文件。
func hasAnyLog(files []LogFile, t Target) bool {
	for _, f := range files {
		if t.Candidate(f) {
			return true
		}
	}
	return false
}

func isLogrotateError(out string) bool {
	return strings.Contains(strings.ToLower(out), "error")
}

func firstErrLine(out string) string {
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(strings.ToLower(ln), "error") {
			return strings.TrimSpace(ln)
		}
	}
	return ""
}

// ---- rotate setup：生成片段内容（推送由 CLI 层走 syncx/sshx）----

// RotateTemplate 按目标类型生成 logrotate 片段内容。
// 语义（对齐规划）：copytruncate 适配 tomcat/jar 进程持续持有文件句柄的场景
// （rename 后进程继续写老 inode 是现场大坑）；不 postrotate 重启；
// 周期 weekly + 保留 8（约 2 个月）；不 compress（gzip 老日志现场普遍没配，先保守）。
func RotateTemplate(t Target) string {
	base := RotateFragmentName(t)
	var dirs []string
	for _, d := range t.LogDirs {
		dirs = append(dirs, strings.TrimSuffix(d, "/")+"/*.log")
		// 应用目录普遍有 .out（catalina.out）；nginx 是 access/error.log 已被 *.log 覆盖
		if t.KindRaw == "tomcat" {
			dirs = append(dirs, strings.TrimSuffix(d, "/")+"/*.out")
		}
	}
	body := strings.Join(dirs, "\n")
	return fmt.Sprintf(`# eops 日志切割（%s：%s@%s 生成；工具可回放 diff）
%s {
    weekly
    rotate 8
    missingok
    notifempty
    copytruncate
    dateext
}
`, base, t.Name, t.Host.Host, body)
}

var _ = syncx.Entry{} // 保持包引用文档化（Walk 来源在 CLI 层）
