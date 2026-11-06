package inspect

// OS / 基础资源检查：系统信息、负载、内存、磁盘、inode、时间同步。
// 全部只读命令；解析逻辑是纯函数，单测覆盖。

import (
	"fmt"
	"strconv"
	"strings"
)

func init() {
	register(Check{
		Name: "os-info", Dimension: DimOS,
		Description: "操作系统 / 内核 / 运行时长（基础信息）",
		Command: func(Env) (string, error) {
			return `(. /etc/os-release 2>/dev/null; printf '%s\n' "${PRETTY_NAME:-unknown}"); uname -r; uptime -p 2>/dev/null || uptime`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			lines := nonEmptyLines(out)
			if len(lines) < 2 {
				return nil, nil, fmt.Errorf("输出不足: %q", strings.TrimSpace(out))
			}
			ms := []Metric{
				{Name: "os", Value: lines[0]},
				{Name: "kernel", Value: lines[1]},
			}
			if len(lines) > 2 {
				ms = append(ms, Metric{Name: "uptime", Value: strings.TrimPrefix(lines[2], "up ")})
			}
			return ms, nil, nil
		},
	})

	register(Check{
		Name: "load", Dimension: DimOS,
		Description: "1/5/15 分钟负载，按 CPU 核数归一（>1.5 预警，>3 严重）",
		Command: func(Env) (string, error) {
			return `awk '{print $1" "$2" "$3}' /proc/loadavg 2>/dev/null; nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			loads, cpus, err := parseLoad(out)
			if err != nil {
				return nil, nil, err
			}
			ms := []Metric{
				{Name: "load1", Value: fmt.Sprintf("%.2f", loads[0])},
				{Name: "load5", Value: fmt.Sprintf("%.2f", loads[1])},
				{Name: "load15", Value: fmt.Sprintf("%.2f", loads[2])},
				{Name: "cpus", Value: strconv.Itoa(cpus)},
			}
			var fs []Finding
			ratio := loads[0] / float64(cpus)
			switch {
			case ratio > 3:
				fs = append(fs, Finding{Severity: SevError, Metric: "load1/cpus",
					Value: fmt.Sprintf("%.2f", ratio), Threshold: ">3",
					Message: fmt.Sprintf("1 分钟负载 %.2f / %d 核 = %.2f，已显著过载", loads[0], cpus, ratio)})
			case ratio > 1.5:
				fs = append(fs, Finding{Severity: SevWarn, Metric: "load1/cpus",
					Value: fmt.Sprintf("%.2f", ratio), Threshold: ">1.5",
					Message: fmt.Sprintf("1 分钟负载 %.2f / %d 核 = %.2f，偏高", loads[0], cpus, ratio)})
			}
			return ms, fs, nil
		},
	})

	register(Check{
		Name: "memory", Dimension: DimOS,
		Description: "内存使用率（>90% 预警，>97% 严重）",
		Command:     func(Env) (string, error) { return `free -m 2>/dev/null`, nil },
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			total, used, avail, err := parseFreeM(out)
			if err != nil {
				return nil, nil, err
			}
			pct := float64(used) / float64(total) * 100
			ms := []Metric{
				{Name: "mem_total_mb", Value: strconv.FormatInt(total, 10), Unit: "MB"},
				{Name: "mem_used_mb", Value: strconv.FormatInt(used, 10), Unit: "MB"},
				{Name: "mem_available_mb", Value: strconv.FormatInt(avail, 10), Unit: "MB"},
				{Name: "mem_used_pct", Value: fmt.Sprintf("%.1f", pct), Unit: "%"},
			}
			var fs []Finding
			switch {
			case pct > 97:
				fs = append(fs, Finding{Severity: SevCritical, Metric: "mem_used_pct",
					Value: fmt.Sprintf("%.1f%%", pct), Threshold: ">97%",
					Message: fmt.Sprintf("内存使用率 %.1f%%（可用 %dMB），随时可能 OOM", pct, avail)})
			case pct > 90:
				fs = append(fs, Finding{Severity: SevWarn, Metric: "mem_used_pct",
					Value: fmt.Sprintf("%.1f%%", pct), Threshold: ">90%",
					Message: fmt.Sprintf("内存使用率 %.1f%%（可用 %dMB），偏高", pct, avail)})
			}
			return ms, fs, nil
		},
	})

	register(Check{
		Name: "disk", Dimension: DimOS,
		Description: "磁盘使用率（>=85% 预警，>=95% 紧急），只统计本地文件系统",
		Command: func(Env) (string, error) {
			return `df -P -l -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			rows, err := parseDf(out)
			if err != nil {
				return nil, nil, err
			}
			var ms []Metric
			var fs []Finding
			for _, r := range rows {
				ms = append(ms, Metric{Name: "disk_use_pct", Value: fmt.Sprintf("%.0f", r.Pct), Unit: "%"},
					Metric{Name: "disk_mount", Value: r.Mount})
				switch {
				case r.Pct >= 95:
					fs = append(fs, Finding{Severity: SevCritical, Metric: "disk_use_pct",
						Value: fmt.Sprintf("%.0f%% %s", r.Pct, r.Mount), Threshold: ">=95%",
						Message: fmt.Sprintf("挂载点 %s 使用率 %.0f%%（%s 可用 %s）", r.Mount, r.Pct, r.Size, r.Avail)})
				case r.Pct >= 85:
					fs = append(fs, Finding{Severity: SevWarn, Metric: "disk_use_pct",
						Value: fmt.Sprintf("%.0f%% %s", r.Pct, r.Mount), Threshold: ">=85%",
						Message: fmt.Sprintf("挂载点 %s 使用率 %.0f%%（可用 %s），需关注", r.Mount, r.Pct, r.Avail)})
				}
			}
			return ms, fs, nil
		},
	})

	register(Check{
		Name: "inode", Dimension: DimOS,
		Description: "inode 使用率（>=85% 预警，>=95% 紧急）",
		Command: func(Env) (string, error) {
			return `df -Pi -l -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			rows, err := parseDf(out)
			if err != nil {
				return nil, nil, err
			}
			var ms []Metric
			var fs []Finding
			for _, r := range rows {
				ms = append(ms, Metric{Name: "inode_use_pct", Value: fmt.Sprintf("%.0f", r.Pct), Unit: "%"},
					Metric{Name: "inode_mount", Value: r.Mount})
				switch {
				case r.Pct >= 95:
					fs = append(fs, Finding{Severity: SevCritical, Metric: "inode_use_pct",
						Value: fmt.Sprintf("%.0f%% %s", r.Pct, r.Mount), Threshold: ">=95%",
						Message: fmt.Sprintf("挂载点 %s inode 使用率 %.0f%%，新建文件可能失败", r.Mount, r.Pct)})
				case r.Pct >= 85:
					fs = append(fs, Finding{Severity: SevWarn, Metric: "inode_use_pct",
						Value: fmt.Sprintf("%.0f%% %s", r.Pct, r.Mount), Threshold: ">=85%",
						Message: fmt.Sprintf("挂载点 %s inode 使用率 %.0f%%，需关注", r.Mount, r.Pct)})
				}
			}
			return ms, fs, nil
		},
	})

	register(Check{
		Name: "timesync", Dimension: DimOS,
		Description: "时间同步状态（未同步会导致日志/集群/证书判断异常）",
		Command: func(Env) (string, error) {
			return `timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			v := strings.TrimSpace(out)
			ms := []Metric{{Name: "ntp_synchronized", Value: v}}
			if v == "no" {
				return ms, []Finding{{Severity: SevWarn, Metric: "ntp_synchronized", Value: v,
					Message: "系统时间未同步（timedatectl NTPSynchronized=no），请检查 chronyd/ntpd"}}, nil
			}
			return ms, nil, nil
		},
	})
}

// nonEmptyLines 去空行。
func nonEmptyLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if t := strings.TrimRight(ln, "\r"); strings.TrimSpace(t) != "" {
			out = append(out, strings.TrimSpace(t))
		}
	}
	return out
}

// parseLoad 解析 "l1 l5 l15" + nproc 两行输出。
func parseLoad(out string) ([3]float64, int, error) {
	var loads [3]float64
	lines := nonEmptyLines(out)
	if len(lines) < 2 {
		return loads, 0, fmt.Errorf("负载输出不足: %q", out)
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 3 {
		return loads, 0, fmt.Errorf("负载行格式异常: %q", lines[0])
	}
	for i := 0; i < 3; i++ {
		v, err := strconv.ParseFloat(parts[i], 64)
		if err != nil {
			return loads, 0, fmt.Errorf("负载值非法 %q: %v", parts[i], err)
		}
		loads[i] = v
	}
	cpus, err := strconv.Atoi(strings.TrimSpace(lines[1]))
	if err != nil || cpus <= 0 {
		return loads, 0, fmt.Errorf("CPU 核数非法: %q", lines[1])
	}
	return loads, cpus, nil
}

// parseFreeM 解析 free -m 的 Mem 行，返回 total/used/available（MB）。
func parseFreeM(out string) (total, used, avail int64, err error) {
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) >= 7 && strings.HasPrefix(f[0], "Mem") {
			total, e1 := strconv.ParseInt(f[1], 10, 64)
			used, e2 := strconv.ParseInt(f[2], 10, 64)
			avail, e3 := strconv.ParseInt(f[6], 10, 64)
			if e1 != nil || e2 != nil || e3 != nil || total <= 0 {
				return 0, 0, 0, fmt.Errorf("free 行解析失败: %q", ln)
			}
			return total, used, avail, nil
		}
	}
	return 0, 0, 0, fmt.Errorf("未找到 Mem 行: %q", out)
}

// dfRow df -P 的一行。
type dfRow struct {
	FS, Size, Avail, Mount string
	Pct                    float64
}

// parseDf 解析 df -P 输出（跳过表头）。
func parseDf(out string) ([]dfRow, error) {
	var rows []dfRow
	for i, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 6 || i == 0 || strings.HasPrefix(f[0], "Filesystem") {
			continue
		}
		pctStr := strings.TrimSuffix(f[4], "%")
		pct, err := strconv.ParseFloat(pctStr, 64)
		if err != nil {
			continue
		}
		rows = append(rows, dfRow{FS: f[0], Size: f[1], Avail: f[3], Pct: pct, Mount: f[5]})
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("df 输出无有效行: %q", strings.TrimSpace(out))
	}
	return rows, nil
}
