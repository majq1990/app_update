package backup

// 台账（ledger）：把现场已有备份导出成结构化清单，供上层推送项目管理
// （ztoa「项目备份中间表」）。工具自己不联网——只产出 JSON，推送由外部决定。

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// LedgerEntry 一份备份的台账行。
type LedgerEntry struct {
	Host      string `json:"host"`
	Target    string `json:"target"`
	Kind      string `json:"kind"`
	File      string `json:"file"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256,omitempty"`
	CreatedAt string `json:"created_at"` // RFC3339（远端 mtime）
	Verified  bool   `json:"verified"`
	Note      string `json:"note,omitempty"`
}

// Ledger 一次台账导出。
type Ledger struct {
	GeneratedAt string        `json:"generated_at"`
	Root        string        `json:"root"`
	KeepDays    int           `json:"keep_days"`
	Entries     []LedgerEntry `json:"entries"`
}

// BuildLedger 由现场文件清单（+ 可选校验结果）生成台账。
// targets 用于把文件名反查回应用/主机；反查不到的行保留，Kind 标 unknown。
func BuildLedger(root string, keepDays int, targets []Target, files []StoredFile,
	verified map[string]VerifyResult, now time.Time) Ledger {

	prefixes := make([]struct {
		prefix string
		t      Target
	}, 0, len(targets))
	for _, t := range targets {
		prefixes = append(prefixes, struct {
			prefix string
			t      Target
		}{prefix: TargetPrefix(t), t: t})
	}
	// 长前缀优先，避免 eops-mysql-... 误配 eops-mysql-xxx
	sort.Slice(prefixes, func(i, j int) bool { return len(prefixes[i].prefix) > len(prefixes[j].prefix) })

	led := Ledger{
		GeneratedAt: now.Format(time.RFC3339),
		Root:        root,
		KeepDays:    keepDays,
		Entries:     make([]LedgerEntry, 0, len(files)),
	}
	for _, f := range files {
		base := path.Base(f.Path)
		e := LedgerEntry{
			File:      f.Path,
			Bytes:     f.Bytes,
			CreatedAt: f.ModTime.Format(time.RFC3339),
			Kind:      "unknown",
		}
		for _, p := range prefixes {
			if strings.HasPrefix(base, p.prefix) {
				e.Target = p.t.Name
				e.Kind = string(p.t.Kind)
				e.Host = p.t.Host.Host
				break
			}
		}
		if v, ok := verified[f.Path]; ok {
			e.SHA256 = v.SHA256
			e.Verified = v.OK
			if !v.OK {
				e.Note = v.Err
			}
		}
		led.Entries = append(led.Entries, e)
	}
	sort.Slice(led.Entries, func(i, j int) bool {
		a, b := led.Entries[i], led.Entries[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.File < b.File
	})
	return led
}

// JSON 序列化（两空格缩进，便于人工核对与 diff）。
func (l Ledger) JSON() ([]byte, error) {
	return json.MarshalIndent(l, "", "  ")
}

// Summary 一行摘要：条目数 / 总量 / 未校验数。
func (l Ledger) Summary() string {
	var total int64
	unverified := 0
	for _, e := range l.Entries {
		total += e.Bytes
		if !e.Verified {
			unverified++
		}
	}
	return fmtSummary(len(l.Entries), total, unverified)
}

// fmtSummary 台账摘要文案（与 CLI 输出口径一致）。
func fmtSummary(n int, total int64, unverified int) string {
	s := fmt.Sprintf("共 %d 份备份，合计 %s", n, HumanBytes(total))
	if unverified > 0 {
		s += fmt.Sprintf("；其中 %d 份未校验", unverified)
	}
	return s
}

// HumanBytes 字节数人类可读。
func HumanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
