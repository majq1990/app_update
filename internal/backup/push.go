package backup

// ztoa「项目备份中间表」payload 生成（backup push）。
//
// 工具只读现场台账、只产出 JSON，不联网：真实写行由上层用 ztoa MCP 执行。
// controlId 与 worksheet 6878e909d26faff4cc8c2c3e 的 schema 一一对应，
// 备份日期/间隔由台账里应用域（kind=app）与数据库域（kind=mysql/dm）的最新 ModTime 计算。

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// 项目备份中间表 controlId（实测自 ztoa schema，改动前先核对线上表结构）。
const (
	ControlProjectName     = "684f91a7f33e0e5bcbb7776e" // 项目名称（文本）
	ControlRegion          = "6837b6c74e6432720b9f0cfc" // 所属大区
	ControlArea            = "6837b6c74e6432720b9f0cfd" // 所属区域
	ControlProjectManager  = "683872f1996564259bd55789" // 项目经理（成员）
	ControlProvinceChief   = "683872f1996564259bd5578a" // 省份工程总（成员）
	ControlRegionChief     = "683872f1996564259bd5578b" // 大区工程总（成员）
	ControlProjectLevel    = "6837d4404e6432720b9f179a" // 项目定级
	ControlProjectStatus   = "6837d4404e6432720b9f179b" // 项目状态
	ControlAppBackupDate   = "68523870f33e0e5bcbb7c3f6" // 应用备份最新上传日期（日期）
	ControlAppBackupGap    = "68523902f33e0e5bcbb7c417" // 应用备份上传间隔（数值·天）
	ControlDBBackupDate    = "687a18add26faff4cc8c4ff7" // 数据库备份最新上传日期（日期）
	ControlDBBackupGap     = "687a18add26faff4cc8c4ff8" // 数据库备份上传间隔（数值·天）
	ControlDeliveryProject = "684a7cb2513516d8a4c922a7" // 交付项目（关联）
)

// Control 一条控件值（明道云写行格式）。
type Control struct {
	ControlID string `json:"controlId"`
	Value     string `json:"value"`
}

// PushPayload 一行写表 payload。
type PushPayload struct {
	Controls []Control `json:"controls"`
}

// PushMeta 台账之外的字段：工具自己拿不到，默认留空由人工/上层补。
type PushMeta struct {
	ProjectName     string
	Region          string
	Area            string
	ProjectManager  string
	ProvinceChief   string
	RegionChief     string
	ProjectLevel    string
	ProjectStatus   string
	DeliveryProject string
}

// BuildPushPayload 由现场台账生成 ztoa 行 payload。
// 有备份的域写「最新上传日期 + 间隔天数」，无备份的域整组省略。
func BuildPushPayload(led Ledger, meta PushMeta, now time.Time) (PushPayload, error) {
	var latestApp, latestDB time.Time
	var hasApp, hasDB bool
	for _, e := range led.Entries {
		t, err := time.Parse(time.RFC3339, e.CreatedAt)
		if err != nil {
			continue
		}
		switch Kind(e.Kind) {
		case KindApp:
			if !hasApp || t.After(latestApp) {
				latestApp, hasApp = t, true
			}
		case KindMySQL, KindDM:
			if !hasDB || t.After(latestDB) {
				latestDB, hasDB = t, true
			}
		}
	}

	p := PushPayload{Controls: make([]Control, 0, 13)}
	// 只写非空值：空字符串写进 ztoa 会覆盖已有字段（实弹教训），宁可省略
	add := func(id, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		p.Controls = append(p.Controls, Control{ControlID: id, Value: value})
	}

	add(ControlProjectName, meta.ProjectName)
	add(ControlRegion, meta.Region)
	add(ControlArea, meta.Area)
	add(ControlProjectManager, meta.ProjectManager)
	add(ControlProvinceChief, meta.ProvinceChief)
	add(ControlRegionChief, meta.RegionChief)
	add(ControlProjectLevel, meta.ProjectLevel)
	add(ControlProjectStatus, meta.ProjectStatus)
	if hasApp {
		add(ControlAppBackupDate, latestApp.Format("2006-01-02"))
		add(ControlAppBackupGap, strconv.Itoa(daysBetween(latestApp, now)))
	}
	if hasDB {
		add(ControlDBBackupDate, latestDB.Format("2006-01-02"))
		add(ControlDBBackupGap, strconv.Itoa(daysBetween(latestDB, now)))
	}
	add(ControlDeliveryProject, meta.DeliveryProject)
	return p, nil
}

// daysBetween 按自然日计算 now 与 earlier 的间隔天数（忽略时分秒）。
func daysBetween(earlier, now time.Time) int {
	loc := now.Location()
	e := earlier.In(loc)
	n := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	start := time.Date(e.Year(), e.Month(), e.Day(), 0, 0, 0, 0, loc)
	return int(n.Sub(start).Hours() / 24)
}

// JSON 序列化（两空格缩进，便于人工核对与 diff）。
func (p PushPayload) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("payload 序列化失败: %w", err)
	}
	return b, nil
}
