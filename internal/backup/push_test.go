package backup

import (
	"encoding/json"
	"testing"
	"time"
)

func pushLedger(entries ...LedgerEntry) Ledger {
	return Ledger{Entries: entries}
}

func pushEntry(kind string, t time.Time) LedgerEntry {
	return LedgerEntry{Kind: kind, CreatedAt: t.Format(time.RFC3339)}
}

func controlMap(p PushPayload) map[string]string {
	m := make(map[string]string, len(p.Controls))
	for _, c := range p.Controls {
		m[c.ControlID] = c.Value
	}
	return m
}

func TestPushControlIDsMatchHandoff(t *testing.T) {
	want := map[string]string{
		ControlProjectName:     "684f91a7f33e0e5bcbb7776e",
		ControlRegion:          "6837b6c74e6432720b9f0cfc",
		ControlArea:            "6837b6c74e6432720b9f0cfd",
		ControlProjectManager:  "683872f1996564259bd55789",
		ControlProvinceChief:   "683872f1996564259bd5578a",
		ControlRegionChief:     "683872f1996564259bd5578b",
		ControlProjectLevel:    "6837d4404e6432720b9f179a",
		ControlProjectStatus:   "6837d4404e6432720b9f179b",
		ControlAppBackupDate:   "68523870f33e0e5bcbb7c3f6",
		ControlAppBackupGap:    "68523902f33e0e5bcbb7c417",
		ControlDBBackupDate:    "687a18add26faff4cc8c4ff7",
		ControlDBBackupGap:     "687a18add26faff4cc8c4ff8",
		ControlDeliveryProject: "684a7cb2513516d8a4c922a7",
	}
	got := []string{
		ControlProjectName, ControlRegion, ControlArea,
		ControlProjectManager, ControlProvinceChief, ControlRegionChief,
		ControlProjectLevel, ControlProjectStatus,
		ControlAppBackupDate, ControlAppBackupGap,
		ControlDBBackupDate, ControlDBBackupGap,
		ControlDeliveryProject,
	}
	for _, id := range got {
		if want[id] != id {
			t.Errorf("controlId %q 与 HANDOFF 不一致", id)
		}
	}
}

func TestBuildPushPayloadAppOnly(t *testing.T) {
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	led := pushLedger(
		pushEntry("app", time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC)),
		pushEntry("app", time.Date(2026, 11, 6, 23, 30, 0, 0, time.UTC)),
		pushEntry("dir", time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)),
		pushEntry("unknown", time.Date(2026, 11, 7, 9, 30, 0, 0, time.UTC)),
	)
	meta := PushMeta{
		ProjectName:    "某市城管项目",
		Region:         "西南大区",
		Area:           "四川区域",
		ProjectManager: "张三",
		ProjectLevel:   "A",
		ProjectStatus:  "在建",
	}
	p, err := BuildPushPayload(led, meta, now)
	if err != nil {
		t.Fatal(err)
	}
	m := controlMap(p)
	if got := m[ControlAppBackupDate]; got != "2026-11-06" {
		t.Errorf("应用备份最新日期应为 2026-11-06，实际 %q", got)
	}
	if got := m[ControlAppBackupGap]; got != "1" {
		t.Errorf("应用备份间隔应为 1 天，实际 %q", got)
	}
	if _, ok := m[ControlDBBackupDate]; ok {
		t.Error("无数据库备份时不应输出数据库备份日期")
	}
	if _, ok := m[ControlDBBackupGap]; ok {
		t.Error("无数据库备份时不应输出数据库备份间隔")
	}
	if m[ControlProjectName] != "某市城管项目" || m[ControlRegion] != "西南大区" ||
		m[ControlArea] != "四川区域" || m[ControlProjectManager] != "张三" {
		t.Errorf("项目字段映射错误: %+v", m)
	}
	if m[ControlProvinceChief] != "" || m[ControlRegionChief] != "" || m[ControlDeliveryProject] != "" {
		t.Errorf("成员/关联字段默认应为空: %+v", m)
	}
	// 9 个项目字段 + 2 个应用备份字段
	if len(p.Controls) != 11 {
		t.Errorf("控件数应为 11，实际 %d: %+v", len(p.Controls), p.Controls)
	}
}

func TestBuildPushPayloadAppAndDB(t *testing.T) {
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	led := pushLedger(
		pushEntry("app", time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)),
		pushEntry("mysql", time.Date(2026, 10, 31, 23, 0, 0, 0, time.UTC)),
		pushEntry("mysql", time.Date(2026, 11, 2, 1, 0, 0, 0, time.UTC)),
	)
	p, err := BuildPushPayload(led, PushMeta{}, now)
	if err != nil {
		t.Fatal(err)
	}
	m := controlMap(p)
	if got := m[ControlAppBackupDate]; got != "2026-11-05" {
		t.Errorf("应用备份最新日期错误: %q", got)
	}
	if got := m[ControlAppBackupGap]; got != "2" {
		t.Errorf("应用备份间隔错误: %q", got)
	}
	if got := m[ControlDBBackupDate]; got != "2026-11-02" {
		t.Errorf("数据库备份最新日期错误: %q", got)
	}
	if got := m[ControlDBBackupGap]; got != "5" {
		t.Errorf("数据库备份间隔错误: %q", got)
	}
	if len(p.Controls) != 13 {
		t.Errorf("控件数应为 13，实际 %d", len(p.Controls))
	}
}

func TestBuildPushPayloadNoBackups(t *testing.T) {
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	p, err := BuildPushPayload(pushLedger(), PushMeta{ProjectName: "p"}, now)
	if err != nil {
		t.Fatal(err)
	}
	m := controlMap(p)
	for _, id := range []string{
		ControlAppBackupDate, ControlAppBackupGap,
		ControlDBBackupDate, ControlDBBackupGap,
	} {
		if _, ok := m[id]; ok {
			t.Errorf("无备份时不应输出控件 %s", id)
		}
	}
	if len(p.Controls) != 9 {
		t.Errorf("无备份时只应输出 9 个项目字段，实际 %d", len(p.Controls))
	}
	if m[ControlProjectName] != "p" {
		t.Errorf("项目名称映射错误: %+v", m)
	}
}

func TestBuildPushPayloadIgnoresBadCreatedAt(t *testing.T) {
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	led := pushLedger(
		LedgerEntry{Kind: "app", CreatedAt: "not-a-time"},
		pushEntry("app", time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC)),
	)
	p, err := BuildPushPayload(led, PushMeta{}, now)
	if err != nil {
		t.Fatal(err)
	}
	m := controlMap(p)
	if m[ControlAppBackupDate] != "2026-11-07" || m[ControlAppBackupGap] != "0" {
		t.Errorf("应跳过非法时间并取有效最新备份: %+v", m)
	}
}

func TestPushPayloadJSONShape(t *testing.T) {
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	p, err := BuildPushPayload(pushLedger(
		pushEntry("app", time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)),
	), PushMeta{ProjectName: "p"}, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Controls []struct {
			ControlID string `json:"controlId"`
			Value     string `json:"value"`
		} `json:"controls"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("payload 不是合法 JSON: %v\n%s", err, b)
	}
	if len(doc.Controls) != 11 {
		t.Fatalf("controls 数量错误: %d", len(doc.Controls))
	}
	for _, c := range doc.Controls {
		if c.ControlID == "" {
			t.Errorf("存在空 controlId: %s", b)
		}
	}
}
