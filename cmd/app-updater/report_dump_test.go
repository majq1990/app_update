package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/majq1990/app-updater-go/internal/inspect"
)

// 报告落盘：写入当日文件、目录自动创建、JSON 可解析。
func TestWriteDailyReport(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 7, 15, 4, 5, 0, time.Local)
	rep := inspect.BuildReport(nil, now)

	path, err := writeDailyReport(dir, reportKindInspect, rep, now)
	if err != nil {
		t.Fatalf("writeDailyReport 失败: %v", err)
	}
	want := filepath.Join(dir, "logs", "eops-20261107-inspect.json")
	if path != want {
		t.Fatalf("路径不符: got %s want %s", path, want)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取报告失败: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("报告不是合法 JSON: %v", err)
	}
	if _, ok := got["generated_at"]; !ok {
		t.Fatalf("报告缺少 generated_at 字段: %s", b)
	}
}

// 当日重复执行覆盖同一文件（幂等），monitor 与 inspect 文件名互不干扰。
func TestWriteDailyReportOverwriteAndKind(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 7, 8, 0, 0, 0, time.Local)

	if _, err := writeDailyReport(dir, reportKindMonitor, inspect.BuildReport(nil, now), now); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	first := inspect.BuildReport(nil, now)
	first.Hosts = 3
	if _, err := writeDailyReport(dir, reportKindMonitor, first, now); err != nil {
		t.Fatalf("覆盖写入失败: %v", err)
	}

	mpath := filepath.Join(dir, "logs", "eops-20261107-monitor.json")
	b, err := os.ReadFile(mpath)
	if err != nil {
		t.Fatalf("读取 monitor 报告失败: %v", err)
	}
	var got inspect.Report
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("monitor 报告不是合法 JSON: %v", err)
	}
	if got.Hosts != 3 {
		t.Fatalf("覆盖未生效: got hosts=%d want 3", got.Hosts)
	}
	if _, err := os.Stat(filepath.Join(dir, "logs", "eops-20261107-inspect.json")); !os.IsNotExist(err) {
		t.Fatalf("monitor 落盘不应产生 inspect 文件: %v", err)
	}
}
