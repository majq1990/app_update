package main

// 巡检 / 监控诊断报告自动落盘（T5）：
// inspect run 与 monitor doctor 成功执行后，把完整 JSON 报告写到工具工作目录
// logs/eops-<YYYYMMDD>-<kind>.json（覆盖当日文件），终端仍只出摘要。
// --json 显式路径由调用方单独处理，不受影响。

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/majq1990/app-updater-go/internal/inspect"
)

// 报告类型（用于落盘文件名）。
const (
	reportKindInspect = "inspect"
	reportKindMonitor = "monitor"
)

// dailyReportPath 返回工作目录下当日报告路径：logs/eops-YYYYMMDD-<kind>.json。
func dailyReportPath(base, kind string, now time.Time) string {
	return filepath.Join(base, "logs", fmt.Sprintf("eops-%s-%s.json", now.Format("20060102"), kind))
}

// writeDailyReport 把报告写成当日 JSON 文件（覆盖当日）；logs 目录不存在则创建。
func writeDailyReport(base, kind string, rep inspect.Report, now time.Time) (string, error) {
	path := dailyReportPath(base, kind, now)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return path, err
	}
	b, err := rep.JSON()
	if err != nil {
		return path, err
	}
	return path, os.WriteFile(path, append(b, '\n'), 0o644)
}

// dumpDailyReport 落盘并提示；写失败不阻断主流程，只打印提示。
func dumpDailyReport(kind string, rep inspect.Report) {
	path, err := writeDailyReport(".", kind, rep, time.Now())
	if err != nil {
		fmt.Printf("⚠️ 报告落盘失败（不影响本次结果）: %v\n", err)
		return
	}
	fmt.Printf("报告已保存: %s\n", path)
}
