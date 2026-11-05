package main

// 交互菜单 5：日志运维（汇聚 / 清理）。
// 复用子命令实现，交互层只做选择编排（与 update/rollback 菜单同风格）。
// clean 始终先 dry-run 出计划，用户看到计划后手动加确认重跑——与子命令宪法一致。

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/majq1990/app-updater-go/internal/config"
)

func menuLogs() {
	for {
		fmt.Printf(`
--- 日志运维（当前配置: %s）---
1. 汇聚日志（时间窗拉取 + ERROR 统计）
2. 清理过期日志（应用 + 支持软件 mysql·redis·nginx·达梦）
0. 返回主菜单
`, curCfgPath)
		switch getIntChoice("请选择", 0, 2) {
		case 1:
			menuLogsGather()
		case 2:
			menuLogsClean()
		case 0:
			return
		}
	}
}

// checkConfigForMenu 菜单路径的配置闸门（校验失败直接返回，复用子命令错误文案）。
func checkConfigForMenu() (*config.Config, bool) {
	cfg, err := config.Load(curCfgPath)
	if err != nil {
		fmt.Println("❌", err)
		return nil, false
	}
	if err := gateValidation(cfg, false); err != nil {
		return nil, false
	}
	return cfg, true
}

func menuLogsGather() {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	sc := bufio.NewReader(os.Stdin)
	fmt.Print("时间窗（1h/4h/24h，默认 4h）: ")
	win := strings.TrimSpace(readLine(sc))
	if win == "" {
		win = "4h"
	}
	fmt.Print("应用名（回车=全部应用）: ")
	app := strings.TrimSpace(readLine(sc))
	if app == "" {
		app = "all"
	}
	fmt.Print("支持软件 kind（回车=全部 mysql/redis/nginx/dm...）: ")
	sup := strings.TrimSpace(readLine(sc))
	if sup == "" {
		sup = "all"
	}
	_ = cmdLogsGather([]string{"-c", curCfgPath, "--app", app, "--support", sup, "--window", win})
}

func menuLogsClean() {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	sc := bufio.NewReader(os.Stdin)
	fmt.Print("应用名（回车=全部应用）: ")
	app := strings.TrimSpace(readLine(sc))
	if app == "" {
		app = "all"
	}
	fmt.Print("支持软件 kind（回车=全部）: ")
	sup := strings.TrimSpace(readLine(sc))
	if sup == "" {
		sup = "all"
	}
	fmt.Println("\n（先出清理计划 dry-run；确认无误后按提示重跑加 --yes / 菜单确认）")
	_ = cmdLogsClean([]string{"-c", curCfgPath, "--app", app, "--support", sup})
}

func readLine(sc *bufio.Reader) string {
	line, _ := sc.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}
