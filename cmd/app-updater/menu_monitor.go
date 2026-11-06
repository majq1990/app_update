package main

// 交互菜单 8：监控运维（诊断 / 白名单修复 / 部署检查清单）。

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func menuMonitor() {
	for {
		fmt.Printf(`
--- 监控运维（当前配置: %s）---
1. 全面诊断（agent + proxy）
2. 只诊断受控机 agent
3. 只诊断主控机 proxy
4. 修复计划（仅重启 agent/proxy，先 dry-run）
5. 监控部署检查清单
0. 返回主菜单
`, curCfgPath)
		switch getIntChoice("请选择", 0, 5) {
		case 1:
			runMonitorMenu("doctor", "all")
		case 2:
			runMonitorMenu("doctor", "agent")
		case 3:
			runMonitorMenu("doctor", "proxy")
		case 4:
			runMonitorMenu("fix", "all")
		case 5:
			_ = cmdMonitorPlan(nil)
		case 0:
			return
		}
	}
}

func runMonitorMenu(action, role string) {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	sc := bufio.NewReader(os.Stdin)
	args := []string{"-c", curCfgPath, "--role", role}
	if action == "doctor" {
		fmt.Print("JSON 报告输出路径（回车=不输出）: ")
		if out := strings.TrimSpace(readLine(sc)); out != "" {
			args = append(args, "--json", out)
		}
		_ = cmdMonitorDoctor(args)
		return
	}
	// fix：先出计划，再二次确认
	_ = cmdMonitorFix(args)
	fmt.Print("\n确认执行以上修复动作？(y/N): ")
	if strings.ToLower(strings.TrimSpace(readLine(sc))) != "y" {
		fmt.Println("已取消")
		return
	}
	args = append(args, "--yes")
	if err := cmdMonitorFix(args); err != nil {
		fmt.Println("❌", err)
	}
}
