package main

// 交互菜单 9：安全加固（只读清单 / 建议片段 / 台账）。
// 首期不自动改配置——与规划红线一致（网络层/SSH 变更必须人工确认）。

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func menuHarden() {
	for {
		fmt.Printf(`
--- 安全加固（只读，当前配置: %s）---
1. 加固清单（全部主机）
2. 加固清单（指定主机）
3. 输出建议片段（可粘贴）
4. 导出加固台账 JSON
0. 返回主菜单
`, curCfgPath)
		switch getIntChoice("请选择", 0, 4) {
		case 1:
			runHardenMenu("check", "all")
		case 2:
			sc := bufio.NewReader(os.Stdin)
			fmt.Print("主机 IP（逗号分隔）: ")
			runHardenMenu("check", strings.TrimSpace(readLine(sc)))
		case 3:
			runHardenMenu("snippets", "all")
		case 4:
			sc := bufio.NewReader(os.Stdin)
			fmt.Print("输出文件（回车=hardening-ledger.json）: ")
			out := strings.TrimSpace(readLine(sc))
			if out == "" {
				out = "hardening-ledger.json"
			}
			runHardenMenu("report", "all", out)
		case 0:
			return
		}
	}
}

func runHardenMenu(action, host string, extra ...string) {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	if host == "" {
		fmt.Println("主机不能为空（要全部主机请选 1）")
		return
	}
	args := []string{"-c", curCfgPath, "--host", host}
	switch action {
	case "check":
		_ = cmdHardenCheck(args, false)
	case "snippets":
		_ = cmdHardenCheck(args, true)
	case "report":
		if len(extra) > 0 && extra[0] != "" {
			args = append(args, "--out", extra[0])
		}
		_ = cmdHardenReport(args)
	}
}
