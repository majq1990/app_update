package main

// 交互菜单 7：项目巡检（Go 直连执行，只读）。
// 与 inspect 子命令共用同一实现，交互层只负责选择。

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func menuInspect() {
	for {
		fmt.Printf(`
--- 项目巡检（当前配置: %s）---
1. 全量巡检（OS + 安全 + 中间件）
2. 仅安全检查
3. 仅 OS 与资源
4. 仅中间件 / 应用端口
5. 检查项清单
0. 返回主菜单
`, curCfgPath)
		switch getIntChoice("请选择", 0, 5) {
		case 1:
			runInspectMenu("", "")
		case 2:
			runInspectMenu("security", "")
		case 3:
			runInspectMenu("os", "")
		case 4:
			runInspectMenu("middleware", "")
		case 5:
			_ = cmdInspectList(nil)
		case 0:
			return
		}
	}
}

func runInspectMenu(dim, host string) {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	sc := bufio.NewReader(os.Stdin)
	if host == "" {
		fmt.Print("主机过滤（回车=全部，可填 IP 或逗号分隔）: ")
		host = strings.TrimSpace(readLine(sc))
		if host == "" {
			host = "all"
		}
	}
	fmt.Print("JSON 报告输出路径（回车=不输出）: ")
	out := strings.TrimSpace(readLine(sc))

	args := []string{"-c", curCfgPath, "--host", host}
	if dim != "" {
		args = append(args, "--dim", dim)
	}
	if out != "" {
		args = append(args, "--json", out)
	}
	// 交互模式下不因 --fail-on 抛错打断菜单
	args = append(args, "--fail-on", "none")
	if err := cmdInspectRun(args, nil); err != nil {
		fmt.Println("❌", err)
	}
}
