package main

// 交互菜单：三方依赖安全检查（只读）。
// 与 depsec 子命令共用同一实现，交互层只负责收集参数。

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func menuDepsec() {
	for {
		fmt.Printf(`
--- 三方依赖安全检查（只读，当前配置: %s）---
  口径：中间件可联网升级；代码内 jar 只登记问题、提单研发更新；工具不做任何替换。
1. 目标机检测（按安全版本清单比对，出问题清单）
2. 单组件版本判定（输入 jar 名或组件标识）
3. 中间件下载地址查询（可选实际取件）
4. 检查项与处置口径说明
0. 返回主菜单
`, curCfgPath)
		switch getIntChoice("请选择", 0, 4) {
		case 1:
			depsecScanMenu()
		case 2:
			depsecQueryMenu()
		case 3:
			depsecFetchMenu()
		case 4:
			_ = cmdDepsecList()
		case 0:
			return
		}
	}
}

func depsecScanMenu() {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	sc := bufio.NewReader(os.Stdin)
	fmt.Print("主机过滤（回车=全部，可填 IP 或逗号分隔）: ")
	host := strings.TrimSpace(readLine(sc))
	if host == "" {
		host = "all"
	}
	fmt.Print("只扫指定目录（回车=默认目录集，如 /egova,/opt）: ")
	dirs := strings.TrimSpace(readLine(sc))
	fmt.Print("跳过 fat jar 内嵌检测可显著加快，是否跳过？(y/N): ")
	skip := strings.ToLower(strings.TrimSpace(readLine(sc))) == "y"
	fmt.Print("报告下载目录（回车=不下载，例 ./logs/depsec）: ")
	out := strings.TrimSpace(readLine(sc))

	args := []string{"-c", curCfgPath, "--host", host}
	if dirs != "" {
		args = append(args, "--dirs", dirs)
	}
	if skip {
		args = append(args, "--no-embedded")
	}
	if out != "" {
		args = append(args, "--out", out)
	}
	if err := cmdDepsecScan(args); err != nil {
		fmt.Printf("  ⚠️ %v\n", err)
	}
}

func depsecQueryMenu() {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	sc := bufio.NewReader(os.Stdin)
	fmt.Print("目标主机 IP: ")
	host := strings.TrimSpace(readLine(sc))
	if host == "" {
		return
	}
	fmt.Print("组件标识或 jar 文件名（如 log4j-core-2.17.1.jar）: ")
	target := strings.TrimSpace(readLine(sc))
	if target == "" {
		return
	}
	if err := cmdDepsecQuery([]string{"-c", curCfgPath, "--host", host, "--target", target}); err != nil {
		fmt.Printf("  ⚠️ %v\n", err)
	}
}

func depsecFetchMenu() {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	sc := bufio.NewReader(os.Stdin)
	fmt.Print("目标主机 IP: ")
	host := strings.TrimSpace(readLine(sc))
	if host == "" {
		return
	}
	fmt.Print("组件标识（如 redis / mysql / tomcat）: ")
	target := strings.TrimSpace(readLine(sc))
	if target == "" {
		return
	}
	fmt.Print("是否实际下载到目标机 /tmp/eops_depsec/artifacts？(y/N，默认只给地址): ")
	dl := strings.ToLower(strings.TrimSpace(readLine(sc))) == "y"
	args := []string{"-c", curCfgPath, "--host", host, "--target", target}
	if dl {
		args = append(args, "--download")
	}
	if err := cmdDepsecFetch(args); err != nil {
		fmt.Printf("  ⚠️ %v\n", err)
	}
}
