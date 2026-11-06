package main

// 交互菜单 6：备份运维（执行 / 清单 / 校验 / 清理 / 台账）。
// 与 logs 菜单同风格：交互层只做选择编排，实际逻辑全部走子命令实现，
// 保证「菜单能做的事 = 脚本能做的事」，不会出现两套行为。

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func menuBackup() {
	for {
		fmt.Printf(`
--- 备份运维（当前配置: %s）---
1. 执行备份（应用目录 + 可选数据库，先出计划）
2. 备份清单（现场已有产物）
3. 备份校验（gzip/tar/sha256）
4. 清理过期备份（保留期，先列出）
5. 导出台账 JSON（可带校验）
6. 从备份恢复应用（停应用→自动备份→解压→属主→启动→健康检查）
7. 生成 ztoa 项目备份中间表 payload（只读台账，不联网）
0. 返回主菜单
`, curCfgPath)
		switch getIntChoice("请选择", 0, 7) {
		case 1:
			menuBackupRun()
		case 2:
			menuBackupList()
		case 3:
			menuBackupVerify()
		case 4:
			menuBackupPrune()
		case 5:
			menuBackupReport()
		case 6:
			menuBackupRestore()
		case 7:
			menuBackupPush()
		case 0:
			return
		}
	}
}

// askBackupScope 交互式收集范围：应用名 + 是否含数据库。
func askBackupScope() (app string, mysql bool) {
	sc := bufio.NewReader(os.Stdin)
	fmt.Print("应用名（回车=全部应用）: ")
	app = strings.TrimSpace(readLine(sc))
	if app == "" {
		app = "all"
	}
	fmt.Print("是否包含数据库逻辑备份 backup.databases？(y/N): ")
	yes := strings.ToLower(strings.TrimSpace(readLine(sc)))
	return app, yes == "y" || yes == "yes"
}

func menuBackupRun() {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	app, mysql := askBackupScope()
	args := []string{"-c", curCfgPath, "--app", app}
	if mysql {
		args = append(args, "--mysql")
	}
	fmt.Println("\n（先出备份计划 dry-run；确认后重跑并以 --yes 执行，或在本菜单二次确认）")
	if err := cmdBackupRun(args); err != nil {
		fmt.Println("❌", err)
		return
	}
	// 计划已展示，交互场景直接二次确认执行（子命令仍保留 --yes 语义）
	fmt.Print("\n确认执行以上备份？(y/N): ")
	sc := bufio.NewReader(os.Stdin)
	if strings.ToLower(strings.TrimSpace(readLine(sc))) != "y" {
		fmt.Println("已取消")
		return
	}
	args = append(args, "--yes")
	if err := cmdBackupRun(args); err != nil {
		fmt.Println("❌", err)
	}
}

func menuBackupList() {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	app, mysql := askBackupScope()
	args := []string{"-c", curCfgPath, "--app", app}
	if mysql {
		args = append(args, "--mysql")
	}
	if err := cmdBackupList(args); err != nil {
		fmt.Println("❌", err)
	}
}

func menuBackupVerify() {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	app, mysql := askBackupScope()
	args := []string{"-c", curCfgPath, "--app", app}
	if mysql {
		args = append(args, "--mysql")
	}
	if err := cmdBackupVerify(args); err != nil {
		fmt.Println("❌", err)
	}
}

func menuBackupPrune() {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	app, mysql := askBackupScope()
	sc := bufio.NewReader(os.Stdin)
	fmt.Print("保留天数（回车=用配置 backup.keep_days）: ")
	keep := strings.TrimSpace(readLine(sc))
	args := []string{"-c", curCfgPath, "--app", app}
	if mysql {
		args = append(args, "--mysql")
	}
	if keep != "" {
		args = append(args, "--keep-days", keep)
	}
	if err := cmdBackupPrune(args); err != nil {
		fmt.Println("❌", err)
		return
	}
	fmt.Print("\n确认删除以上过期备份？(y/N): ")
	if strings.ToLower(strings.TrimSpace(readLine(sc))) != "y" {
		fmt.Println("已取消")
		return
	}
	args = append(args, "--yes")
	if err := cmdBackupPrune(args); err != nil {
		fmt.Println("❌", err)
	}
}

func menuBackupRestore() {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	sc := bufio.NewReader(os.Stdin)
	fmt.Print("要恢复的应用名: ")
	app := strings.TrimSpace(readLine(sc))
	if app == "" {
		fmt.Println("应用名不能为空")
		return
	}
	fmt.Print("远端备份包路径（backup.root 下 eops-*.tar.gz）: ")
	file := strings.TrimSpace(readLine(sc))
	if file == "" {
		fmt.Println("备份包路径不能为空")
		return
	}
	args := []string{"-c", curCfgPath, "--app", app, "--file", file}
	fmt.Println("\n（先出恢复计划 dry-run；确认后执行）")
	if err := cmdBackupRestore(args); err != nil {
		fmt.Println("❌", err)
		return
	}
	fmt.Print("\n确认按以上计划执行恢复？(y/N): ")
	if strings.ToLower(strings.TrimSpace(readLine(sc))) != "y" {
		fmt.Println("已取消")
		return
	}
	args = append(args, "--yes")
	if err := cmdBackupRestore(args); err != nil {
		fmt.Println("❌", err)
	}
}

func menuBackupPush() {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	sc := bufio.NewReader(os.Stdin)
	fmt.Print("应用名（回车=全部应用）: ")
	app := strings.TrimSpace(readLine(sc))
	if app == "" {
		app = "all"
	}
	fmt.Print("输出文件（回车=tool-ztoa-backup-payload.json）: ")
	out := strings.TrimSpace(readLine(sc))
	if out == "" {
		out = "tool-ztoa-backup-payload.json"
	}
	fmt.Print("是否同时校验每份备份？(y/N): ")
	verify := strings.ToLower(strings.TrimSpace(readLine(sc)))
	args := []string{"-c", curCfgPath, "--app", app, "--out", out}
	if verify == "y" || verify == "yes" {
		args = append(args, "--verify")
	}
	if err := cmdBackupPush(args); err != nil {
		fmt.Println("❌", err)
	}
}

func menuBackupReport() {
	if _, ok := checkConfigForMenu(); !ok {
		return
	}
	app, mysql := askBackupScope()
	sc := bufio.NewReader(os.Stdin)
	fmt.Print("输出文件（回车=tool-backup-ledger.json）: ")
	out := strings.TrimSpace(readLine(sc))
	if out == "" {
		out = "tool-backup-ledger.json"
	}
	fmt.Print("是否同时校验每份备份？(y/N): ")
	verify := strings.ToLower(strings.TrimSpace(readLine(sc)))
	args := []string{"-c", curCfgPath, "--app", app, "--out", out}
	if mysql {
		args = append(args, "--mysql")
	}
	if verify == "y" || verify == "yes" {
		args = append(args, "--verify")
	}
	if err := cmdBackupReport(args); err != nil {
		fmt.Println("❌", err)
	}
}
