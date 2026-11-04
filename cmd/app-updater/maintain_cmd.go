package main

// 工作目录维护子命令：clean-update（清理历史更新包）、compress-backups（多线程压缩备份）。

import (
	"flag"
	"fmt"
	"runtime"
	"time"

	"github.com/majq1990/app-updater-go/internal/maintain"
)

func cmdCleanUpdate(args []string) error {
	fs := flag.NewFlagSet("clean-update", flag.ExitOnError)
	dir := fs.String("dir", "update", "更新包根目录")
	dryRun := fs.Bool("dry-run", false, "只统计不删除")
	yes := fs.Bool("yes", false, "确认执行删除")
	fs.Parse(args)

	dry := *dryRun || !*yes
	res, err := maintain.CleanUpdatePackages(*dir, true)
	if err != nil {
		return err
	}
	if len(res.RemovedApps) == 0 {
		fmt.Printf("%s 下没有可清理的应用包目录\n", *dir)
		return nil
	}
	fmt.Printf("将清理 %s 下 %d 个应用包目录（%d 个文件，%s）：\n",
		*dir, len(res.RemovedApps), res.RemovedFiles, maintain.HumanBytes(res.FreedBytes))
	for _, a := range res.RemovedApps {
		fmt.Println("  -", a+"/")
	}
	if dry {
		fmt.Println("\n（dry-run，未实际删除；确认后加 --yes 执行）")
		return nil
	}
	if _, err := maintain.CleanUpdatePackages(*dir, false); err != nil {
		return err
	}
	fmt.Printf("\n✅ 已清理，释放 %s\n", maintain.HumanBytes(res.FreedBytes))
	return nil
}

func cmdCompressBackups(args []string) error {
	fs := flag.NewFlagSet("compress-backups", flag.ExitOnError)
	dir := fs.String("dir", "backups", "备份根目录")
	workers := fs.Int("workers", 0, "并发数（默认按 CPU 数，最多 8）")
	dryRun := fs.Bool("dry-run", false, "只统计不压缩")
	yes := fs.Bool("yes", false, "确认执行压缩")
	fs.Parse(args)

	dry := *dryRun || !*yes
	pre, err := maintain.CompressBackups(*dir, *workers, true)
	if err != nil {
		return err
	}
	if len(pre.Archives) == 0 {
		fmt.Printf("%s 下没有需要压缩的备份版本目录\n", *dir)
		for _, s := range pre.Skipped {
			fmt.Println("  跳过:", s)
		}
		return nil
	}
	fmt.Printf("待压缩 %d 个版本目录，原始体积 %s\n", len(pre.Archives), maintain.HumanBytes(pre.Bytes))
	for _, s := range pre.Skipped {
		fmt.Println("  跳过:", s)
	}
	if dry {
		fmt.Println("\n（dry-run，未实际压缩；确认后加 --yes 执行）")
		return nil
	}

	fmt.Println("\n压缩中...")
	res, err := maintain.CompressBackups(*dir, *workers, false)
	if err != nil {
		fmt.Println("❌", err)
	}
	w := *workers
	if w <= 0 {
		w = runtime.NumCPU()
		if w > 8 {
			w = 8
		}
	}
	fmt.Printf("\n✅ 完成：%d 个版本（%d 线程），%s → %s（耗时 %s）\n",
		len(res.Archives), w, maintain.HumanBytes(res.Bytes), maintain.HumanBytes(res.Packed),
		res.Elapsed.Round(time.Second))
	if res.Bytes > 0 {
		fmt.Printf("   压缩率 %.1f%%\n", float64(res.Packed)/float64(res.Bytes)*100)
	}
	for _, a := range res.Archives {
		fmt.Println("  ", a)
	}
	return nil
}
