package main

// 三方依赖安全检查子命令（只读）。
//
//	eops depsec scan  -c config.yaml [--host all|ip,ip] [--no-embedded] [--dirs /egova,/opt]
//	eops depsec query -c config.yaml --host <ip> --target fastjson-1.2.83.jar
//	eops depsec fetch -c config.yaml --host <ip> --target redis [--download]
//	eops depsec list
//
// 口径：只检测、只登记、给出处理建议，不做任何替换/下载（jar 类由脚本直接拒绝）。
// 资产随二进制内嵌，运行时下发到目标机 /tmp/eops_depsec，不依赖现场已有文件。

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/depsec"
	"github.com/majq1990/app-updater-go/internal/sshx"
)

func cmdDepsec(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: eops depsec scan|query|fetch|list -c config.yaml [选项]")
	}
	switch args[0] {
	case "scan":
		return cmdDepsecScan(args[1:])
	case "query":
		return cmdDepsecQuery(args[1:])
	case "fetch":
		return cmdDepsecFetch(args[1:])
	case "list":
		return cmdDepsecList()
	default:
		return fmt.Errorf("未知 depsec 子命令: %s（可用 scan|query|fetch|list）", args[0])
	}
}

func cmdDepsecList() error {
	fmt.Println(`三方依赖安全检查（只读）：
  scan    按安全版本清单比对目标机现场依赖，输出问题清单（Markdown + CSV）
  query   单组件版本判定：VULNERABLE / OK / 无可用安全版本 / 未收录(rc=2)
  fetch   中间件下载地址查询；带 --download 才取件（jar 类脚本直接拒绝，rc=5）

处置口径：
  中间件/独立软件 —— 可联网升级；无外网用清单内中国大陆下载地址，由人执行
  代码内 jar 包   —— 只登记问题，提单由研发更新；工具不下载、不替换、不重启服务`)
	return nil
}

// depsecHosts 从配置里取目标主机（去重）。
func depsecHosts(cfg *config.Config, filter string) []config.Host {
	seen := map[string]bool{}
	var out []config.Host
	pick := func(h config.Host) {
		key := h.Host
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, h)
	}
	for _, app := range cfg.Webs {
		for _, h := range app.Master {
			pick(h)
		}
		for _, h := range app.Update {
			pick(h)
		}
	}
	if len(out) == 0 {
		for _, s := range cfg.Supports {
			for _, h := range s.Hosts {
				pick(h)
			}
		}
	}
	if filter == "" || strings.EqualFold(filter, "all") {
		return out
	}
	want := map[string]bool{}
	for _, s := range strings.Split(filter, ",") {
		if s = strings.TrimSpace(s); s != "" {
			want[s] = true
		}
	}
	var hit []config.Host
	for _, h := range out {
		if want[h.Host] {
			hit = append(hit, h)
		}
	}
	return hit
}

// depsecPrepare 连接主机并下发资产。
func depsecPrepare(dial *execDialer, h config.Host) (*sshx.Client, error) {
	conn, err := dial.Dial(h)
	if err != nil {
		return nil, err
	}
	cli, ok := conn.(*sshx.Client)
	if !ok {
		return nil, fmt.Errorf("连接类型异常")
	}
	// 资产先落本地临时目录，再 SFTP 上传（避免超长命令行）
	tmp, err := os.MkdirTemp("", "eops-depsec-")
	if err != nil {
		return nil, err
	}
	files, err := depsec.Materialize(tmp)
	if err != nil {
		return nil, err
	}
	if _, err := cli.Run("mkdir -p " + depsec.RemoteDir + "/conf"); err != nil {
		return nil, fmt.Errorf("创建远端目录失败: %w", err)
	}
	for _, name := range []string{"scan_secure_deps.sh", "query_secure_version.sh", "fetch_secure_artifact.sh", "conf/secure-versions.flat"} {
		if err := cli.Upload(files[name], depsec.RemoteDir+"/"+name, time.Now()); err != nil {
			return nil, fmt.Errorf("上传 %s 失败: %w", name, err)
		}
	}
	_ = os.RemoveAll(tmp)
	return cli, nil
}

func cmdDepsecScan(args []string) error {
	fs := flag.NewFlagSet("depsec scan", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	host := fs.String("host", "all", "主机过滤：IP / all / 逗号分隔")
	dirs := fs.String("dirs", "", "只扫描指定目录（逗号分隔），空=默认目录集")
	noEmbedded := fs.Bool("no-embedded", false, "跳过 fat jar / WEB-INF 内嵌检测（更快）")
	parallel := fs.Int("parallel", 2, "并发主机数（默认 2，避免把目标机压住）")
	reportDir := fs.String("out", "", "报告下载目录（空=只回显，不下载）")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	hosts := depsecHosts(cfg, *host)
	if len(hosts) == 0 {
		fmt.Println("没有匹配的目标主机（检查 config.yaml 的 webs.master/update）")
		return nil
	}
	fmt.Printf("三方依赖安全检查（只读）：%d 台主机，清单 %d 条\n", len(hosts), depsec.FlatCount())
	fmt.Println("口径：中间件可联网升级；jar 只登记问题，提单研发更新；工具不做任何替换。")

	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()

	type result struct {
		host string
		sum  depsec.Summary
		err  error
	}
	results := make([]result, 0, len(hosts))
	sem := make(chan struct{}, max(1, *parallel))
	done := make(chan result, len(hosts))

	for _, h := range hosts {
		go func(h config.Host) {
			sem <- struct{}{}
			defer func() { <-sem }()
			cli, err := depsecPrepare(dial, h)
			if err != nil {
				done <- result{host: h.Host, err: err}
				return
			}
			fmt.Printf("\n== %s ==\n" , h.Host)
			raw, err := cli.Run(depsec.Wrap(depsec.ScanCommand(*dirs, !*noEmbedded)))
			if err != nil {
				done <- result{host: h.Host, err: err}
				return
			}
			out, rc, _ := depsec.SplitRC(raw)
			fmt.Print(tailLines(out, 14))
			if rc == 2 {
				done <- result{host: h.Host, err: fmt.Errorf("安全版本清单缺失或不可读")}
				return
			}
			// 取最新报告正文用于摘要与落盘
			rep, _ := cli.Run("ls -t " + depsec.RemoteDir + "/*.md 2>/dev/null | head -1 | xargs -r cat")
			sum := depsec.ParseSummary(rep)
			if *reportDir != "" && rep != "" {
				_ = os.MkdirAll(*reportDir, 0o755)
				p := filepath.Join(*reportDir, fmt.Sprintf("depsec-%s.md", h.Host))
				_ = os.WriteFile(p, []byte(rep), 0o644)
				fmt.Printf("报告已保存: %s\n", p)
			}
			done <- result{host: h.Host, sum: sum}
		}(h)
	}

	for i := 0; i < len(hosts); i++ {
		r := <-done
		results = append(results, r)
	}
	fmt.Println("\n===== 汇总 =====")
	totalHigh, totalReview := 0, 0
	for _, r := range results {
		if r.err != nil {
			fmt.Printf("%-16s 失败: %v\n", r.host, r.err)
			continue
		}
		totalHigh += r.sum.High
		totalReview += r.sum.Review
		fmt.Printf("%-16s 高危/需处理 %-4d 待复核 %-3d 正常 %-4d\n", r.host, r.sum.High, r.sum.Review, r.sum.OK)
	}
	fmt.Printf("合计：高危/需处理 %d，待复核 %d\n", totalHigh, totalReview)
	fmt.Println("提示：结果已按组件去重口径登记时可导入 AI 表格「依赖安全问题清单」。")
	if totalHigh > 0 {
		return fmt.Errorf("发现 %d 项低于安全版本", totalHigh)
	}
	return nil
}

func cmdDepsecQuery(args []string) error {
	fs := flag.NewFlagSet("depsec query", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	host := fs.String("host", "", "目标主机 IP（必填）")
	target := fs.String("target", "", "组件标识或 jar 文件名（必填）")
	fs.Parse(args)
	if *host == "" || *target == "" {
		return fmt.Errorf("用法: eops depsec query -c config.yaml --host <ip> --target <组件或jar>")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	hosts := depsecHosts(cfg, *host)
	if len(hosts) == 0 {
		return fmt.Errorf("配置里没有主机 %s", *host)
	}
	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()
	cli, err := depsecPrepare(dial, hosts[0])
	if err != nil {
		return err
	}
	raw, err := cli.Run(depsec.Wrap(depsec.QueryCommand(*target)))
	out, rc, _ := depsec.SplitRC(raw)
	fmt.Print(out)
	if err != nil {
		return err
	}
	if rc == 2 {
		return fmt.Errorf("清单未收录该组件（rc=2）")
	}
	return nil
}

func cmdDepsecFetch(args []string) error {
	fs := flag.NewFlagSet("depsec fetch", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	host := fs.String("host", "", "目标主机 IP（必填）")
	target := fs.String("target", "", "组件标识（必填）")
	download := fs.Bool("download", false, "实际取件（仅中间件/软件；jar 类脚本会拒绝）")
	fs.Parse(args)
	if *host == "" || *target == "" {
		return fmt.Errorf("用法: eops depsec fetch -c config.yaml --host <ip> --target <组件> [--download]")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	hosts := depsecHosts(cfg, *host)
	if len(hosts) == 0 {
		return fmt.Errorf("配置里没有主机 %s", *host)
	}
	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()
	cli, err := depsecPrepare(dial, hosts[0])
	if err != nil {
		return err
	}
	raw, err := cli.Run(depsec.Wrap(depsec.FetchCommand(*target, *download)))
	out, rc, _ := depsec.SplitRC(raw)
	fmt.Print(out)
	if err != nil {
		return err
	}
	switch rc {
	case 2:
		return fmt.Errorf("清单未收录该组件（rc=2）")
	case 3:
		return fmt.Errorf("该组件无可用安全版本（rc=3）")
	case 5:
		fmt.Println("提示：jar 类由研发提单更新，工具不下载不替换（rc=5）")
		return nil
	}
	return nil
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return s + "\n"
	}
	return strings.Join(lines[len(lines)-n:], "\n") + "\n"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
