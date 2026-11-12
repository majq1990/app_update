package main

// harden_sec_cmd.go —— harden 安全工具箱子命令（对齐 oneinstall_v2 安全工具箱语义）：
//
//	eops harden sec check  [hosts]   只读体检：未授权探测 / nginx / tomcat 基线
//	eops harden sec fix    [hosts]   写修复（默认 dry-run，--yes 执行；改前逐文件备份，
//	                                   nginx -t 失败自动还原；不带 --yes 永不落盘）
//	eops harden sec rollback --manifest m.json  按备份 manifest 回滚
//	eops harden sec gap              输出 oneinstall 安全工具箱能力对照表
//
// 红线：SSH 登录方式不改（无密钥确认不碰）；数据库只读；拦截链可整链回退。

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/harden"
)

func cmdHardenSec(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: eops harden sec check|fix|rollback|gap -c config.yaml [--host IP] [--yes]")
	}
	switch args[0] {
	case "check":
		return cmdHardenSecCheck(args[1:])
	case "fix":
		return cmdHardenSecFix(args[1:])
	case "rollback":
		return cmdHardenSecRollback(args[1:])
	case "gap":
		gaps := harden.GapTable()
		fmt.Println("oneinstall_v2 安全工具箱 → eops 能力对照（工具 / 状态 / 能力 / eops 入口）：")
		for _, g := range gaps {
			fmt.Printf("  %-26s %-14s %-30s %s\n", g.Tool, g.Status, g.Capability, g.Note)
		}
		return nil
	default:
		return fmt.Errorf("未知 sec 子命令: %s（可用 check|fix|rollback|gap）", args[0])
	}
}

// secDialer 把 execDialer 适配成 harden.SecRunner（按主机）。
// Dial 返回的接口是 appflow.Conn，其动态类型 *sshx.Client 满足 SecRunner
// （Run + RunWithStdin）；这里做一次类型断言兜底。
func secDialer(cfg *config.Config) func(string) (harden.SecRunner, error) {
	dial := &execDialer{cfg: cfg, over: sshOverride()}
	return func(host string) (harden.SecRunner, error) {
		c, err := dial.Dial(config.Host{Host: host})
		if err != nil {
			return nil, err
		}
		sr, ok := c.(harden.SecRunner)
		if !ok {
			return nil, fmt.Errorf("%s 连接不支持脚本下发（SecRunner）", host)
		}
		return sr, nil
	}
}

// inspectTargetHosts 从配置取全部巡检主机 IP（应用 + 支持软件，去重）。
func inspectTargetHosts(cfg *config.Config) []string {
	seen := map[string]bool{}
	var out []string
	push := func(h string) {
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, app := range cfg.Webs {
		for _, g := range []string{config.GroupMaster, config.GroupUpdate, config.GroupStatic} {
			for _, h := range app.GroupHosts(g) {
				push(h.Host)
			}
		}
	}
	for _, s := range cfg.Supports {
		for _, h := range s.Hosts {
			push(h.Host)
		}
	}
	return out
}

// secHosts 解析 --host（all = 配置里全部巡检主机）。
func secHosts(cfg *config.Config, sel string) []string {
	var all []string
	seen := map[string]bool{}
	add := func(h string) {
		if h != "" && !seen[h] {
			seen[h] = true
			all = append(all, h)
		}
	}
	for _, t := range inspectTargetHosts(cfg) {
		add(t)
	}
	if sel == "" || sel == "all" {
		return all
	}
	want := parseSet(sel)
	var out []string
	for _, h := range all {
		if want[h] {
			out = append(out, h)
		}
	}
	return out
}

func cmdHardenSecCheck(args []string) error {
	fs := flag.NewFlagSet("harden sec check", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	host := fs.String("host", "all", "主机（IP / all / 逗号分隔）")
	jsonOut := fs.String("json", "", "JSON 报告输出路径")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := gateValidation(cfg, false); err != nil {
		return err
	}
	hosts := secHosts(cfg, *host)
	if len(hosts) == 0 {
		return fmt.Errorf("没有匹配的主机")
	}
	dial := secDialer(cfg)
	rep := harden.NewSecReport("eops", hosts, time.Now())
	for _, h := range hosts {
		harden.SetCurrentHost(h, dial)
		harden.RunExposureCheck(h, rep)
		harden.RunNginxCheck(h, rep)
		harden.RunTomcatCheck(h, rep)
	}
	rep.SortFindings()
	return printSecReport(rep, *jsonOut)
}

func cmdHardenSecFix(args []string) error {
	fs := flag.NewFlagSet("harden sec fix", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	host := fs.String("host", "all", "主机（IP / all / 逗号分隔）")
	yes := fs.Bool("yes", false, "确认执行修复（默认 dry-run）")
	manifest := fs.String("manifest-out", "", "备份 manifest 输出路径")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := gateValidation(cfg, *yes); err != nil {
		return err
	}
	hosts := secHosts(cfg, *host)
	if len(hosts) == 0 {
		return fmt.Errorf("没有匹配的主机")
	}
	if !*yes {
		fmt.Println("（dry-run：将执行 nginx/tomcat 基线修复；改前逐文件备份，nginx -t 失败自动还原。确认后加 --yes）")
	}
	dial := secDialer(cfg)
	rep := harden.NewSecReport("eops", hosts, time.Now())
	for _, h := range hosts {
		harden.SetCurrentHost(h, dial)
		if err := harden.RunNginxFix(h, rep, *yes); err != nil {
			rep.AddError(fmt.Sprintf("nginx fix %s: %v", h, err))
		}
		if err := harden.RunTomcatFix(h, rep, *yes); err != nil {
			rep.AddError(fmt.Sprintf("tomcat fix %s: %v", h, err))
		}
	}
	rep.SortFindings()
	if *manifest != "" {
		b, jerr := json.MarshalIndent(harden.ManifestBackups(rep), "", "  ")
		if jerr == nil {
			_ = os.WriteFile(*manifest, append(b, '\n'), 0o644)
			fmt.Printf("备份 manifest: %s\n", *manifest)
		}
	}
	if !*yes {
		fmt.Println("（dry-run 完成，未落盘）")
		return nil
	}
	return printSecReport(rep, "")
}

func cmdHardenSecRollback(args []string) error {
	fs := flag.NewFlagSet("harden sec rollback", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	manifestPath := fs.String("manifest", "", "备份 manifest 文件（sec fix --manifest-out 产物）")
	yes := fs.Bool("yes", false, "确认回滚")
	fs.Parse(args)

	if *manifestPath == "" {
		return fmt.Errorf("--manifest 必填（sec fix 的备份清单）")
	}
	b, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}
	var entries []harden.BackupEntry
	if err := json.Unmarshal(b, &entries); err != nil {
		return fmt.Errorf("manifest 解析失败: %w", err)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := gateValidation(cfg, *yes); err != nil {
		return err
	}
	dial := secDialer(cfg)
	// 按主机分组回滚
	byHost := map[string][]harden.BackupEntry{}
	order := []string{}
	for _, e := range entries {
		h := hostOfBackup(e.Backup)
		if _, ok := byHost[h]; !ok {
			order = append(order, h)
		}
		byHost[h] = append(byHost[h], e)
	}
	for _, h := range order {
		harden.SetCurrentHost(h, dial)
		cmdStr, cerr := harden.RollbackCommand(byHost[h])
		if cerr != nil {
			return cerr
		}
		if !*yes {
			fmt.Printf("[将回滚] %s: %d 个文件\n", h, len(byHost[h]))
			continue
		}
		rn, derr := dial(h)
		if derr != nil {
			fmt.Printf("  ❌ %s SSH 连接失败: %v\n", h, derr)
			return fmt.Errorf("%s 连接失败", h)
		}
		out, rerr := rn.Run(cmdStr)
		if rerr != nil {
			fmt.Printf("  ❌ %s 回滚失败: %v\n%s\n", h, rerr, out)
			return fmt.Errorf("%s 回滚失败", h)
		}
		fmt.Printf("  ✅ %s 已回滚 %d 个文件\n", h, len(byHost[h]))
	}
	if !*yes {
		fmt.Println("（dry-run，未执行；确认后加 --yes）")
	}
	return nil
}

// hostOfBackup 从备份路径解析源主机（备份文件名含 host 段）。
// manifest 行形如 {origin: /etc/nginx/nginx.conf, backup: /egova/eops-sec-backup/<host>/<ts>/nginx.conf}。
func hostOfBackup(backupPath string) string {
	const marker = "/eops-sec-backup/"
	if i := strings.Index(backupPath, marker); i >= 0 {
		rest := backupPath[i+len(marker):]
		if j := strings.IndexByte(rest, '/'); j > 0 {
			return rest[:j]
		}
	}
	return "unknown"
}

// printSecReport 终端摘要 + 可选 JSON；检出条目数与阻塞级计数。
func printSecReport(rep *harden.SecReport, jsonOut string) error {
	rep.Text(os.Stdout)
	if jsonOut != "" {
		b, err := rep.JSON()
		if err != nil {
			return err
		}
		if werr := os.WriteFile(jsonOut, append(b, '\n'), 0o644); werr != nil {
			return werr
		}
		fmt.Printf("JSON 报告: %s\n", jsonOut)
	}
	return nil
}
