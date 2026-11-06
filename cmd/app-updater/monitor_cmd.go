package main

// 监控运维子命令：monitor doctor / fix / plan。
// doctor 只读诊断；fix 只执行白名单动作（重启 agent/proxy），默认 dry-run。

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/inspect"
	"github.com/majq1990/app-updater-go/internal/monitor"
)

func cmdMonitor(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: app-updater monitor doctor|fix|plan -c config.yaml [选项]")
	}
	switch args[0] {
	case "doctor":
		return cmdMonitorDoctor(args[1:])
	case "fix":
		return cmdMonitorFix(args[1:])
	case "plan":
		return cmdMonitorPlan(args[1:])
	default:
		return fmt.Errorf("未知 monitor 子命令: %s（可用 doctor|fix|plan）", args[0])
	}
}

func cmdMonitorDoctor(args []string) error {
	fs := flag.NewFlagSet("monitor doctor", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	role := fs.String("role", "all", "角色过滤：agent|proxy|all")
	host := fs.String("host", "all", "主机过滤：IP / all / 逗号分隔")
	jsonOut := fs.String("json", "", "JSON 报告输出路径")
	fs.Parse(args)

	cfg, targets, err := monitorCfg(*cfgPath, *role, *host)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println("没有匹配的监控诊断目标（可在 monitor.proxy_hosts / agent_hosts 配置）")
		return nil
	}
	fmt.Printf("监控诊断 %d 个目标（agent 端口 %d / proxy 端口 %d / 云中心 %s:%d）...\n",
		len(targets), cfg.Monitor.EffectiveAgentPort(), cfg.Monitor.EffectiveProxyPort(),
		cfg.Monitor.EffectiveServer(), cfg.Monitor.EffectiveServerPort())

	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()
	results := monitor.Results(cfg, targets, func(h config.Host) (inspect.Conn, error) { return dial.Dial(h) })

	rep := inspect.BuildReport(results, time.Now())
	rep.Text(os.Stdout)

	if *jsonOut != "" {
		b, jerr := rep.JSON()
		if jerr != nil {
			return jerr
		}
		if werr := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); werr != nil {
			return werr
		}
		fmt.Printf("JSON 报告: %s\n", *jsonOut)
	}
	return nil
}

// cmdMonitorFix 只执行白名单动作（重启 agent/proxy）；默认 dry-run。
func cmdMonitorFix(args []string) error {
	fs := flag.NewFlagSet("monitor fix", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	role := fs.String("role", "all", "角色过滤：agent|proxy|all")
	dryRun := fs.Bool("dry-run", false, "只出修复计划")
	yes := fs.Bool("yes", false, "确认执行白名单修复动作")
	fs.Parse(args)

	cfg, targets, err := monitorCfg(*cfgPath, *role, "all")
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println("没有匹配的监控诊断目标")
		return nil
	}
	dial := &execDialer{cfg: cfg, over: sshOverride()}
	defer dial.Close()

	results := monitor.Results(cfg, targets, func(h config.Host) (inspect.Conn, error) { return dial.Dial(h) })
	plan := monitor.FixPlan(results)
	if len(plan) == 0 {
		fmt.Println("没有可自动修复的服务类问题（其余问题见 doctor 报告，需人工处理）")
		return nil
	}
	fmt.Printf("修复计划（白名单动作）%d 条：\n", len(plan))
	for _, a := range plan {
		fmt.Printf("  %s [%s] %s   ← %s\n", a.Host.Host, a.Role, a.Cmd, a.Why)
	}
	dry := *dryRun || !*yes
	if dry {
		fmt.Println("\n（dry-run，未执行；确认后加 --yes）")
		return nil
	}

	okN, failN := 0, 0
	hostByIP := map[string]config.Host{}
	for _, t := range targets {
		hostByIP[t.Host.Host] = t.Host
	}
	for _, a := range plan {
		cmdStr, cerr := monitor.FixCommand(a)
		if cerr != nil {
			fmt.Printf("  ❌ %v\n", cerr)
			failN++
			continue
		}
		c, derr := dial.Dial(hostByIP[a.Host.Host])
		if derr != nil {
			fmt.Printf("  ❌ %s SSH 连接失败: %v\n", a.Host.Host, derr)
			failN++
			continue
		}
		out, rerr := c.Run(cmdStr)
		if rerr != nil {
			fmt.Printf("  ❌ %s %s 失败: %v\n%s\n", a.Host.Host, cmdStr, rerr, indent(out, "    "))
			failN++
			continue
		}
		fmt.Printf("  ✅ %s %s\n", a.Host.Host, cmdStr)
		okN++
	}
	fmt.Printf("\n修复完成：成功 %d / 失败 %d\n", okN, failN)
	if failN > 0 {
		return fmt.Errorf("%d 个修复动作失败", failN)
	}
	return nil
}

// cmdMonitorPlan 输出监控部署/更新检查清单（只读，不执行）。
func cmdMonitorPlan(args []string) error {
	fs := flag.NewFlagSet("monitor plan", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := gateValidation(cfg, false); err != nil {
		return err
	}
	m := cfg.Monitor
	fmt.Printf(`监控部署检查清单（对照 FAQ wiki《监控相关》）

拓扑：云中心 %s:%d ← 主控机(proxy %d) ← 受控机(agent %d)

主控机：
  1. 与受控机同网段；22 / %d / %d 双向互通
  2. 先装本地 yum 源（端口 %d，避开 %d/%d），再装 ansible
  3. zabbix-proxy 配置：Server=%s:%d、Hostname=项目名(<=15 字符拼音)
  4. 受控机清单由一键部署 /egova/conf/install-multi.conf 生成（或由本工具配置导出）

受控机：
  1. 从主控机本地 yum 源离线安装 zabbix-agent（端口 %d）
  2. userparameter 片段 → %s，脚本 → %s（zabbix:zabbix 0755）
  3. 主动/被动模式与云中心一致；PSK 文件权限 600
  4. 备份目录监控清单：%s/backup_dirs.txt（backup run 会自动登记）

执行顺序：先 doctor 全面诊断 → 按报告修复 → 再跑 doctor 确认转绿。
`,
		m.EffectiveServer(), m.EffectiveServerPort(), m.EffectiveProxyPort(), m.EffectiveAgentPort(),
		m.EffectiveAgentPort(), m.EffectiveProxyPort(), m.EffectiveYumPort(),
		m.EffectiveAgentPort(), m.EffectiveProxyPort(),
		m.EffectiveServer(), m.EffectiveServerPort(),
		m.EffectiveAgentPort(), m.EffectivePluginDir(), m.EffectiveScriptDir(), m.EffectivePluginDir())
	return nil
}

// monitorCfg 加载配置并筛选诊断目标。
func monitorCfg(path, role, hostSel string) (*config.Config, []monitor.Target, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, err
	}
	if err := gateValidation(cfg, false); err != nil {
		return nil, nil, err
	}
	targets := monitor.Targets(cfg)
	wantHost := parseSet(hostSel)
	var out []monitor.Target
	for _, t := range targets {
		if !wantHost["all"] && !wantHost[t.Host.Host] {
			continue
		}
		switch strings.ToLower(role) {
		case "agent":
			if t.Role != monitor.RoleAgent {
				continue
			}
		case "proxy":
			if t.Role != monitor.RoleProxy {
				continue
			}
		}
		out = append(out, t)
	}
	return cfg, out, nil
}
