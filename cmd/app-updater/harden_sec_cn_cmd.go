package main

// harden_sec_cn_cmd.go —— 境外 IP 默认拉黑（cn 子命令）。
//
//	eops harden sec cn status  -c config.yaml
//	eops harden sec cn enable  -c config.yaml --allow 1.2.3.4/32,172.21.133.0/24 --yes
//	eops harden sec cn disable -c config.yaml --yes

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/harden"
)

func cmdHardenSecCN(args []string) error {
	if len(args) == 0 || (args[0] != "status" && args[0] != "enable" && args[0] != "disable") {
		return fmt.Errorf("用法: eops harden sec cn status|enable|disable -c config.yaml [--host IP] [--allow CIDR,...] [--yes]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("harden sec cn "+sub, flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件")
	host := fs.String("host", "all", "主机（IP / all / 逗号分隔）")
	allow := fs.String("allow", "", "额外放行 CIDR（逗号分隔，如运维出口 IP、VPC 网段）")
	yes := fs.Bool("yes", false, "确认执行（enable/disable 默认 dry-run）")
	jsonOut := fs.String("json", "", "JSON 报告输出路径")
	fs.StringVar(&secKeyPath, "key", "", "SSH 私钥路径（默认 ~/.ssh/id_rsa）")
	fs.StringVar(&secPass, "pass", "", "SSH 口令（也可用 APP_UPDATER_SSH_PASS）")
	fs.Parse(args[1:])

	var allowList []string
	for _, a := range strings.Split(*allow, ",") {
		if t := strings.TrimSpace(a); t != "" {
			allowList = append(allowList, t)
		}
	}

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

	dial := secDialer(cfg)
	rep := harden.NewSecReport("cn", hosts, time.Now())
	for _, h := range hosts {
		harden.SetCurrentHost(h, dial)
		switch sub {
		case "status":
			harden.RunCNStatus(h, rep)
		case "enable":
			if e := harden.RunCNEnable(h, rep, *yes, allowList); e != nil {
				rep.AddError(fmt.Sprintf("cn enable %s: %v", h, e))
			}
		case "disable":
			if e := harden.RunCNDisable(h, rep, *yes); e != nil {
				rep.AddError(fmt.Sprintf("cn disable %s: %v", h, e))
			}
		}
	}
	rep.SortFindings()
	if sub != "status" && !*yes {
		fmt.Println("（dry-run 完成，未落盘；确认后加 --yes）")
		return nil
	}
	return printSecReport(rep, *jsonOut)
}
