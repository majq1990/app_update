// eops（原名 app-updater）是统一运维工具的 Go 实现。
// 本阶段实现配置链路：Excel 模板生成 / 导入校验 / YAML 兼容 / 反向导出。
// 更新与回滚执行链路为后续阶段（命令已占位）。
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xuri/excelize/v2"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/oneinstall"
	"github.com/majq1990/app-updater-go/internal/sshx"
	"github.com/majq1990/app-updater-go/internal/xlsx"
)

const usage = `eops — 统一运维工具（应用更新/回滚 · 日志 · 备份 · 巡检 · 监控 · 加固）

直接运行（无参数）进入交互菜单模式；以下子命令供脚本化调用。
可用 eops version 查看版本。
用法:
  eops template [-o 模板.xlsx]          生成 Excel 配置模板
  eops import  -f 配置.xlsx [-o config.yaml]  导入+校验，生成 YAML
  eops validate -f 配置.xlsx            只校验不落盘
  eops export  -c config.yaml [-o 配置.xlsx]  YAML 反向导出 Excel（存量迁移核对）
  eops gen-from-oneinstall              从一键部署自动生成配置初稿。
      无参数时在本机自动识别（工具装在一键部署控制节点上可直接运行）；
      否则来源三选一:
      --ssh <主机> [--port N] [--user root] [--pass xxx | --key path]
          连接服务器自动识别：v2 inventory（/egova/onekey_install/oneinstall_v2/...）
          或 v1 现场约定（/egova/conf/install-multi.conf）
      --dir <本地inventory目录>                   本地 v2 三件套
      --conf <本地 install-multi.conf>            本地 v1 conf
      [-o 初稿.xlsx] [--yaml config.yaml] [--include-undeployed]
  eops setup-ssh -c config.yaml [--app 名称] [--pass xxx]
      确保本机密钥对存在，并把公钥推送到各主机的 authorized_keys（免密登录，
      纯 Go 实现，替代 sshpass+ssh-copy-id；密码优先级 --pass > 环境变量 > 配置）
  eops update -c config.yaml --app 名称  执行应用更新（源目录 update/<应用名>/）
      [--groups master,update]                  默认先 master 后 update
      [--static full|partial|jar]               静态页面更新模式（tomcat full 需先更代码群组）
      [--static-path view/css]                  partial 模式：应用内相对路径
      [--static-src 本地目录]                    jar 模式：本地静态文件目录
      [--dry-run] [--yes]                       不带 --yes 一律只出计划不执行
  eops rollback -c config.yaml --app 名称 [--version 备份版本]
      [--groups master,update,static] [--list] [--dry-run] [--yes]
  eops clean-update [--dir update] [--dry-run] [--yes]
      清理 update/ 下的历史更新包（交互菜单：配置管理 11）
  eops compress-backups [--dir backups] [--workers N] [--dry-run] [--yes]
      对未压缩的备份版本目录做多线程 tar.gz 压缩（交互菜单：配置管理 12）
  eops logs clean -c config.yaml [--app 名称|all] [--support kind|all] [--dry-run] [--yes]
      清理过期日志（应用 log_dir + supports 支持软件目录；白名单命中才删，dry-run 默认）
  eops logs gather -c config.yaml [--app 名称|all] [--support kind|all] [--window 4h] [--out 目录]
      拉取时间窗内的日志段到本地（远端 awk 过滤，只传命中行；catalina.out 走末尾 tail），
      并统计 ERROR/Exception 计数
  eops logs rotate check -c config.yaml [--app 名称|all] [--support kind|all]
      切割体检（只读）：logrotate 配置存在性/语法/覆盖漂移 + 未切割大文件 + 增长率预警
  eops logs rotate setup -c config.yaml [--app 名称|all] [--support kind|all] [--dry-run] [--yes] [--force]
      生成并推送 /etc/logrotate.d/ 片段（copytruncate 适配；推送后 logrotate -d 语法验证，
      绝不强制轮转；远端已有不同配置默认跳过，--force 才覆盖）
  eops backup run -c config.yaml [--app 名称|all] [--mysql] [--dry-run] [--yes]
      现场备份：应用目录打包（web_path）+ 可选数据库逻辑备份，产物落 backup.root（默认 /egova/backup）
  eops backup list -c config.yaml [--app 名称|all] [--mysql] [--json]
      列出现场已有备份（只认本工具 eops- 前缀产物），--json 输出台账
  eops backup verify -c config.yaml [--app 名称|all] [--mysql]
      校验备份完整性（gzip -t / tar -t / sha256 / 大小）
  eops backup prune -c config.yaml [--keep-days N] [--dry-run] [--yes]
      清理超过保留期的备份（只处理本工具 eops- 产物，绝不碰现场其他文件）
  eops backup report -c config.yaml [--out 台账.json] [--verify]
      导出台账 JSON（供项目管理表推送；--verify 同时校验并带 sha256）
  eops backup restore -c config.yaml --app 应用名 --file 备份包.tar.gz [--dry-run] [--yes]
      从现场 eops-*.tar.gz 恢复应用：停应用→变更前自动备份→解压→属主→启动→健康检查
      （默认 dry-run 打印完整计划；备份包必须位于 backup.root 下）
  eops backup push -c config.yaml [--verify] [--out payload.json]
      读现场台账生成 ztoa「项目备份中间表」行 payload（应用/数据库备份最新日期与间隔）；
      本命令不联网，真实写表由上层用 ztoa MCP 执行
  eops inspect run -c config.yaml [--dim os,security,middleware] [--host IP|all]
      [--json 报告.json] [--parallel 4] [--fail-on warn|error|critical|none]
      项目巡检：SSH 直连执行只读检查（OS/安全/中间件），终端摘要 + 可选 JSON 报告
  eops inspect security -c config.yaml [--json 报告.json]
      安全检查快捷入口（等同 --dim security）
  eops inspect list [--dim os|security|middleware]
      列出内置检查项
  eops monitor doctor -c config.yaml [--role agent|proxy|all] [--host IP|all] [--json 报告.json]
      监控诊断（只读）：agent/proxy 进程、端口、配置、插件、PSK、备份目录、云中心连通性
  eops monitor fix -c config.yaml [--role agent|proxy|all] [--dry-run] [--yes]
      白名单修复：仅 systemctl start/restart zabbix-agent|zabbix-proxy，默认 dry-run
  eops monitor plan -c config.yaml
      输出监控部署检查清单（对照 FAQ wiki，不执行）
  eops harden check -c config.yaml [--host IP|all]
      安全加固清单（只读）：把安全巡检发现映射成加固建议与风险级别
  eops harden snippets -c config.yaml
      输出可粘贴的加固片段（sshd/sysctl/防火墙），人工确认后执行
  eops harden report -c config.yaml [--out 台账.json]
      导出加固台账 JSON
  eops version                          查看版本
`

// cliArgs 复刻 os.Args 的受控副本：只读一次，之后全程序（含子命令 flag 解析）
// 只消费这份数据，不再直接引用 os.Args。
// 防注入设计：所有进入 flag 解析的字符串都是「值」，没有任何一条链路把它拼进 shell；
// 变更类操作另被 config.ShellSafetyIssues + gateValidation 双闸拦截（详见 internal/config/shellsafe.go）。
var cliArgs []string

// initCliArgs 在 main 最先执行，固定 os.Args 的副本。
func initCliArgs() {
	cliArgs = make([]string, len(os.Args))
	for i, a := range os.Args {
		// 剔除控制字符（参数值里出现 \n/\r/\x00 属于异常输入，直接截断处理）
		buf := []byte(a)
		out := buf[:0]
		for _, b := range buf {
			if b >= 0x20 || b == '\t' {
				out = append(out, b)
			}
		}
		cliArgs[i] = string(out)
	}
}

func main() {
	initCliArgs()
	// 首次运行构建完整工作目录（update/backups/logs，幂等）。
	// 仅交互模式与执行类命令需要；纯查询类（version/help/compress 自定义目录）不打扰。
	if len(cliArgs) < 2 {
		if created := ensureWorkspace(); len(created) > 0 {
			fmt.Printf("已初始化工作目录: %s\n", strings.Join(created, "/ "))
		}
		runInteractive() // 无参数 = 交互模式（菜单式，对齐旧版操作习惯）
		return
	}
	var err error
	switch cliArgs[1] {
	case "update", "rollback", "setup-ssh", "clean-update", "compress-backups":
		if created := ensureWorkspace(); len(created) > 0 {
			fmt.Printf("已初始化工作目录: %s\n", strings.Join(created, "/ "))
		}
	}
	switch cliArgs[1] {
	case "template":
		err = cmdTemplate(cliArgs[2:])
	case "import":
		err = cmdImport(cliArgs[2:])
	case "validate":
		err = cmdValidate(cliArgs[2:])
	case "export":
		err = cmdExport(cliArgs[2:])
	case "gen-from-oneinstall":
		err = cmdGenFromOneinstall(cliArgs[2:])
	case "setup-ssh":
		err = cmdSetupSSH(cliArgs[2:])
	case "update":
		err = cmdUpdate(cliArgs[2:])
	case "rollback":
		err = cmdRollback(cliArgs[2:])
	case "clean-update":
		err = cmdCleanUpdate(cliArgs[2:])
	case "compress-backups":
		err = cmdCompressBackups(cliArgs[2:])
	case "logs":
		if len(cliArgs) > 2 {
			sub := cliArgs[2]
			if sub == "clean" || sub == "gather" {
				if created := ensureWorkspace(); len(created) > 0 {
					fmt.Printf("已初始化工作目录: %s\n", strings.Join(created, "/ "))
				}
				if sub == "clean" {
					err = cmdLogsClean(cliArgs[3:])
				} else {
					err = cmdLogsGather(cliArgs[3:])
				}
			} else if sub == "rotate" {
				err = cmdLogsRotate(cliArgs[3:])
			} else {
				err = fmt.Errorf("用法: eops logs clean|gather|rotate ... -c config.yaml（详见 eops 帮助）")
			}
		} else {
			err = fmt.Errorf("用法: eops logs clean|gather|rotate ... -c config.yaml（详见 eops 帮助）")
		}
	case "backup":
		err = cmdBackup(cliArgs[2:])
	case "inspect":
		err = cmdInspect(cliArgs[2:])
	case "monitor":
		err = cmdMonitor(cliArgs[2:])
	case "harden":
		err = cmdHarden(cliArgs[2:])
	case "version", "-v", "--version":
		fmt.Println(versionString())
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n%s", cliArgs[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

// genSource 一键部署识别来源。
type genSource struct {
	SSHHost           string
	SSHPort           int
	SSHUser           string
	SSHPass           string
	KeyPath           string
	Dir               string
	Conf              string
	IncludeUndeployed bool
}

// loadGenConfig 按来源识别一键部署并转换为配置（不落盘）。
// 来源优先级：SSH > Dir > Conf > 本机自动识别。
func loadGenConfig(src genSource) (*config.Config, []config.Issue, string, error) {
	var (
		cfg    *config.Config
		notes  []config.Issue
		source string
		err    error
	)

	switch {
	case src.SSHHost != "":
		// SSH 密码获取走单点函数（含环境变量回退）；
		// 该值仅作为 sshx.Auth.Password 传给 SSH 认证库，不拼 shell、不写文件、不进日志。
		pass := sshPassOrDefault(src.SSHPass)
		cli, cerr := sshx.Connect(sshx.Auth{
			Host: src.SSHHost, Port: src.SSHPort, User: src.SSHUser, Password: pass, KeyPath: src.KeyPath,
		})
		if cerr != nil {
			return nil, nil, "", cerr
		}
		defer cli.Close()

		det, derr := oneinstall.DetectRemote(cli)
		if derr != nil {
			return nil, nil, "", derr
		}
		source = fmt.Sprintf("%s [%s]", det.Source, det.Mode)
		if det.Mode == "v2" {
			cfg, notes, err = oneinstall.Convert(det.Inv, oneinstall.Options{IncludeUndeployed: src.IncludeUndeployed})
		} else {
			var conf map[string]string
			if conf, err = oneinstall.ParseInstallMultiConf(det.V1Conf); err == nil {
				cfg, notes, err = oneinstall.ConvertV1(conf)
			}
		}
	case src.Dir != "":
		read := func(name string) ([]byte, error) {
			return os.ReadFile(filepath.Join(src.Dir, name))
		}
		inv := oneinstall.Inventory{}
		if inv.Hosts, err = read("hosts.yml"); err != nil {
			return nil, nil, "", err
		}
		if inv.Metadata, err = read("metadata.yml"); err != nil {
			return nil, nil, "", err
		}
		haveGroup := false
		for _, gf := range []struct {
			name string
			dst  *[]byte
		}{
			{"eurbanpro_multi_server.yml", &inv.MultiServer},
			{"multi_server.yml", &inv.MultiServerBase},
			{"mjing_multi_server.yml", &inv.MultiServerMjing},
		} {
			if data, gerr := read(gf.name); gerr == nil && len(data) > 0 {
				haveGroup = true
				*gf.dst = data
			}
		}
		if !haveGroup {
			return nil, nil, "", fmt.Errorf("目录中未找到任何服务组配置（eurbanpro_multi_server.yml / multi_server.yml / mjing_multi_server.yml 至少其一）")
		}
		source = src.Dir + " [v2]"
		cfg, notes, err = oneinstall.Convert(inv, oneinstall.Options{IncludeUndeployed: src.IncludeUndeployed})
	case src.Conf != "":
		data, rerr := os.ReadFile(src.Conf)
		if rerr != nil {
			return nil, nil, "", rerr
		}
		var conf map[string]string
		if conf, err = oneinstall.ParseInstallMultiConf(data); err != nil {
			return nil, nil, "", err
		}
		source = src.Conf + " [v1]"
		cfg, notes, err = oneinstall.ConvertV1(conf)
	default:
		// 未指定来源：在本机自动识别（工具装在一键部署控制节点时零参数使用）
		det, ok := oneinstall.DetectLocal()
		if !ok {
			return nil, nil, "", fmt.Errorf("本机未识别到一键部署信息，请用 --ssh / --dir / --conf 指定来源")
		}
		source = fmt.Sprintf("%s [%s·本机自动识别]", det.Source, det.Mode)
		if det.Mode == "v2" {
			cfg, notes, err = oneinstall.Convert(det.Inv, oneinstall.Options{IncludeUndeployed: src.IncludeUndeployed})
		} else {
			var conf map[string]string
			if conf, err = oneinstall.ParseInstallMultiConf(det.V1Conf); err == nil {
				cfg, notes, err = oneinstall.ConvertV1(conf)
			}
		}
	}
	if err != nil {
		return nil, nil, "", err
	}
	if len(cfg.Webs) == 0 {
		return nil, nil, source, fmt.Errorf("没有生成任何应用（当前部署信息中没有 status=success 的应用；部署未完成可加 --include-undeployed）")
	}
	return cfg, notes, source, nil
}

func cmdGenFromOneinstall(args []string) error {
	fs := flag.NewFlagSet("gen-from-oneinstall", flag.ExitOnError)
	sshHost := fs.String("ssh", "", "远端服务器地址（自动识别 v2 inventory / v1 install-multi.conf）")
	sshPort := fs.Int("port", 22, "SSH 端口")
	sshUser := fs.String("user", "root", "SSH 用户")
	sshPass := fs.String("pass", "", "SSH 密码（留空先试默认私钥；也可用环境变量 APP_UPDATER_SSH_PASS）")
	keyPath := fs.String("key", "", "SSH 私钥路径（默认 ~/.ssh/id_rsa）")
	dir := fs.String("dir", "", "本地 inventory 目录（v2 三件套）")
	confFile := fs.String("conf", "", "本地 install-multi.conf（v1）")
	out := fs.String("o", "app_updater_初稿.xlsx", "输出 Excel 初稿路径")
	yamlOut := fs.String("yaml", "", "同时输出 YAML 配置到指定路径（可选）")
	all := fs.Bool("include-undeployed", false, "包含 status=undeployed 的应用（仅 v2 有效）")
	fs.Parse(args)

	cfg, notes, source, err := loadGenConfig(genSource{
		SSHHost: *sshHost, SSHPort: *sshPort, SSHUser: *sshUser, SSHPass: *sshPass,
		KeyPath: *keyPath, Dir: *dir, Conf: *confFile, IncludeUndeployed: *all,
	})
	if err != nil {
		return err
	}

	fmt.Println("配置来源:", source)
	printIssues(notes)
	return writeGenOutput(cfg, *out, *yamlOut)
}

func writeGenOutput(cfg *config.Config, xlsxPath, yamlPath string) error {
	// 与 Excel 导入链路保持一致：未配置全局日志排除时预填默认值，
	// 使「gen 直出 YAML」与「初稿表格 → import」两条路产物对齐。
	if len(cfg.GlobalExcludeLogs) == 0 {
		cfg.GlobalExcludeLogs = []string{"*.log", "logs/"}
	}
	f := excelize.NewFile()
	defer f.Close()
	if err := xlsx.BuildFromConfig(f, cfg); err != nil {
		return err
	}
	if err := f.SaveAs(xlsxPath); err != nil {
		return err
	}
	fmt.Printf("初稿已生成: %s（%d 个应用）\n", xlsxPath, len(cfg.Webs))
	if yamlPath != "" {
		if err := cfg.Save(yamlPath); err != nil {
			return err
		}
		fmt.Printf("YAML 已生成: %s\n", yamlPath)
	}
	issues := cfg.Validate()
	printIssues(issues)
	if config.HasError(issues) {
		return fmt.Errorf("生成的配置未通过自检，请核对上方错误")
	}
	return nil
}

func cmdTemplate(args []string) error {
	fs := flag.NewFlagSet("template", flag.ExitOnError)
	out := fs.String("o", "app_updater_配置模板.xlsx", "输出文件路径")
	fs.Parse(args)

	f := excelize.NewFile()
	defer f.Close()
	if err := xlsx.BuildTemplate(f); err != nil {
		return err
	}
	if err := f.SaveAs(*out); err != nil {
		return err
	}
	fmt.Println("模板已生成:", *out)
	return nil
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	file := fs.String("f", "", "Excel 配置文件")
	out := fs.String("o", "config/config.yaml", "输出 YAML 路径")
	fs.Parse(args)
	if *file == "" {
		return fmt.Errorf("必须用 -f 指定 Excel 文件")
	}

	cfg, issues, err := xlsx.Import(*file)
	if err != nil {
		return err
	}
	issues = append(issues, cfg.Validate()...)
	printIssues(issues)
	if config.HasError(issues) {
		return fmt.Errorf("校验未通过，已放弃生成 %s", *out)
	}
	if err := cfg.Save(*out); err != nil {
		return err
	}
	fmt.Printf("校验通过，已生成 %s（%d 个应用）\n", *out, len(cfg.Webs))
	return nil
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	file := fs.String("f", "", "Excel 配置文件")
	fs.Parse(args)
	if *file == "" {
		return fmt.Errorf("必须用 -f 指定 Excel 文件")
	}

	cfg, issues, err := xlsx.Import(*file)
	if err != nil {
		return err
	}
	issues = append(issues, cfg.Validate()...)
	printIssues(issues)
	if config.HasError(issues) {
		return fmt.Errorf("发现错误")
	}
	fmt.Println("校验通过")
	return nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	cfgPath := fs.String("c", "config/config.yaml", "YAML 配置文件")
	out := fs.String("o", "app_updater_导出.xlsx", "输出 Excel 路径")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	f := excelize.NewFile()
	defer f.Close()
	if err := xlsx.BuildFromConfig(f, cfg); err != nil {
		return err
	}
	if err := f.SaveAs(*out); err != nil {
		return err
	}
	fmt.Printf("已导出 %s（%d 个应用）\n", *out, len(cfg.Webs))
	return nil
}

func printIssues(issues []config.Issue) {
	if len(issues) == 0 {
		return
	}
	fmt.Println("---- 校验结果 ----")
	for _, is := range issues {
		fmt.Println(is.String())
	}
}
