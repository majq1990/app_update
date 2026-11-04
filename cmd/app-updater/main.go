// app-updater 是 Java 应用更新工具的 Go 重写版。
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

const usage = `app-updater — Java 应用更新工具 (Go 版)

直接运行（无参数）进入交互菜单模式；以下子命令供脚本化调用。
可用 app-updater version 查看版本。
用法:
  app-updater template [-o 模板.xlsx]          生成 Excel 配置模板
  app-updater import  -f 配置.xlsx [-o config.yaml]  导入+校验，生成 YAML
  app-updater validate -f 配置.xlsx            只校验不落盘
  app-updater export  -c config.yaml [-o 配置.xlsx]  YAML 反向导出 Excel（存量迁移核对）
  app-updater gen-from-oneinstall              从一键部署自动生成配置初稿。
      无参数时在本机自动识别（工具装在一键部署控制节点上可直接运行）；
      否则来源三选一:
      --ssh <主机> [--port N] [--user root] [--pass xxx | --key path]
          连接服务器自动识别：v2 inventory（/egova/onekey_install/oneinstall_v2/...）
          或 v1 现场约定（/egova/conf/install-multi.conf）
      --dir <本地inventory目录>                   本地 v2 三件套
      --conf <本地 install-multi.conf>            本地 v1 conf
      [-o 初稿.xlsx] [--yaml config.yaml] [--include-undeployed]
  app-updater setup-ssh -c config.yaml [--app 名称] [--pass xxx]
      确保本机密钥对存在，并把公钥推送到各主机的 authorized_keys（免密登录，
      纯 Go 实现，替代 sshpass+ssh-copy-id；密码优先级 --pass > 环境变量 > 配置）
  app-updater update -c config.yaml --app 名称  执行应用更新（源目录 update/<应用名>/）
      [--groups master,update]                  默认先 master 后 update
      [--static full|partial|jar]               静态页面更新模式（tomcat full 需先更代码群组）
      [--static-path view/css]                  partial 模式：应用内相对路径
      [--static-src 本地目录]                    jar 模式：本地静态文件目录
      [--dry-run] [--yes]                       不带 --yes 一律只出计划不执行
  app-updater rollback -c config.yaml --app 名称 [--version 备份版本]
      [--groups master,update,static] [--list] [--dry-run] [--yes]
  app-updater clean-update [--dir update] [--dry-run] [--yes]
      清理 update/ 下的历史更新包（交互菜单：配置管理 11）
  app-updater compress-backups [--dir backups] [--workers N] [--dry-run] [--yes]
      对未压缩的备份版本目录做多线程 tar.gz 压缩（交互菜单：配置管理 12）
  app-updater version                          查看版本
`

func main() {
	// 首次运行构建完整工作目录（update/backups/logs，幂等）。
	// 仅交互模式与执行类命令需要；纯查询类（version/help/compress 自定义目录）不打扰。
	if len(os.Args) < 2 {
		if created := ensureWorkspace(); len(created) > 0 {
			fmt.Printf("已初始化工作目录: %s\n", strings.Join(created, "/ "))
		}
		runInteractive() // 无参数 = 交互模式（菜单式，对齐旧版操作习惯）
		return
	}
	var err error
	switch os.Args[1] {
	case "update", "rollback", "setup-ssh", "clean-update", "compress-backups":
		if created := ensureWorkspace(); len(created) > 0 {
			fmt.Printf("已初始化工作目录: %s\n", strings.Join(created, "/ "))
		}
	}
	switch os.Args[1] {
	case "template":
		err = cmdTemplate(os.Args[2:])
	case "import":
		err = cmdImport(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "gen-from-oneinstall":
		err = cmdGenFromOneinstall(os.Args[2:])
	case "setup-ssh":
		err = cmdSetupSSH(os.Args[2:])
	case "update":
		err = cmdUpdate(os.Args[2:])
	case "rollback":
		err = cmdRollback(os.Args[2:])
	case "clean-update":
		err = cmdCleanUpdate(os.Args[2:])
	case "compress-backups":
		err = cmdCompressBackups(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println(versionString())
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n%s", os.Args[1], usage)
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
		pass := src.SSHPass
		if pass == "" {
			pass = os.Getenv("APP_UPDATER_SSH_PASS")
		}
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
