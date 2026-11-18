package main

// harden_sec_init_cmd.go —— `eops harden sec init`：安全加固工具箱初始化。
//
// 做三件事：
//  1. 生成 config.yaml 模板（给 --hosts 时直接填入主机），已存在则不覆盖（除非 --force）；
//  2. 体检依赖文件：公司版本库 / 互联网最新版缓存 / 判定清单 / SSH 私钥；
//  3. 逐主机探活 SSH（只做一次 echo，不落盘、不改配置）。
//
// 设计口径：初始化只读本地文件 + 只读 SSH 探测，不写远端、不改远端配置。

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/harden"
	"github.com/majq1990/app-updater-go/internal/sshx"
)

const secInitTemplate = `# eops 安全加固配置（由 eops harden sec init 生成）
# 说明：安全体检只需要「主机 + SSH 凭据」；webs/supports 用于把主机分组归类。
ansible_user: root
ansible_ssh_port: 22

webs:
  - web: core
    middle_type: tomcat
    master:
      - host: 10.0.0.1            # 换成目标机 IP
        web_path: /egova/web/core # 应用部署路径（jar 扫描/配置体检会用到）
        user: egova
        ssh_user: root
        ssh_port: 22
        # ssh_pass: "口令"        # 用口令认证时填；用密钥则留空，走 --key 或 ~/.ssh/id_rsa
    update:
      - host: 10.0.0.1
        web_path: /egova/web/core
        user: egova

# 支持软件（数据库/redis/nginx 等）也要体检时补这里
# supports:
#   - name: mysql
#     hosts:
#       - host: 10.0.0.1
#         ssh_user: root
`

func cmdHardenSecInit(args []string) error {
	fs := flag.NewFlagSet("harden sec init", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "要生成/检查的配置文件路径")
	hostsCSV := fs.String("hosts", "", "目标主机（逗号分隔），给出则写入模板并逐个探活")
	outDir := fs.String("out-dir", ".", "知识库文件存放目录（放 safe_versions_company.json 等）")
	force := fs.Bool("force", false, "覆盖已存在的 config.yaml")
	noProbe := fs.Bool("no-probe", false, "跳过 SSH 探活")
	fs.StringVar(&secKeyPath, "key", "", "SSH 私钥路径（默认 ~/.ssh/id_rsa）")
	fs.StringVar(&secPass, "pass", "", "SSH 口令（也可用 APP_UPDATER_SSH_PASS）")
	fs.Parse(args)

	fmt.Println("==== eops 安全加固工具箱 · 初始化 ====")

	// ---- 1. 生成配置模板 ----
	hosts := splitCSV(*hostsCSV)
	if _, err := os.Stat(*cfgPath); err == nil && !*force {
		fmt.Printf("[配置] 已存在，跳过生成：%s（如需重建加 --force）\n", *cfgPath)
	} else {
		body := secInitTemplate
		if len(hosts) > 0 {
			body = renderTemplate(hosts)
		}
		if err := os.WriteFile(*cfgPath, []byte(body), 0o644); err != nil {
			return fmt.Errorf("写配置失败: %w", err)
		}
		fmt.Printf("[配置] 已生成：%s（主机 %d 台）\n", *cfgPath, len(hosts))
	}

	// ---- 2. 依赖文件体检 ----
	fmt.Println("[知识库] 依赖文件检查：")
	checkFile := func(name string, required bool) bool {
		p := filepath.Join(*outDir, name)
		if st, err := os.Stat(p); err == nil {
			fmt.Printf("   ✅ %-32s %d bytes\n", name, st.Size())
			return true
		}
		if required {
			fmt.Printf("   ❌ %-32s 缺失（必需）\n", name)
		} else {
			fmt.Printf("   ⚪ %-32s 未提供（可选）\n", name)
		}
		return false
	}
	checkFile("safe_versions_company.json", false) // 缺省用内置 28 项 jar 基线
	checkFile("maven_latest.json", false)          // 缺省不比对互联网最新版
	checkFile("secure-versions.flat", false)       // shell 工具箱的判定清单

	// 内置版本库规模提示，便于判断是否已覆盖现场组件
	fmt.Printf("   内置依赖基线：%d 项 jar（%s）\n",
		len(harden.DepTable()), strings.Join([]string{"fastjson", "log4j", "jackson", "xstream", "rocketmq"}, "/"))

	// ---- 3. SSH 凭据 ----
	fmt.Println("[SSH] 凭据检查：")
	key := secKeyPath
	if key == "" {
		if h, err := os.UserHomeDir(); err == nil {
			cand := filepath.Join(h, ".ssh", "id_rsa")
			if _, err := os.Stat(cand); err == nil {
				key = cand
			}
		}
	}
	if key != "" {
		fmt.Printf("   ✅ 私钥：%s\n", key)
	} else if secPass != "" || os.Getenv("APP_UPDATER_SSH_PASS") != "" {
		fmt.Println("   ✅ 使用口令认证（--pass / APP_UPDATER_SSH_PASS）")
	} else {
		fmt.Println("   ⚠️ 未发现默认私钥且未提供口令：请配 ~/.ssh/id_rsa、或加 --key/--pass")
	}

	// ---- 4. 配置可解析性 + 主机清单 ----
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Printf("   ❌ 配置解析失败：%v\n", err)
		return err
	}
	targets := inspectTargetHosts(cfg)
	fmt.Printf("[配置] 解析成功，巡检主机 %d 台：%s\n", len(targets), strings.Join(targets, ", "))
	if len(targets) == 0 {
		fmt.Println("   ⚠️ 没有任何主机：请在 webs/supports 里填 host")
	}

	// ---- 5. SSH 探活 ----
	if !*noProbe && len(targets) > 0 {
		fmt.Println("[探活] SSH 连通性（只执行 echo，不改远端）：")
		dial := secDialerFrom(cfg)
		for _, h := range targets {
			rn, derr := dial(h)
			if derr != nil {
				fmt.Printf("   ❌ %-16s 连接失败：%v\n", h, derr)
				continue
			}
			start := time.Now()
			out, rerr := rn.Run("echo sec-init-ok")
			if rerr != nil || !strings.Contains(out, "sec-init-ok") {
				fmt.Printf("   ❌ %-16s 执行失败：%v\n", h, rerr)
				continue
			}
			fmt.Printf("   ✅ %-16s 连通（%d ms）\n", h, time.Since(start).Milliseconds())
		}
	}

	// ---- 6. 下一步 ----
	fmt.Println("")
	fmt.Println("下一步（按顺序）：")
	fmt.Printf("  1) 编辑 %s：确认 host / web_path / ssh_user\n", *cfgPath)
	fmt.Printf("  2) %s harden sec check -c %s\n", filepath.Base(os.Args[0]), *cfgPath)
	fmt.Printf("  3) %s harden sec knowledge check -c %s --json report.json\n", filepath.Base(os.Args[0]), *cfgPath)
	fmt.Printf("  4) 需要修复时先 dry-run：%s harden sec fix -c %s（确认后加 --yes）\n",
		filepath.Base(os.Args[0]), *cfgPath)
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// renderTemplate 按给定主机生成最小可用配置（每台一个 app 组）。
func renderTemplate(hosts []string) string {
	var b strings.Builder
	b.WriteString("# eops 安全加固配置（由 eops harden sec init --hosts 生成）\n")
	b.WriteString("ansible_user: root\nansible_ssh_port: 22\n\nwebs:\n")
	for i, h := range hosts {
		fmt.Fprintf(&b, "  - web: node%d\n    middle_type: tomcat\n    master:\n", i+1)
		fmt.Fprintf(&b, "      - host: %s\n        web_path: /egova\n", h)
		b.WriteString("        user: egova\n        ssh_user: root\n        ssh_port: 22\n")
		b.WriteString("    update: []\n")
	}
	return b.String()
}

// secDialerFrom 与 secDialer 同逻辑，但避免 init 里重复构造 execDialer 的耦合。
func secDialerFrom(cfg *config.Config) func(string) (harden.SecRunner, error) {
	over := sshx.Auth{
		Password: firstStr(secPass, os.Getenv("APP_UPDATER_SSH_PASS")),
		KeyPath:  secKeyPath,
	}
	d := &execDialer{cfg: cfg, over: over}
	cache := map[string]harden.SecRunner{}
	return func(host string) (harden.SecRunner, error) {
		if r, ok := cache[host]; ok {
			return r, nil
		}
		c, err := d.Dial(config.Host{Host: host})
		if err != nil {
			return nil, err
		}
		sr, ok := c.(harden.SecRunner)
		if !ok {
			return nil, fmt.Errorf("%s 连接不支持脚本下发", host)
		}
		cache[host] = sr
		return sr, nil
	}
}
