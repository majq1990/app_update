package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Issue 一条校验结果。
type Issue struct {
	Severity string // "error" | "warn"
	Where    string // 位置，如 "主机清单!第5行" 或 "应用清单>eUrbanGIS"
	Msg      string
}

func (i Issue) String() string {
	tag := "⚠️ "
	if i.Severity == "error" {
		tag = "❌"
	}
	return fmt.Sprintf("%s [%s] %s", tag, i.Where, i.Msg)
}

// HasError 是否存在错误级问题。
func HasError(issues []Issue) bool {
	for _, is := range issues {
		if is.Severity == "error" {
			return true
		}
	}
	return false
}

// Validate 对整份配置做完整性校验，返回全部问题（错误+警告）。
func (c *Config) Validate() []Issue {
	var issues []Issue

	// ---- 全局设置 ----
	if strings.TrimSpace(c.AnsibleUser) == "" {
		issues = append(issues, Issue{"error", "全局设置", "ansible_user 未填写"})
	} else if _, err := strconv.Atoi(strings.TrimSpace(c.AnsibleUser)); err == nil {
		// 防御列错位：曾因 Excel 导出行号 off-by-one 导致 ansible_user 变成端口值 "22"
		issues = append(issues, Issue{"error", "全局设置",
			fmt.Sprintf("ansible_user 是纯数字 %q，疑似配置列错位（应为用户名如 root）", c.AnsibleUser)})
	}
	if c.AnsibleSSHPort < 1 || c.AnsibleSSHPort > 65535 {
		issues = append(issues, Issue{"error", "全局设置",
			fmt.Sprintf("ansible_ssh_port 非法: %d（应为 1-65535）", c.AnsibleSSHPort)})
	}

	if len(c.Webs) == 0 {
		issues = append(issues, Issue{"error", "应用清单", "没有任何应用（示例行已被忽略，请填写正式数据）"})
	}

	seen := map[string]bool{}
	for _, app := range c.Webs {
		w := "应用>" + app.Web
		if strings.TrimSpace(app.Web) == "" {
			w = "应用清单"
			issues = append(issues, Issue{"error", w, "存在应用名称为空的数据行"})
			continue
		}
		if seen[app.Web] {
			issues = append(issues, Issue{"error", w, "应用名称重复"})
		}
		seen[app.Web] = true

		if app.MiddleType != "tomcat" && app.MiddleType != "jar" {
			issues = append(issues, Issue{"error", w,
				fmt.Sprintf("middle_type 非法: %q（只能 tomcat / jar）", app.MiddleType)})
		}
		if app.MiddleType == "jar" && len(app.RetainedConfigFile) == 0 {
			issues = append(issues, Issue{"warn", w,
				"JAR 应用未配置保留配置文件（retained_config_file），更新后可能无法启动"})
		}
		if len(app.Master) == 0 {
			issues = append(issues, Issue{"error", w, "没有配置任何 master 群组主机"})
		}
		// 主机重复检测（同一 IP:端口 出现在多个群组 = 会重复更新/回滚）
		hostSeen := map[string]string{}
		for _, g := range []struct {
			name  string
			hosts []Host
		}{
			{GroupMaster, app.Master}, {GroupUpdate, app.Update}, {GroupStatic, app.StaticPageGroup},
		} {
			for j, h := range g.hosts {
				issues = append(issues, validateHost(w+"#"+g.name, fmt.Sprintf("第%d台", j+1), h, g.name)...)
				if h.Host != "" {
					key := fmt.Sprintf("%s:%d", h.Host, h.ServicePort)
					if prev, dup := hostSeen[key]; dup {
						issues = append(issues, Issue{"error", w,
							fmt.Sprintf("主机重复：%s 同时出现在 %s 与 %s 群组", key, prev, g.name)})
					} else {
						hostSeen[key] = g.name
					}
				}
			}
		}
		// master 群组多台主机时服务端口应一致（同一套应用对外端口相同）
		if len(app.Master) > 1 {
			base := app.Master[0].ServicePort
			for _, h := range app.Master[1:] {
				if base > 0 && h.ServicePort > 0 && h.ServicePort != base {
					issues = append(issues, Issue{"warn", w,
						fmt.Sprintf("master 群组服务端口不一致（首台 %d，%s 为 %d），请确认是否预期",
							base, h.Host, h.ServicePort)})
					break
				}
			}
		}
		// log_dir：必须相对路径，且不得与保留配置冲突
		if ld := strings.TrimSpace(app.LogDir); ld != "" {
			if strings.HasPrefix(ld, "/") {
				issues = append(issues, Issue{"error", w,
					fmt.Sprintf("log_dir 应为相对路径: %q", ld)})
			}
			for _, rf := range app.RetainedConfigFile {
				if strings.Trim(strings.TrimSpace(rf), "/") == strings.Trim(ld, "/") {
					issues = append(issues, Issue{"error", w,
						fmt.Sprintf("log_dir 与 retained_config_file 冲突: %q", ld)})
				}
			}
		}
		// exclude_paths 格式
		for _, ep := range app.ExcludePaths {
			if strings.TrimSpace(ep) == "" {
				issues = append(issues, Issue{"error", w, "exclude_paths 含空项"})
			} else if strings.HasPrefix(ep, "/") {
				issues = append(issues, Issue{"warn", w,
					fmt.Sprintf("exclude_paths 建议用相对路径: %q", ep)})
			}
		}
		// 保留配置与 master 专属文件交集（语义冲突）
		for _, rf := range app.RetainedConfigFile {
			for _, ex := range app.MasterExclusiveFiles {
				if rf == ex {
					issues = append(issues, Issue{"warn", w,
						fmt.Sprintf("%q 同时在 retained_config_file 与 master_exclusive_files 中，请确认语义", rf)})
				}
			}
		}
	}

	// ---- shell 安全闸门（字段拼进远端命令的注入面；错误级阻止执行）----
	issues = append(issues, c.ShellSafetyIssues()...)

	// ---- 支持软件（supports）----
	kindSeen := map[string]string{}
	for i, s := range c.Supports {
		w := fmt.Sprintf("支持软件>%d", i+1)
		if strings.TrimSpace(s.Kind) == "" {
			issues = append(issues, Issue{"error", w, "kind 为空"})
			continue
		}
		if prev, dup := kindSeen[s.Kind]; dup {
			issues = append(issues, Issue{"error", w,
				fmt.Sprintf("kind %q 与第 %s 个支持软件重复，请合并 hosts", s.Kind, prev)})
		}
		kindSeen[s.Kind] = fmt.Sprint(i + 1)
		if len(s.Hosts) == 0 {
			issues = append(issues, Issue{"error", w, "hosts 为空"})
		}
		for _, d := range s.LogDirs {
			if strings.TrimSpace(d) == "" {
				issues = append(issues, Issue{"error", w, "log_dirs 含空项"})
			} else if !strings.HasPrefix(d, "/") {
				issues = append(issues, Issue{"error", w,
					fmt.Sprintf("log_dirs 必须是绝对路径: %q", d)})
			}
		}
		for _, d := range s.BackupPaths {
			if strings.TrimSpace(d) == "" {
				issues = append(issues, Issue{"error", w, "backup_paths 含空项"})
			} else if !strings.HasPrefix(d, "/") {
				issues = append(issues, Issue{"error", w,
					fmt.Sprintf("backup_paths 必须是绝对路径: %q", d)})
			} else if !pathSafe(d) {
				issues = append(issues, Issue{"error", w,
					fmt.Sprintf("backup_paths 含非法字符: %q", d)})
			}
		}
		if _, known := defaultSupportLogDirs[s.Kind]; len(s.LogDirs) == 0 && !known {
			issues = append(issues, Issue{"error", w,
				fmt.Sprintf("kind %q 无内置日志目录约定，必须显式配置 log_dirs", s.Kind)})
		}
		for j, h := range s.Hosts {
			// 支持软件主机只需基础校验（端口/URI/启停命令不适用；属主不涉及文件推送）
			loc := w + ">" + fmt.Sprint(j+1)
			if strings.TrimSpace(h.Host) == "" {
				issues = append(issues, Issue{"error", loc, "主机 IP 为空"})
				continue
			}
			if h.SSHPort != 0 && (h.SSHPort < 1 || h.SSHPort > 65535) {
				issues = append(issues, Issue{"error", loc,
					fmt.Sprintf("SSH 端口非法: %d", h.SSHPort)})
			}
		}
	}

	// ---- 备份运维（backup）----
	issues = append(issues, c.validateBackup()...)

	// ---- 监控运维（monitor）----
	issues = append(issues, c.validateMonitor()...)
	return issues
}

// hostnameSafe 主机名/IP 白名单（会进远端 TCP 探测命令）。
func hostnameSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// validateMonitor 监控段校验：端口范围、路径形态、云中心地址白名单。
func (c *Config) validateMonitor() []Issue {
	m := c.Monitor
	if m == nil {
		return nil
	}
	const w = "监控设置"
	var issues []Issue
	if s := strings.TrimSpace(m.Server); s != "" && !hostnameSafe(s) {
		issues = append(issues, Issue{"error", w, fmt.Sprintf("server 非法: %q（只允许字母数字.-_）", s)})
	}
	for name, v := range map[string]int{
		"server_port": m.ServerPort, "agent_port": m.AgentPort,
		"proxy_port": m.ProxyPort, "yum_port": m.YumPort,
	} {
		if v != 0 && (v < 1 || v > 65535) {
			issues = append(issues, Issue{"error", w, fmt.Sprintf("%s 非法: %d", name, v)})
		}
	}
	for name, p := range map[string]string{
		"agent_conf": m.AgentConf, "proxy_conf": m.ProxyConf,
		"plugin_dir": m.PluginDir, "script_dir": m.ScriptDir, "psk_file": m.PSKFile,
	} {
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") || !pathSafe(p) {
			issues = append(issues, Issue{"error", w, fmt.Sprintf("%s 必须是不含特殊字符的绝对路径: %q", name, p)})
		}
	}
	for _, h := range append(append([]Host{}, m.ProxyHosts...), m.AgentHosts...) {
		if strings.TrimSpace(h.Host) == "" {
			issues = append(issues, Issue{"error", w, "hosts 含空主机"})
		}
	}
	return issues
}

// sqlNameSafe 数据库名白名单：字母数字 _ $ . -（会进 mysqldump 命令行）。
func sqlNameSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '$' || r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

// validateBackup 备份段校验：路径/库名/凭据文件都按「会进远端命令」的严格口径。
func (c *Config) validateBackup() []Issue {
	b := c.Backup
	if b == nil {
		return nil
	}
	const w = "备份设置"
	var issues []Issue
	if root := strings.TrimSpace(b.Root); root != "" {
		if !strings.HasPrefix(root, "/") {
			issues = append(issues, Issue{"error", w, fmt.Sprintf("root 必须是绝对路径: %q", root)})
		} else if !pathSafe(root) {
			issues = append(issues, Issue{"error", w, fmt.Sprintf("root 含非法字符: %q", root)})
		}
	}
	if b.KeepDays < 0 {
		issues = append(issues, Issue{"error", w, fmt.Sprintf("keep_days 不能为负: %d", b.KeepDays)})
	}
	for _, db := range b.Databases {
		if !sqlNameSafe(db) {
			issues = append(issues, Issue{"error", w,
				fmt.Sprintf("databases 含非法库名: %q（只允许字母数字_$.-）", db)})
		}
	}
	if u := strings.TrimSpace(b.DumpUser); u != "" && !sqlNameSafe(u) {
		issues = append(issues, Issue{"error", w, fmt.Sprintf("dump_user 非法: %q", u)})
	}
	if f := strings.TrimSpace(b.DumpDefaultsFile); f != "" {
		if !strings.HasPrefix(f, "/") || !pathSafe(f) {
			issues = append(issues, Issue{"error", w,
				fmt.Sprintf("dump_defaults_file 必须是不含特殊字符的绝对路径: %q", f)})
		}
	}
	for _, ex := range b.Exclude {
		if strings.TrimSpace(ex) == "" {
			issues = append(issues, Issue{"error", w, "exclude 含空项"})
		} else if strings.ContainsAny(ex, "'\"`$;&|<>(){}\\") {
			issues = append(issues, Issue{"error", w,
				fmt.Sprintf("exclude 含 shell 元字符: %q", ex)})
		} else if strings.HasPrefix(ex, "/") {
			issues = append(issues, Issue{"warn", w,
				fmt.Sprintf("exclude 应为相对应用根的路径: %q", ex)})
		}
	}
	// 配了数据库备份但没有 mysql 支持软件段 = 无处执行 mysqldump
	if len(b.Databases) > 0 {
		found := false
		for _, s := range c.Supports {
			if s.Kind == "mysql" && len(s.Hosts) > 0 {
				found = true
				break
			}
		}
		if !found {
			issues = append(issues, Issue{"error", w,
				"backup.databases 非空但没有 mysql 类型的 supports 段（mysqldump 无目标主机）"})
		}
	}
	// 达梦段：模式名白名单 + 凭据文件远端绝对路径 + 必须有 dm 支持软件主机
	if s := strings.TrimSpace(b.DMSchema); s != "" {
		if !sqlNameSafe(s) {
			issues = append(issues, Issue{"error", w,
				fmt.Sprintf("dm_schema 含非法模式名: %q（只允许字母数字_$.-）", s)})
		}
		f := strings.TrimSpace(b.DMCredentialFile)
		if f == "" || !strings.HasPrefix(f, "/") || !pathSafe(f) {
			issues = append(issues, Issue{"error", w,
				fmt.Sprintf("dm_credential_file 必须是不含特殊字符的远端绝对路径（凭据文件内容一行 USER/密码@host:port）: %q", f)})
		}
		found := false
		for _, sp := range c.Supports {
			if sp.Kind == "dm" && len(sp.Hosts) > 0 {
				found = true
				break
			}
		}
		if !found {
			issues = append(issues, Issue{"error", w,
				"backup.dm_schema 非空但没有 dm 类型的 supports 段（dexp 无目标主机）"})
		}
	}
	return issues
}

func validateHost(where, idx string, h Host, group string) []Issue {
	var issues []Issue
	loc := where + ">" + idx + "(" + h.Host + ")"

	if strings.TrimSpace(h.Host) == "" {
		return []Issue{{"error", loc, "主机 IP 为空"}}
	}
	if strings.ContainsAny(h.Host, " \t/\\") || net.ParseIP(h.Host) == nil {
		// 允许主机名，但提示未通过 IP 格式校验
		issues = append(issues, Issue{"warn", loc, "主机地址不是合法 IP，将按主机名处理"})
	}
	if !strings.HasPrefix(h.WebPath, "/") {
		issues = append(issues, Issue{"error", loc,
			fmt.Sprintf("部署路径必须是绝对路径: %q", h.WebPath)})
	}
	if h.SSHPort != 0 && (h.SSHPort < 1 || h.SSHPort > 65535) {
		issues = append(issues, Issue{"error", loc,
			fmt.Sprintf("SSH 端口非法: %d", h.SSHPort)})
	}
	switch h.HealthMode {
	case "", "local", "remote", "none":
	default:
		issues = append(issues, Issue{"error", loc,
			fmt.Sprintf("health_mode 非法: %q（留空/remote=目标机本地探测，local=工具机，none=跳过）", h.HealthMode)})
	}
	if strings.TrimSpace(h.User) == "" {
		issues = append(issues, Issue{"error", loc, "文件属主用户(user)为空"})
	}

	switch group {
	case GroupMaster, GroupUpdate:
		if h.ServicePort < 1 || h.ServicePort > 65535 {
			issues = append(issues, Issue{Severity: "error", Where: loc,
				Msg: fmt.Sprintf("服务端口非法: %d（master/update 群组必填 1-65535）", h.ServicePort)})
		}
		if h.CheckURI == "" {
			// 留空 URI = 按 service_port 做 TCP 端口探测（一键部署标准默认），不是错误
		} else if !strings.HasPrefix(h.CheckURI, "/") {
			issues = append(issues, Issue{Severity: "error", Where: loc,
				Msg: fmt.Sprintf("健康检查 URI 非法: %q（只填相对路径，应以 / 开头，如 /app/main.htm）", h.CheckURI)})
		}
		if h.StartCmd == "" || h.StopCmd == "" {
			issues = append(issues, Issue{"error", loc, "启动/停止命令未填写"})
		}
	case GroupStatic:
		// 静态页面服务器：端口/URI/启停命令均可留空
	}
	return issues
}
