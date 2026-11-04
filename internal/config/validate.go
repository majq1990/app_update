package config

import (
	"fmt"
	"net"
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
		for _, g := range []struct {
			name  string
			hosts []Host
		}{
			{GroupMaster, app.Master}, {GroupUpdate, app.Update}, {GroupStatic, app.StaticPageGroup},
		} {
			for j, h := range g.hosts {
				issues = append(issues, validateHost(w+"#"+g.name, fmt.Sprintf("第%d台", j+1), h, g.name)...)
			}
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
