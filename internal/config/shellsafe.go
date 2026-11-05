package config

// ShellSafe：远端 shell 拼接字段的安全闸门。
// 本工具大量场景是把配置字段拼进 SSH 远端命令（chown、健康检查 /dev/tcp 探测、
// logs 的 awk/tail/logrotate 等）。shellQuote 只能保证"词法闭合"，挡不住
// start_cmd 这类本来就允许复杂语法的字段被人塞 `; rm -rf` 或反引号。
// 策略分两层：
//   - 严格字段（路径/URI/用户名/kind）：白名单字符集 + 显式格式校验，出错即 error；
//   - 命令字段（start_cmd/stop_cmd）：本来就是 shell 命令，不能用白名单——
//     只拒绝"明显超出 systemctl/service 语义"的危险元字符组合，warn 级 +
//     执行层 DryRun 展示原文，最终由人确认。

import (
	"fmt"
	"strings"
)

// pathSafeChars 路径白名单：字母数字、- _ . / 空格（中文路径现实存在，一并放行）。
// 拒绝所有 shell 元字符与控制字符。
func pathSafe(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_' || r == '/' || r == ' ':
		case r >= 0x4e00 && r <= 0x9fff: // CJK（中文目录名）
		case r >= 0x80: // 其他非 ASCII（现场路径常见，非 shell 元字符）
		default:
			return false
		}
	}
	return !strings.ContainsAny(s, "\x00\n\r\t")
}

// uriSafe 健康检查 URI：以 / 开头，拒绝引号/分号/反引号/$/空白。
func uriSafe(s string) bool {
	if s == "" {
		return true
	}
	if !strings.HasPrefix(s, "/") {
		return false
	}
	return !strings.ContainsAny(s, "\"'`;$&|<>\\\n\r\t {}()")
}

// cmdDangerous start/stop 类命令字段的危险模式。
// 这些模式在 systemctl start/stop <unit> 语义里不可能合法出现。
func cmdDangerous(s string) string {
	lower := strings.ToLower(s)
	dangers := []struct {
		pat  string
		desc string
	}{
		{"rm -rf", "rm -rf"},
		{"rm -fr", "rm -rf"},
		{">/dev/", "重定向到设备"},
		{"> /dev/", "重定向到设备"},
		{"mkfs", "格式化"},
		{"dd if=", "dd 写盘"},
		{"shutdown", "关机"},
		{"reboot", "重启"},
		{"poweroff", "关机"},
		{"init 0", "关机"},
		{":(){", "fork 炸弹"},
		{"chmod -r 777 /", "全盘 777"},
		{">~/.ssh", "覆写 SSH 配置"},
		{">/etc/", "覆写系统文件"},
		{"> /etc/", "覆写系统文件"},
	}
	for _, d := range dangers {
		if strings.Contains(lower, d.pat) {
			return d.desc
		}
	}
	return ""
}

// ShellSafetyIssues 对整个配置跑 shell 安全闸门，返回问题清单（含级别）。
// 由 Validate() 统一调用；错误级会阻止执行（gateValidation 拦截）。
func (c *Config) ShellSafetyIssues() []Issue {
	var issues []Issue

	// 路径/名称类：白名单（error 级——这些字段本不该含元字符）
	pathCheck := func(where, field, val string) {
		if !pathSafe(val) {
			issues = append(issues, Issue{"error", where,
				fmt.Sprintf("%s 含 shell 元字符或控制字符，拒绝执行: %q", field, val)})
		}
	}
	uriCheck := func(where, val string) {
		if !uriSafe(val) {
			issues = append(issues, Issue{"error", where,
				fmt.Sprintf("check_uri 含危险字符（引号/分号/反引号/$ 等）: %q", val)})
		}
	}
	cmdCheck := func(where, field, val string) {
		if d := cmdDangerous(val); d != "" {
			issues = append(issues, Issue{"error", where,
				fmt.Sprintf("%s 含危险命令模式（%s）: %q", field, d, val)})
		}
	}

	for i := range c.Webs {
		app := &c.Webs[i]
		w := "应用>" + app.Web
		pathCheck(w, "web(应用名)", app.Web)
		for _, group := range []struct {
			name  string
			hosts []Host
		}{{"master", app.Master}, {"update", app.Update}, {"static", app.StaticPageGroup}} {
			for hi := range group.hosts {
				h := &group.hosts[hi]
				loc := fmt.Sprintf("%s>%s[%d](%s)", w, group.name, hi+1, h.Host)
				pathCheck(loc, "web_path", h.WebPath)
				pathCheck(loc, "user", h.User)
				pathCheck(loc, "group", h.Group)
				pathCheck(loc, "static_page_path", h.StaticPagePath)
				uriCheck(loc, h.CheckURI)
				cmdCheck(loc, "start_cmd", h.StartCmd)
				cmdCheck(loc, "stop_cmd", h.StopCmd)
			}
		}
	}

	for i := range c.Supports {
		s := &c.Supports[i]
		w := fmt.Sprintf("支持软件>%d(%s)", i+1, s.Kind)
		pathCheck(w, "kind", s.Kind)
		pathCheck(w, "name", s.Name)
		for _, d := range s.LogDirs {
			pathCheck(w, "log_dirs", d)
		}
		for _, p := range s.ExcludePatterns {
			// 排除模式允许 glob 字符 * ? [ ]，但拒绝引号/分号/反引号/$/&
			if strings.ContainsAny(p, "\"'`;$&|<>\\\n\r\t") {
				issues = append(issues, Issue{"error", w,
					fmt.Sprintf("exclude_patterns 含危险字符: %q", p)})
			}
		}
	}
	return issues
}
