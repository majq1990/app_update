package xlsx

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xuri/excelize/v2"

	"github.com/majq1990/app-updater-go/internal/config"
)

// Import 从 Excel 工作簿解析配置。示例行自动忽略；
// 解析阶段的行级问题（群组非法、应用未定义等）随 issues 返回，
// 业务完整性校验交给 config.Config.Validate。
func Import(path string) (*config.Config, []config.Issue, error) {
	f, err := excelize.OpenFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("打开 Excel: %w", err)
	}
	defer f.Close()

	for _, sheet := range []string{SheetGlobal, SheetApps, SheetHosts} {
		if _, err := f.GetSheetIndex(sheet); err != nil {
			return nil, nil, fmt.Errorf("缺少工作表 %q: %w", sheet, err)
		}
	}

	cfg := &config.Config{}
	var issues []config.Issue

	// ---- 全局设置：A=键 B=值 ----
	rows, _ := f.GetRows(SheetGlobal)
	for i, row := range rows {
		if i < 2 || len(row) < 2 {
			continue
		}
		key, val := strings.TrimSpace(row[0]), strings.TrimSpace(row[1])
		switch key {
		case "ansible_user":
			cfg.AnsibleUser = val
		case "ansible_ssh_port":
			cfg.AnsibleSSHPort = atoiOr(val, 22)
		case "ansible_ssh_pass":
			cfg.AnsibleSSHPass = val
		case "global_exclude_logs":
			cfg.GlobalExcludeLogs = splitList(val)
		case "tomcat_check_minutes":
			cfg.TomcatCheckMinutes = atoiOr(val, 0)
		case "jar_check_minutes":
			cfg.JarCheckMinutes = atoiOr(val, 0)
		}
	}
	cfg.Normalize()

	// ---- 应用清单 ----
	apps := map[string]bool{}
	rows, _ = f.GetRows(SheetApps)
	for i, row := range rows {
		if i < 2 || len(row) < 2 {
			continue
		}
		name := strings.TrimSpace(row[0])
		if name == "" || strings.HasPrefix(name, ExamplePrefix) {
			continue
		}
		where := fmt.Sprintf("%s!第%d行", SheetApps, i+1)
		app := config.App{
			Web:        name,
			MiddleType: strings.TrimSpace(row[1]),
		}
		if len(row) > 2 {
			app.LogDir = strings.TrimSpace(row[2])
		}
		if len(row) > 3 {
			app.RetainedConfigFile = splitList(row[3])
		}
		if len(row) > 4 {
			app.MasterExclusiveFiles = splitList(row[4])
		}
		if apps[name] {
			issues = append(issues, config.Issue{Severity: "error", Where: where, Msg: "应用名称重复"})
		}
		apps[name] = true
		cfg.Webs = append(cfg.Webs, app)
	}

	// ---- 主机清单 ----
	rows, _ = f.GetRows(SheetHosts)
	for i, row := range rows {
		if i < 2 || len(row) < 3 {
			continue
		}
		appName := strings.TrimSpace(row[0])
		if appName == "" || strings.HasPrefix(appName, ExamplePrefix) {
			continue
		}
		where := fmt.Sprintf("%s!第%d行", SheetHosts, i+1)
		app := cfg.AppByName(appName)
		if app == nil {
			issues = append(issues, config.Issue{Severity: "error", Where: where,
				Msg: fmt.Sprintf("应用 %q 在应用清单中不存在", appName)})
			continue
		}
		group := strings.TrimSpace(row[1])
		if group != config.GroupMaster && group != config.GroupUpdate && group != config.GroupStatic {
			issues = append(issues, config.Issue{Severity: "error", Where: where,
				Msg: fmt.Sprintf("群组非法: %q（master/update/static）", group)})
			continue
		}
		h := parseHostRow(row, where, &issues)
		switch group {
		case config.GroupMaster:
			app.Master = append(app.Master, h)
		case config.GroupUpdate:
			app.Update = append(app.Update, h)
		case config.GroupStatic:
			app.StaticPageGroup = append(app.StaticPageGroup, h)
		}
	}
	return cfg, issues, nil
}

func parseHostRow(row []string, where string, issues *[]config.Issue) config.Host {
	get := func(i int) string {
		if i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}
	h := config.Host{
		Host:     get(2), // C 主机IP
		SSHPort:  atoiOr(get(3), 0),
		SSHUser:  get(4),
		WebPath:  get(5),
		CheckURI: get(7),
		StartCmd: get(8),
		StopCmd:  get(9),
		User:     get(10),
		Group:    get(11),
		Remark:   get(12),
	}
	if v := get(6); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			*issues = append(*issues, config.Issue{Severity: "error", Where: where, Msg: "服务端口不是数字: " + v})
		}
		h.ServicePort = p
	}
	return h
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '，' }) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func atoiOr(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
