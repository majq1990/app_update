package xlsx

import (
	"strings"

	"github.com/xuri/excelize/v2"

	"github.com/majq1990/app-updater-go/internal/config"
)

// BuildFromConfig 把已有配置写成工作簿（反向导出）：真实数据行 + 填写说明，
// 不写示例行。用于 config.yaml → Excel 的存量迁移核对。
func BuildFromConfig(f *excelize.File, cfg *config.Config) error {
	if err := writeLayout(f); err != nil {
		return err
	}
	if err := writeNotes(f); err != nil {
		return err
	}
	if err := writeValidations(f); err != nil {
		return err
	}

	// 全局设置：把当前配置值覆盖到布局默认行（第2行起，行序同 globalRows）
	gvals := map[string]interface{}{
		"ansible_user":         cfg.AnsibleUser,
		"ansible_ssh_port":     ifZero(cfg.AnsibleSSHPort, 22),
		"ansible_ssh_pass":     cfg.AnsibleSSHPass,
		"global_exclude_logs":  strings.Join(cfg.GlobalExcludeLogs, ","),
		"tomcat_check_minutes": ifZero(cfg.TomcatCheckMinutes, 20),
		"jar_check_minutes":    ifZero(cfg.JarCheckMinutes, 5),
	}
	for i, g := range globalRows {
		if v, ok := gvals[g.key]; ok {
			f.SetCellValue(SheetGlobal, cellName(2, i+2), v)
		}
	}

	for r, app := range cfg.Webs {
		rn := r + 3
		vals := []interface{}{
			app.Web, app.MiddleType, app.LogDir,
			strings.Join(app.RetainedConfigFile, ","),
			strings.Join(app.MasterExclusiveFiles, ","),
			"",
		}
		for c, v := range vals {
			f.SetCellValue(SheetApps, cellName(c+1, rn), v)
		}
	}
	rn := 3
	for _, app := range cfg.Webs {
		for _, grp := range []struct {
			name  string
			hosts []config.Host
		}{
			{config.GroupMaster, app.Master},
			{config.GroupUpdate, app.Update},
			{config.GroupStatic, app.StaticPageGroup},
		} {
			for _, h := range grp.hosts {
				vals := []interface{}{
					app.Web, grp.name, h.Host,
					ifZero(h.SSHPort, ""), h.SSHUser, h.WebPath,
					ifZero(h.ServicePort, ""), h.CheckURI,
					h.StartCmd, h.StopCmd, h.User, h.Group, h.Remark,
				}
				for c, v := range vals {
					f.SetCellValue(SheetHosts, cellName(c+1, rn), v)
				}
				rn++
			}
		}
	}
	return nil
}

func ifZero(n int, zero interface{}) interface{} {
	if n == 0 {
		return zero
	}
	return n
}
