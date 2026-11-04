package xlsx

import (
	"path/filepath"
	"testing"

	"github.com/xuri/excelize/v2"
	"gopkg.in/yaml.v3"

	"github.com/majq1990/app-updater-go/internal/config"
)

func saveAndImport(t *testing.T, build func(f *excelize.File) error) (*config.Config, []config.Issue) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wb.xlsx")
	f := excelize.NewFile()
	if err := build(f); err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := f.SaveAs(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	f.Close()
	cfg, issues, err := Import(path)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	return cfg, issues
}

// 模板导入：示例行全部忽略，得到空配置且无错误。
func TestTemplateImportEmpty(t *testing.T) {
	cfg, issues := saveAndImport(t, BuildTemplate)
	if config.HasError(issues) {
		t.Fatalf("模板导入不应有错误: %+v", issues)
	}
	if len(cfg.Webs) != 0 {
		t.Fatalf("示例行未被忽略, apps=%d", len(cfg.Webs))
	}
	if cfg.AnsibleUser != "root" || cfg.AnsibleSSHPort != 22 {
		t.Fatalf("全局设置读取错误: user=%q port=%d", cfg.AnsibleUser, cfg.AnsibleSSHPort)
	}
	if len(cfg.GlobalExcludeLogs) != 2 {
		t.Fatalf("global_exclude_logs 解析错误: %v", cfg.GlobalExcludeLogs)
	}
}

// 反向导出再导入，字段应完整还原。
func TestExportImportRoundTrip(t *testing.T) {
	want := &config.Config{
		Global: config.Global{
			AnsibleUser: "root", AnsibleSSHPort: 2222, AnsibleSSHPass: "",
			GlobalExcludeLogs: []string{"*.log", "logs/"},
		},
		Webs: []config.App{{
			Web: "eUrbanGIS", MiddleType: "tomcat", LogDir: "WEB-INF/logs",
			RetainedConfigFile:   []string{"WEB-INF/classes/jdbc.properties"},
			MasterExclusiveFiles: []string{"egova-liquibase-*.jar"},
			Master: []config.Host{{
				Host: "10.2.0.172", ServicePort: 8085,
				CheckURI: "/eUrbanGIS/symbol/default.png", WebPath: "/egova/web/eUrbanGIS",
				StartCmd: "systemctl start tomcat-GIS", StopCmd: "systemctl stop tomcat-GIS",
				User: "egova", Group: "egova", SSHPort: 0, SSHUser: "",
			}},
			Update: []config.Host{{
				Host: "10.2.0.173", ServicePort: 8085,
				CheckURI: "/eUrbanGIS/symbol/default.png", WebPath: "/egova/web/eUrbanGIS",
				StartCmd: "systemctl start tomcat-GIS", StopCmd: "systemctl stop tomcat-GIS",
				User: "egova", Group: "egova", SSHPort: 22022, SSHUser: "deploy",
			}},
			StaticPageGroup: []config.Host{{
				Host: "10.2.0.172", WebPath: "/egova/web/nginx_deploy/eUrbanGIS",
				User: "nginx", Group: "nginx",
			}},
		}},
	}

	cfg, issues := saveAndImport(t, func(f *excelize.File) error { return BuildFromConfig(f, want) })
	if config.HasError(issues) {
		t.Fatalf("导出导入不应有错误: %+v", issues)
	}
	got := cfg.Webs
	if len(got) != 1 {
		t.Fatalf("应用数不符: %d", len(got))
	}
	a := got[0]
	if a.Web != want.Webs[0].Web || a.MiddleType != "tomcat" || a.LogDir != "WEB-INF/logs" ||
		len(a.RetainedConfigFile) != 1 || len(a.MasterExclusiveFiles) != 1 {
		t.Fatalf("应用字段不符: %+v", a)
	}
	if len(a.Master) != 1 || len(a.Update) != 1 || len(a.StaticPageGroup) != 1 {
		t.Fatalf("群组主机数不符: %+v", a)
	}
	if a.Update[0].SSHPort != 22022 || a.Update[0].SSHUser != "deploy" {
		t.Fatalf("按主机覆盖 SSH 失效: %+v", a.Update[0])
	}
	if a.Master[0].ServicePort != 8085 || a.Master[0].CheckURI != "/eUrbanGIS/symbol/default.png" {
		t.Fatalf("master 字段不符: %+v", a.Master[0])
	}
	if a.StaticPageGroup[0].User != "nginx" || a.StaticPageGroup[0].ServicePort != 0 {
		t.Fatalf("static 字段不符: %+v", a.StaticPageGroup[0])
	}
	// 校验应通过
	if iss := cfg.Validate(); config.HasError(iss) {
		t.Fatalf("回环配置应通过校验: %+v", iss)
	}
}

// 旧版 Python 工具的 config.yaml 应可直接读取。
func TestLegacyYAMLCompat(t *testing.T) {
	legacy := `
ansible_ssh_pass: ''
ansible_ssh_port: 22
ansible_user: root
is_checked_successful: false
webs:
- log_dir: WEB-INF/log
  master:
  - check_uri: /eUrbanMIS/main.htm
    group: egova
    host: 10.2.0.172
    service_port: 8081
    start_cmd: systemctl start tomcat-MIS
    stop_cmd: systemctl stop tomcat-MIS
    user: egova
    web_path: /egova/web/eUrbanMIS
  master_exclusive_files:
  - egova-liquibase-[0-9]*.jar
  middle_type: tomcat
  retained_config_file:
  - WEB-INF/classes/jdbc.properties
  static_page_group:
  - group: nginx
    host: 10.2.0.172
    user: nginx
    web_path: /egova/web/nginx_deploy/eUrbanMIS/
  update: []
  web: eUrbanMIS
`
	c := &config.Config{}
	if err := yaml.Unmarshal([]byte(legacy), c); err != nil {
		t.Fatalf("旧版 YAML 解析失败: %v", err)
	}
	c.Normalize()
	if len(c.Webs) != 1 || c.Webs[0].Web != "eUrbanMIS" {
		t.Fatalf("应用解析错误: %+v", c.Webs)
	}
	if c.Webs[0].Master[0].ServicePort != 8081 || c.Webs[0].Master[0].User != "egova" {
		t.Fatalf("主机字段解析错误: %+v", c.Webs[0].Master[0])
	}
	if iss := c.Validate(); config.HasError(iss) {
		t.Fatalf("旧版配置应通过校验: %+v", iss)
	}
}
