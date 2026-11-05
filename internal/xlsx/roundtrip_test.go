package xlsx

import (
	"path/filepath"
	"strconv"
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
			ExcludePaths:         []string{"tilemap/"},
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
	// 排除路径必须走完 Excel 链路（曾漏实现，导致 tilemap 被备份传输）
	if len(a.ExcludePaths) != 1 || a.ExcludePaths[0] != "tilemap/" {
		t.Fatalf("exclude_paths 回环失败: %v", a.ExcludePaths)
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

	// 全局设置必须原样回环（2026-11-04 实测踩坑：export 写全局值行号 off-by-one，
	// 导致 ansible_user 变成端口值 "22"，整份配置 SSH 全部认证失败）
	if cfg.AnsibleUser != want.AnsibleUser {
		t.Fatalf("全局 ansible_user 回环错误: got %q want %q", cfg.AnsibleUser, want.AnsibleUser)
	}
	if cfg.AnsibleSSHPort != want.AnsibleSSHPort {
		t.Fatalf("全局 ansible_ssh_port 回环错误: got %d want %d", cfg.AnsibleSSHPort, want.AnsibleSSHPort)
	}
	if cfg.AnsibleSSHPass != want.AnsibleSSHPass {
		t.Fatalf("全局 ansible_ssh_pass 回环错误: got %q want %q", cfg.AnsibleSSHPass, want.AnsibleSSHPass)
	}
	if len(cfg.GlobalExcludeLogs) != len(want.GlobalExcludeLogs) {
		t.Fatalf("全局 global_exclude_logs 回环错误: got %v", cfg.GlobalExcludeLogs)
	}
	for i := range want.GlobalExcludeLogs {
		if cfg.GlobalExcludeLogs[i] != want.GlobalExcludeLogs[i] {
			t.Fatalf("global_exclude_logs[%d] 错误: got %v", i, cfg.GlobalExcludeLogs)
		}
	}
	// 防御：用户名不能是纯数字（曾因列错位变成 "22"）
	if _, err := strconv.Atoi(cfg.AnsibleUser); err == nil {
		t.Fatalf("ansible_user 不应是纯数字，疑似列错位: %q", cfg.AnsibleUser)
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

// 支持软件 sheet 往返：导出 → 导入 → 字段完整还原（含 kind 聚合与段级字段）。
func TestSupportsRoundTrip(t *testing.T) {
	want := &config.Config{
		Global: config.Global{
			AnsibleUser:       "root",
			AnsibleSSHPort:    22,
			GlobalExcludeLogs: []string{"*.log", "logs/"},
			LogKeepDays:       10,
		},
		Webs: []config.App{{
			Web: "usercenter", MiddleType: "jar", LogDir: "logs/",
			Master: []config.Host{{
				Host: "10.2.0.180", ServicePort: 8090, WebPath: "/egova/web/usercenter",
				StartCmd: "systemctl start usercenter", StopCmd: "systemctl stop usercenter",
				User: "egova", Group: "egova",
			}},
		}},
		Supports: []config.Support{
			{
				Kind: "mysql", KeepDays: 15,
				Hosts: []config.Host{
					{Host: "10.2.0.190", SSHPort: 22, SSHUser: "root"},
					{Host: "10.2.0.191", SSHPort: 22, SSHUser: "root"},
				},
			},
			{
				Kind: "redis", Name: "Redis缓存", KeepDays: 7,
				LogDirs:         []string{"/egova/apps/redis/log"},
				ExcludePatterns: []string{"*.log-*"},
				Hosts:           []config.Host{{Host: "10.2.0.192"}},
			},
			{
				// 显式目录的自定义类型
				Kind: "oracle", LogDirs: []string{"/opt/oracle/diag"}, KeepDays: 30,
				Hosts: []config.Host{{Host: "10.2.0.193"}},
			},
		},
	}

	cfg, issues := saveAndImport(t, func(f *excelize.File) error { return BuildFromConfig(f, want) })
	if config.HasError(issues) {
		t.Fatalf("导出导入不应有错误: %+v", issues)
	}

	if cfg.LogKeepDays != 10 {
		t.Fatalf("log_keep_days 回环错误: %d", cfg.LogKeepDays)
	}
	if len(cfg.Supports) != 3 {
		t.Fatalf("支持软件段数量不符: %d", len(cfg.Supports))
	}

	byKind := map[string]*config.Support{}
	for i := range cfg.Supports {
		byKind[cfg.Supports[i].Kind] = &cfg.Supports[i]
	}

	my := byKind["mysql"]
	if my == nil || len(my.Hosts) != 2 || my.Hosts[1].Host != "10.2.0.191" {
		t.Fatalf("mysql 聚合错误: %+v", my)
	}
	if my.KeepDays != 15 {
		t.Fatalf("mysql keep_days 回环错误: %d", my.KeepDays)
	}
	// Normalize 会给 mysql 补内置目录——往返后应保留（导出时已写出或导入后补齐均算过）
	if len(my.LogDirs) == 0 || my.LogDirs[0] != "/egova/apps/mysql/data" {
		t.Fatalf("mysql 日志目录（内置约定补齐）错误: %v", my.LogDirs)
	}

	rd := byKind["redis"]
	if rd == nil || rd.Name != "Redis缓存" || rd.KeepDays != 7 {
		t.Fatalf("redis 段级字段回环错误: %+v", rd)
	}
	if len(rd.LogDirs) != 1 || rd.LogDirs[0] != "/egova/apps/redis/log" {
		t.Fatalf("redis 日志目录回环错误: %v", rd.LogDirs)
	}
	if len(rd.ExcludePatterns) != 1 || rd.ExcludePatterns[0] != "*.log-*" {
		t.Fatalf("redis 排除模式回环错误: %v", rd.ExcludePatterns)
	}

	or := byKind["oracle"]
	if or == nil || len(or.LogDirs) != 1 || or.LogDirs[0] != "/opt/oracle/diag" {
		t.Fatalf("oracle 显式目录回环错误: %+v", or)
	}

	// 校验含 shell 安全闸门也应通过
	if iss := cfg.Validate(); config.HasError(iss) {
		t.Fatalf("回环配置应通过校验: %+v", iss)
	}
}

// 模板里的支持软件示例行导入时忽略；全局 log_keep_days 默认 30。
func TestTemplateSupportsExampleIgnored(t *testing.T) {
	cfg, issues := saveAndImport(t, BuildTemplate)
	if config.HasError(issues) {
		t.Fatalf("模板导入不应有错误: %+v", issues)
	}
	if len(cfg.Supports) != 0 {
		t.Fatalf("支持软件示例行未被忽略: %+v", cfg.Supports)
	}
	if cfg.LogKeepDays != 30 {
		t.Fatalf("log_keep_days 默认值错误: %d", cfg.LogKeepDays)
	}
}
