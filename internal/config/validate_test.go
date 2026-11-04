package config

import (
	"strings"
	"testing"
)

func baseApp() App {
	return App{
		Web:                "usercenter",
		MiddleType:         "jar",
		LogDir:             "logs/",
		RetainedConfigFile: []string{"usercenter.env"},
		Master: []Host{{
			Host: "10.0.0.1", ServicePort: 10050, CheckURI: "/x/check",
			WebPath: "/egova/apps/usercenter", StartCmd: "systemctl start u", StopCmd: "systemctl stop u",
			User: "egova",
		}},
	}
}

func baseCfg(app App) *Config {
	return &Config{
		Global: Global{AnsibleUser: "root", AnsibleSSHPort: 22},
		Webs:   []App{app},
	}
}

func hasMsg(issues []Issue, sub string) bool {
	for _, is := range issues {
		if strings.Contains(is.Msg, sub) {
			return true
		}
	}
	return false
}

func TestValidateBaseOK(t *testing.T) {
	if iss := baseCfg(baseApp()).Validate(); HasError(iss) {
		t.Fatalf("基础配置不应有错误: %+v", iss)
	}
}

// 同一 IP:端口 同时出现在 master 与 update → 错误。
func TestValidateDuplicateHost(t *testing.T) {
	app := baseApp()
	app.Update = []Host{app.Master[0]}
	iss := baseCfg(app).Validate()
	if !HasError(iss) || !hasMsg(iss, "主机重复") {
		t.Fatalf("应检出主机重复: %+v", iss)
	}
}

// 同 IP 不同端口不算重复（两个实例同机不同端口是合法部署）。
func TestValidateSameHostDifferentPort(t *testing.T) {
	app := baseApp()
	u := app.Master[0]
	u.ServicePort = 10051
	app.Update = []Host{u}
	if iss := baseCfg(app).Validate(); HasError(iss) {
		t.Fatalf("同 IP 不同端口不应报重复: %+v", iss)
	}
}

// log_dir 绝对路径 / 与保留配置冲突 → 错误。
func TestValidateLogDir(t *testing.T) {
	app := baseApp()
	app.LogDir = "/egova/logs"
	if iss := baseCfg(app).Validate(); !HasError(iss) || !hasMsg(iss, "log_dir 应为相对路径") {
		t.Fatalf("应检出 log_dir 绝对路径: %+v", iss)
	}

	app2 := baseApp()
	app2.LogDir = "usercenter.env"
	app2.RetainedConfigFile = []string{"usercenter.env"}
	if iss := baseCfg(app2).Validate(); !hasMsg(iss, "log_dir 与 retained_config_file 冲突") {
		t.Fatalf("应检出 log_dir 与保留配置冲突: %+v", iss)
	}
}

// exclude_paths 空项 → 错误；绝对路径 → 警告。
func TestValidateExcludePaths(t *testing.T) {
	app := baseApp()
	app.ExcludePaths = []string{""}
	if iss := baseCfg(app).Validate(); !HasError(iss) || !hasMsg(iss, "exclude_paths 含空项") {
		t.Fatalf("应检出空排除项: %+v", iss)
	}

	app2 := baseApp()
	app2.ExcludePaths = []string{"/tilemap/"}
	iss := baseCfg(app2).Validate()
	if HasError(iss) || !hasMsg(iss, "建议用相对路径") {
		t.Fatalf("绝对排除路径应只警告: %+v", iss)
	}
}

// master 多主机端口不一致 → 警告。
func TestValidateMasterPortMismatch(t *testing.T) {
	app := baseApp()
	h2 := app.Master[0]
	h2.Host = "10.0.0.2"
	h2.ServicePort = 10099
	app.Master = append(app.Master, h2)
	iss := baseCfg(app).Validate()
	if !hasMsg(iss, "master 群组服务端口不一致") {
		t.Fatalf("应提示 master 端口不一致: %+v", iss)
	}
}

// 保留配置与 master 专属文件交集 → 警告。
func TestValidateRetainedExclusiveOverlap(t *testing.T) {
	app := baseApp()
	app.MasterExclusiveFiles = []string{"usercenter.env"}
	iss := baseCfg(app).Validate()
	if !hasMsg(iss, "请确认语义") {
		t.Fatalf("应提示保留/排除语义冲突: %+v", iss)
	}
}

// 无效 health_mode → 错误。
func TestValidateHealthMode(t *testing.T) {
	app := baseApp()
	app.Master[0].HealthMode = "bogus"
	if iss := baseCfg(app).Validate(); !HasError(iss) || !hasMsg(iss, "health_mode 非法") {
		t.Fatalf("应检出非法 health_mode: %+v", iss)
	}
}
