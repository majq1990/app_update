package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Shell 安全闸门回归：注入面字段全部拦截（error 级，gateValidation 会拒绝执行）。
func TestShellSafetyInjection(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string // 期望的错误消息关键词
	}{
		{
			"check_uri 反引号命令替换",
			`
ansible_user: root
webs:
  - web: app1
    middle_type: jar
    master: [{host: 10.0.0.1, web_path: /egova/apps/app1, user: egova, service_port: 100, check_uri: "/x;` + "`id`" + `", start_cmd: "systemctl start a", stop_cmd: "systemctl stop a"}]
`,
			"危险字符",
		},
		{
			"start_cmd rm -rf",
			`
ansible_user: root
webs:
  - web: app1
    middle_type: jar
    master: [{host: 10.0.0.1, web_path: /egova/apps/app1, user: egova, service_port: 100, start_cmd: "systemctl start a; rm -rf /", stop_cmd: "systemctl stop a"}]
`,
			"危险命令模式",
		},
		{
			"stop_cmd 关机",
			`
ansible_user: root
webs:
  - web: app1
    middle_type: jar
    master: [{host: 10.0.0.1, web_path: /egova/apps/app1, user: egova, service_port: 100, start_cmd: "systemctl start a", stop_cmd: "shutdown -h now"}]
`,
			"危险命令模式",
		},
		{
			"user 含分号",
			`
ansible_user: root
webs:
  - web: app1
    middle_type: jar
    master: [{host: 10.0.0.1, web_path: /egova/apps/app1, user: "egova;touch /tmp/pwned", service_port: 100, start_cmd: "systemctl start a", stop_cmd: "systemctl stop a"}]
`,
			"shell 元字符",
		},
		{
			"web_path 命令替换",
			`
ansible_user: root
webs:
  - web: app1
    middle_type: jar
    master: [{host: 10.0.0.1, web_path: "/egova/$(rm -rf /)", user: egova, service_port: 100, start_cmd: "systemctl start a", stop_cmd: "systemctl stop a"}]
`,
			"shell 元字符",
		},
		{
			"supports kind 注入",
			`
ansible_user: root
supports:
  - kind: "mysql;rm"
    log_dirs: [/egova/apps/mysql/data]
    hosts: [{host: 10.0.0.9}]
`,
			"shell 元字符",
		},
		{
			"supports log_dirs 反引号",
			`
ansible_user: root
supports:
  - kind: mysql
    log_dirs: ["/egova/x` + "`id`" + `"]
    hosts: [{host: 10.0.0.9}]
`,
			"shell 元字符",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{}
			if err := yaml.Unmarshal([]byte(tc.yaml), c); err != nil {
				t.Fatal(err)
			}
			c.Normalize()
			issues := c.Validate()
			var hit bool
			for _, i := range issues {
				if i.Severity == "error" && (strings.Contains(i.Msg, tc.want) ||
					strings.Contains(i.Msg, "危险") || strings.Contains(i.Msg, "元字符")) {
					hit = true
				}
			}
			if !hit {
				t.Errorf("未拦截注入:\n%s", tc.name)
				for _, i := range issues {
					t.Logf("  %s", i.String())
				}
			}
		})
	}
}

// 正常配置（含中文路径、复杂 systemctl 命令）不应误伤。
func TestShellSafetyNoFalsePositive(t *testing.T) {
	c := &Config{}
	const raw = "ansible_user: root\n" +
		"log_keep_days: 7\n" +
		"webs:\n" +
		"  - web: 用户中心\n" +
		"    middle_type: jar\n" +
		"    log_dir: logs/\n" +
		"    master: [{host: 10.0.0.1, web_path: /egova/apps/basic/用户中心, user: egova, group: egova, service_port: 10050, check_uri: \"/usercenter-api/free/application/check\", start_cmd: \"systemctl start usercenter\", stop_cmd: \"systemctl stop usercenter\"}]\n" +
		"supports:\n" +
		"  - kind: mysql\n" +
		"    log_dirs: [/egova/apps/mysql/data]\n" +
		"    exclude_patterns: [\"*.log-*\", \"slow_query?\"]\n" +
		"    hosts: [{host: 10.0.0.9}]\n"
	if err := yaml.Unmarshal([]byte(raw), c); err != nil {
		t.Fatalf("YAML 解析失败: %v", err)
	}
	c.Normalize()
	for _, i := range c.Validate() {
		if i.Severity == "error" {
			t.Errorf("正常配置被误伤: %s", i.String())
		}
	}
}
