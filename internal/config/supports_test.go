package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Supports 段：Normalize 缺省值（目录约定、名称、保留天数）。
func TestNormalizeSupports(t *testing.T) {
	c := &Config{}
	yaml.Unmarshal([]byte(`
ansible_user: root
supports:
  - kind: mysql
    hosts: [{host: 10.0.0.1}]
  - kind: my-custom
    log_dirs: [/data/mylogs]
    hosts: [{host: 10.0.0.2}]
  - kind: redis
    keep_days: 7
    hosts: [{host: 10.0.0.3}]
`), c)
	c.Normalize()

	if c.LogKeepDays != 30 {
		t.Errorf("应用日志默认保留天数 = %d, want 30", c.LogKeepDays)
	}
	s := c.SupportByKind("mysql")
	if s == nil {
		t.Fatal("mysql 段缺失")
	}
	if len(s.LogDirs) != 1 || s.LogDirs[0] != "/egova/apps/mysql/data" {
		t.Errorf("mysql 日志目录未按约定补齐: %v", s.LogDirs)
	}
	if s.Name != "mysql" {
		t.Errorf("name 缺省应取 kind: %q", s.Name)
	}
	if s.KeepDays != SupportsLogKeepDays {
		t.Errorf("mysql keep_days = %d, want %d", s.KeepDays, SupportsLogKeepDays)
	}
	if got := c.SupportByKind("my-custom"); got == nil || got.LogDirs[0] != "/data/mylogs" {
		t.Errorf("自定义 kind 显式目录被覆盖: %+v", got)
	}
	if r := c.SupportByKind("redis"); r == nil || r.KeepDays != 7 {
		t.Errorf("redis 显式 keep_days=7 被覆盖: %+v", r)
	}
}

// Supports 段：校验（空 kind、无 hosts、无目录约定的 kind、相对路径目录）。
func TestValidateSupports(t *testing.T) {
	c := &Config{}
	yaml.Unmarshal([]byte(`
ansible_user: root
webs:
  - web: usercenter
    middle_type: jar
    master: [{host: 10.0.0.1, web_path: /egova/apps/basic/usercenter, user: egova, service_port: 10050, start_cmd: "systemctl start usercenter", stop_cmd: "systemctl stop usercenter"}]
supports:
  - kind: ""
    hosts: [{host: 10.0.0.1}]
  - kind: mysql
    hosts: []
  - kind: my-custom
    hosts: [{host: 10.0.0.2}]
  - kind: redis
    log_dirs: [relative/path]
    hosts: [{host: 10.0.0.3}]
  - kind: redis
    hosts: [{host: 10.0.0.4}]
`), c)
	c.Normalize()
	issues := c.Validate()

	var msgs []string
	for _, i := range issues {
		if strings.HasPrefix(i.Where, "支持软件") {
			msgs = append(msgs, i.Where+": "+i.Msg)
		}
	}
	join := strings.Join(msgs, "\n")
	for _, want := range []string{"kind 为空", "hosts 为空", "必须显式配置 log_dirs", "绝对路径", "重复"} {
		if !strings.Contains(join, want) {
			t.Errorf("校验结果缺少 %q:\n%s", want, join)
		}
	}
}

// 旧配置（无 supports 段）完全不受影响。
func TestValidateNoSupports(t *testing.T) {
	c := &Config{}
	yaml.Unmarshal([]byte(`
ansible_user: root
webs:
  - web: usercenter
    middle_type: jar
    log_dir: logs/
    master: [{host: 10.0.0.1, web_path: /egova/apps/basic/usercenter, user: egova, service_port: 10050, start_cmd: "systemctl start usercenter", stop_cmd: "systemctl stop usercenter"}]
`), c)
	c.Normalize()
	for _, i := range c.Validate() {
		if strings.HasPrefix(i.Where, "支持软件") {
			t.Errorf("无 supports 段不应产生支持软件校验项: %s", i)
		}
	}
}

// 信创矩阵软件清单：别名归一 + 内置目录补齐（覆盖《拉包打包矩阵》日志型软件）。
func TestNormalizeMatrixKinds(t *testing.T) {
	c := &Config{}
	yaml.Unmarshal([]byte(`
ansible_user: root
webs:
  - web: probe
    middle_type: jar
    log_dir: logs/
    master: [{host: 10.0.0.1, web_path: /egova/apps/basic/probe, user: egova, service_port: 10050, start_cmd: "systemctl start probe", stop_cmd: "systemctl stop probe"}]
supports:
  - kind: PostgreSQL
    hosts: [{host: 10.0.0.1}]
  - kind: kafka
    hosts: [{host: 10.0.0.1}]
  - kind: 达梦
    hosts: [{host: 10.0.0.1}]
  - kind: ES
    hosts: [{host: 10.0.0.1}]
  - kind: zk
    hosts: [{host: 10.0.0.1}]
  - kind: td2
    hosts: [{host: 10.0.0.1}]
  - kind: td3
    hosts: [{host: 10.0.0.1}]
  - kind: openresty
    hosts: [{host: 10.0.0.1}]
  - kind: nacos
    hosts: [{host: 10.0.0.1}]
  - kind: minio
    hosts: [{host: 10.0.0.1}]
  - kind: docker
    hosts: [{host: 10.0.0.1}]
  - kind: proxysql
    hosts: [{host: 10.0.0.1}]
  - kind: cetus
    hosts: [{host: 10.0.0.1}]
  - kind: onlyoffice
    hosts: [{host: 10.0.0.1}]
`), c)
	c.Normalize()

	wants := map[string]string{
		"PostgreSQL": "postgres",
		"达梦":         "dm",
		"ES":         "elasticsearch",
		"zk":         "zookeeper",
		"td2":        "tdengine",
		"td3":        "tdengine3",
		"openresty":  "nginx",
	}
	for orig, want := range wants {
		if got := NormalizeSupportKind(orig); got != want {
			t.Errorf("别名归一 %q = %q, want %q", orig, got, want)
		}
	}
	// 归一后目录补齐抽查
	byKind := map[string]*Support{}
	for i := range c.Supports {
		byKind[c.Supports[i].Kind] = &c.Supports[i]
	}
	dirWants := map[string]string{
		"postgres":      "/egova/pgsql/log",
		"kafka":         "/egova/data/kafka",
		"elasticsearch": "/egova/data/elasticsearch/logs",
		"zookeeper":     "/egova/log/zookeeper",
		"tdengine":      "/egova/log/TDengine",
		"tdengine3":     "/egova/log/TDengine3",
		"nacos":         "/egova/nacos/standalone-logs",
		"docker":        "/var/lib/docker/containers",
		"proxysql":      "/egova/log/proxysql",
		"onlyoffice":    "/var/log/onlyoffice",
	}
	for kind, wantDir := range dirWants {
		s := byKind[kind]
		if s == nil {
			t.Errorf("kind %q 归一后丢失", kind)
			continue
		}
		if len(s.LogDirs) == 0 || s.LogDirs[0] != wantDir {
			t.Errorf("kind %q 日志目录 = %v, want %s", kind, s.LogDirs, wantDir)
		}
	}
	// 全部通过校验（含 shell 安全闸门）
	if iss := c.Validate(); HasError(iss) {
		t.Errorf("矩阵配置应通过校验: %v", iss)
	}
}
