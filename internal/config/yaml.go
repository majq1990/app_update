package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load 从 YAML 文件读取配置（兼容旧版 Python 工具生成的 config.yaml）。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件: %w", err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("解析 YAML: %w", err)
	}
	c.Normalize()
	return c, nil
}

// Save 写出 YAML 文件。
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("序列化 YAML: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// defaultSupportLogDirs 支持软件按 Kind 的日志目录内置约定。
// 覆盖《信创第三方软件拉包打包矩阵》全部日志型软件（30 款中 22 款有日志面）。
// 路径来源：oneinstall_v2 ansible roles 实测约定（log_root_dir=/egova/log 统一根，
// 部分软件日志落 data 目录或自带 logs/ 子目录）；现场偏离时在 supports 段显式配置 log_dirs 覆盖。
var defaultSupportLogDirs = map[string][]string{
	// ---- 原有四类（app-updater v1.2 之前的约定，兼容保留）----
	"mysql": {"/egova/apps/mysql/data"}, // 旧约定；oneinstall 实际为 /egova/log/mysql（见 mysql_log）
	"dm":    {"/egova/apps/dm/log"},
	"redis": {"/egova/apps/redis/log"}, // 旧约定；oneinstall 实际为 /egova/log/redis
	"nginx": {"/egova/apps/nginx/logs"},

	// ---- oneinstall_v2 统一日志根 /egova/log/<name> ----
	"mysql_log":     {"/egova/log/mysql"}, // mysqld.log / slow log
	"redis_log":     {"/egova/log/redis"}, // redis.log
	"nginx_log":     {"/egova/log/nginx"}, // access.log / error.log（openresty 同源）
	"zookeeper":     {"/egova/log/zookeeper"},
	"tdengine":      {"/egova/log/TDengine"}, // taosdlog.0 按序滚动
	"tdengine3":     {"/egova/log/TDengine3"},
	"proxysql":      {"/egova/log/proxysql"},
	"postgres":      {"/egova/pgsql/log"},  // pg_log 常见别名见 cleanPatternsFor
	"kafka":         {"/egova/data/kafka"}, // kafka log_path=data 根下（server.log 等）
	"elasticsearch": {"/egova/data/elasticsearch/logs"},
	"nacos":         {"/egova/nacos/standalone-logs"},
	"minio":         {"/egova/data/minio"},
	"docker":        {"/var/lib/docker/containers"}, // json-file 驱动逐容器目录
	"cetus":         {"/egova/log/cetus"},           // oneops 监控套件同源路径
	"onlyoffice":    {"/var/log/onlyoffice"},        // documentserver
	"openresty":     {"/egova/log/nginx"},           // 与 nginx 同路径（别名）
}

// SupportKindAliases kind 别名归一（Excel 手填等价写法 → 规范 kind）。
// 便于工程同事按习惯写法填写，导入侧统一收敛。
var SupportKindAliases = map[string]string{
	"达梦":               "dm",
	"mysql-server":     "mysql",
	"mysql_server":     "mysql",
	"mysqlclient":      "mysql", // client 不产慢日志，但目录约定一致
	"percona":          "mysql",
	"mydumper":         "mysql",
	"pgsql":            "postgres",
	"postgresql":       "postgres",
	"pg":               "postgres",
	"postgis":          "postgres",
	"tdengine2":        "tdengine",
	"td2":              "tdengine",
	"td3":              "tdengine3",
	"es":               "elasticsearch",
	"zk":               "zookeeper",
	"minio":            "minio",
	"rs":               "rustfs",
	"openresty":        "nginx",
	"nginx(openresty)": "nginx",
}

// NormalizeSupportKind 返回规范 kind（小写 + 别名收敛）；无别名的自定义字符串原样返回小写。
// 导出供 xlsx 导入链路复用（Excel 手填等价写法 → 规范 kind）。
func NormalizeSupportKind(kind string) string {
	k := strings.ToLower(strings.TrimSpace(kind))
	if a, ok := SupportKindAliases[k]; ok {
		return a
	}
	return k
}

// Normalize 填补缺省值。
func (c *Config) Normalize() {
	if c.AnsibleSSHPort == 0 {
		c.AnsibleSSHPort = 22
	}
	if c.LogKeepDays == 0 {
		c.LogKeepDays = 30
	}
	// 支持软件段：kind 归一（别名/大小写收敛）→ 名称缺省取 Kind → 日志目录缺省按内置约定补齐。
	for i := range c.Supports {
		s := &c.Supports[i]
		s.Kind = NormalizeSupportKind(s.Kind)
		if s.Name == "" {
			s.Name = s.Kind
		}
		if len(s.LogDirs) == 0 {
			if dirs, ok := defaultSupportLogDirs[s.Kind]; ok {
				s.LogDirs = dirs
			}
		}
		if s.KeepDays == 0 {
			s.KeepDays = SupportsLogKeepDays
		}
	}
	// 标准健康检查地址自动补齐：历史配置里 jar 应用 check_uri 为空时，
	// 按《服务健康检查地址标准》补齐 backend 探针路径（显式清空想走 TCP 的，
	// 可设 health_mode: none 或自行确认——标准表外的应用不受影响）。
	for i := range c.Webs {
		app := &c.Webs[i]
		if app.MiddleType == "tomcat" {
			// WAR 健康检查兼容修正：早期转换器生成 /<应用>/main.htm，
			// 实测多数 WAR 没有 main.htm（返回 404），改为上下文根 /<应用>/。
			fix := func(h *Host) {
				if strings.HasSuffix(h.CheckURI, "/main.htm") && h.ServicePort > 0 {
					h.CheckURI = strings.TrimSuffix(h.CheckURI, "main.htm")
				}
			}
			for j := range app.Master {
				fix(&app.Master[j])
			}
			for j := range app.Update {
				fix(&app.Update[j])
			}
			continue
		}
		uri, ok := StandardCheckURI[app.Web]
		if !ok {
			continue
		}
		for j := range app.Master {
			if app.Master[j].CheckURI == "" && app.Master[j].ServicePort > 0 {
				app.Master[j].CheckURI = uri
			}
		}
		for j := range app.Update {
			if app.Update[j].CheckURI == "" && app.Update[j].ServicePort > 0 {
				app.Update[j].CheckURI = uri
			}
		}
	}
}
