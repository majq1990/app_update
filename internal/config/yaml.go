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

// Normalize 填补缺省值。
func (c *Config) Normalize() {
	if c.AnsibleSSHPort == 0 {
		c.AnsibleSSHPort = 22
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
