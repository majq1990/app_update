// Package config 定义应用更新工具的配置模型。
// YAML 结构与旧版 Python 工具 (majq1990/app_update) 的 config.yaml 保持兼容，
// 并为 Go 版新增了按主机覆盖 SSH 端口/用户的能力（可选字段，旧文件照常读取）。
package config

// Global 全局设置（对应旧版 config.yaml 顶层字段 + 新增 global_exclude_logs）。
type Global struct {
	AnsibleSSHPass      string   `yaml:"ansible_ssh_pass"`
	AnsibleSSHPort      int      `yaml:"ansible_ssh_port"`
	AnsibleUser         string   `yaml:"ansible_user"`
	IsCheckedSuccessful bool     `yaml:"is_checked_successful,omitempty"`
	GlobalExcludeLogs   []string `yaml:"global_exclude_logs,omitempty"`
	// TomcatCheckMinutes tomcat 应用健康检查预算（分钟）。0 = 默认 20。
	// 大站 WAR 从端口监听到 HTTP 就绪可能要几分钟（usercenter 这类大 jar 同理，见 JarCheckMinutes）。
	TomcatCheckMinutes int `yaml:"tomcat_check_minutes,omitempty"`
	// JarCheckMinutes jar 应用健康检查预算（分钟）。0 = 默认 5（435MB 级大 jar 启动可能 >1 分钟）。
	JarCheckMinutes int `yaml:"jar_check_minutes,omitempty"`
}

// StandardCheckURI 一键部署标准健康检查地址（《服务健康检查地址标准》，现场实测 200）。
// 均为核心 Java 服务自带的 backend 探针路径。Normalize 时对留空 check_uri 的 jar 应用
// 自动补齐（历史配置无需重新识别即可获得标准地址）。
var StandardCheckURI = map[string]string{
	"dataflow":        "/dataflow-api/free/sysconfig/get-all-free-config",
	"dex":             "/dex-api/free/option/group/dex_front",
	"eurbanpro":       "/eurbanpro-api/free/sysconfig/get-all-free-config",
	"evaluation":      "/bi-api/free/status",
	"linglong":        "/linglong-api/free/license/info",
	"eurbanpro_media": "/media-api/free/application/check",
	"patrol_gather":   "/patrol-gather-api/free/status",
	"sms":             "/sms-api/free/application/check",
	"trajectory":      "/trajectory-api/free/application/check",
	"usercenter":      "/usercenter-api/free/application/check",
	"workflow":        "/workflow-center-api/free/status",
	"xuanzang":        "/xuanzang-api/free/application/check",
}

// Host 一台目标主机。对应旧版 master/update/static_page_group 列表元素。
type Host struct {
	Host        string `yaml:"host"`                   // 主机 IP 或主机名
	ServicePort int    `yaml:"service_port,omitempty"` // 应用监听端口（健康检查：留空 URI 时做 TCP 端口探测）
	CheckURI    string `yaml:"check_uri,omitempty"`    // 健康检查相对路径；留空=按 service_port 做 TCP 端口探测
	WebPath     string `yaml:"web_path"`               // 部署绝对路径
	StartCmd    string `yaml:"start_cmd,omitempty"`
	StopCmd     string `yaml:"stop_cmd,omitempty"`
	User        string `yaml:"user"`            // 更新后文件属主
	Group       string `yaml:"group,omitempty"` // 更新后文件属组

	// 健康检查执行位置：""/"local"=工具所在机发起（默认）；"remote"=目标主机本地发起
	// （服务器间严格网络限制、工具机无法访问应用端口时使用，走 SSH 通道在目标机探测）；
	// "none"=显式跳过健康检查。
	HealthMode string `yaml:"health_mode,omitempty"`

	// 以下为 Go 版新增：按主机覆盖全局 SSH 设置；零值表示回落到全局。
	SSHPort int    `yaml:"ssh_port,omitempty"`
	SSHPass string `yaml:"ssh_pass,omitempty"`
	SSHUser string `yaml:"ssh_user,omitempty"`

	// 旧版遗留：静态页面更新时的应用内子路径，保留兼容。
	StaticPagePath string `yaml:"static_page_path,omitempty"`

	// Go 版新增：备注，仅存在于 Excel。
	Remark string `yaml:"remark,omitempty"`
}

// App 一个 Java 应用（WAR/JAR）的完整配置。
type App struct {
	Web                  string   `yaml:"web"`         // 应用名称
	MiddleType           string   `yaml:"middle_type"` // tomcat | jar
	LogDir               string   `yaml:"log_dir,omitempty"`
	RetainedConfigFile   []string `yaml:"retained_config_file,omitempty"`
	MasterExclusiveFiles []string `yaml:"master_exclusive_files,omitempty"`
	Master               []Host   `yaml:"master"`
	Update               []Host   `yaml:"update"`
	StaticPageGroup      []Host   `yaml:"static_page_group,omitempty"`
}

// Config 顶层配置。
type Config struct {
	Global `yaml:",inline"` // yaml.v3 需显式声明内联，否则全局字段不会被解析
	Webs   []App            `yaml:"webs"`
}

// 群组名称常量。
const (
	GroupMaster = "master"
	GroupUpdate = "update"
	GroupStatic = "static"
)

// AppByName 按应用名称查找。
func (c *Config) AppByName(name string) *App {
	for i := range c.Webs {
		if c.Webs[i].Web == name {
			return &c.Webs[i]
		}
	}
	return nil
}

// GroupHosts 返回某群组的主机列表引用。
func (a *App) GroupHosts(group string) []Host {
	switch group {
	case GroupMaster:
		return a.Master
	case GroupUpdate:
		return a.Update
	case GroupStatic:
		return a.StaticPageGroup
	}
	return nil
}
