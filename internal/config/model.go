// Package config 定义应用更新工具的配置模型。
// YAML 结构与旧版 Python 工具 (majq1990/app_update) 的 config.yaml 保持兼容，
// 并为 Go 版新增了按主机覆盖 SSH 端口/用户的能力（可选字段，旧文件照常读取）。
package config

import "strings"

// Global 全局设置（对应旧版 config.yaml 顶层字段 + 新增 global_exclude_logs）。
type Global struct {
	AnsibleSSHPass      string   `yaml:"ansible_ssh_pass"`
	AnsibleSSHPort      int      `yaml:"ansible_ssh_port"`
	AnsibleUser         string   `yaml:"ansible_user"`
	IsCheckedSuccessful bool     `yaml:"is_checked_successful,omitempty"`
	GlobalExcludeLogs   []string `yaml:"global_exclude_logs,omitempty"`
	// LogKeepDays 应用日志默认保留天数（logs clean 用）。0 = 30。
	LogKeepDays int `yaml:"log_keep_days,omitempty"`
	// GlobalExcludeLogs 之外，logs clean 对支持软件（supports）日志同样适用的全局排除。
	// 缺省为空：支持软件目录本来只放日志，不需要应用目录那套排除。
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
	// ExcludePaths 排除路径（相对部署路径）：备份与同步都跳过，且不参与 --delete 清理。
	// 用于体积巨大且无需随包更新的目录（如 eUrbanGIS 的 tilemap/ 切片缓存）。
	ExcludePaths    []string `yaml:"exclude_paths,omitempty"`
	Master          []Host   `yaml:"master"`
	Update          []Host   `yaml:"update"`
	StaticPageGroup []Host   `yaml:"static_page_group,omitempty"`
}

// Config 顶层配置。
type Config struct {
	Global   `yaml:",inline"` // yaml.v3 需显式声明内联，否则全局字段不会被解析
	Webs     []App            `yaml:"webs"`
	Supports []Support        `yaml:"supports,omitempty"` // 支持软件（数据库/redis/nginx 等）日志与运维目标
	Backup   *Backup          `yaml:"backup,omitempty"`   // 备份运维（v1.4）：现场留包 + 校验 + 台账
	Monitor  *Monitor         `yaml:"monitor,omitempty"`  // 监控运维（v1.6）：部署辅助 + 诊断
}

// Monitor 监控运维配置（monitor doctor / fix / deploy 计划）。
// 拓扑对齐 FAQ wiki《监控相关》：云中心 zabbix ← 主控机(proxy) ← 受控机(agent)。
type Monitor struct {
	// Server 云中心地址；空 = zabbix.egova.com.cn。
	Server string `yaml:"server,omitempty"`
	// ServerPort 云中心端口；0 = 7001。
	ServerPort int `yaml:"server_port,omitempty"`
	// AgentPort 受控机 agent 监听端口；0 = 9000（wiki 约定，非官方默认 10050）。
	AgentPort int `yaml:"agent_port,omitempty"`
	// ProxyPort 主控机 proxy 端口；0 = 9001。
	ProxyPort int `yaml:"proxy_port,omitempty"`
	// AgentConf agent 配置文件路径；空 = /etc/zabbix/zabbix_agentd.conf。
	AgentConf string `yaml:"agent_conf,omitempty"`
	// ProxyConf 主控机 proxy 配置路径；空 = /etc/zabbix/zabbix_proxy.conf。
	ProxyConf string `yaml:"proxy_conf,omitempty"`
	// PluginDir userparameter 片段目录；空 = /etc/zabbix/zabbix_agentd.d。
	PluginDir string `yaml:"plugin_dir,omitempty"`
	// ScriptDir 监控脚本目录；空 = /egova/devops/script。
	ScriptDir string `yaml:"script_dir,omitempty"`
	// PSKFile 预共享密钥文件；空 = /etc/zabbix/zabbix_agentd.psk（不存在视为未启用 PSK）。
	PSKFile string `yaml:"psk_file,omitempty"`
	// YumPort 主控机本地 yum 源端口（离线安装用）；0 = 8080。
	YumPort int `yaml:"yum_port,omitempty"`
	// ProxyHosts 主控机清单；空 = 做 agent 诊断时把 webs/supports 主机当受控机。
	ProxyHosts []Host `yaml:"proxy_hosts,omitempty"`
	// AgentHosts 受控机清单；空 = 用 webs + supports 的全部主机。
	AgentHosts []Host `yaml:"agent_hosts,omitempty"`
}

// 监控默认值（对齐 wiki 现场约定）。
const (
	MonitorServerDefault     = "zabbix.egova.com.cn"
	MonitorServerPortDefault = 7001
	MonitorAgentPortDefault  = 9000
	MonitorProxyPortDefault  = 9001
	MonitorYumPortDefault    = 8080
	MonitorAgentConfDefault  = "/etc/zabbix/zabbix_agentd.conf"
	MonitorProxyConfDefault  = "/etc/zabbix/zabbix_proxy.conf"
	MonitorPluginDirDefault  = "/etc/zabbix/zabbix_agentd.d"
	MonitorScriptDirDefault  = "/egova/devops/script"
	MonitorPSKFileDefault    = "/etc/zabbix/zabbix_agentd.psk"
)

func (m *Monitor) EffectiveServer() string {
	if m == nil || strings.TrimSpace(m.Server) == "" {
		return MonitorServerDefault
	}
	return strings.TrimSpace(m.Server)
}

func (m *Monitor) EffectiveServerPort() int {
	return effectivePort(m, func(x *Monitor) int { return x.ServerPort }, MonitorServerPortDefault)
}
func (m *Monitor) EffectiveAgentPort() int {
	return effectivePort(m, func(x *Monitor) int { return x.AgentPort }, MonitorAgentPortDefault)
}
func (m *Monitor) EffectiveProxyPort() int {
	return effectivePort(m, func(x *Monitor) int { return x.ProxyPort }, MonitorProxyPortDefault)
}
func (m *Monitor) EffectiveYumPort() int {
	return effectivePort(m, func(x *Monitor) int { return x.YumPort }, MonitorYumPortDefault)
}

func effectivePort(m *Monitor, get func(*Monitor) int, def int) int {
	if m == nil {
		return def
	}
	if v := get(m); v > 0 {
		return v
	}
	return def
}

func effectivePath(m *Monitor, get func(*Monitor) string, def string) string {
	if m == nil {
		return def
	}
	if v := strings.TrimSpace(get(m)); v != "" {
		return v
	}
	return def
}

func (m *Monitor) EffectiveAgentConf() string {
	return effectivePath(m, func(x *Monitor) string { return x.AgentConf }, MonitorAgentConfDefault)
}
func (m *Monitor) EffectiveProxyConf() string {
	return effectivePath(m, func(x *Monitor) string { return x.ProxyConf }, MonitorProxyConfDefault)
}
func (m *Monitor) EffectivePluginDir() string {
	return effectivePath(m, func(x *Monitor) string { return x.PluginDir }, MonitorPluginDirDefault)
}
func (m *Monitor) EffectiveScriptDir() string {
	return effectivePath(m, func(x *Monitor) string { return x.ScriptDir }, MonitorScriptDirDefault)
}
func (m *Monitor) EffectivePSKFile() string {
	return effectivePath(m, func(x *Monitor) string { return x.PSKFile }, MonitorPSKFileDefault)
}

// Backup 备份运维配置（backup run/list/verify/prune/report）。
// 设计口径（与统一运维工具规划一致）：备份产物只留现场，不自动拉回中心；
// 工具负责执行、校验、保留期清理与台账导出，台账再由人工/上层推送项目管理。
type Backup struct {
	// Root 现场备份根目录。空 = /egova/backup。
	Root string `yaml:"root,omitempty"`
	// KeepDays 保留天数。0 = 14（BackupKeepDaysDefault）。
	KeepDays int `yaml:"keep_days,omitempty"`
	// Databases 需要 mysqldump 的库名列表；空 = 不做数据库备份。
	// 库名会进远端命令，按 [A-Za-z0-9_$.-] 白名单校验。
	Databases []string `yaml:"databases,omitempty"`
	// DumpUser mysqldump 用户，空 = root。
	DumpUser string `yaml:"dump_user,omitempty"`
	// DumpDefaultsFile 凭据文件（如 /root/.my.cnf）；空 = 依赖 mysqldump 默认读取。
	// 工具不保存数据库口令：凭据由现场文件持有，避免口令进入配置与命令行。
	DumpDefaultsFile string `yaml:"dump_defaults_file,omitempty"`
	// Exclude 打包排除（相对应用部署根，tar 通配）。默认会追加 logs/ 与更新期 backups/。
	Exclude []string `yaml:"exclude,omitempty"`
}

// BackupDefaults 备份模块默认值。
const (
	BackupRootDefault     = "/egova/backup"
	BackupKeepDaysDefault = 14
	BackupFilePrefix      = "eops-"
)

// EffectiveRoot 备份根目录（空值回落默认）。
func (b *Backup) EffectiveRoot() string {
	if b == nil || b.Root == "" {
		return BackupRootDefault
	}
	return b.Root
}

// EffectiveKeepDays 保留天数（0 回落默认；负数视为 1）。
func (b *Backup) EffectiveKeepDays() int {
	if b == nil || b.KeepDays == 0 {
		return BackupKeepDaysDefault
	}
	if b.KeepDays < 0 {
		return 1
	}
	return b.KeepDays
}

// EffectiveDumpUser mysqldump 用户（空 = root）。
func (b *Backup) EffectiveDumpUser() string {
	if b == nil || b.DumpUser == "" {
		return "root"
	}
	return b.DumpUser
}

// Support 一类支持软件的运维目标。Kind 决定日志目录的默认约定：
//   - mysql:   datadir（默认 /egova/apps/mysql/data）下 *.err|slow.log|binlog
//   - dm/达梦:  安装目录 log 子目录（默认 /egova/apps/dm/log）
//   - redis:   logfile（默认 /egova/apps/redis/log/redis.log）
//   - nginx:   access/error log（默认 /egova/apps/nginx/logs）
//   - tomcat:  独立 tomcat（不属于任何 webs 应用）的 logs 目录
//
// Hosts 复用应用主机的 SSH 语义（ssh_port/ssh_user/ssh_pass 可按主机覆盖）。
type Support struct {
	Kind            string   `yaml:"kind"`                       // mysql | dm | redis | nginx | tomcat（自定义字符串亦允许，配了 LogDirs 即生效）
	Name            string   `yaml:"name,omitempty"`             // 可读名称；缺省用 Kind
	LogDirs         []string `yaml:"log_dirs,omitempty"`         // 日志目录；缺省按 Kind 内置约定补齐（Normalize）
	KeepDays        int      `yaml:"keep_days,omitempty"`        // 日志保留天数；0 = 回落 LogKeepDays（SupportsLog 默认 15）
	ExcludePatterns []string `yaml:"exclude_patterns,omitempty"` // 清理时额外排除（如 binlog 需要保留的场景）
	// BackupPaths 需要打包备份的绝对路径（如 redis 的 dump.rdb、nginx 的 conf 目录）。
	// 空 = 该支持软件不参与文件备份；mysql 走 backup.databases 的 mysqldump。
	BackupPaths []string `yaml:"backup_paths,omitempty"`
	Hosts       []Host   `yaml:"hosts"`
}

// SupportsLogKeepDays 支持软件日志的默认保留天数（应用日志默认走 Global.LogKeepDays）。
const SupportsLogKeepDays = 15

// SupportByKind 按类型查找第一个匹配的支持软件配置段。
func (c *Config) SupportByKind(kind string) *Support {
	for i := range c.Supports {
		if c.Supports[i].Kind == kind {
			return &c.Supports[i]
		}
	}
	return nil
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
