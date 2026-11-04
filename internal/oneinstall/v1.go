package oneinstall

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/majq1990/app-updater-go/internal/config"
)

// v1 现场一键部署的 Web 应用映射（install-multi.conf → app-updater 配置）。
// 端口在 v1 conf 中不存在，置 0 由校验器提示人工补填。
var v1WebApps = []struct {
	ConfSuffix string // conf 键后缀：IP_WEB_<SUFFIX>
	App        string // 应用名
}{
	{"MIS", "eUrbanMIS"},
	{"GIS", "eUrbanGIS"},
	{"MF", "eUrbanMF"},
	{"UMA", "eUrbanUMA"},
}

// ParseInstallMultiConf 解析现场一键部署 v1 的 install-multi.conf（KEY=VALUE 环境变量风格，
// 约定对齐 oneops shell/tools/init_hosts_from_oneinstall.sh）。
func ParseInstallMultiConf(data []byte) (map[string]string, error) {
	out := map[string]string{}
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.Index(line, "=")
		if eq <= 0 {
			return nil, fmt.Errorf("第%d行不是 KEY=VALUE 格式: %q", i+1, raw)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.Trim(strings.TrimSpace(line[eq+1:]), `"'`)
		out[key] = val
	}
	return out, nil
}

// ConvertV1 把 install-multi.conf 转换为配置初稿。
// v1 conf 只有节点角色（IP_WEB_MIS/GIS/MF/UMA、IP_DB_*、IP_PROXY 等）与 SSH 连接参数，
// 应用端口/URI 等细节不在其中，按 WAR 约定生成并标记人工核对项。
func ConvertV1(conf map[string]string) (*config.Config, []config.Issue, error) {
	cfg := &config.Config{
		Global: config.Global{
			AnsibleUser:    orDefault(conf["devops_ssh_user"], "root"),
			AnsibleSSHPort: atoiOr(conf["devops_ssh_port"], 22),
		},
	}

	var notes []config.Issue
	notes = append(notes, config.Issue{Severity: "warn", Where: "转换器(v1)",
		Msg: "install-multi.conf 只含节点角色，无端口/URI 细节：服务端口已置 0（校验会标错，请人工补填）；" +
			"路径/命令按 WAR 约定生成；属主 egova:egova；check_uri /<应用>/main.htm 需验证返回 200"})

	// 收集 IP_WEB_<SUFFIX>[N] → 应用 master/update 群组（同一应用合并进一个 App 条目）
	for _, def := range v1WebApps {
		prefix := "IP_WEB_" + def.ConfSuffix

		var masterHosts, updateHosts []config.Host

		// 主节点：IP_WEB_<SUFFIX>（不带数字后缀）
		if ip := strings.TrimSpace(conf[prefix]); ip != "" {
			masterHosts = append(masterHosts, v1Host(def.ConfSuffix, def.App, ip, ""))
		}

		// 扩展/备节点：IP_WEB_<SUFFIX><N>（数字后缀）→ update 群组
		var nums []int
		for k := range conf {
			if rest, ok := trimNumberedPrefix(k, prefix); ok && rest != "" {
				if n, err := strconv.Atoi(rest); err == nil {
					nums = append(nums, n)
				}
			}
		}
		sort.Ints(nums)
		for _, n := range nums {
			ip := strings.TrimSpace(conf[fmt.Sprintf("%s%d", prefix, n)])
			if ip == "" {
				continue
			}
			updateHosts = append(updateHosts, v1Host(def.ConfSuffix, def.App, ip,
				fmt.Sprintf("IP_WEB_%s%d 备节点", def.ConfSuffix, n)))
		}

		if len(masterHosts) > 0 || len(updateHosts) > 0 {
			cfg.Webs = append(cfg.Webs, config.App{
				Web:        def.App,
				MiddleType: "tomcat",
				LogDir:     "WEB-INF/logs",
				Master:     masterHosts,
				Update:     updateHosts,
			})
		}
	}

	// 未识别的 IP_WEB_* 键提示。
	// 已认知的基础设施角色（非应用服务器）语义化说明；真正未知的才提示"未在映射表"。
	appKeys := map[string]bool{"MIS": true, "GIS": true, "MF": true, "UMA": true}
	infraKeys := map[string]string{
		"REDIS":  "Redis 服务器",
		"MEDIA":  "多媒体/文件服务器",
		"JOB":    "Zookeeper/定时任务服务器",
		"GATHER": "采集服务器",
		"SG":     "社会治理应用（v1 映射表未收录）",
	}
	var infraSeen []string
	for k := range conf {
		if rest, ok := trimNumberedPrefix(k, "IP_WEB_"); ok {
			suffix := strings.TrimRight(rest, "0123456789")
			if suffix == "" || appKeys[suffix] {
				continue
			}
			if _, ok := infraKeys[suffix]; ok {
				if !containsStr(infraSeen, suffix) {
					infraSeen = append(infraSeen, suffix)
				}
				continue
			}
			notes = append(notes, config.Issue{Severity: "warn", Where: "转换器(v1)",
				Msg: fmt.Sprintf("IP_WEB_%s 未在映射表中（已知应用：%v），已跳过", suffix, knownKeys())})
		}
	}
	if len(infraSeen) > 0 {
		sort.Strings(infraSeen)
		var parts []string
		for _, s := range infraSeen {
			parts = append(parts, fmt.Sprintf("IP_WEB_%s(%s)", s, infraKeys[s]))
		}
		notes = append(notes, config.Issue{Severity: "warn", Where: "转换器(v1)",
			Msg: "以下为基础设施服务器角色（非受管应用，已跳过）：" + strings.Join(parts, "、")})
	}
	return cfg, notes, nil
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func v1Host(suffix, app, ip, remark string) config.Host {
	return config.Host{
		Host:     ip,
		WebPath:  "/egova/web/" + app,
		CheckURI: "/" + app + "/main.htm",
		StartCmd: "systemctl start tomcat-" + suffix,
		StopCmd:  "systemctl stop tomcat-" + suffix,
		User:     "egova",
		Group:    "egova",
		Remark:   remark,
	}
}

// trimNumberedPrefix 判断 key 是否形如 prefix<数字>，返回数字部分。
func trimNumberedPrefix(key, prefix string) (string, bool) {
	if !strings.HasPrefix(key, prefix) || key == prefix {
		return "", false
	}
	return key[len(prefix):], true
}

func knownKeys() []string {
	var ks []string
	for _, d := range v1WebApps {
		ks = append(ks, d.ConfSuffix)
	}
	return ks
}

func atoiOr(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}
