// Package oneinstall 解析 oneinstall_v2 的 inventory（hosts.yml / eurbanpro_multi_server.yml / metadata.yml），
// 并转换为 app-updater 的配置模型。
package oneinstall

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/majq1990/app-updater-go/internal/config"
)

// Inventory inventory 文件的内容。
type Inventory struct {
	Hosts            []byte // hosts.yml
	MultiServer      []byte // eurbanpro_multi_server.yml（麒舰产品线服务组）
	MultiServerBase  []byte // multi_server.yml（传统产品线服务组；麒舰 WAR 部署也会加载）
	MultiServerMjing []byte // mjing_multi_server.yml（明镜执法产品线服务组，可选）
	Metadata         []byte // metadata.yml
}

// Options 转换选项。
type Options struct {
	IncludeUndeployed bool // 含 undeployed 应用（部署未完成时预生成初稿用）
}

// 参与更新工具管理的模块类型；其余（mysql/redis/nacos/minio/zookeeper/kafka/postgresql/TDengine/cetus）跳过。
var managedModuleTypes = map[string]string{
	"service":      "service",      // WAR + tomcat
	"microservice": "microservice", // JAR
}

// 应用部署细节（metadata.yml 中 service.<app>.<实例> / microservice.<app>.<实例>）。
type appInstance struct {
	Name       string  `yaml:"name"`
	BizType    string  `yaml:"biz_type"`
	ServerPort flexInt `yaml:"server_port"`
	BasePath   string  `yaml:"base_path"`
	JarName    string  `yaml:"jar_name"`
	Status     string  `yaml:"status"`
	Host       string  `yaml:"host"`
	IP         string  `yaml:"ip"`
	LoginURL   string  `yaml:"login_url"`
}

// metadata.yml 顶层只取 service 与 microservice 两段。
type metadataFile struct {
	Service      map[string]map[string]appInstance `yaml:"service"`
	Microservice map[string]map[string]appInstance `yaml:"microservice"`
}

// strOrList 兼容 YAML 标量与序列：新版 oneinstall 把空 slave 写成 `slave: []`，
// 多备节点场景是 `slave: [nodeB, nodeC]`；旧版是空字符串或单节点字符串。
type strOrList []string

func (s *strOrList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		var items []string
		if err := node.Decode(&items); err != nil {
			return err
		}
		*s = items
	case yaml.ScalarNode:
		var v string
		if err := node.Decode(&v); err != nil {
			return err
		}
		if strings.TrimSpace(v) == "" {
			*s = nil
		} else {
			*s = []string{v}
		}
	default:
		*s = nil
	}
	return nil
}

// eurbanpro_multi_server.yml：服务组 → 节点分配（master/slave，slave 可为多节点）。
type serviceGroup struct {
	Name    string `yaml:"name"`
	Modules []struct {
		Type    string `yaml:"type"`
		SubType string `yaml:"sub_type"`
	} `yaml:"modules"`
	Hosts struct {
		Master string    `yaml:"master"`
		Slave  strOrList `yaml:"slave"`
	} `yaml:"hosts"`
}

// hosts.yml：节点 → IP / SSH 端口。
type hostsFile struct {
	All struct {
		Hosts map[string]struct {
			SSHHost string `yaml:"ansible_ssh_host"`
			SSHPort string `yaml:"ansible_ssh_port"`
		} `yaml:"hosts"`
	} `yaml:"all"`
}

// flexInt 兼容 metadata.yml 中 yq 写入的带引号端口（"8085"）与模板中的裸整数（8085）。
type flexInt int

func (f *flexInt) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err == nil {
		n, err := strconv.Atoi(strings.Trim(s, `'"`))
		if err != nil {
			*f = 0
			return nil
		}
		*f = flexInt(n)
		return nil
	}
	var n int
	if err := node.Decode(&n); err != nil {
		return fmt.Errorf("server_port 非法: %w", err)
	}
	*f = flexInt(n)
	return nil
}

// Convert 把三份 inventory 转换为配置 + 说明性 notes。
func Convert(inv Inventory, opts Options) (*config.Config, []config.Issue, error) {
	var hf hostsFile
	if err := yaml.Unmarshal(inv.Hosts, &hf); err != nil {
		return nil, nil, fmt.Errorf("解析 hosts.yml: %w", err)
	}
	var meta metadataFile
	if err := yaml.Unmarshal(inv.Metadata, &meta); err != nil {
		return nil, nil, fmt.Errorf("解析 metadata.yml: %w", err)
	}

	nodeIP := map[string]string{}
	nodePort := map[string]int{}
	for node, e := range hf.All.Hosts {
		nodeIP[node] = e.SSHHost
		if p, err := strconv.Atoi(strings.TrimSpace(e.SSHPort)); err == nil && p > 0 {
			nodePort[node] = p
		}
	}

	// sub_type → master/slave 节点。服务组拓扑分布在多个 multi_server 文件（麒舰/传统/明镜三条产品线，
	// install_eurbanpro_tomcat_app.yml 会同时加载前两者），合并取并集，同 sub_type 首个文件生效。
	slaveOf := map[string][]string{}
	masterOf := map[string]string{}
	for _, gf := range []struct {
		name string
		data []byte
	}{
		{"eurbanpro_multi_server.yml", inv.MultiServer},
		{"multi_server.yml", inv.MultiServerBase},
		{"mjing_multi_server.yml", inv.MultiServerMjing},
	} {
		if len(gf.data) == 0 {
			continue
		}
		var multi map[string]serviceGroup
		if err := yaml.Unmarshal(gf.data, &multi); err != nil {
			return nil, nil, fmt.Errorf("解析 %s: %w", gf.name, err)
		}
		for _, g := range multi {
			for _, m := range g.Modules {
				if _, ok := managedModuleTypes[m.Type]; !ok {
					continue
				}
				if _, exists := masterOf[m.SubType]; !exists && g.Hosts.Master != "" {
					masterOf[m.SubType] = g.Hosts.Master
				}
				if _, exists := slaveOf[m.SubType]; !exists && len(g.Hosts.Slave) > 0 {
					slaveOf[m.SubType] = g.Hosts.Slave
				}
			}
		}
	}

	cfg := &config.Config{
		Global: config.Global{
			AnsibleUser:    "root",
			AnsibleSSHPort: 22,
		},
	}
	var notes []config.Issue
	notes = append(notes, config.Issue{Severity: "warn", Where: "转换器",
		Msg: "以下按约定自动填充，均需人工核对：文件属主 egova:egova（oneinstall ops_user 默认值）；" +
			"JAR 保留配置 <服务名>.env,application.properties；WAR 保留配置 jdbc/redis(/timeseries/postgres/kafka).properties" +
			"（对齐 tomcat_app role 模板清单）；log_dir（旧版 WAR 曾用 WEB-INF/log 或 WEB-INF/logs）；" +
			"WAR 健康检查 /<应用>/main.htm（须验证返回 200）；JAR 健康检查按《服务健康检查地址标准》自动填充 backend 探针路径" +
			"（/xxx-api/free/...，现场实测 200）；标准清单外的服务留空=按服务端口做 TCP 连通性探测；" +
			"WAR 自动配置 master 专属排除 egova-liquibase-*.jar,liquibase-core-*.jar（备节点不推且更新时自动清理，防数据库锁冲突）"})

	// 以 metadata 为准遍历应用（含 status 过滤），multi_server 只提供 slave 拓扑。
	sections := []struct {
		section string
		middle  string
		apps    map[string]map[string]appInstance
	}{
		{"service", "tomcat", meta.Service},
		{"microservice", "jar", meta.Microservice},
	}
	skippedUndeployed := 0
	for _, sec := range sections {
		appKeys := make([]string, 0, len(sec.apps))
		for k := range sec.apps {
			appKeys = append(appKeys, k)
		}
		sort.Strings(appKeys)
		for _, appKey := range appKeys {
			insts := sec.apps[appKey]
			if len(insts) == 0 {
				continue // 空键（模板里预留的 eUrbanMIS: 等）
			}
			instKeys := make([]string, 0, len(insts))
			for k := range insts {
				instKeys = append(instKeys, k)
			}
			sort.Strings(instKeys)

			// ---- 聚合本应用的有效实例：多实例合并为一个 App（主实例→master，从实例→update），
			//      避免同名应用重复（如 usercenter 部署主备两实例的场景）----
			type instRec struct {
				key  string
				inst appInstance
			}
			var kept []instRec
			for _, instKey := range instKeys {
				inst := insts[instKey]
				if inst.Status != "success" && !opts.IncludeUndeployed {
					skippedUndeployed++
					continue
				}
				kept = append(kept, instRec{key: instKey, inst: inst})
			}
			if len(kept) == 0 {
				continue
			}

			// IM（即时通讯）由 IM role 以 docker-compose 方式部署（Open-IM-Server + start_all.sh），
			// 无 systemd 单元，更新流程不同，整应用跳过并提示。
			if appKey == "IM" {
				notes = append(notes, config.Issue{Severity: "warn", Where: "metadata>IM",
					Msg: "即时通讯（IM）为 docker-compose 多进程服务（Open-IM-Server + start_all.sh），" +
						"无 systemd 单元，更新流程不同，本次未生成；如需纳管请人工补充启动/停止机制"})
				continue
			}

			// systemd unit 名（实机验证 2026-11-03：usercenter 主备两台的单元均为 usercenter.service，
			// EnvironmentFile 均为 usercenter.env——跨机主备实例不区分 _N）：
			//   microservice（JAR）：单元 = sub_type；仅同一台主机上部署多个实例时才用 sub_type_N 区分
			//   service（WAR）：tomcat-<biz_type>（tomcat_app role 的 systemd 单元约定）
			multi := len(kept) > 1
			hostInstCount := map[string]int{}
			for _, rec := range kept {
				hostInstCount[rec.inst.Host]++
			}
			unitFor := func(rec instRec) string {
				switch sec.middle {
				case "tomcat":
					if bt := strings.TrimSpace(rec.inst.BizType); bt != "" {
						return "tomcat-" + bt
					}
					notes = append(notes, config.Issue{Severity: "warn", Where: "metadata>" + appKey,
						Msg: "metadata 缺少 biz_type，无法按 tomcat-<biz_type> 生成 systemd 单元名，已按应用名回退，请人工核对"})
					return appKey
				default:
					if multi && hostInstCount[rec.inst.Host] > 1 {
						return rec.key
					}
					return appKey
				}
			}

			buildHost := func(rec instRec, unit string) (config.Host, bool) {
				webPath := strings.TrimRight(rec.inst.BasePath, "/")
				if sec.middle == "tomcat" && !strings.HasSuffix(webPath, "/"+appKey) {
					webPath = webPath + "/" + appKey
				}
				ip := rec.inst.IP
				if ip == "" {
					ip = nodeIP[rec.inst.Host]
				}
				if ip == "" {
					notes = append(notes, config.Issue{Severity: "error", Where: "metadata>" + appKey,
						Msg: fmt.Sprintf("实例 %s 无法确定主机 IP（metadata.ip 与 hosts.yml 均未提供），跳过", rec.key)})
					return config.Host{}, false
				}
				checkURI := ""
				if sec.middle == "tomcat" {
					checkURI = "/" + appKey + "/main.htm"
				} else {
					// 一键部署标准健康检查地址（核心 Java 服务自带 backend 探针）；
					// 清单外服务留空 → 更新后按 service_port 做 TCP 端口探测。
					checkURI = config.StandardCheckURI[appKey]
				}
				return config.Host{
					Host:        ip,
					ServicePort: int(rec.inst.ServerPort),
					CheckURI:    checkURI,
					WebPath:     webPath,
					StartCmd:    "systemctl start " + unit,
					StopCmd:     "systemctl stop " + unit,
					User:        "egova",
					Group:       "egova",
					SSHPort:     nodePort[rec.inst.Host],
					Remark:      "node=" + orDefault(rec.inst.Host, "?") + " unit=" + unit,
				}, true
			}

			var masters, updates []config.Host
			var jarEnvs []string
			envSeen := map[string]bool{}
			masterNode := masterOf[appKey]
			// 主实例索引：multi_server master 节点上恰有一个实例时选它；
			// 同机多实例（都在 master 节点上）或拓扑缺失时取第一个实例。
			masterIdx := 0
			if masterNode != "" {
				matches, idx := 0, -1
				for j, rec := range kept {
					if rec.inst.Host == masterNode {
						matches++
						idx = j
					}
				}
				if matches == 1 {
					masterIdx = idx
				}
			}
			for i, rec := range kept {
				unit := unitFor(rec)
				h, ok := buildHost(rec, unit)
				if !ok {
					continue
				}
				if sec.middle == "jar" {
					envName := unit + ".env"
					if !envSeen[envName] {
						envSeen[envName] = true
						jarEnvs = append(jarEnvs, envName)
					}
				}
				if multi {
					if i := strings.LastIndex(h.Remark, "unit="+unit); i >= 0 {
						h.Remark = h.Remark[:i+len("unit="+unit)] + " inst=" + rec.key + h.Remark[i+len("unit="+unit):]
					}
				}
				if !multi {
					masters = append(masters, h)
					// 单实例：slave → update 群组（主备语义映射为部署批次：先更主、验证后再更备；
					// 多备节点逐台加入 update 群组）
					for _, slaveNode := range slaveOf[appKey] {
						if slaveIP := nodeIP[slaveNode]; slaveIP != "" {
							s := h
							s.Host = slaveIP
							s.SSHPort = nodePort[slaveNode]
							s.Remark = "node=" + slaveNode + " unit=" + unit + " (slave)"
							updates = append(updates, s)
						} else {
							notes = append(notes, config.Issue{Severity: "warn", Where: "metadata>" + appKey,
								Msg: fmt.Sprintf("slave 节点 %q 在 hosts.yml 中未找到 IP，未加入 update 群组", slaveNode)})
						}
					}
					continue
				}
				// 多实例：主实例索引决定 master，其余 → update
				if i == masterIdx {
					masters = append(masters, h)
				} else {
					h.Remark += " (slave)"
					updates = append(updates, h)
				}
			}
			if len(masters) == 0 {
				continue // 全部实例都无法确定 IP
			}

			retained := []string(nil)
			exclusive := []string(nil)
			if sec.middle == "jar" {
				// 多实例各自有 <unit>.env，合并保留
				retained = append(retained, jarEnvs...)
				retained = append(retained, "application.properties")
			} else {
				// tomcat_app role 模板写入 WEB-INF/classes 的配置文件（更新时须保留）
				retained = []string{
					"WEB-INF/classes/jdbc.properties",
					"WEB-INF/classes/redis.properties",
				}
				switch appKey {
				case "eUrbanMIS", "eUrbanUMA", "eUrbanMF", "eUrbanSG":
					retained = append(retained,
						"WEB-INF/classes/timeseries.properties",
						"WEB-INF/classes/postgres.properties")
				}
				switch appKey {
				case "eUrbanMIS", "eUrbanUMA", "eUrbanMF":
					retained = append(retained, "WEB-INF/classes/kafka.properties")
				}
				// 旧版标准做法：liquibase 只在主节点跑，备节点不推且更新时自动清理（防数据库锁冲突）
				exclusive = []string{"egova-liquibase-*.jar", "liquibase-core-*.jar"}
			}

			logDir := "logs/" // JAR 微服务日志目录约定
			if sec.middle == "tomcat" {
				logDir = "WEB-INF/logs" // WAR 应用日志目录约定（个别应用为 WEB-INF/log，初稿需人工核对）
			}

			cfg.Webs = append(cfg.Webs, config.App{
				Web:                  appKey,
				MiddleType:           sec.middle,
				LogDir:               logDir,
				RetainedConfigFile:   retained,
				MasterExclusiveFiles: exclusive,
				Master:               masters,
				Update:               updates,
			})
		}
	}
	if skippedUndeployed > 0 {
		notes = append(notes, config.Issue{Severity: "warn", Where: "转换器",
			Msg: fmt.Sprintf("已跳过 %d 个 status=undeployed 的应用（如需包含请加 --include-undeployed）", skippedUndeployed)})
	}
	return cfg, notes, nil
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
