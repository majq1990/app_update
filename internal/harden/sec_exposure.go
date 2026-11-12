package harden

// sec_exposure.go —— 暴露面与未授权访问体检（对齐 oneinstall scan_exposure.sh）。
//
// 采集监听端口 → 高危字典比对 → 未授权主动探测（仅本机回环，等价上游约定）。
// 只读；拦截类动作在 network guard（sec_network.go）里，带确认与可回退链。

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// highRiskPorts 高危端口字典（端口|服务|风险|建议），与上游 HIGH_RISK_TABLE 对齐。
var highRiskPorts = map[string]struct {
	Svc          string
	Risk         string
	Advice       string
	IntranetOnly bool // 建议仅内网互通
}{
	"3306":  {"MySQL", "数据库端口对全网暴露", "仅允许应用服务器 IP 访问", true},
	"5432":  {"PostgreSQL", "数据库端口暴露", "仅允许应用服务器 IP 访问", true},
	"5236":  {"达梦DM", "数据库端口暴露", "仅允许应用服务器 IP 访问", true},
	"54321": {"人大金仓", "数据库端口暴露", "仅允许应用服务器 IP 访问", true},
	"5866":  {"瀚高", "数据库端口暴露", "仅允许应用服务器 IP 访问", true},
	"6379":  {"Redis", "未授权可写 ssh key/计划任务", "开启 requirepass 并限源", true},
	"9200":  {"Elasticsearch", "未授权可读写/删除索引", "开启认证并限源", true},
	"9300":  {"ES 传输", "集群传输端口暴露", "仅集群内网互通", true},
	"2181":  {"ZooKeeper", "未授权可读配置/删节点", "限源并启用 ACL", true},
	"2888":  {"ZK 集群", "集群端口暴露", "仅集群内网互通", true},
	"3888":  {"ZK 选举", "选举端口暴露", "仅集群内网互通", true},
	"9092":  {"Kafka", "未授权可消费/投递", "限源，开启 SASL", true},
	"8848":  {"Nacos", "默认口令 nacos/nacos", "改默认口令+限源", true},
	"9848":  {"Nacos gRPC", "客户端端口暴露", "限源", true},
	"2375":  {"Docker API", "未授权等同 root", "关闭远程 API 或启用 TLS", true},
	"2376":  {"Docker TLS", "远程 API 暴露", "仅运维网段可达", true},
	"9000":  {"MinIO/RustFS", "对象存储未授权可读写桶", "限源并改默认口令", true},
	"9001":  {"MinIO 控制台", "控制台暴露+默认口令", "限源", true},
	"27017": {"MongoDB", "未授权可读写全库", "开启认证并限源", true},
	"8500":  {"Consul", "未授权可注册/注销服务", "限源", true},
	"8761":  {"Eureka", "注册中心未授权", "限源", true},
	"11211": {"Memcached", "未授权可读写缓存", "限源（SASL/监听 127.0.0.1）", true},
	"6030":  {"TDengine", "数据库端口暴露", "仅允许应用服务器 IP 访问", true},
	"8086":  {"InfluxDB", "时序库暴露", "开启认证并限源", true},
	"61616": {"ActiveMQ", "消息队列暴露", "限源", true},
	"15672": {"RabbitMQ 管理台", "管理台暴露+默认口令", "限源并改默认口令", true},
	"1883":  {"MQTT", "消息端口暴露", "开启认证并限源", true},
	"7001":  {"WebLogic", "控制台暴露", "限源", true},
	"8081":  {"Tomcat manager 常见口", "管理端暴露", "移除 manager 应用或限源", true},
}

// listeningPortsCmd 采集监听端口（去重排序）。
const listeningPortsCmd = `ss -lntH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | grep -E '^[0-9]+$' | sort -nu`

// parseListeningPorts 解析 ss 输出为端口集合。
func parseListeningPorts(out string) []string {
	set := map[string]bool{}
	for _, ln := range strings.Split(out, "\n") {
		p := strings.TrimSpace(ln)
		if p == "" {
			continue
		}
		if _, err := strconv.Atoi(p); err == nil && p != "0" {
			set[p] = true
		}
	}
	var ports []string
	for p := range set {
		ports = append(ports, p)
	}
	sort.Strings(ports)
	return ports
}

// checkExposurePorts 高危端口字典比对。
func checkExposurePorts(ports []string, protected map[string]bool, host string, r *SecReport) {
	for _, p := range ports {
		hr, risky := highRiskPorts[p]
		if !risky {
			continue
		}
		if protected[p] {
			r.Add(SecFinding{Host: host, Category: "暴露面", Item: "高危端口 " + p + "(" + hr.Svc + ")",
				Result: "已登记 egova-expose-ports 白名单", Level: SecInfo, Fixable: "no"})
			continue
		}
		r.Add(SecFinding{Host: host, Category: "暴露面", Item: "高危端口 " + p + "(" + hr.Svc + ")",
			Result: hr.Risk, Evidence: "监听在全部网卡", Advice: hr.Advice, Level: SecHigh, Fixable: "yes"})
	}
}

// probeHTTP 未授权 HTTP 探测（仅本机回环）：
// 输出 "unauth"（命中关键字）/ "auth"（401/403）/ "closed"/"unknown"。
func probeHTTP(port int, path string) string {
	cmd := fmt.Sprintf(`out=$(curl -sk --max-time 4 -w '\n%%{http_code}' 'http://127.0.0.1:%d%s' 2>/dev/null); code=$(printf '%%s' "$out" | tail -1); body=$(printf '%%s' "$out" | head -c 400); case "$code" in 000|'') echo closed;; 401|403) echo auth;; *) case "$body" in *cluster_name*|*nacos*|*swagger*|*doc.html*|*knife4j*|*"_links"*|*Whitelabel*|*{"*|*pageList*) echo unauth;; *) echo unknown;; esac;; esac`, port, path)
	out, _ := remoteRun(cmd)
	return strings.TrimSpace(firstLine(out))
}

// probeRedis Redis PING 探测。
func probeRedis(port int) string {
	cmd := fmt.Sprintf(`out=$(timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/%d; printf "PING\r\n" >&3; head -c 64 <&3' 2>/dev/null); case "$out" in *PONG*) echo unauth;; *NOAUTH*|*WRONGPASS*) echo auth;; *) echo unknown;; esac`, port)
	out, _ := remoteRun(cmd)
	return strings.TrimSpace(firstLine(out))
}

// probeZK ZooKeeper 4lw 探测。
func probeZK(port int) string {
	cmd := fmt.Sprintf(`out=$(timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/%d; printf "stat\n" >&3; head -c 64 <&3' 2>/dev/null); case "$out" in *Zookeeper*|*Zxid*) echo unauth;; * stat*) echo unauth;; "") echo closed;; *) echo unknown;; esac`, port)
	out, _ := remoteRun(cmd)
	return strings.TrimSpace(firstLine(out))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// runExposureCheck 一次完整暴露面体检（主机级）。
func RunExposureCheck(host string, r *SecReport) {
	// 0) 采集受保护端口（egova-expose-ports 白名单）
	protected := map[string]bool{}
	if out, err := remoteRun(`ipset list -n 2>/dev/null | grep -q '^egova-expose-ports$' && ipset list egova-expose-ports 2>/dev/null | sed -n '6,40p' | awk '{print $1}' | grep -E '^[0-9]+$'`); err == nil {
		for _, p := range strings.Fields(out) {
			protected[p] = true
		}
	}

	// 1) 监听端口采集 + 字典比对
	out, err := remoteRun(listeningPortsCmd)
	if err != nil {
		r.AddError(host + " 监听采集失败: " + err.Error())
		return
	}
	ports := parseListeningPorts(out)
	r.Add(SecFinding{Host: host, Category: "暴露面", Item: "监听端口采集",
		Result: fmt.Sprintf("%d 个端口", len(ports)), Level: SecInfo, Fixable: "no"})
	checkExposurePorts(ports, protected, host, r)

	// 2) 未授权主动探测（仅对在监听的端口）
	listening := map[string]bool{}
	for _, p := range ports {
		listening[p] = true
	}
	probe := func(name, pport string, level SecLevel, method string, onUnauth, onAuth string) {
		if !listening[pport] {
			return
		}
		var st string
		switch method {
		case "redis":
			st = probeRedis(mustAtoi(pport))
		case "zk":
			st = probeZK(mustAtoi(pport))
		default:
			st = "unknown"
		}
		switch st {
		case "unauth":
			r.Add(SecFinding{Host: host, Category: "未授权访问", Item: name + "(" + pport + ")",
				Result: onUnauth, Level: level, Advice: "开启认证并限源；禁止 0.0.0.0 监听", Fixable: "yes"})
		case "auth":
			r.Add(SecFinding{Host: host, Category: "未授权访问", Item: name + "(" + pport + ")",
				Result: onAuth, Level: SecInfo, Fixable: "no"})
		}
	}
	probe("Redis", "6379", SecCritical, "redis", "PING 返回 PONG，未设置 requirepass，等同主机沦陷风险", "已开启认证")

	httpProbes := []struct {
		name, port, path string
		level            SecLevel
		onUnauth, onAuth string
	}{
		{"Elasticsearch", "9200", "/", SecCritical, "返回 cluster_name，未开启认证", "已开启认证"},
		{"Nacos", "8848", "/nacos/v1/auth/users?pageNo=1&pageSize=1", SecCritical, "用户列表接口可匿名访问", "已开启鉴权"},
		{"Docker API", "2375", "/version", SecCritical, "API 可匿名访问，等同宿主机 root", "已开启认证"},
		{"MinIO", "9000", "/minio/health/live", SecMedium, "健康检查可达（需核对 AK/SK 默认口令）", "不可达"},
		{"Tomcat manager", "8081", "/manager/html", SecCritical, "manager 页面可访问", "已鉴权(401)"},
	}
	for _, p := range httpProbes {
		if !listening[p.port] {
			continue
		}
		st := probeHTTP(mustAtoi(p.port), p.path)
		switch st {
		case "unauth":
			r.Add(SecFinding{Host: host, Category: "未授权访问", Item: p.name + "(" + p.port + ")",
				Result: p.onUnauth, Level: p.level, Advice: "开启认证/移除应用并限源", Fixable: "yes"})
		case "auth":
			r.Add(SecFinding{Host: host, Category: "未授权访问", Item: p.name + "(" + p.port + ")",
				Result: p.onAuth, Level: SecInfo, Fixable: "no"})
		}
	}

	// Actuator / Swagger 常见端口兜底（应用端口已知时按 service_port，未知则扫 8080/8081）
	cand := map[string]bool{"8080": true, "8081": true}
	for _, p := range []string{"8080", "8081"} {
		if !listening[p] || protected[p] {
			continue
		}
		_ = cand
		for _, path := range []string{"/actuator/env", "/v2/api-docs", "/doc.html"} {
			st := probeHTTP(mustAtoi(p), path)
			if st == "unauth" {
				r.Add(SecFinding{Host: host, Category: "未授权访问", Item: "调试接口 " + p + path,
					Result: "可匿名访问", Level: SecHigh,
					Advice: "关闭 actuator 暴露 / swagger production 或由 nginx 拦截（见 harden nginx fix）", Fixable: "yes"})
				break
			}
		}
	}

	// 3) Docker 暴露面（0.0.0.0 发布 + 特权容器）
	dockerOut, derr := remoteRun(`docker ps --format '{{.Names}}|{{.Ports}}' 2>/dev/null; echo ---; docker ps --format '{{.Names}}|{{.HostConfig.Privileged}}' 2>/dev/null`)
	if derr == nil && strings.TrimSpace(dockerOut) != "" {
		parts := strings.SplitN(dockerOut, "---", 2)
		for _, ln := range strings.Split(parts[0], "\n") {
			f := strings.SplitN(strings.TrimSpace(ln), "|", 2)
			if len(f) != 2 {
				continue
			}
			for _, seg := range strings.Split(f[1], ",") {
				if strings.Contains(seg, "0.0.0.0:") {
					r.Add(SecFinding{Host: host, Category: "容器", Item: "Docker " + f[0] + " 发布端口对全网",
						Result: strings.TrimSpace(seg), Level: SecHigh,
						Advice: "harden network docker fix：DOCKER-USER 链按 egova-vpc-nets 限源", Fixable: "yes"})
					break
				}
			}
		}
		if len(parts) == 2 {
			for _, ln := range strings.Split(parts[1], "\n") {
				f := strings.SplitN(strings.TrimSpace(ln), "|", 2)
				if len(f) == 2 && strings.EqualFold(f[1], "true") {
					r.Add(SecFinding{Host: host, Category: "容器", Item: "Docker " + f[0] + " 特权容器",
						Result: "--privileged", Level: SecCritical,
						Advice: "去除 --privileged（等同 root），按需最小挂载", Fixable: "no"})
				}
			}
		}
	}

	// 4) ipset 防护状态
	vpcOut, verr := remoteRun(`ipset list -n 2>/dev/null | grep -c '^egova-vpc-nets$'; iptables -S 2>/dev/null | grep -c 'egova-vpc-nets'`)
	if verr == nil {
		n := strings.Fields(strings.TrimSpace(vpcOut))
		if len(n) == 2 && (n[0] == "0" || n[1] == "0") {
			r.Add(SecFinding{Host: host, Category: "暴露面", Item: "egova-vpc-nets 白名单",
				Result: "未建立或未挂载", Level: SecMedium,
				Advice: "harden network guard fix：创建白名单集合并挂载 EGOVA-SEC-GUARD 链", Fixable: "yes"})
		}
	}
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
