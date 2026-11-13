package harden

// sec_network.go —— 网络层拦截（对齐 oneinstall harden_network_guard.sh）。
//
// 子命令：status / docker / guard / ban / unban / install-cron。
// 设计：iptables/ipset 白名单链 EGOVA-SEC-GUARD 与封禁链 EGOVA-BAN（egova-ban 集合 24h 超时）；
//       DOCKER-USER 解决容器发布端口绕过 firewalld；私网 IP 不封禁防误伤；
//       所有变更均 dry-run 默认、--yes 执行、可整链回退。

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	vpcSet       = "egova-vpc-nets"
	banSet       = "egova-ban"
	guardChain   = "EGOVA-SEC-GUARD"
	banChain     = "EGOVA-BAN"
	banThreshold = 20
	banSeconds   = 86400
)

// isPrivateIPOutput 私网判断（IPv4 私网段 + 回环 + 链路本地）。
const isPrivateIPOutput = `python3 -c "
import sys
ip=sys.argv[1].strip().split('.')[0:4]
if not ip or len(ip)!=4: print('no'); raise SystemExit
try: o=[int(x) for x in ip]
except: print('no'); raise SystemExit
private = o[0]==10 or (o[0]==172 and 16<=o[1]<=31) or (o[0]==192 and o[1]==168) or o[0]==127 or (o[0]==169 and o[1]==254)
print('yes' if private else 'no')
" "$1" 2>/dev/null || echo no`

// runNetworkStatus 只读：链/集合现状 + docker 暴露端口 + 最近可疑 IP TOP。
func RunNetworkStatus(host string, r *SecReport) {
	rec := func(level SecLevel, item, result, evidence string) {
		r.Add(SecFinding{Host: host, Category: "网络拦截", Item: item, Result: result,
			Evidence: evidence, Level: level, Fixable: "yes"})
	}
	out, _ := remoteRun(fmt.Sprintf(
		`printf 'vpc=%%s\n' "$(ipset list -n 2>/dev/null | grep -c '^%s$')"; `+
			`printf 'guard=%%s\n' "$(iptables -S %s 2>/dev/null | grep -c '^-A')"; `+
			`printf 'ban=%%s\n' "$(ipset list %s 2>/dev/null | sed -n '6,200p' | awk 'NF{c++} END{print c+0}')"; `+
			`printf 'chain_in=%%s\n' "$(iptables -nL INPUT 2>/dev/null | grep -c '%s')"`,
		vpcSet, guardChain, banSet, banChain))
	if strings.TrimSpace(out) == "" {
		r.AddError(host + " iptables/ipset 查询失败（可能无权限）")
		return
	}
	kv := map[string]string{}
	for _, ln := range strings.Split(out, "\n") {
		if i := strings.IndexByte(ln, '='); i > 0 {
			kv[strings.TrimSpace(ln[:i])] = strings.TrimSpace(ln[i+1:])
		}
	}
	rec(SecInfo, "白名单集合 "+vpcSet, ternary(kv["vpc"] != "0", "存在", "未建立"), "")
	rec(SecInfo, "限源链 "+guardChain, ternary(kv["guard"] != "0", fmt.Sprintf("%s 条规则", kv["guard"]), "未建立"), "")
	rec(SecInfo, "封禁集合 "+banSet, fmt.Sprintf("%s 个 IP（24h 自动解封）", kv["ban"]), "")
	rec(SecInfo, "INPUT 挂载", ternary(kv["chain_in"] != "0", "已挂载", "未挂载"), "")

	// docker 暴露端口（已由 DOCKER-USER 限源的降为信息）
	guarded := guardedPorts()
	dOut, _ := remoteRun(`docker ps --format '{{.Names}}|{{.Ports}}' 2>/dev/null | head -10`)
	for _, ln := range strings.Split(dOut, "\n") {
		f := strings.SplitN(strings.TrimSpace(ln), "|", 2)
		if len(f) != 2 || f[0] == "" {
			continue
		}
		if !strings.Contains(f[1], "0.0.0.0:") {
			continue
		}
		ports := publishedHostPorts(f[1])
		var un []string
		for _, p := range ports {
			if !guarded[p] {
				un = append(un, p)
			}
		}
		if len(ports) > 0 && len(un) == 0 {
			rec(SecInfo, "Docker "+f[0]+" 发布端口",
				"已由 DOCKER-USER 限源至内网/VPC（"+strings.Join(ports, ",")+"）", "")
			continue
		}
		rec(SecHigh, "Docker "+f[0]+" 发布端口", "对全网暴露（绕过 firewalld）",
			"未限源端口: "+strings.Join(un, ",")+" | "+strings.TrimSpace(f[1]))
	}

	// 可疑 IP TOP
	badOut, _ := remoteRun(badIPsCmd())
	ips := parseBadIPs(badOut)
	if len(ips) > 0 {
		rec(SecMedium, "可疑 IP（≥"+itoa(banThreshold)+" 次）", fmt.Sprintf("检测到 %d 个，harden network ban --yes 执行封禁", len(ips)), strings.Join(ips[:minInt(5, len(ips))], ", "))
	} else {
		r.Add(SecFinding{Host: host, Category: "网络拦截", Item: "可疑 IP",
			Result: "未达到封禁阈值", Level: SecInfo, Fixable: "no"})
	}
}

// publishedHostPorts 从 docker ps 的 Ports 字段解析宿主端口（含范围展开）。
// 形如 "0.0.0.0:8848->8848/tcp, [::]:2379-2380->2379-2380/tcp"。
func publishedHostPorts(s string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		i := strings.Index(part, "->")
		if i < 0 {
			continue
		}
		left := part[:i]
		if !strings.HasPrefix(left, "0.0.0.0:") {
			continue
		}
		j := strings.LastIndex(left, ":")
		if j < 0 {
			continue
		}
		ps := left[j+1:]
		if k := strings.Index(ps, "-"); k > 0 {
			a, e1 := strconv.Atoi(ps[:k])
			b, e2 := strconv.Atoi(ps[k+1:])
			if e1 == nil && e2 == nil && b >= a && b-a <= 100 {
				for n := a; n <= b; n++ {
					add(strconv.Itoa(n))
				}
			}
			continue
		}
		add(ps)
	}
	return out
}

// parseBadIPs 解析 badIPsCmd 输出（unbound: "次数 IP"），只保留合法 IPv4，去重。
// status 与 ban 共用，保证两处计数一致。
func parseBadIPs(out string) []string {
	seen := map[string]bool{}
	var ips []string
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(ln))
		if len(f) < 2 || !isDigits(f[0]) || !isIPv4(f[1]) {
			continue
		}
		if !seen[f[1]] {
			seen[f[1]] = true
			ips = append(ips, f[1])
		}
	}
	return ips
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// badIPsCmd 恶意 IP 统计（nginx 401/403/444/404 + sshd Failed password，取 ≥阈值）。
func badIPsCmd() string {
	return `logs=$(find /egova/log /egova/logs /var/log/nginx /egova/nginx/logs -type f -name '*access*.log' 2>/dev/null | head -20); tmp=/tmp/.eops_badip.$$$$; : > $tmp; for f in $logs; do tail -n 50000 "$f" 2>/dev/null | awk 'match($0,/\" (401|403|444|404) /){print $1}' >> $tmp; done; for f in /var/log/secure /var/log/auth.log; do grep 'Failed password' "$f" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' >> $tmp; done; sort $tmp 2>/dev/null | uniq -c | awk '$1>=` + itoa(banThreshold) + `{print $1, $2}'; rm -f $tmp`
}

// networkEnsureCmd 建链挂载（幂等）。
func networkEnsureCmd() string {
	return fmt.Sprintf(
		`ipset create -! %s hash:net 2>/dev/null; ipset create -! %s hash:ip timeout %d 2>/dev/null; `+
			`iptables -nL %s >/dev/null 2>&1 || iptables -N %s; `+
			`iptables -C %s -m set --match-set %s src -j DROP 2>/dev/null || iptables -A %s -m set --match-set %s src -j DROP; `+
			`iptables -C INPUT -j %s 2>/dev/null || iptables -I INPUT 1 -j %s; `+
			`iptables -nL DOCKER-USER >/dev/null 2>&1 && { iptables -C DOCKER-USER -j %s 2>/dev/null || iptables -I DOCKER-USER 1 -j %s; }; echo ENSURED`,
		vpcSet, banSet, banSeconds,
		guardChain, guardChain,
		guardChain, vpcSet, guardChain, vpcSet,
		banChain, banChain, banChain, banChain)
}

// runNetworkGuard 高危端口限源（DOCKER/INPUT 双挂 EGOVA-SEC-GUARD）。
// vpcMemberCount 返回白名单集合成员数（集合不存在或为空 → 0）。
// 限源前必须校验：集合为空时加 DROP 规则会让所有来源都不可达（含运维），
// 因此 guard/docker 在 --yes 前强制要求集合非空。
func vpcMemberCount() int {
	out, err := remoteRun(fmt.Sprintf(
		`ipset list %s 2>/dev/null | sed -n '6,100000p' | awk 'NF{c++} END{print c+0}'`, vpcSet))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(out))
	return n
}

// requireVpcMembers 空集合拒绝执行（返回错误并由 CLI 记录）。
func requireVpcMembers(host string, r *SecReport) error {
	n := vpcMemberCount()
	if n > 0 {
		return nil
	}
	r.Add(SecFinding{Host: host, Category: "网络拦截", Item: "白名单集合为空，已拒绝限源",
		Result: "egova-vpc-nets 无成员，执行 DROP 会导致全站不可达",
		Advice: "先导入内部网段：ipset add egova-vpc-nets <网段>（或执行 oneinstall 端口加固导入配置）",
		Level:  SecCritical, Fixable: "no"})
	return fmt.Errorf("egova-vpc-nets 为空，拒绝执行限源（防误封）")
}

func RunNetworkGuard(host string, r *SecReport, yes bool) error {
	// 采集高危且在监听的端口
	out, err := remoteRun(listeningPortsCmd)
	if err != nil {
		return err
	}
	ports := parseListeningPorts(out)
	var targets []string
	for _, p := range ports {
		if _, risky := highRiskPorts[p]; risky {
			targets = append(targets, p)
		}
	}
	if len(targets) == 0 {
		r.Add(SecFinding{Host: host, Category: "网络拦截", Item: "高危端口限源",
			Result: "无监听中的高危端口", Level: SecInfo, Fixable: "no"})
		return nil
	}
	var rules []string
	for _, p := range targets {
		rules = append(rules,
			fmt.Sprintf(`iptables -C %s -p tcp --dport %s -m set --match-set %s src -j RETURN 2>/dev/null || iptables -I %s 1 -p tcp --dport %s -m set --match-set %s src -j RETURN`,
				guardChain, p, vpcSet, guardChain, p, vpcSet),
			fmt.Sprintf(`iptables -C %s -p tcp --dport %s -j DROP 2>/dev/null || iptables -I %s 1 -p tcp --dport %s -m comment --comment eops-sec-guard -j DROP`,
				guardChain, p, guardChain, p))
	}
	if !yes {
		if vpcMemberCount() == 0 {
			fmt.Printf("  ⚠️ %s 未建立/为空：真实执行会被拒绝（先导入内网网段）\n", vpcSet)
		}
		fmt.Printf("  [network guard 计划] %s：限源端口 %v\n", host, targets)
		for _, rl := range rules {
			fmt.Printf("    $ %s\n", truncate(rl, 130))
		}
		fmt.Println("  （dry-run；确认后加 --yes 执行）")
		return nil
	}
	if err := requireVpcMembers(host, r); err != nil {
		return err
	}
	if _, err := remoteRun(networkEnsureCmd()); err != nil {
		return err
	}
	for _, rl := range rules {
		if _, err := remoteRun(rl); err != nil {
			return err
		}
	}
	_, _ = remoteRun(`iptables-save > /etc/sysconfig/iptables 2>/dev/null || true`)
	r.Add(SecFinding{Host: host, Category: "网络拦截", Item: "高危端口限源",
		Result: fmt.Sprintf("%v 已限源至 %s 白名单（iptables-save 已持久化）", targets, vpcSet),
		Level:  SecInfo, Fixable: "no"})
	return nil
}

// runNetworkDocker 容器发布端口收敛（DOCKER-USER 链）。
func RunNetworkDocker(host string, r *SecReport, yes bool) error {
	out, err := remoteRun(`docker ps --format '{{.Names}}|{{.Ports}}' 2>/dev/null`)
	if err != nil || strings.TrimSpace(out) == "" {
		r.Add(SecFinding{Host: host, Category: "容器", Item: "端口收敛",
			Result: "docker 不可用或无容器", Level: SecInfo, Fixable: "no"})
		return nil
	}
	var exposed []string
	for _, ln := range strings.Split(out, "\n") {
		f := strings.SplitN(strings.TrimSpace(ln), "|", 2)
		if len(f) != 2 {
			continue
		}
		exposed = append(exposed, publishedHostPorts(f[1])...)
	}
	if len(exposed) == 0 {
		r.Add(SecFinding{Host: host, Category: "容器", Item: "端口收敛",
			Result: "未发现 0.0.0.0 发布端口", Level: SecInfo, Fixable: "no"})
		return nil
	}
	var rules []string
	for _, p := range dedupeStrings(exposed) {
		rules = append(rules,
			fmt.Sprintf(`iptables -C DOCKER-USER -p tcp --dport %s -m set --match-set %s src -j RETURN 2>/dev/null || iptables -I DOCKER-USER 1 -p tcp --dport %s -m set --match-set %s src -j RETURN`,
				p, vpcSet, p, vpcSet),
			fmt.Sprintf(`iptables -C DOCKER-USER -p tcp --dport %s -j DROP 2>/dev/null || iptables -I DOCKER-USER 1 -p tcp --dport %s -m comment --comment eops-sec-guard -j DROP`, p, p))
	}
	if !yes {
		if vpcMemberCount() == 0 {
			fmt.Printf("  ⚠️ %s 未建立/为空：真实执行会被拒绝（先导入内网网段）\n", vpcSet)
		}
		fmt.Printf("  [network docker 计划] %s：容器端口限源 %v\n", host, dedupeStrings(exposed))
		for _, rl := range rules {
			fmt.Printf("    $ %s\n", truncate(rl, 130))
		}
		fmt.Println("  （dry-run；确认后加 --yes 执行）")
		return nil
	}
	if err := requireVpcMembers(host, r); err != nil {
		return err
	}
	if _, err := remoteRun(networkEnsureCmd()); err != nil {
		return err
	}
	for _, rl := range rules {
		if _, err := remoteRun(rl); err != nil {
			return err
		}
	}
	_, _ = remoteRun(`iptables-save > /etc/sysconfig/iptables 2>/dev/null || true`)
	r.Add(SecFinding{Host: host, Category: "容器", Item: "端口收敛",
		Result: fmt.Sprintf("%v 已在 DOCKER-USER 限源至 %s", dedupeStrings(exposed), vpcSet), Level: SecInfo, Fixable: "no"})
	return nil
}

// runNetworkBan 恶意 IP 封禁（统计 → egova-ban 24h → EGOVA-BAN 挂 INPUT+DOCKER-USER）。
func RunNetworkBan(host string, r *SecReport, yes, installCron bool) error {
	out, err := remoteRun(badIPsCmd())
	if err != nil {
		return err
	}
	var ips []string
	ips = parseBadIPs(out)
	var willBan []string
	for _, ip := range ips {
		if !isIPv4(ip) || isPrivateIPv4(ip) {
			continue // 格式非法/私网一律豁免（防误伤内网扫描器，与上游约定一致）
		}
		pi, perr := remoteRun(fmt.Sprintf(`%s %s`, isPrivateIPOutput, sq(ip)))
		if perr == nil && strings.TrimSpace(pi) == "yes" {
			continue
		}
		willBan = append(willBan, ip)
	}
	if !yes {
		fmt.Printf("  [network ban 计划] %s：候选 %d 个可疑 IP，私网豁免后封禁 %d 个（24h）\n",
			host, len(ips), len(willBan))
		for _, ip := range willBan {
			fmt.Printf("    ban %s\n", ip)
		}
		fmt.Printf("    + 安装 5 分钟 cron（--install-cron 开关：%v）\n", installCron)
		fmt.Println("  （dry-run；确认后加 --yes 执行）")
		return nil
	}
	if _, err := remoteRun(networkEnsureCmd()); err != nil {
		return err
	}
	n := 0
	for _, ip := range willBan {
		cmd := fmt.Sprintf(`ipset add -! %s %s timeout %d 2>/dev/null && echo BANNED`, banSet, sq(ip), banSeconds)
		o, e := remoteRun(cmd)
		if e == nil && strings.Contains(o, "BANNED") {
			n++
		}
	}
	if installCron {
		cron := fmt.Sprintf(`(crontab -l 2>/dev/null | grep -v 'eops network ban'; echo '*/5 * * * * %s network ban --yes --install-cron=false >> /egova/log/eops-ban.log 2>&1') | crontab -`, eopsPathHint())
		_, _ = remoteRun(cron)
	}
	r.Add(SecFinding{Host: host, Category: "网络拦截", Item: "恶意 IP 封禁",
		Result: fmt.Sprintf("本次封禁 %d 个 IP（24h 自动解封；私网豁免 %d 个）", n, len(ips)-len(willBan)),
		Level:  SecInfo, Fixable: "no"})
	return nil
}

// runNetworkUnban 解封指定 IP（或 all 清空）。
func RunNetworkUnban(host string, ip string, r *SecReport) error {
	if ip == "all" {
		_, err := remoteRun(fmt.Sprintf(`ipset flush %s && echo FLUSHED`, banSet))
		if err != nil {
			return err
		}
		r.Add(SecFinding{Host: host, Category: "网络拦截", Item: "解封",
			Result: "已清空封禁集合", Level: SecInfo, Fixable: "no"})
		return nil
	}
	if !isIPv4(ip) {
		return fmt.Errorf("IP 非法: %q", ip)
	}
	_, err := remoteRun(fmt.Sprintf(`ipset del %s %s 2>/dev/null; echo DONE`, banSet, sq(ip)))
	if err != nil {
		return err
	}
	r.Add(SecFinding{Host: host, Category: "网络拦截", Item: "解封 " + ip,
		Result: "已解封", Level: SecInfo, Fixable: "no"})
	return nil
}

// eopsPathHint cron 里用的工具路径（远端约定安装位）。
func eopsPathHint() string { return "/egova/eops/eops" }

func ternary(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isIPv4 简单 IPv4 校验（0-255 四段）。
// isPrivateIPv4 内置私网段判断（RFC1918 + 回环 + 链路本地），先于远端脚本兜底。
func isPrivateIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 || !isDigits(parts[0]) {
		return false
	}
	o := make([]int, 4)
	for i, p := range parts {
		o[i] = mustAtoi(p)
	}
	return o[0] == 10 ||
		(o[0] == 172 && o[1] >= 16 && o[1] <= 31) ||
		(o[0] == 192 && o[1] == 168) ||
		o[0] == 127 ||
		(o[0] == 169 && o[1] == 254)
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if !isDigits(p) || len(p) > 3 || greater(p, 255) {
			return false
		}
	}
	return true
}
