package harden

// sec_cn.go —— 境外 IP 默认拉黑（对齐 oneinstall cn_whitelist.sh）。
//
// 机制：
//   - ipset egova-cn-nets：内置中国网段（chnroute.txt，8786 条）
//   - ipset egova-cn-allow：额外放行（运维出口 IP、VPC 网段、健康检查等）
//   - iptables 链 EGOVA-CN-GUARD：lo / allow / CN 放行，其余 DROP
//   - 挂载到 INPUT 与 DOCKER-USER（覆盖容器发布端口）
//
// 安全闸门：中国网段加载少于 1000 条时拒绝启用，避免空集合导致全站不可达。

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"
)

//go:embed chnroute.txt
var cnCIDRsRaw string

const (
	cnSet      = "egova-cn-nets"
	cnAllowSet = "egova-cn-allow"
	cnChain    = "EGOVA-CN-GUARD"
)

// cnMinEntries 最低网段数，低于此值拒绝启用。
const cnMinEntries = 1000

// cnCIDRs 解析内置网段（去空行/注释）。
func cnCIDRs() []string {
	var out []string
	for _, ln := range strings.Split(cnCIDRsRaw, "\n") {
		s := strings.TrimSpace(ln)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	return out
}

// validCIDR 简单校验 IPv4/CIDR（避免把脏数据写进 ipset）。
func validCIDR(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t;'\"`$") {
		return false
	}
	ip, mask, ok := strings.Cut(s, "/")
	if !ok {
		mask = "32"
	}
	if !isIPv4(ip) {
		return false
	}
	n, err := strconv.Atoi(mask)
	return err == nil && n >= 0 && n <= 32
}

// cnAllowList 合并默认放行项与用户追加项（去重、校验）。
func cnAllowList(extra []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] || !validCIDR(s) {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, s := range extra {
		add(s)
	}
	return out, nil
}

// cnEnableScript 生成启用脚本（bash -s 下发）。
func cnEnableScript(allow []string) (string, error) {
	cidrs := cnCIDRs()
	if len(cidrs) < cnMinEntries {
		return "", fmt.Errorf("内置中国网段仅 %d 条（<%d），拒绝启用", len(cidrs), cnMinEntries)
	}
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString("ipset create " + cnSet + " hash:net -exist\n")
	b.WriteString("ipset flush " + cnSet + "\n")
	b.WriteString("ipset create " + cnAllowSet + " hash:net -exist\n")
	b.WriteString("ipset flush " + cnAllowSet + "\n")
	for _, a := range allow {
		if validCIDR(a) {
			b.WriteString(fmt.Sprintf("ipset add -exist %s %s\n", cnAllowSet, sq(a)))
		}
	}
	b.WriteString("ipset restore -exist <<'EOFCN'\n")
	for _, c := range cidrs {
		b.WriteString("add " + cnSet + " " + c + "\n")
	}
	b.WriteString("EOFCN\n")
	b.WriteString("n=$(ipset list " + cnSet + " | grep -c '^[0-9]')\n")
	b.WriteString(fmt.Sprintf("[ \"$n\" -ge %d ] || { echo \"CN_SET_TOO_SMALL=$n\"; exit 3; }\n", cnMinEntries))
	b.WriteString("iptables -N " + cnChain + " 2>/dev/null || true\n")
	b.WriteString("iptables -F " + cnChain + "\n")
	b.WriteString("iptables -A " + cnChain + " -i lo -j RETURN\n")
	b.WriteString("iptables -A " + cnChain + " -m set --match-set " + cnAllowSet + " src -j RETURN\n")
	b.WriteString("iptables -A " + cnChain + " -m set --match-set " + cnSet + " src -j RETURN\n")
	b.WriteString("iptables -A " + cnChain + " -j DROP\n")
	b.WriteString("iptables -C INPUT -j " + cnChain + " 2>/dev/null || iptables -I INPUT 1 -j " + cnChain + "\n")
	b.WriteString("iptables -C DOCKER-USER -j " + cnChain + " 2>/dev/null || iptables -I DOCKER-USER 1 -j " + cnChain + " 2>/dev/null || true\n")
	b.WriteString("echo CN_ENABLED=$n\n")
	return b.String(), nil
}

// RunCNStatus 中国网段/放行集合/挂载状态。
func RunCNStatus(host string, r *SecReport) {
	out, _ := remoteRun(fmt.Sprintf(`echo "set=$(ipset list %s 2>/dev/null | grep -c '^[0-9]')"; echo "allow=$(ipset list %s 2>/dev/null | grep -c '^[0-9]')"; echo "input=$(iptables -C INPUT -j %s 2>/dev/null && echo yes || echo no)"; echo "docker=$(iptables -C DOCKER-USER -j %s 2>/dev/null && echo yes || echo no)"`,
		cnSet, cnAllowSet, cnChain, cnChain))
	vals := map[string]string{}
	for _, ln := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(ln), "="); ok {
			vals[k] = v
		}
	}
	n, _ := strconv.Atoi(vals["set"])
	if n == 0 {
		r.Add(SecFinding{Host: host, Category: "境外拦截", Item: "中国网段集合",
			Result: "未启用", Advice: "harden sec cn enable --yes", Level: SecMedium, Fixable: "yes"})
		return
	}
	lv := SecInfo
	if n < cnMinEntries {
		lv = SecMedium
	}
	r.Add(SecFinding{Host: host, Category: "境外拦截", Item: "中国网段集合",
		Result: fmt.Sprintf("%d 条", n), Level: lv, Fixable: "no"})
	r.Add(SecFinding{Host: host, Category: "境外拦截", Item: "额外放行",
		Result: vals["allow"] + " 条", Level: SecInfo, Fixable: "no"})
	for _, kv := range [][2]string{{"input", "INPUT"}, {"docker", "DOCKER-USER"}} {
		if vals[kv[0]] != "yes" {
			r.Add(SecFinding{Host: host, Category: "境外拦截", Item: kv[1] + " 未挂载",
				Result: "境外 IP 可访问", Level: SecMedium, Fixable: "yes"})
		}
	}
}

// RunCNEnable 启用境外 IP 默认拉黑（allow 为额外放行 CIDR）。
func RunCNEnable(host string, r *SecReport, yes bool, allow []string) error {
	cidrs := cnCIDRs()
	if len(cidrs) < cnMinEntries {
		return fmt.Errorf("内置中国网段仅 %d 条（<%d），拒绝启用", len(cidrs), cnMinEntries)
	}
	if !yes {
		fmt.Printf("  [cn enable 计划] %s：内置 %d 个中国网段 + 额外放行 %d 个；命中 INPUT/DOCKER-USER 后其余 DROP\n",
			host, len(cidrs), len(allow))
		fmt.Printf("    放行: %s\n", strings.Join(allow, ", "))
		fmt.Println("  （dry-run；确认后加 --yes 执行）")
		return nil
	}
	rn, rerr := runnerOf(host)
	if rerr != nil {
		return rerr
	}

	// 分块上传网段清单（单次 stdin 过大时 SSH 可能短写，按 1000 行分片）
	const chunk = 1000
	_, _ = remoteRun(`rm -f /tmp/.eops_cn.txt`)
	for i := 0; i < len(cidrs); i += chunk {
		end := i + chunk
		if end > len(cidrs) {
			end = len(cidrs)
		}
		payload := strings.Join(cidrs[i:end], "\n") + "\n"
		if _, werr := rn.RunWithStdin(`cat >> /tmp/.eops_cn.txt`, []byte(payload)); werr != nil {
			return fmt.Errorf("上传中国网段失败: %w", werr)
		}
	}

	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString("ipset create " + cnSet + " hash:net -exist\n")
	b.WriteString("ipset flush " + cnSet + "\n")
	b.WriteString("ipset create " + cnAllowSet + " hash:net -exist\n")
	b.WriteString("ipset flush " + cnAllowSet + "\n")
	for _, a := range allow {
		if validCIDR(a) {
			b.WriteString(fmt.Sprintf("ipset add -exist %s %s\n", cnAllowSet, sq(a)))
		}
	}
	b.WriteString("sed 's/^/add " + cnSet + " /' /tmp/.eops_cn.txt | ipset restore -exist\n")
	b.WriteString("rm -f /tmp/.eops_cn.txt\n")
	b.WriteString("n=$(ipset list " + cnSet + " | grep -c '^[0-9]')\n")
	b.WriteString(fmt.Sprintf("[ \"$n\" -ge %d ] || { echo \"CN_SET_TOO_SMALL=$n\"; exit 3; }\n", cnMinEntries))
	b.WriteString("iptables -N " + cnChain + " 2>/dev/null || true\n")
	b.WriteString("iptables -F " + cnChain + "\n")
	b.WriteString("iptables -A " + cnChain + " -i lo -j RETURN\n")
	b.WriteString("iptables -A " + cnChain + " -m set --match-set " + cnAllowSet + " src -j RETURN\n")
	b.WriteString("iptables -A " + cnChain + " -m set --match-set " + cnSet + " src -j RETURN\n")
	b.WriteString("iptables -A " + cnChain + " -j DROP\n")
	b.WriteString("iptables -C INPUT -j " + cnChain + " 2>/dev/null || iptables -I INPUT 1 -j " + cnChain + "\n")
	b.WriteString("iptables -C DOCKER-USER -j " + cnChain + " 2>/dev/null || iptables -I DOCKER-USER 1 -j " + cnChain + " 2>/dev/null || true\n")
	b.WriteString("echo CN_ENABLED=$n\n")

	tmp := "/tmp/.eops_cn_apply.sh"
	if _, werr := rn.RunWithStdin(fmt.Sprintf(`cat > %s`, sq(tmp)), []byte(b.String())); werr != nil {
		return fmt.Errorf("下发启用脚本失败: %w", werr)
	}
	out, serr := remoteRun(fmt.Sprintf(`bash %s`, sq(tmp)))
	_, _ = remoteRun(fmt.Sprintf(`rm -f %s`, sq(tmp)))
	if serr != nil || !strings.Contains(out, "CN_ENABLED=") {
		return fmt.Errorf("cn enable 失败: %v %s", serr, strings.TrimSpace(out))
	}
	n := strings.TrimSpace(strings.TrimPrefix(firstLine(out), "CN_ENABLED="))
	_, _ = remoteRun(`ipset save > /etc/sysconfig/ipset 2>/dev/null; iptables-save > /etc/sysconfig/iptables 2>/dev/null; true`)
	r.Add(SecFinding{Host: host, Category: "境外拦截", Item: "境外 IP 默认拉黑",
		Result: "已启用（中国网段 " + n + " 条，其余境外 IP DROP）", Level: SecInfo, Fixable: "no"})
	return nil
}

// RunCNDisable 关闭境外拦截（移除挂载，保留集合便于快速恢复）。
func RunCNDisable(host string, r *SecReport, yes bool) error {
	if !yes {
		fmt.Printf("  [cn disable 计划] %s：移除 INPUT / DOCKER-USER 上的 %s 跳转（保留集合）\n", host, cnChain)
		return nil
	}
	_, _ = remoteRun(fmt.Sprintf(`iptables -D INPUT -j %s 2>/dev/null; iptables -D DOCKER-USER -j %s 2>/dev/null; iptables-save > /etc/sysconfig/iptables 2>/dev/null; echo CN_DISABLED`, cnChain, cnChain))
	r.Add(SecFinding{Host: host, Category: "境外拦截", Item: "境外 IP 拉黑",
		Result: "已关闭", Level: SecInfo, Fixable: "no"})
	return nil
}
