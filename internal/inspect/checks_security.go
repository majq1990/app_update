package inspect

// 安全巡检：SSH 策略、空口令/UID0 账户、sudo 免密、高风险端口暴露、
// 内核网络参数、防火墙/SELinux、可写目录。全部只读。

import (
	"fmt"
	"strconv"
	"strings"
)

// riskyPorts 高风险端口：一旦监听在 0.0.0.0/:: 就应确认是否必要。
var riskyPorts = map[string]string{
	"3306":  "MySQL",
	"6379":  "Redis",
	"9200":  "Elasticsearch",
	"27017": "MongoDB",
	"27018": "MongoDB",
	"5432":  "PostgreSQL",
	"11211": "Memcached",
	"2181":  "ZooKeeper",
	"2375":  "Docker API（未加密）",
	"2376":  "Docker API",
}

func init() {
	register(Check{
		Name: "ssh-policy", Dimension: DimSecurity,
		Description: "sshd 关键策略：root 登录 / 口令登录 / 空口令",
		Command: func(Env) (string, error) {
			return `grep -Ei '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords)' /etc/ssh/sshd_config 2>/dev/null`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			kv := parseSshd(out)
			var ms []Metric
			for k, v := range kv {
				ms = append(ms, Metric{Name: "sshd_" + strings.ToLower(k), Value: v})
			}
			var fs []Finding
			if v := kv["PermitRootLogin"]; strings.EqualFold(v, "yes") {
				fs = append(fs, Finding{Severity: SevWarn, Metric: "PermitRootLogin", Value: v,
					Message: "sshd 允许 root 直接登录（PermitRootLogin yes）"})
			}
			if v := kv["PasswordAuthentication"]; strings.EqualFold(v, "yes") {
				fs = append(fs, Finding{Severity: SevWarn, Metric: "PasswordAuthentication", Value: v,
					Message: "sshd 允许口令登录（PasswordAuthentication yes），建议改为密钥"})
			}
			if v := kv["PermitEmptyPasswords"]; strings.EqualFold(v, "yes") {
				fs = append(fs, Finding{Severity: SevError, Metric: "PermitEmptyPasswords", Value: v,
					Message: "sshd 允许空口令登录（PermitEmptyPasswords yes），必须关闭"})
			}
			return ms, fs, nil
		},
	})

	register(Check{
		Name: "account-empty-password", Dimension: DimSecurity,
		Description: "存在空口令账户（安全红线）",
		Command: func(Env) (string, error) {
			return `awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			users := nonEmptyLines(out)
			ms := []Metric{{Name: "empty_password_accounts", Value: strconv.Itoa(len(users))}}
			if len(users) > 0 {
				return ms, []Finding{{Severity: SevCritical, Metric: "empty_password_accounts",
					Value:   strings.Join(users, ","),
					Message: "存在空口令账户：" + strings.Join(users, ", ")}}, nil
			}
			return ms, nil, nil
		},
	})

	register(Check{
		Name: "account-uid0", Dimension: DimSecurity,
		Description: "除 root 外还有 UID=0 的账户",
		Command: func(Env) (string, error) {
			return `awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			var extra []string
			for _, u := range nonEmptyLines(out) {
				if u != "root" {
					extra = append(extra, u)
				}
			}
			ms := []Metric{{Name: "uid0_accounts", Value: strconv.Itoa(len(extra) + 1)}}
			if len(extra) > 0 {
				return ms, []Finding{{Severity: SevError, Metric: "uid0_accounts",
					Value:   strings.Join(extra, ","),
					Message: "存在非 root 的 UID=0 账户：" + strings.Join(extra, ", ")}}, nil
			}
			return ms, nil, nil
		},
	})

	register(Check{
		Name: "sudo-nopasswd", Dimension: DimSecurity,
		Description: "sudoers 中的 NOPASSWD 条目（确认是否必要）",
		Command: func(Env) (string, error) {
			return `grep -rEls 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -10`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			files := nonEmptyLines(out)
			ms := []Metric{{Name: "sudo_nopasswd_files", Value: strconv.Itoa(len(files))}}
			if len(files) > 0 {
				return ms, []Finding{{Severity: SevWarn, Metric: "sudo_nopasswd_files",
					Value:   strings.Join(files, ","),
					Message: "sudoers 存在 NOPASSWD 配置：" + strings.Join(files, ", ") + "（请确认必要性）"}}, nil
			}
			return ms, nil, nil
		},
	})

	register(Check{
		Name: "ports-exposure", Dimension: DimSecurity,
		Description: "高风险端口是否监听在全部网卡（0.0.0.0/::）",
		Command: func(Env) (string, error) {
			return `ss -lntH 2>/dev/null | awk '{print $4}'`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			exposed := exposedRiskyPorts(out)
			ms := []Metric{{Name: "risky_ports_exposed", Value: strconv.Itoa(len(exposed))}}
			var fs []Finding
			for _, p := range exposed {
				fs = append(fs, Finding{Severity: SevWarn, Metric: "listen_port",
					Value:   p.port,
					Message: fmt.Sprintf("%s(%s) 监听在 %s，请确认是否需要对外暴露", p.port, riskyPorts[p.port], p.addr)})
			}
			return ms, fs, nil
		},
	})

	register(Check{
		Name: "kernel-network-params", Dimension: DimSecurity,
		Description: "内核网络参数（syncookies / ip_forward / 重定向 / 源路由）",
		Command: func(Env) (string, error) {
			return `for k in net.ipv4.tcp_syncookies net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.accept_source_route; do printf '%s=' "$k"; sysctl -n "$k" 2>/dev/null || echo unknown; done`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			kv := parseKV(out)
			var ms []Metric
			for k, v := range kv {
				ms = append(ms, Metric{Name: strings.ReplaceAll(k, ".", "_"), Value: v})
			}
			var fs []Finding
			if kv["net.ipv4.tcp_syncookies"] == "0" {
				fs = append(fs, Finding{Severity: SevWarn, Metric: "tcp_syncookies", Value: "0",
					Message: "tcp_syncookies=0，建议开启以缓解 SYN Flood"})
			}
			if kv["net.ipv4.ip_forward"] == "1" {
				fs = append(fs, Finding{Severity: SevInfo, Metric: "ip_forward", Value: "1",
					Message: "ip_forward=1（开启了转发），非路由/容器主机请确认是否预期"})
			}
			if kv["net.ipv4.conf.all.accept_redirects"] == "1" {
				fs = append(fs, Finding{Severity: SevWarn, Metric: "accept_redirects", Value: "1",
					Message: "accept_redirects=1，建议关闭（防 ICMP 重定向攻击）"})
			}
			if kv["net.ipv4.conf.all.accept_source_route"] == "1" {
				fs = append(fs, Finding{Severity: SevWarn, Metric: "accept_source_route", Value: "1",
					Message: "accept_source_route=1，建议关闭（防源路由欺骗）"})
			}
			return ms, fs, nil
		},
	})

	register(Check{
		Name: "firewall-selinux", Dimension: DimSecurity,
		Description: "防火墙与 SELinux 状态（两层都关闭时预警）",
		Command: func(Env) (string, error) {
			return `printf 'firewalld=%s\n' "$(systemctl is-active firewalld 2>/dev/null || echo unknown)"; printf 'ufw=%s\n' "$(systemctl is-active ufw 2>/dev/null || echo unknown)"; printf 'iptables_rules=%s\n' "$(iptables -S 2>/dev/null | wc -l)"; printf 'selinux=%s\n' "$(getenforce 2>/dev/null || echo N/A)"`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			kv := parseKV(out)
			var ms []Metric
			for k, v := range kv {
				ms = append(ms, Metric{Name: k, Value: v})
			}
			rules, _ := strconv.Atoi(kv["iptables_rules"])
			fwOff := kv["firewalld"] != "active" && kv["ufw"] != "active" && rules <= 1
			var fs []Finding
			if fwOff {
				fs = append(fs, Finding{Severity: SevWarn, Metric: "firewall", Value: "off",
					Message: "firewalld/ufw 均未启用且 iptables 规则为空，主机没有主机层防护"})
			}
			if s := strings.ToLower(kv["selinux"]); s == "permissive" || s == "disabled" {
				fs = append(fs, Finding{Severity: SevInfo, Metric: "selinux", Value: kv["selinux"],
					Message: "SELinux 处于 " + kv["selinux"] + " 状态（现场通常如此，记录备查）"})
			}
			return ms, fs, nil
		},
	})

	register(Check{
		Name: "world-writable", Dimension: DimSecurity,
		Description: "/egova 下全局可写目录（排除预期目录）",
		Command: func(Env) (string, error) {
			return `find /egova -maxdepth 4 -type d -perm -0002 2>/dev/null | head -20`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			dirs := nonEmptyLines(out)
			ms := []Metric{{Name: "world_writable_dirs", Value: strconv.Itoa(len(dirs))}}
			if len(dirs) > 0 {
				return ms, []Finding{{Severity: SevWarn, Metric: "world_writable_dirs",
					Value:   strings.Join(dirs, ","),
					Message: fmt.Sprintf("/egova 下存在 %d 个全局可写目录（如无必要请收紧权限）", len(dirs))}}, nil
			}
			return ms, nil, nil
		},
	})
}

// parseSshd 解析 sshd_config 的关键指令（大小写不敏感，取最后一个生效值）。
func parseSshd(out string) map[string]string {
	kv := map[string]string{}
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		f := strings.Fields(ln)
		if len(f) >= 2 {
			kv[canonSshdKey(f[0])] = f[1]
		}
	}
	return kv
}

func canonSshdKey(k string) string {
	switch strings.ToLower(k) {
	case "permitrootlogin":
		return "PermitRootLogin"
	case "passwordauthentication":
		return "PasswordAuthentication"
	case "permitemptypasswords":
		return "PermitEmptyPasswords"
	default:
		return k
	}
}

// parseKV 解析 k=v 行。
func parseKV(out string) map[string]string {
	kv := map[string]string{}
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if i := strings.IndexByte(ln, '='); i > 0 {
			kv[strings.TrimSpace(ln[:i])] = strings.TrimSpace(ln[i+1:])
		}
	}
	return kv
}

// exposedRiskyPorts 从 ss 的本地地址列筛出监听在全部网卡的高风险端口。
func exposedRiskyPorts(out string) []struct{ port, addr string } {
	seen := map[string]bool{}
	var res []struct{ port, addr string }
	for _, ln := range nonEmptyLines(out) {
		addr := strings.TrimSpace(ln)
		port := portOf(addr)
		if port == "" || seen[port] {
			continue
		}
		if _, risky := riskyPorts[port]; !risky {
			continue
		}
		if !isWildcardAddr(addr) {
			continue
		}
		seen[port] = true
		res = append(res, struct{ port, addr string }{port: port, addr: addr})
	}
	return res
}

// portOf 取 "0.0.0.0:3306" / "[::]:3306" / "*:3306" 的端口。
func portOf(addr string) string {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 || i == len(addr)-1 {
		return ""
	}
	p := addr[i+1:]
	if _, err := strconv.Atoi(p); err != nil {
		return ""
	}
	return p
}

// isWildcardAddr 判断监听地址是否为全部网卡。
func isWildcardAddr(addr string) bool {
	return strings.HasPrefix(addr, "0.0.0.0:") || strings.HasPrefix(addr, "[::]:") ||
		strings.HasPrefix(addr, "*:") || strings.HasPrefix(addr, ":::")
}
