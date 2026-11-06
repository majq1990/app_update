// Package harden 实现「安全加固」的只读侧：把巡检的安全发现映射成可执行的加固建议，
// 输出加固清单 / 建议片段 / 台账 JSON。
//
// 与规划一致的红线：**首期不自动改网络层与应用层配置**——
//   - 防火墙/内核参数：只出建议清单，不碰系统；
//   - SSH/账户/sudo：只出建议与片段，人工确认后执行；
//   - 每个加固项都标注风险级别与是否需要重启连接，避免"一键加固"变成一键失联。
//
// 后续 `harden apply`（带备份 + 逐项确认 + 复检）在资产迁移完成后再开，
// 本包先把「检查 → 建议 → 台账」这条只读链路做完整。
package harden

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/inspect"
)

// Risk 加固风险级别。
type Risk string

const (
	RiskLow    Risk = "low"
	RiskMedium Risk = "medium"
	RiskHigh   Risk = "high"
)

// Item 一个可加固项（来源 = inspect 的安全类发现）。
type Item struct {
	Host      string `json:"host"`
	Target    string `json:"target,omitempty"`
	Check     string `json:"check"`
	Severity  string `json:"severity"`
	Risk      Risk   `json:"risk"`
	Title     string `json:"title"`
	Evidence  string `json:"evidence"`
	Action    string `json:"action"`              // 建议动作（人类可读）
	Snippet   string `json:"snippet,omitempty"`   // 可直接粘贴的配置/命令片段
	AutoApply bool   `json:"auto_apply"`          // 首期恒为 false
	NeedsSSH  bool   `json:"needs_ssh_reconnect"` // 动作是否可能中断当前 SSH
}

// report 加固台账。
type Report struct {
	GeneratedAt string `json:"generated_at"`
	Hosts       int    `json:"hosts"`
	Items       []Item `json:"items"`
	Summary     struct {
		Total    int `json:"total"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
		Autoable int `json:"autoable"`
	} `json:"summary"`
}

// Build 把安全巡检结果映射为加固项。
func Build(results []inspect.Result, now time.Time) Report {
	var items []Item
	seen := map[string]bool{}
	for _, r := range results {
		for _, f := range r.Findings {
			it, ok := mapFinding(f)
			if !ok {
				continue
			}
			key := it.Host + "\x00" + it.Check
			if seen[key] {
				continue
			}
			seen[key] = true
			items = append(items, it)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Risk != items[j].Risk {
			return riskRank(items[i].Risk) > riskRank(items[j].Risk)
		}
		if items[i].Host != items[j].Host {
			return items[i].Host < items[j].Host
		}
		return items[i].Check < items[j].Check
	})
	rep := Report{GeneratedAt: now.Format(time.RFC3339), Items: items}
	hosts := map[string]bool{}
	for _, it := range items {
		hosts[it.Host] = true
		switch it.Risk {
		case RiskHigh:
			rep.Summary.High++
		case RiskMedium:
			rep.Summary.Medium++
		default:
			rep.Summary.Low++
		}
		if it.AutoApply {
			rep.Summary.Autoable++
		}
	}
	rep.Hosts = len(hosts)
	rep.Summary.Total = len(items)
	return rep
}

func riskRank(r Risk) int {
	switch r {
	case RiskHigh:
		return 3
	case RiskMedium:
		return 2
	default:
		return 1
	}
}

// mapFinding 单条发现 → 加固项。未纳入加固域的检查返回 false。
func mapFinding(f inspect.Finding) (Item, bool) {
	it := Item{Host: f.Host, Target: f.Target, Check: f.Check,
		Severity: string(f.Severity), Evidence: f.Message}
	switch f.Check {
	case "ssh-policy":
		it.Risk = RiskMedium
		it.NeedsSSH = true
		it.Title = "SSH 登录策略加固"
		it.Action = "按建议修改 /etc/ssh/sshd_config，先 `sshd -t` 校验，再重载 sshd（保留一个已登录会话）"
		it.Snippet = "# /etc/ssh/sshd_config\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nPermitEmptyPasswords no"
	case "account-empty-password":
		it.Risk = RiskHigh
		it.Title = "空口令账户处置"
		it.Action = "为空口令账户设置强口令或锁定账户（usermod -L），并核查是否可删除"
		it.Snippet = "passwd -l <账户>   # 锁定；确认无业务依赖后再 userdel"
	case "account-uid0":
		it.Risk = RiskHigh
		it.Title = "非 root 的 UID=0 账户处置"
		it.Action = "确认用途后改回非 0 UID 或禁用，防止提权后门"
		it.Snippet = "usermod -u <新UID> <账户>"
	case "sudo-nopasswd":
		it.Risk = RiskMedium
		it.Title = "sudo 免密收敛"
		it.Action = "核对 /etc/sudoers.d 下 NOPASSWD 范围，只保留部署必需命令"
		it.Snippet = "# 用 visudo 编辑，避免语法错误锁死 sudo\nvisudo -c"
	case "ports-exposure":
		it.Risk = RiskMedium
		it.Title = "高风险端口对外暴露"
		it.Action = "确认业务必要性；非必要则改为监听 127.0.0.1 或加防火墙白名单（首期只报告不改）"
		it.Snippet = "# 示例：只允许应用网段访问 MySQL\nfirewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=<应用网段>/24 port port=3306 protocol=tcp accept'\nfirewall-cmd --reload"
	case "kernel-network-params":
		it.Risk = RiskLow
		it.Title = "内核网络参数加固"
		it.Action = "写入 /etc/sysctl.d/99-eops-hardening.conf 后 sysctl --system（可在维护窗口执行）"
		it.Snippet = "cat >/etc/sysctl.d/99-eops-hardening.conf <<'EOF'\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.all.accept_source_route = 0\nEOF\nsysctl --system"
	case "firewall-selinux":
		it.Risk = RiskMedium
		it.Title = "主机层防护缺失"
		it.Action = "启用 firewalld 并只放行 22/业务端口；SELinux 状态记录备查（首期不改）"
		it.Snippet = "systemctl enable --now firewalld\nfirewall-cmd --permanent --add-service=ssh && firewall-cmd --reload"
	case "world-writable":
		it.Risk = RiskLow
		it.Title = "全局可写目录收敛"
		it.Action = "对 /egova 下全局可写目录收紧权限（chmod o-w），确认应用属主仍可写"
		it.Snippet = "chmod o-w <目录>   # 逐个确认，避免影响业务写入"
	default:
		return Item{}, false
	}
	// 首期一律不自动执行
	it.AutoApply = false
	return it, true
}

// JSON 台账序列化。
func (r Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// Text 终端输出。
func (r Report) Text(b *strings.Builder) {
	fmt.Fprintf(b, "加固清单（%s）：%d 项（高 %d / 中 %d / 低 %d）\n",
		r.GeneratedAt, r.Summary.Total, r.Summary.High, r.Summary.Medium, r.Summary.Low)
	if r.Summary.Total == 0 {
		b.WriteString("未发现需要加固的项。\n")
		return
	}
	curHost := ""
	for _, it := range r.Items {
		if it.Host != curHost {
			curHost = it.Host
			fmt.Fprintf(b, "\n主机 %s：\n", curHost)
		}
		fmt.Fprintf(b, "  [%s] %-22s %s\n", riskLabel(it.Risk), it.Check, it.Title)
		fmt.Fprintf(b, "        现象：%s\n", it.Evidence)
		fmt.Fprintf(b, "        建议：%s\n", it.Action)
		if it.NeedsSSH {
			fmt.Fprintf(b, "        ⚠️ 该操作可能影响当前 SSH 连接，请保留一个已登录会话\n")
		}
	}
	if r.Summary.Autoable == 0 {
		b.WriteString("\n说明：首期加固只出清单与建议片段，不自动修改防火墙/内核/SSH。\n")
	}
}

func riskLabel(r Risk) string {
	switch r {
	case RiskHigh:
		return "高"
	case RiskMedium:
		return "中"
	default:
		return "低"
	}
}

// Snippets 汇总去重后的建议片段（同 check 只保留一份，便于复制）。
func (r Report) Snippets() []struct{ Check, Title, Snippet string } {
	seen := map[string]bool{}
	var out []struct{ Check, Title, Snippet string }
	for _, it := range r.Items {
		if it.Snippet == "" || seen[it.Check] {
			continue
		}
		seen[it.Check] = true
		out = append(out, struct{ Check, Title, Snippet string }{it.Check, it.Title, it.Snippet})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Check < out[j].Check })
	return out
}
