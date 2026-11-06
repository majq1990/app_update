// Package monitor 实现「监控运维」的诊断侧：agent / proxy 的进程、端口、配置、
// 插件脚本、PSK、备份目录监控与云中心连通性检查，并给出可执行的修复建议。
//
// 口径（对齐 FAQ wiki《监控相关》）：
//   - 两层拓扑：云中心 zabbix ← 主控机(proxy 9001) ← 受控机(agent 9000)；
//   - 受控机插件：userparameter 片段在 /etc/zabbix/zabbix_agentd.d，
//     脚本在 /egova/devops/script（zabbix:zabbix 0755）；
//   - 备份目录监控清单：/etc/zabbix/zabbix_agentd.d/backup_dirs.txt。
//
// 复用 inspect 的报告与分级模型：Dimension 固定为 "monitor"，
// 这样终端摘要 / JSON 输出与巡检同构，上传链路可以直接复用。
package monitor

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/inspect"
)

// DimMonitor 监控诊断维度（复用 inspect.Report 的分级/汇总）。
const DimMonitor = "monitor"

// Role 主机角色。
type Role string

const (
	RoleAgent Role = "agent"
	RoleProxy Role = "proxy"
)

// Target 一台监控诊断目标。
type Target struct {
	Host config.Host
	Role Role
}

// Label 显示名。
func (t Target) Label() string { return string(t.Role) + "@" + t.Host.Host }

// Targets 展开诊断目标：主控机来自 monitor.proxy_hosts；
// 受控机来自 monitor.agent_hosts，未配置时用 webs + supports 的主机（去重）。
func Targets(c *config.Config) []Target {
	var out []Target
	seen := map[string]bool{}
	push := func(h config.Host, r Role) {
		if h.Host == "" {
			return
		}
		key := h.Host + "\x00" + string(r)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Target{Host: h, Role: r})
	}
	if c.Monitor != nil {
		for _, h := range c.Monitor.ProxyHosts {
			push(h, RoleProxy)
		}
		if len(c.Monitor.AgentHosts) > 0 {
			for _, h := range c.Monitor.AgentHosts {
				push(h, RoleAgent)
			}
			return out
		}
	}
	for _, t := range inspect.Targets(c) {
		push(t.Host, RoleAgent)
	}
	return out
}

// Env 检查上下文。
type Env struct {
	Target Target
	Cfg    *config.Config
}

// Check 诊断项（结构对齐 inspect.Check：命令 + 纯函数解析）。
type Check struct {
	Name        string
	Description string
	ForRole     Role // 仅对某角色执行
	Command     func(Env) (string, error)
	Evaluate    func(Env, string) ([]inspect.Finding, error)
}

var registry []Check

func register(c Check) { registry = append(registry, c) }

// Checks 全部诊断项。
func Checks() []Check { return append([]Check{}, registry...) }

// Results 执行诊断（按主机串行，主机间不改动状态——全部只读）。
func Results(cfg *config.Config, targets []Target, conn func(config.Host) (inspect.Conn, error)) []inspect.Result {
	var out []inspect.Result
	for _, t := range targets {
		env := Env{Target: t, Cfg: cfg}
		c, err := conn(t.Host)
		if err != nil {
			// 一台主机只报一条连接失败，不按检查项重复刷屏
			out = append(out, inspect.Result{Host: t.Host.Host, Target: t.Label(),
				Check: "connection", Dimension: DimMonitor, Err: "SSH 连接失败: " + err.Error()})
			continue
		}
		for _, chk := range Checks() {
			if chk.ForRole != "" && chk.ForRole != t.Role {
				continue
			}
			res := inspect.Result{Host: t.Host.Host, Target: t.Label(),
				Check: chk.Name, Dimension: DimMonitor}
			cmdStr, cerr := chk.Command(env)
			if cerr != nil {
				res.Err = "构建命令失败: " + cerr.Error()
				out = append(out, res)
				continue
			}
			raw, rerr := c.Run(cmdStr)
			if rerr != nil {
				res.Err = "执行失败: " + rerr.Error()
				out = append(out, res)
				continue
			}
			fs, ferr := chk.Evaluate(env, raw)
			if ferr != nil {
				res.Err = "解析失败: " + ferr.Error()
				out = append(out, res)
				continue
			}
			for i := range fs {
				fs[i].Host = t.Host.Host
				fs[i].Target = t.Label()
				fs[i].Check = chk.Name
				fs[i].Dimension = DimMonitor
				if fs[i].Severity == "" {
					fs[i].Severity = inspect.SevInfo
				}
			}
			res.Findings = fs
			out = append(out, res)
		}
	}
	return out
}

// FixPlan 根据诊断结果生成修复计划（只含白名单动作）。
type FixAction struct {
	Host config.Host
	Role Role
	Cmd  string
	Why  string
}

// whitelist 允许执行的修复命令（严格白名单，防止把诊断结果变成任意命令执行）。
var fixWhitelist = map[string]string{
	"systemctl start zabbix-agent":   "agent 未运行",
	"systemctl restart zabbix-agent": "agent 未运行或配置漂移",
	"systemctl start zabbix-proxy":   "proxy 未运行",
	"systemctl restart zabbix-proxy": "proxy 未运行或配置漂移",
}

// FixPlan 从诊断结果推导修复动作（agent/proxy 服务类问题→重启，其余只提示）。
func FixPlan(results []inspect.Result) []FixAction {
	var out []FixAction
	seen := map[string]bool{}
	for _, r := range results {
		for _, f := range r.Findings {
			var cmd string
			switch f.Check {
			case "agent-service":
				cmd = "systemctl restart zabbix-agent"
			case "proxy-service":
				cmd = "systemctl restart zabbix-proxy"
			default:
				continue
			}
			if f.Severity != inspect.SevError && f.Severity != inspect.SevWarn {
				continue
			}
			key := f.Host + "\x00" + cmd
			if seen[key] {
				continue
			}
			seen[key] = true
			role := RoleAgent
			if f.Check == "proxy-service" {
				role = RoleProxy
			}
			out = append(out, FixAction{
				Host: config.Host{Host: f.Host}, Role: role, Cmd: cmd,
				Why: f.Message,
			})
		}
	}
	return out
}

// FixCommand 校验并返回可执行命令（白名单外的动作一律拒绝）。
func FixCommand(a FixAction) (string, error) {
	if _, ok := fixWhitelist[a.Cmd]; !ok {
		return "", fmt.Errorf("修复动作不在白名单内: %q", a.Cmd)
	}
	if !hostnameSafe(a.Host.Host) {
		return "", fmt.Errorf("主机地址非法: %q", a.Host.Host)
	}
	return a.Cmd, nil
}

func hostnameSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// ---- 解析辅助（纯函数，单测覆盖） ----

// ParseAgentConf 解析 zabbix_agentd.conf 的关键指令。
func ParseAgentConf(out string) map[string]string {
	kv := map[string]string{}
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if i := strings.IndexByte(ln, '='); i > 0 {
			kv[strings.TrimSpace(ln[:i])] = strings.TrimSpace(ln[i+1:])
		}
	}
	return kv
}

// portListed ss 输出中是否包含指定端口。
func portListed(out string, port int) bool {
	p := strconv.Itoa(port)
	for _, ln := range strings.Split(out, "\n") {
		addr := strings.TrimSpace(ln)
		if i := strings.LastIndexByte(addr, ':'); i >= 0 && addr[i+1:] == p {
			return true
		}
	}
	return false
}
