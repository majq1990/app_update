package monitor

// 诊断项定义：agent / proxy 的进程、端口、配置、插件、PSK、
// 备份目录监控清单、云中心连通性、agent 日志错误。
// 全部只读命令；路径全部来自配置校验后的常量/绝对路径。

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/majq1990/app-updater-go/internal/inspect"
)

// q 单引号引用（路径进远端命令前统一处理；配置层已做白名单校验）。
func q(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func init() {
	register(Check{
		Name: "agent-service", Description: "zabbix-agent 服务与进程状态", ForRole: RoleAgent,
		Command: func(Env) (string, error) {
			return `printf 'service=%s\n' "$(systemctl is-active zabbix-agent 2>/dev/null || echo unknown)"; pgrep -x zabbix_agentd >/dev/null 2>&1 && echo PROCESS=RUNNING || echo PROCESS=DOWN`, nil
		},
		Evaluate: func(_ Env, out string) ([]inspect.Finding, error) {
			kv := parseKV(out)
			var fs []inspect.Finding
			svc, proc := kv["service"], kv["PROCESS"]
			switch {
			case proc != "RUNNING" && svc != "active":
				fs = append(fs, inspect.Finding{Severity: inspect.SevError, Metric: "agent_service",
					Value: svc + "/" + proc, Message: "zabbix-agent 未运行（service=" + svc + ", process=" + proc + "）"})
			case proc != "RUNNING":
				fs = append(fs, inspect.Finding{Severity: inspect.SevWarn, Metric: "agent_process",
					Value: proc, Message: "systemd 显示 " + svc + " 但没有 zabbix_agentd 进程，可能频繁重启"})
			}
			return fs, nil
		},
	})

	register(Check{
		Name: "agent-port", Description: "agent 监听端口（默认 9000）", ForRole: RoleAgent,
		Command: func(e Env) (string, error) { return `ss -lntH 2>/dev/null | awk '{print $4}'`, nil },
		Evaluate: func(e Env, out string) ([]inspect.Finding, error) {
			port := e.Cfg.Monitor.EffectiveAgentPort()
			if portListed(out, port) {
				return nil, nil
			}
			return []inspect.Finding{{Severity: inspect.SevError, Metric: "agent_port",
				Value: strconv.Itoa(port), Message: fmt.Sprintf("agent 端口 %d 未监听，主控机/云中心无法采集", port)}}, nil
		},
	})

	register(Check{
		Name: "agent-conf", Description: "agent 配置关键项（Server/Hostname/Include/PSK）", ForRole: RoleAgent,
		Command: func(e Env) (string, error) {
			conf := e.Cfg.Monitor.EffectiveAgentConf()
			return fmt.Sprintf(`test -f %s && grep -E '^[[:space:]]*(Server|ServerActive|Hostname|Include|TLSConnect|TLSAccept|TLSPSKFile)=' %s 2>/dev/null || echo MISSING`,
				q(conf), q(conf)), nil
		},
		Evaluate: func(e Env, out string) ([]inspect.Finding, error) {
			if strings.Contains(out, "MISSING") {
				return []inspect.Finding{{Severity: inspect.SevError, Metric: "agent_conf",
					Value:   e.Cfg.Monitor.EffectiveAgentConf(),
					Message: "agent 配置文件不存在：" + e.Cfg.Monitor.EffectiveAgentConf()}}, nil
			}
			kv := ParseAgentConf(out)
			var fs []inspect.Finding
			if kv["Server"] == "" && kv["ServerActive"] == "" {
				fs = append(fs, inspect.Finding{Severity: inspect.SevWarn, Metric: "agent_server",
					Message: "Server/ServerActive 未配置，agent 不知道该连哪台主控机"})
			}
			if kv["Hostname"] == "" {
				fs = append(fs, inspect.Finding{Severity: inspect.SevError, Metric: "agent_hostname",
					Message: "Hostname 未配置（主动模式必须配置，否则云中心识别不到主机）"})
			}
			if kv["Include"] == "" {
				fs = append(fs, inspect.Finding{Severity: inspect.SevWarn, Metric: "agent_include",
					Message: "Include 未配置，userparameter 插件不会被加载"})
			}
			return fs, nil
		},
	})

	register(Check{
		Name: "plugin-scripts", Description: "userparameter 片段与监控脚本", ForRole: RoleAgent,
		Command: func(e Env) (string, error) {
			dir := q(e.Cfg.Monitor.EffectivePluginDir())
			script := q(e.Cfg.Monitor.EffectiveScriptDir())
			return fmt.Sprintf(`printf 'conf_count=%%s\n' "$(ls -1 %s/*.conf 2>/dev/null | wc -l)"; `+
				`if [ -d %s ]; then printf 'script_count=%%s\n' "$(find %s -maxdepth 1 -type f 2>/dev/null | wc -l)"; printf 'script_mode=%%s\n' "$(stat -c %%a %s 2>/dev/null || echo unknown)"; else echo SCRIPT_DIR_MISSING; fi`,
				dir, script, script, script), nil
		},
		Evaluate: func(e Env, out string) ([]inspect.Finding, error) {
			var fs []inspect.Finding
			kv := parseKV(out)
			if kv["conf_count"] == "0" {
				fs = append(fs, inspect.Finding{Severity: inspect.SevWarn, Metric: "plugin_conf",
					Value: "0", Message: "插件目录下没有 *.conf 片段，自定义监控项未部署"})
			}
			if strings.Contains(out, "SCRIPT_DIR_MISSING") {
				fs = append(fs, inspect.Finding{Severity: inspect.SevWarn, Metric: "script_dir",
					Value:   e.Cfg.Monitor.EffectiveScriptDir(),
					Message: "监控脚本目录不存在：" + e.Cfg.Monitor.EffectiveScriptDir()})
			} else if kv["script_count"] == "0" {
				fs = append(fs, inspect.Finding{Severity: inspect.SevWarn, Metric: "script_count",
					Value: "0", Message: "监控脚本目录为空，插件可能缺少依赖脚本"})
			}
			if m := kv["script_mode"]; m != "" && m != "unknown" && m != "755" && m != "750" && m != "700" {
				fs = append(fs, inspect.Finding{Severity: inspect.SevInfo, Metric: "script_mode",
					Value: m, Message: "脚本目录权限为 " + m + "（约定 755，zabbix 用户需可读可执行）"})
			}
			return fs, nil
		},
	})

	register(Check{
		Name: "psk", Description: "PSK 文件存在性与 600 权限", ForRole: RoleAgent,
		Command: func(e Env) (string, error) {
			psk := q(e.Cfg.Monitor.EffectivePSKFile())
			return fmt.Sprintf(`if [ -f %s ]; then printf 'psk=present\nmode=%%s\n' "$(stat -c %%a %s 2>/dev/null || echo unknown)"; else echo psk=absent; fi`,
				psk, psk), nil
		},
		Evaluate: func(_ Env, out string) ([]inspect.Finding, error) {
			kv := parseKV(out)
			if kv["psk"] == "absent" {
				return []inspect.Finding{{Severity: inspect.SevInfo, Metric: "psk", Value: "absent",
					Message: "未启用 PSK（如云中心要求 PSK 加密，需研发提供密钥并配置 TLSConnect/TLSAccept）"}}, nil
			}
			if m := kv["mode"]; m != "600" {
				return []inspect.Finding{{Severity: inspect.SevError, Metric: "psk_mode", Value: m,
					Message: "PSK 文件权限为 " + m + "，必须为 600（否则 agent 拒绝启动或告警）"}}, nil
			}
			return nil, nil
		},
	})

	register(Check{
		Name: "backup-dirs", Description: "zabbix 备份目录监控清单", ForRole: RoleAgent,
		Command: func(e Env) (string, error) {
			f := q(e.Cfg.Monitor.EffectivePluginDir() + "/backup_dirs.txt")
			return fmt.Sprintf(`if [ -f %s ]; then printf 'present=1\nlines=%%s\n' "$(grep -cve '^[[:space:]]*$' %s 2>/dev/null || echo 0)"; else echo present=0; fi`,
				f, f), nil
		},
		Evaluate: func(_ Env, out string) ([]inspect.Finding, error) {
			kv := parseKV(out)
			if kv["present"] == "0" {
				return []inspect.Finding{{Severity: inspect.SevWarn, Metric: "backup_dirs",
					Message: "backup_dirs.txt 不存在，备份目录容量没有纳入监控（backup run 首次执行会自动登记）"}}, nil
			}
			if kv["lines"] == "0" {
				return []inspect.Finding{{Severity: inspect.SevWarn, Metric: "backup_dirs_lines",
					Value: "0", Message: "backup_dirs.txt 为空，没有任何备份目录被监控"}}, nil
			}
			return nil, nil
		},
	})

	register(Check{
		Name: "proxy-service", Description: "zabbix-proxy 服务与进程状态", ForRole: RoleProxy,
		Command: func(Env) (string, error) {
			return `printf 'service=%s\n' "$(systemctl is-active zabbix-proxy 2>/dev/null || echo unknown)"; pgrep -x zabbix_proxy >/dev/null 2>&1 && echo PROCESS=RUNNING || echo PROCESS=DOWN`, nil
		},
		Evaluate: func(_ Env, out string) ([]inspect.Finding, error) {
			kv := parseKV(out)
			svc, proc := kv["service"], kv["PROCESS"]
			switch {
			case proc != "RUNNING" && svc != "active":
				return []inspect.Finding{{Severity: inspect.SevError, Metric: "proxy_service",
					Value: svc + "/" + proc, Message: "zabbix-proxy 未运行（service=" + svc + ", process=" + proc + "）"}}, nil
			case proc != "RUNNING":
				return []inspect.Finding{{Severity: inspect.SevWarn, Metric: "proxy_process", Value: proc,
					Message: "systemd 显示 " + svc + " 但没有 zabbix_proxy 进程"}}, nil
			}
			return nil, nil
		},
	})

	register(Check{
		Name: "proxy-port", Description: "proxy 监听端口（默认 9001）", ForRole: RoleProxy,
		Command: func(Env) (string, error) { return `ss -lntH 2>/dev/null | awk '{print $4}'`, nil },
		Evaluate: func(e Env, out string) ([]inspect.Finding, error) {
			port := e.Cfg.Monitor.EffectiveProxyPort()
			if portListed(out, port) {
				return nil, nil
			}
			return []inspect.Finding{{Severity: inspect.SevError, Metric: "proxy_port",
				Value: strconv.Itoa(port), Message: fmt.Sprintf("proxy 端口 %d 未监听，受控机无法接入", port)}}, nil
		},
	})

	register(Check{
		Name: "proxy-conf", Description: "proxy 配置关键项（Server/Hostname）", ForRole: RoleProxy,
		Command: func(e Env) (string, error) {
			conf := q(e.Cfg.Monitor.EffectiveProxyConf())
			return fmt.Sprintf(`test -f %s && grep -E '^[[:space:]]*(Server|Hostname|ProxyMode)=' %s 2>/dev/null || echo MISSING`, conf, conf), nil
		},
		Evaluate: func(e Env, out string) ([]inspect.Finding, error) {
			if strings.Contains(out, "MISSING") {
				return []inspect.Finding{{Severity: inspect.SevError, Metric: "proxy_conf",
					Value:   e.Cfg.Monitor.EffectiveProxyConf(),
					Message: "proxy 配置文件不存在：" + e.Cfg.Monitor.EffectiveProxyConf()}}, nil
			}
			kv := ParseAgentConf(out)
			var fs []inspect.Finding
			if kv["Server"] == "" {
				fs = append(fs, inspect.Finding{Severity: inspect.SevError, Metric: "proxy_server",
					Message: "proxy 未配置 Server（云中心地址），无法上报"})
			}
			if kv["Hostname"] == "" {
				fs = append(fs, inspect.Finding{Severity: inspect.SevError, Metric: "proxy_hostname",
					Message: "proxy 未配置 Hostname（云中心靠它识别主控机）"})
			}
			return fs, nil
		},
	})

	register(Check{
		Name: "cloud-connectivity", Description: "主控机到云中心的 TCP 连通性", ForRole: RoleProxy,
		Command: func(e Env) (string, error) {
			server := e.Cfg.Monitor.EffectiveServer()
			port := e.Cfg.Monitor.EffectiveServerPort()
			// server 已在配置校验层做主机名白名单，port 为整数
			return fmt.Sprintf(`timeout 5 bash -c 'exec 3<>/dev/tcp/%s/%d' 2>/dev/null && echo CONNECT=OK || echo CONNECT=FAIL`,
				server, port), nil
		},
		Evaluate: func(e Env, out string) ([]inspect.Finding, error) {
			kv := parseKV(out)
			if kv["CONNECT"] == "OK" {
				return nil, nil
			}
			return []inspect.Finding{{Severity: inspect.SevError, Metric: "cloud_connectivity",
				Value:   e.Cfg.Monitor.EffectiveServer() + ":" + strconv.Itoa(e.Cfg.Monitor.EffectiveServerPort()),
				Message: "主控机无法连接云中心（检查出网策略/端口转发）"}}, nil
		},
	})

	register(Check{
		Name: "yum-repo", Description: "本地 yum 源端口（离线装 agent 用）", ForRole: RoleProxy,
		Command: func(Env) (string, error) { return `ss -lntH 2>/dev/null | awk '{print $4}'`, nil },
		Evaluate: func(e Env, out string) ([]inspect.Finding, error) {
			port := e.Cfg.Monitor.EffectiveYumPort()
			if portListed(out, port) {
				return nil, nil
			}
			return []inspect.Finding{{Severity: inspect.SevWarn, Metric: "yum_port",
				Value:   strconv.Itoa(port),
				Message: fmt.Sprintf("本地 yum 源端口 %d 未监听，离线环境下受控机装不上 agent", port)}}, nil
		},
	})

	register(Check{
		Name: "agent-log", Description: "agent 日志中的错误行", ForRole: RoleAgent,
		Command: func(Env) (string, error) {
			return `f=/var/log/zabbix/zabbix_agentd.log; if [ -f "$f" ]; then printf 'errors=%s\n' "$(tail -100 "$f" 2>/dev/null | grep -ciE 'error|cannot|failed|refused')"; else echo LOG_MISSING; fi`, nil
		},
		Evaluate: func(_ Env, out string) ([]inspect.Finding, error) {
			if strings.Contains(out, "LOG_MISSING") {
				return []inspect.Finding{{Severity: inspect.SevInfo, Metric: "agent_log",
					Message: "agent 日志文件不存在（可能日志输出到 syslog 或尚未产生）"}}, nil
			}
			kv := parseKV(out)
			n, _ := strconv.Atoi(kv["errors"])
			if n >= 5 {
				return []inspect.Finding{{Severity: inspect.SevWarn, Metric: "agent_log_errors",
					Value: kv["errors"], Message: fmt.Sprintf("agent 最近 100 行日志有 %d 条错误，检查连接/PSK/权限", n)}}, nil
			}
			return nil, nil
		},
	})
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
