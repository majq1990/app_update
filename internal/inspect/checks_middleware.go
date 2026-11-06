package inspect

// 中间件 / 应用检查：Java 运行时、应用端口、MySQL/Redis/Nginx/Tomcat 进程与监听。
// 只做「是否在跑 + 是否监听」这类只读判断，不连接业务、不做 SQL 查询。

import (
	"fmt"
	"strconv"
	"strings"
)

func init() {
	register(Check{
		Name: "java-runtime", Dimension: DimMiddleware,
		Description: "Java 运行时版本（应用主机）",
		Applies:     func(e Env) bool { return e.Target.App != "" },
		Command: func(Env) (string, error) {
			return `(java -version 2>&1 | head -3) || echo "java not found"`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			lines := nonEmptyLines(out)
			if len(lines) == 0 || strings.Contains(strings.ToLower(out), "not found") || strings.Contains(out, "command not found") {
				return nil, []Finding{{Severity: SevError, Metric: "java",
					Message: "未找到 java 命令（应用主机缺少 Java 运行时或未进 PATH）"}}, nil
			}
			ver := lines[0]
			ms := []Metric{{Name: "java_version", Value: ver}}
			var fs []Finding
			// 1.8 以下属明显过旧，提示升级路径
			if strings.Contains(ver, `"1.7`) || strings.Contains(ver, `"1.6`) {
				fs = append(fs, Finding{Severity: SevWarn, Metric: "java_version", Value: ver,
					Message: "Java 版本过旧（" + ver + "），确认应用兼容性"})
			}
			return ms, fs, nil
		},
	})

	register(Check{
		Name: "app-port", Dimension: DimMiddleware,
		Description: "应用服务端口是否处于监听状态",
		Applies:     func(e Env) bool { return e.Target.App != "" && e.Target.Host.ServicePort > 0 },
		Command: func(e Env) (string, error) {
			_ = e
			return `ss -lntH 2>/dev/null | awk '{print $4}'`, nil
		},
		Evaluate: func(e Env, out string) ([]Metric, []Finding, error) {
			port := strconv.Itoa(e.Target.Host.ServicePort)
			listening := false
			for _, addr := range nonEmptyLines(out) {
				if portOf(addr) == port {
					listening = true
					break
				}
			}
			ms := []Metric{{Name: "service_port", Value: port},
				{Name: "listening", Value: strconv.FormatBool(listening)}}
			if !listening {
				return ms, []Finding{{Severity: SevError, Metric: "service_port", Value: port,
					Message: fmt.Sprintf("应用 %s 的端口 %s 未监听，服务可能未启动", e.Target.App, port)}}, nil
			}
			return ms, nil, nil
		},
	})

	register(Check{
		Name: "mysql-service", Dimension: DimMiddleware,
		Description: "MySQL 进程与 3306 监听",
		Applies:     func(e Env) bool { return e.Target.SupportKind == "mysql" },
		Command: func(Env) (string, error) {
			return `pgrep -x mysqld >/dev/null 2>&1 && echo PROCESS=RUNNING || echo PROCESS=DOWN; printf 'PORT=%s\n' "$(ss -lntH 2>/dev/null | awk '{print $4}' | grep -c ':3306$')"`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			kv := parseKV(out)
			ms := []Metric{{Name: "mysqld", Value: kv["PROCESS"]}, {Name: "port_3306", Value: kv["PORT"]}}
			var fs []Finding
			if kv["PROCESS"] != "RUNNING" {
				fs = append(fs, Finding{Severity: SevError, Metric: "mysqld", Value: kv["PROCESS"],
					Message: "mysqld 进程不存在，MySQL 未运行"})
			}
			if kv["PORT"] == "0" {
				fs = append(fs, Finding{Severity: SevError, Metric: "port_3306", Value: "0",
					Message: "3306 未监听，数据库不可连"})
			}
			return ms, fs, nil
		},
	})

	register(Check{
		Name: "redis-service", Dimension: DimMiddleware,
		Description: "Redis 进程与 6379 监听",
		Applies:     func(e Env) bool { return e.Target.SupportKind == "redis" },
		Command: func(Env) (string, error) {
			return `pgrep -x redis-server >/dev/null 2>&1 && echo PROCESS=RUNNING || echo PROCESS=DOWN; printf 'PORT=%s\n' "$(ss -lntH 2>/dev/null | awk '{print $4}' | grep -c ':6379$')"`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			kv := parseKV(out)
			ms := []Metric{{Name: "redis", Value: kv["PROCESS"]}, {Name: "port_6379", Value: kv["PORT"]}}
			var fs []Finding
			if kv["PROCESS"] != "RUNNING" {
				fs = append(fs, Finding{Severity: SevError, Metric: "redis", Value: kv["PROCESS"],
					Message: "redis-server 进程不存在，Redis 未运行"})
			}
			if kv["PORT"] == "0" {
				fs = append(fs, Finding{Severity: SevError, Metric: "port_6379", Value: "0",
					Message: "6379 未监听，缓存不可用"})
			}
			return ms, fs, nil
		},
	})

	register(Check{
		Name: "nginx-service", Dimension: DimMiddleware,
		Description: "Nginx 进程与配置语法",
		Applies:     func(e Env) bool { return e.Target.SupportKind == "nginx" },
		Command: func(Env) (string, error) {
			return `pgrep -x nginx >/dev/null 2>&1 && echo PROCESS=RUNNING || echo PROCESS=DOWN; (nginx -t 2>&1 | tail -2) || true`, nil
		},
		Evaluate: func(_ Env, out string) ([]Metric, []Finding, error) {
			kv := parseKV(out)
			ms := []Metric{{Name: "nginx", Value: kv["PROCESS"]}}
			var fs []Finding
			if kv["PROCESS"] != "RUNNING" {
				fs = append(fs, Finding{Severity: SevError, Metric: "nginx", Value: kv["PROCESS"],
					Message: "nginx 进程不存在，Web 服务未运行"})
			}
			if strings.Contains(out, "syntax is ok") {
				ms = append(ms, Metric{Name: "nginx_config", Value: "ok"})
			} else if strings.Contains(out, "failed") || strings.Contains(out, "emerg") {
				fs = append(fs, Finding{Severity: SevError, Metric: "nginx_config",
					Message: "nginx -t 语法检查失败", Value: "failed"})
			}
			return ms, fs, nil
		},
	})

	register(Check{
		Name: "tomcat-process", Dimension: DimMiddleware,
		Description: "Tomcat 进程（catalina Bootstrap）",
		Applies: func(e Env) bool {
			return e.Target.App != "" && strings.EqualFold(e.Target.MiddleType, "tomcat")
		},
		Command: func(Env) (string, error) {
			return `pgrep -f 'org.apache.catalina.startup.Bootstrap' >/dev/null 2>&1 && echo PROCESS=RUNNING || echo PROCESS=DOWN`, nil
		},
		Evaluate: func(e Env, out string) ([]Metric, []Finding, error) {
			kv := parseKV(out)
			ms := []Metric{{Name: "tomcat", Value: kv["PROCESS"]}}
			if kv["PROCESS"] != "RUNNING" {
				return ms, []Finding{{Severity: SevError, Metric: "tomcat", Value: kv["PROCESS"],
					Message: fmt.Sprintf("应用 %s 的 Tomcat 进程不存在", e.Target.App)}}, nil
			}
			return ms, nil, nil
		},
	})
}
