package harden

// sec_appconfig.go —— 应用安全配置项体检与受限写入（对齐 oneinstall harden_app_config.sh）。
//
// 扫描目标机 /egova 下的 properties/yml/yaml/env/conf/config，按 9 类规则体检：
//   Actuator / Swagger-Knife4j / 异常堆栈 / 明文口令 / Cookie-Session /
//   平台安全开关 / 内置超级用户 / 中间件认证(ES/Nacos/MinIO/Redis) / Redis 配置文件
//
// fix 只写白名单键（Swagger/Actuator/错误页），写前逐文件备份，其余仅报告：
//   - 明文口令需改造成密文，属研发/加密规范，工具不自动改
//   - IP 防火墙/审计/越权开关涉及业务口径，只提示

import (
	"fmt"
	"sort"
	"strings"
)

// appConfigScanCmd 一次性采集所有规则命中行；输出按 "##SECTION" 分段。
// 说明：远端只做 grep，不判断等级，等级判定在 Go 侧（便于单测）。
const appConfigScanCmd = `set -u
ROOT="${EOPS_APP_ROOT:-/egova}"
LIST=$(mktemp /tmp/.eops_ac.XXXXXX) || exit 1
trap 'rm -f "$LIST"' EXIT
find "$ROOT" -maxdepth 7 -type f \( -name '*.properties' -o -name '*.yml' -o -name '*.yaml' \
  -o -name '*.env' -o -name '*.conf' -o -name '*.config' \) -size -2M 2>/dev/null \
  | grep -vE '/(logs?|node_modules|media|temp|tmp|backup|\.git)/' | head -2000 > "$LIST"
scan() {
  echo "##$1"
  while IFS= read -r f; do
    grep -nEi -- "$2" "$f" 2>/dev/null | head -3 | sed "s#^#$f:#"
  done < "$LIST"
  echo "##END"
}
scan ACTUATOR 'management\.endpoints\.web\.exposure\.include|^[[:space:]]*endpoints\.enabled'
scan SWAGGER 'swagger\.enable|swagger2\.enable|knife4j\.production|springfox\.documentation\.enabled'
scan ERRORPAGE 'server\.error\.include-(stacktrace|message)'
scan PASSWORD '(password|passwd|pwd|secret|accesskey|secretkey)[[:space:]]*[=:]'
scan COOKIE 'cookie\.(http-only|secure)|session\.timeout'
scan SWITCH '(ip-firewall|operate-log|operation-log|audit|vertical|authz)[^=:]*[=:][[:space:]]*(false|0|off)'
scan AGENT 'egova\.security\.agent[^=:]*[=:][[:space:]]*(false|0|off)'
scan MWAUTH 'xpack\.security\.enabled|nacos\.core\.auth\.enabled|MINIO_ROOT_PASSWORD|MINIO_ACCESS_KEY|^[[:space:]]*#?[[:space:]]*requirepass'
echo "##REDIS"
for f in /etc/redis.conf /etc/redis/redis.conf /egova/redis/conf/redis.conf /egova/data/redis/redis.conf; do
  [ -f "$f" ] || continue
  echo "$f:requirepass:$(grep -cE '^[[:space:]]*requirepass[[:space:]]+[^[:space:]]' "$f" 2>/dev/null)"
  echo "$f:bind:$(grep -E '^[[:space:]]*bind' "$f" 2>/dev/null | head -1)"
done
echo "##END"
`

// appCfgSections 解析 scan 输出为 section → 命中行。
func appCfgSections(out string) map[string][]string {
	sec := map[string][]string{}
	cur := ""
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if strings.HasPrefix(ln, "##") {
			name := strings.TrimPrefix(ln, "##")
			if name == "END" {
				cur = ""
			} else {
				cur = name
			}
			continue
		}
		if cur != "" {
			sec[cur] = append(sec[cur], ln)
		}
	}
	return sec
}

// filesOf 从命中行提取文件路径（"path:line:content"）。
func filesOf(lines []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, ln := range lines {
		i := strings.Index(ln, ":")
		if i <= 0 {
			continue
		}
		p := ln[:i]
		if !strings.HasPrefix(p, "/") || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// isSecretPlaceholder 判断口令行是否为密文/占位/非口令项（不报明文）。
func isSecretPlaceholder(line string) bool {
	l := strings.ToLower(line)
	if strings.Contains(l, "enc(") || strings.Contains(l, "{cipher}") ||
		strings.Contains(l, "${") || strings.Contains(l, "$(") {
		return true
	}
	for _, k := range []string{
		"password.policy", "password.length", "password.expire", "password.max",
		"password.min", "password.strength", "password.enabled", "maxattempts",
		"placeholder", "changeme", "change-me", "example", "xxxx", "validate",
	} {
		if strings.Contains(l, k) {
			return true
		}
	}
	// 必须有实际值
	i := strings.IndexAny(l, "=:")
	if i < 0 {
		return true
	}
	v := strings.TrimSpace(l[i+1:])
	v = strings.Trim(v, `"'`)
	return v == ""
}

func anyMatch(lines []string, subs ...string) bool {
	for _, ln := range lines {
		l := strings.ToLower(ln)
		for _, s := range subs {
			if strings.Contains(l, s) {
				return true
			}
		}
	}
	return false
}

func evidenceOf(lines []string, n int) string {
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " | ")
}

// RunAppConfigCheck 主机级应用配置体检（只读）。
func RunAppConfigCheck(host string, r *SecReport) {
	out, err := remoteRun(appConfigScanCmd)
	if err != nil {
		r.Add(SecFinding{Host: host, Category: "应用配置", Item: "配置扫描",
			Result: "扫描失败: " + err.Error(), Level: SecLow, Fixable: "no"})
		return
	}
	sec := appCfgSections(out)

	// 1. Actuator
	act := sec["ACTUATOR"]
	if anyMatch(act, "=*", "include=*", "include:*", "include=env", "include:env",
		"include=beans", "include=heapdump", "include=threaddump", "endpoints.enabled=true",
		"endpoints.enabled:true", "endpoints.enabled = true") {
		r.Add(SecFinding{Host: host, Category: "应用配置", Item: "Actuator 端点暴露",
			Result: "暴露 env/beans/heapdump 等敏感端点", Evidence: evidenceOf(act, 3),
			Advice: "management.endpoints.web.exposure.include=health；health.show-details=never",
			Level:  SecHigh, Fixable: "yes"})
	} else if len(act) > 0 {
		r.Add(SecFinding{Host: host, Category: "应用配置", Item: "Actuator 配置",
			Result: "已存在限制性配置", Evidence: evidenceOf(act, 2), Level: SecInfo, Fixable: "no"})
	}

	// 2. Swagger / Knife4j
	sw := sec["SWAGGER"]
	if anyMatch(sw, "swagger.enable=true", "swagger.enable:true", "swagger2.enable=true",
		"swagger2.enable:true", "springfox.documentation.enabled=true", "knife4j.production=false") {
		r.Add(SecFinding{Host: host, Category: "应用配置", Item: "在线接口文档开启",
			Result: "Swagger/Knife4j 可被未授权访问", Evidence: evidenceOf(sw, 3),
			Advice: "swagger.enable=false / swagger2.enable=false / knife4j.production=true",
			Level:  SecHigh, Fixable: "yes"})
	}

	// 3. 异常堆栈
	ep := sec["ERRORPAGE"]
	if anyMatch(ep, "always", "on_param", "=true") {
		r.Add(SecFinding{Host: host, Category: "应用配置", Item: "异常堆栈返回前端",
			Result: "报错页面泄露类名/路径/SQL", Evidence: evidenceOf(ep, 3),
			Advice: "include-stacktrace=never；include-message=never", Level: SecMedium, Fixable: "yes"})
	}

	// 4. 明文口令
	var secrets []string
	for _, ln := range sec["PASSWORD"] {
		if !isSecretPlaceholder(ln) {
			secrets = append(secrets, ln)
		}
	}
	if len(secrets) > 0 {
		r.Add(SecFinding{Host: host, Category: "应用配置", Item: "疑似明文口令",
			Result: fmt.Sprintf("%d 处", len(secrets)), Evidence: evidenceOf(secrets, 3),
			Advice: "改为 SM4/AES 密文(ENC(...))或密钥中心注入；禁止配置文件落明文",
			Level:  SecHigh, Fixable: "no"})
	}

	// 5. Cookie / Session
	ck := sec["COOKIE"]
	if anyMatch(ck, "http-only=false", "http-only:false", "secure=false", "secure:false") {
		r.Add(SecFinding{Host: host, Category: "应用配置", Item: "Cookie 安全属性关闭",
			Result: "可被脚本读取或明文传输", Evidence: evidenceOf(ck, 3),
			Advice: "http-only=true；https 场景 secure=true", Level: SecMedium, Fixable: "no"})
	}

	// 6. 平台安全开关
	if sw2 := sec["SWITCH"]; len(sw2) > 0 {
		r.Add(SecFinding{Host: host, Category: "应用配置", Item: "平台安全开关未开启",
			Result: "IP防火墙/操作日志/纵向越权校验等被关闭", Evidence: evidenceOf(sw2, 3),
			Advice: "按产品安全配置文档开启；越权与审计类开关必须开启", Level: SecMedium, Fixable: "no"})
	}

	// 7. 内置超级用户
	if ag := sec["AGENT"]; len(ag) > 0 {
		r.Add(SecFinding{Host: host, Category: "应用配置", Item: "内置超级用户保护未启用",
			Result: "服务内置管理员可绕过平台登录", Evidence: evidenceOf(ag, 2),
			Advice: "启用 egova.security.agent 或按「密码加固」禁用内置超级用户",
			Level:  SecMedium, Fixable: "no"})
	}

	// 8. 中间件认证
	mw := sec["MWAUTH"]
	var bad []string
	if anyMatch(mw, "xpack.security.enabled=false", "xpack.security.enabled:false") {
		bad = append(bad, "Elasticsearch 未开启认证")
	}
	if anyMatch(mw, "nacos.core.auth.enabled=false", "nacos.core.auth.enabled:false") {
		bad = append(bad, "Nacos 未开启鉴权")
	}
	if anyMatch(mw, "minio_root_password=minioadmin", "minio_root_password:minioadmin",
		"minio_access_key=minioadmin", "minio_root_password=admin", "minio_root_password=123456") {
		bad = append(bad, "对象存储使用默认口令")
	}
	if len(bad) > 0 {
		r.Add(SecFinding{Host: host, Category: "应用配置", Item: "中间件认证未开启",
			Result: strings.Join(bad, "; "), Evidence: evidenceOf(mw, 3),
			Advice: "ES: xpack.security.enabled=true；Nacos: nacos.core.auth.enabled=true；对象存储改默认AK/SK",
			Level:  SecHigh, Fixable: "no"})
	}

	// 9. Redis
	for _, ln := range sec["REDIS"] {
		parts := strings.SplitN(ln, ":", 3)
		if len(parts) < 3 {
			continue
		}
		switch parts[1] {
		case "requirepass":
			if strings.TrimSpace(parts[2]) == "0" {
				r.Add(SecFinding{Host: host, Category: "应用配置", Item: "Redis 未设置口令",
					Result: "requirepass 未配置(或仍为注释)", Evidence: parts[0],
					Advice: "设置 requirepass <强口令> 并 bind 内网地址", Level: SecHigh, Fixable: "no"})
			}
		case "bind":
			if strings.Contains(parts[2], "0.0.0.0") {
				r.Add(SecFinding{Host: host, Category: "应用配置", Item: "Redis 监听 0.0.0.0",
					Result: "对全网可达", Evidence: strings.TrimSpace(ln),
					Advice: "bind 127.0.0.1 <内网IP>", Level: SecMedium, Fixable: "no"})
			}
		}
	}
}

// appCfgFixRules 允许自动写入的键（与 oneinstall --apply 白名单一致）。
var appCfgFixRules = []struct {
	Key   string
	Value string
}{
	{"swagger.enable", "false"},
	{"swagger2.enable", "false"},
	{"springfox.documentation.enabled", "false"},
	{"knife4j.production", "true"},
	{"management.endpoints.web.exposure.include", "health"},
	{"management.endpoint.health.show-details", "never"},
	{"server.error.include-stacktrace", "never"},
	{"server.error.include-message", "never"},
}

// appCfgFixFiles 从体检输出中挑出需写入的文件（只含白名单键所在文件）。
func appCfgFixFiles(sec map[string][]string) []string {
	var all []string
	for _, k := range []string{"ACTUATOR", "SWAGGER", "ERRORPAGE"} {
		all = append(all, filesOf(sec[k])...)
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range all {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// RunAppConfigFix 写白名单安全值；dry-run 返回计划，--yes 落盘（先备份）。
func RunAppConfigFix(host string, r *SecReport, yes bool) error {
	out, err := remoteRun(appConfigScanCmd)
	if err != nil {
		return fmt.Errorf("appconfig fix: 扫描失败: %w", err)
	}
	sec := appCfgSections(out)
	files := appCfgFixFiles(sec)
	if len(files) == 0 {
		r.Add(SecFinding{Host: host, Category: "应用配置", Item: "安全值写入",
			Result: "未发现需要写入的白名单键", Level: SecInfo, Fixable: "no"})
		return nil
	}

	var files2 []string
	for _, f := range files {
		if secPathOK(f) {
			files2 = append(files2, f)
		}
	}
	if len(files2) == 0 {
		r.Add(SecFinding{Host: host, Category: "应用配置", Item: "安全值写入",
			Result: "未发现需要写入的白名单键", Level: SecInfo, Fixable: "no"})
		return nil
	}

	// 单次 SSH 下发执行：逐文件、逐白名单键「存在才改值」，避免键不存在时新增
	var sb strings.Builder
	sb.WriteString("set -u\n")
	for _, f := range files2 {
		sb.WriteString(fmt.Sprintf("F=%s\n", sq(f)))
		for _, rule := range appCfgFixRules {
			sb.WriteString(fmt.Sprintf(
				"grep -qiE '^[[:space:]]*%s[[:space:]]*[=:]' \"$F\" 2>/dev/null && "+
					"sed -i -E 's#^([[:space:]]*%s[[:space:]]*[=:][[:space:]]*).*#\\1%s#I' \"$F\"\n",
				rule.Key, rule.Key, rule.Value))
		}
	}
	sb.WriteString("echo APPLY_DONE\n")
	script := sb.String()

	if !yes {
		fmt.Printf("  [appconfig fix 计划] %s：%d 个文件（仅写 8 个白名单键，存在才改值）\n", host, len(files2))
		for _, f := range files2 {
			fmt.Printf("    $ %s\n", f)
		}
		fmt.Println("  （dry-run；确认后加 --yes 执行；写入前逐文件备份）")
		return nil
	}

	// 备份（逐文件；backupFile 对同一路径幂等）
	for _, f := range files2 {
		if _, berr := backupFile(host, f, r); berr != nil {
			return berr
		}
	}
	rn, rerr := runnerOf(host)
	if rerr != nil {
		return rerr
	}
	out2, aerr := rn.RunWithStdin("bash -s", []byte(script))
	if aerr != nil || !strings.Contains(out2, "APPLY_DONE") {
		return fmt.Errorf("appconfig fix 写入失败: %v %s", aerr, strings.TrimSpace(out2))
	}
	r.Add(SecFinding{Host: host, Category: "应用配置", Item: "安全值写入",
		Result:   fmt.Sprintf("已按白名单写入 %d 个文件", len(files2)),
		Evidence: fmt.Sprintf("备份 %d 项", len(r.Backups)),
		Advice:   "需重启对应服务生效", Level: SecInfo, Fixable: "no"})
	return nil
}
