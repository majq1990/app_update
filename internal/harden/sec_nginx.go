package harden

// sec_nginx.go —— Nginx 安全基线（对齐 oneinstall harden_nginx.sh）。
//
// check：server_tokens / autoindex / 安全响应头 / 敏感文件拦截 / 调试接口兜底 / TRACE / TLS。
// fix：写 nginx.conf 幂等块（server_tokens/autoindex/响应头/TLS）+ conf.d/00-egova-security-locations.conf
//      （敏感文件与调试接口拦截），并给每个 server{} 注入 include；
//      nginx -t 失败自动还原。rollback：按备份清单回滚并 nginx -t。

import (
	"fmt"
	"strings"
)

// nginxConfDirCmd 探测 nginx 配置目录（优先 /egova/apps 下现场布局）。
const nginxConfDirCmd = `for d in /egova/apps/nginx/conf /etc/nginx /usr/local/nginx/conf; do [ -f "$d/nginx.conf" ] && echo "$d" && break; done`

// nginxGrepExcludes 扫描时排除备份/临时文件：现场 conf.d 里常有 all.location.bak-*、
// *.tcpbak、*.fixed 等历史副本，一条 autoindex on 出现在备份里会造成误报。
const nginxGrepExcludes = `--exclude='*bak*' --exclude='*backup*' --exclude='*.old*' --exclude='*~' --exclude='*.fixed*' --exclude='*.tcpbak*' --exclude='*.disabled' --exclude='*.orig' --exclude='*.tmp' --exclude='*.save'`

func detectNginxConfDir() (string, error) {
	out, err := remoteRun(nginxConfDirCmd)
	d := strings.TrimSpace(firstLine(out))
	if err != nil || d == "" {
		return "", fmt.Errorf("未找到 nginx 配置目录")
	}
	if !secPathOK(d) {
		return "", fmt.Errorf("配置目录非法: %q", d)
	}
	return d, nil
}

// runNginxCheck nginx 基线体检（主机级，只读）。
func RunNginxCheck(host string, r *SecReport) {
	dir, err := detectNginxConfDir()
	if err != nil {
		r.Add(SecFinding{Host: host, Category: "Nginx", Item: "配置探测",
			Result: "未发现 nginx（或不可读）", Level: SecInfo, Fixable: "no"})
		return
	}
	dQ := sq(dir)

	// server_tokens
	out, _ := remoteRun(fmt.Sprintf(`grep -rEis '^[[:space:]]*server_tokens[[:space:]]+off' %s %s | head -1`, nginxGrepExcludes, dQ))
	if strings.TrimSpace(out) == "" {
		r.Add(SecFinding{Host: host, Category: "Nginx", Item: "server_tokens",
			Result: "未关闭，响应头暴露 nginx 版本", Evidence: dir,
			Advice: "设置 server_tokens off;（harden nginx fix）", Level: SecMedium, Fixable: "yes"})
	} else {
		r.Add(SecFinding{Host: host, Category: "Nginx", Item: "server_tokens",
			Result: "已关闭版本号显示", Level: SecInfo, Fixable: "no"})
	}

	// autoindex
	out, _ = remoteRun(fmt.Sprintf(`grep -rEis '^[[:space:]]*autoindex[[:space:]]+on' %s %s | head -3`, nginxGrepExcludes, dQ))
	if strings.TrimSpace(out) != "" {
		r.Add(SecFinding{Host: host, Category: "Nginx", Item: "目录浏览 autoindex",
			Result: "已开启，会列出目录全部文件", Evidence: strings.TrimSpace(firstLine(out)),
			Advice: "改为 autoindex off;（harden nginx fix）", Level: SecHigh, Fixable: "yes"})
	} else {
		r.Add(SecFinding{Host: host, Category: "Nginx", Item: "目录浏览",
			Result: "未开启 autoindex", Level: SecInfo, Fixable: "no"})
	}

	// 安全响应头
	missing := ""
	for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		out, _ = remoteRun(fmt.Sprintf(`grep -rqiE 'add_header[[:space:]]*%s' %s %s && echo yes || echo no`, h, nginxGrepExcludes, dQ))
		if strings.TrimSpace(out) == "no" {
			missing += h + " "
		}
	}
	if missing != "" {
		r.Add(SecFinding{Host: host, Category: "Nginx", Item: "安全响应头缺失",
			Result: strings.TrimSpace(missing), Level: SecMedium,
			Advice: "统一添加 nosniff / SAMEORIGIN / Referrer-Policy（harden nginx fix）", Fixable: "yes"})
	} else {
		r.Add(SecFinding{Host: host, Category: "Nginx", Item: "安全响应头",
			Result: "已配置", Level: SecInfo, Fixable: "no"})
	}

	// 敏感文件拦截
	out, _ = remoteRun(`test -f /egova/apps/nginx/conf/conf.d/00-egova-security-locations.conf && echo yes || echo no`)
	if strings.TrimSpace(out) == "no" {
		out2, _ := remoteRun(fmt.Sprintf(`grep -rEis '\.git|WEB-INF|swagger-ui|actuator' %s %s | head -1`, nginxGrepExcludes, dQ))
		if strings.TrimSpace(out2) == "" {
			r.Add(SecFinding{Host: host, Category: "Nginx", Item: "敏感文件/调试接口拦截",
				Result: "未部署（.git/.bak/WEB-INF/actuator/swagger 可被下载）", Level: SecHigh,
				Advice: "harden nginx fix 下发 00-egova-security-locations.conf 并注入 include", Fixable: "yes"})
		} else {
			r.Add(SecFinding{Host: host, Category: "Nginx", Item: "敏感文件/调试接口拦截",
				Result: "业务配置已含部分规则，建议统一到安全片段", Evidence: strings.TrimSpace(firstLine(out2)),
				Level: SecLow, Fixable: "yes"})
		}
	} else {
		r.Add(SecFinding{Host: host, Category: "Nginx", Item: "敏感文件/调试接口拦截",
			Result: "已部署安全片段", Level: SecInfo, Fixable: "no"})
	}

	// TLS 协议（有 443 监听才检查）
	out, _ = remoteRun(fmt.Sprintf(`ss -lntH 2>/dev/null | grep -q ':443 ' && grep -rEis 'ssl_protocols' %s %s | head -2 || echo none`, nginxGrepExcludes, dQ))
	tls := strings.TrimSpace(out)
	if tls != "none" && tls != "" {
		if strings.Contains(tls, "SSLv3") || strings.Contains(tls, "TLSv1 ") || strings.Contains(tls, "TLSv1;") || strings.Contains(tls, "TLSv1.0") || strings.Contains(tls, "SSLv2") {
			r.Add(SecFinding{Host: host, Category: "Nginx", Item: "TLS 协议过旧",
				Result: "启用了 TLSv1.0/SSLv3 等弱协议", Evidence: tls, Level: SecMedium,
				Advice: "ssl_protocols TLSv1.2 TLSv1.3;（harden nginx fix）", Fixable: "yes"})
		}
	}
}

// nginxHTTPBlock fix 注入的幂等块（与上游 write_http_conf 同内容）。
const nginxHTTPBlock = `    # 隐藏版本号
    server_tokens off;
    # 关闭目录浏览
    autoindex off;
    autoindex_exact_size off;

    # 安全响应头(子级 location 若自行 add_header 会覆盖，需在业务配置中同步)
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # TLS 协议与套件收敛(无 https 时无副作用)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
    ssl_session_tickets off;
`

// nginxLocationsBlock 敏感文件与调试接口拦截片段（conf.d/00-egova-security-locations.conf）。
const nginxLocationsBlock = `# eops 安全片段：敏感文件与调试接口拦截（由 eops harden nginx fix 生成）
location ~* /\.(git|svn|hg|env)(/|$) { return 404; }
location ~* \.(bak|old|sql|zip|tar\.gz|war|sh|log)$ { return 404; }
location ~* /(WEB-INF|META-INF)/ { return 404; }
location ~* ^/(actuator|env|v2/api-docs|swagger-ui(\.html)?|doc\.html|druid)(/|$) { return 404; }
if ($request_method = TRACE) { return 405; }
`

// nginxServerIncludeCmd 向每个 server{} 注入安全片段 include（幂等：已含标记则跳过）。
const nginxServerIncludeCmd = `conf=$1; loc=$2
  # 仅处理含 server { 的 conf 文件（排除 sites-enabled 软链重复：以 readlink 去重）
  grep -lE '^[[:space:]]*server[[:space:]]*\{' "$conf" 2>/dev/null || exit 0
  grep -q '00-egova-security-locations' "$conf" && exit 0
  # 在每个 server { 后一行插入 include
  awk -v inc="    include ${loc};" '
    /^[[:space:]]*server[[:space:]]*\{/ && !done2 {
      print; print inc; next
    } { print }' "$conf" > "$conf.eops-new" && mv -f "$conf.eops-new" "$conf"
  echo INJECTED`

// runNginxFix nginx 加固写修复（dry-run 返回计划命令）。
func RunNginxFix(host string, r *SecReport, yes bool) error {
	dir, err := detectNginxConfDir()
	if err != nil {
		return fmt.Errorf("nginx fix: %w", err)
	}
	conf := dir + "/nginx.conf"
	// 收集需注入 include 的 server 配置文件
	out, _ := remoteRun(fmt.Sprintf(`grep -rlE '^[[:space:]]*server[[:space:]]*\{' %s --include='*.conf' 2>/dev/null | grep -v 00-egova-security | head -10`, sq(dir)))
	var serverFiles []string
	for _, ln := range strings.Split(out, "\n") {
		if p := strings.TrimSpace(ln); p != "" && secPathOK(p) {
			serverFiles = append(serverFiles, p)
		}
	}

	var steps []string
	if yes {
		if _, berr := backupFile(host, conf, r); berr != nil {
			return berr
		}
	}
	blk, _ := ensureBlock(conf, "egova-security-http", nginxHTTPBlock)
	steps = append(steps, blk)

	locFile := dir + "/conf.d/00-egova-security-locations.conf"
	if yes {
		// conf.d 目录存在性 + 片段下发（stdin，避免引号嵌套）
		remoteRun(fmt.Sprintf(`mkdir -p %s`, sq(dir+"/conf.d")))
		if rn, rerr := runnerOf(host); rerr == nil {
			wcmd := fmt.Sprintf(`cat > %s`, sq(locFile))
			if _, werr := rn.RunWithStdin(wcmd, []byte(nginxLocationsBlock)); werr != nil {
				return werr
			}
		}
		r.Backups = append(r.Backups, locFile)
	}
	for _, sf := range serverFiles {
		if yes {
			if _, berr := backupFile(host, sf, r); berr != nil {
				return berr
			}
		}
		steps = append(steps, fmt.Sprintf(`bash -c '%s' -- %s %s`,
			strings.ReplaceAll(nginxServerIncludeCmd, "'", `'\''`), sq(sf), sq(locFile)))
	}

	dry := !yes
	if dry {
		fmt.Printf("  [nginx fix 计划] %s\n", host)
		for _, s := range steps {
			fmt.Printf("    $ %s\n", truncate(s, 160))
		}
		fmt.Printf("    + 下发 %s（%d bytes）\n", locFile, len(nginxLocationsBlock))
		fmt.Println("  （dry-run；确认后加 --yes 执行）")
		return nil
	}

	for _, s := range steps {
		if _, err := remoteRun(s); err != nil {
			return fmt.Errorf("nginx fix 步骤失败: %w", err)
		}
	}
	// nginx -t 校验，失败自动还原
	if verr := validateAndRollback(host, `nginx -t 2>&1`, ManifestBackups(r), r); verr != nil {
		return verr
	}
	_, _ = remoteRun(`nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || true`)
	r.Add(SecFinding{Host: host, Category: "Nginx", Item: "基线加固",
		Result: "已写入幂等块与拦截片段并 reload", Evidence: fmt.Sprintf("备份 %d 项", len(r.Backups)),
		Level: SecInfo, Fixable: "no"})
	return nil
}

// ManifestBackups 导出备份清单（CLI 写 manifest 用）。
func ManifestBackups(r *SecReport) []BackupEntry {
	var out []BackupEntry
	for _, b := range r.Backups {
		out = append(out, BackupEntry{Origin: originOf(b), Backup: b})
	}
	return out
}

// originOf 从备份路径还原原路径（backupFile 的镜像规则：
// <root>/<host>/<ts><path> → path）。
func originOf(backup string) string {
	marker := BackupRoot + "/"
	i := strings.Index(backup, marker)
	if i < 0 {
		return backup
	}
	rest := backup[i+len(marker):] // <host>/<ts><path>
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[j+1:] // <ts><path>
		if k := strings.Index(rest, "/"); k >= 0 {
			return rest[k:] // path
		}
	}
	return backup
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
