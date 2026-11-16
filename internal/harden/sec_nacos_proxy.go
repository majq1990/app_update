package harden

// sec_nacos_proxy.go —— nacos 禁止经 nginx 对外转发。
//
// 背景：nacos 控制台/API（8848/9848/9849）一旦被 nginx proxy_pass 出去，
// 等于把未授权访问入口暴露到公网（知识库多起“未授权接口访问”与此同根因）。
// 策略：nacos 只允许内网直连，一律不走 nginx 转发。
//
// check：扫描 nginx 配置中 proxy_pass 到 8848/9848/9849 的行（Critical），
//       以及 server_name/location 含 nacos 关键字（Medium，需人工确认）。
// fix：命中文件先 backupFile 进 manifest；在命中 location 内插入
//      `allow 127.0.0.1; deny all;`（本机经 nginx 可用，外部一律拒绝；
//      nacos 本体端口不受影响，内网直连照常）；nginx -t 失败自动还原并 reload。
//      默认 dry-run，只打印计划；--yes 真执行。

import (
	"fmt"
	"strings"
)

// nacosProxyPorts nacos 相关端口（控制台/API/grpc）。
const nacosProxyPorts = `8848|9848|9849`

// nacosConfDirs 候选配置目录（与 detectNginxConfDir 同口径，逐个扫描）。
const nacosConfDirs = `/egova/apps/nginx/conf /etc/nginx /usr/local/nginx/conf /usr/local/openresty/nginx/conf`

// RunNginxNacosProxyCheck nacos 转发体检（主机级，只读）。
func RunNginxNacosProxyCheck(host string, r *SecReport) {
	grepDirs := fmt.Sprintf(`for d in %s; do [ -f "$d/nginx.conf" ] && echo "$d"; done`, nacosConfDirs)
	dirsOut, _ := remoteRun(grepDirs)
	var dirs []string
	for _, ln := range strings.Split(dirsOut, "\n") {
		if d := strings.TrimSpace(ln); d != "" && secPathOK(d) {
			dirs = append(dirs, d)
		}
	}
	if len(dirs) == 0 {
		r.Add(SecFinding{Host: host, Category: "Nginx", Item: "nacos 转发探测",
			Result: "未发现 nginx（跳过）", Level: SecInfo, Fixable: "no"})
		return
	}
	found, keyword := "", ""
	for _, dir := range dirs {
		dQ := sq(dir)
		out, _ := remoteRun(fmt.Sprintf(`grep -REin 'proxy_pass[^;]*:(%s)\b' %s --include='*.conf' %s 2>/dev/null | head -10`, nacosProxyPorts, nginxGrepExcludes, dQ))
		if strings.TrimSpace(out) != "" {
			found += strings.TrimSpace(out) + "\n"
		}
		out2, _ := remoteRun(fmt.Sprintf(`grep -REin 'server_name[^;]*nacos|location[^;{]*nacos' %s --include='*.conf' %s 2>/dev/null | head -10`, nginxGrepExcludes, dQ))
		if strings.TrimSpace(out2) != "" {
			keyword += strings.TrimSpace(out2) + "\n"
		}
	}
	// 直接证据：proxy_pass 到 nacos 端口
	hits := strings.TrimSpace(found)
	kw := strings.TrimSpace(keyword)
	if hits == "" && kw == "" {
		r.Add(SecFinding{Host: host, Category: "Nginx", Item: "nacos 经 nginx 转发",
			Result: "未发现 proxy_pass 到 8848/9848/9849 或 nacos 关键字", Level: SecInfo, Fixable: "no"})
		return
	}
	if hits != "" {
		r.Add(SecFinding{Host: host, Category: "Nginx", Item: "nacos 经 nginx 对外转发",
			Result:   "发现 proxy_pass 到 nacos 端口，控制台/API 可经 nginx 访问",
			Evidence: firstLine(hits), Level: SecCritical,
			Advice: "harden sec fix 下发 allow 127.0.0.1 + deny all（仅本机经 nginx 可用）", Fixable: "yes"})
	}
	if kw != "" {
		r.Add(SecFinding{Host: host, Category: "Nginx", Item: "疑似 nacos 转发",
			Result:   "server_name/location 含 nacos 关键字，需人工确认是否转发到 nacos",
			Evidence: firstLine(kw), Level: SecMedium,
			Advice: "确认后按上条处置；纯静态/文档页无碍", Fixable: "no"})
	}
}

// nacosDenyGuard 插入到命中 location 的 guard（幂等标记 eops-nacos-deny）。
const nacosDenyGuard = `# eops-nacos-deny: nacos 禁止经 nginx 对外转发（仅本机可用，内网请直连 8848/9848/9849）
    allow 127.0.0.1;
    deny all;`

// nacosGuardCmd 对含 nacos 转发的 conf 文件插入 guard（幂等：已有标记则跳过）。
// 对 proxy_pass 行：在其同缩进行前插入；对含 nacos 的 location 行：在 { 后插入。
const nacosGuardCmd = `f=$1
grep -qF 'eops-nacos-deny' "$f" && exit 0
awk '
/proxy_pass[^;]*:(8848|9848|9849)\b/ {
  match($0, /^[[:space:]]*/); ind = substr($0, RSTART, RLENGTH)
  print ind "# eops-nacos-deny: nacos 禁止经 nginx 对外转发（仅本机可用）"
  print ind "allow 127.0.0.1;"
  print ind "deny all;"
}
/location[^;{]*nacos[^;{]*\{/ {
  print $0
  print "    # eops-nacos-deny: nacos 禁止经 nginx 对外转发（仅本机可用）"
  print "    allow 127.0.0.1;"
  print "    deny all;"
  next
} { print }' "$f" > "$f.eops-new" && mv -f "$f.eops-new" "$f"
echo GUARDED`

// RunNginxNacosProxyFix nacos 转发封堵（dry-run 返回计划）。
func RunNginxNacosProxyFix(host string, r *SecReport, yes bool) error {
	dirsOut, _ := remoteRun(fmt.Sprintf(`for d in %s; do [ -f "$d/nginx.conf" ] && echo "$d"; done`, nacosConfDirs))
	var files []string
	seen := map[string]bool{}
	for _, ln := range strings.Split(dirsOut, "\n") {
		dir := strings.TrimSpace(ln)
		if dir == "" || !secPathOK(dir) {
			continue
		}
		out, _ := remoteRun(fmt.Sprintf(`grep -REl 'proxy_pass[^;]*:(%s)\b|location[^;{]*nacos' %s --include='*.conf' %s 2>/dev/null | head -10`, nacosProxyPorts, nginxGrepExcludes, sq(dir)))
		for _, p := range strings.Split(out, "\n") {
			p = strings.TrimSpace(p)
			if p != "" && secPathOK(p) && !seen[p] {
				seen[p] = true
				files = append(files, p)
			}
		}
	}
	if len(files) == 0 {
		return nil
	}
	var steps []string
	for _, f := range files {
		if yes {
			if _, berr := backupFile(host, f, r); berr != nil {
				return berr
			}
		}
		steps = append(steps, fmt.Sprintf(`bash -c '%s' -- %s`,
			strings.ReplaceAll(nacosGuardCmd, "'", `'\''`), sq(f)))
	}
	if !yes {
		fmt.Printf("  [nacos-proxy fix 计划] %s\n", host)
		for _, s := range steps {
			fmt.Printf("    $ %s\n", truncate(s, 160))
		}
		fmt.Println("  （dry-run；确认后加 --yes 执行，nginx -t 失败自动还原）")
		return nil
	}
	for _, s := range steps {
		o, err := remoteRun(s)
		if err != nil {
			if rb, rberr := RollbackCommand(ManifestBackups(r)); rberr == nil {
				_, _ = remoteRun(rb)
			}
			return fmt.Errorf("nacos-proxy fix 步骤失败: %v（%s）", err, strings.TrimSpace(o))
		}
	}
	if verr := validateAndRollback(host, `nginx -t 2>&1`, ManifestBackups(r), r); verr != nil {
		return verr
	}
	_, _ = remoteRun(`nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || true`)
	r.Add(SecFinding{Host: host, Category: "Nginx", Item: "nacos 转发封堵",
		Result:   "已在命中 location 插入 allow 127.0.0.1 + deny all 并 reload",
		Evidence: fmt.Sprintf("文件 %d 个，备份 %d 项", len(files), len(r.Backups)),
		Level:    SecInfo, Fixable: "no"})
	return nil
}
