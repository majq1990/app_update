package harden

// sec_tomcat.go —— Tomcat 基线（对齐 oneinstall harden_tomcat.sh）。
//
// check：Server port 远程 shutdown / Connector server&allowTrace / AJP / listings /
//        默认应用（manager 等）/ 东方通·金蝶提示。
// fix：server.xml 修改（port=-1、server="egova" allowTrace="false"、注释 AJP）+
//      web.xml listings=false；xmllint 校验失败自动还原；--rollback 按备份回滚。

import (
	"fmt"
	"strings"
)

// tomcatBaseCmd 发现 catalina.base（进程参数 → 常见目录）。
const tomcatBaseCmd = `for p in $(pgrep -f 'catalina.startup.Bootstrap' 2>/dev/null); do tr '\0' '\n' < /proc/$p/environ 2>/dev/null | grep '^CATALINA_BASE=' | cut -d= -f2; done | head -3; for d in /egova/apps/*/tomcat* /egova/web/*/tomcat* /usr/local/tomcat*; do [ -f "$d/conf/server.xml" ] && echo "$d"; done | sort -u | head -6`

// tomcatBases 发现 Tomcat 实例目录。
func tomcatBases() []string {
	out, err := remoteRun(tomcatBaseCmd)
	if err != nil {
		return nil
	}
	var bases []string
	for _, ln := range strings.Split(out, "\n") {
		d := strings.TrimSpace(ln)
		if d != "" && secPathOK(d) && !strings.Contains(d, "\r") {
			bases = append(bases, d)
		}
	}
	return bases
}

// runTomcatCheck tomcat 基线体检（主机级，只读）。
func RunTomcatCheck(host string, r *SecReport) {
	bases := tomcatBases()
	if len(bases) == 0 {
		r.Add(SecFinding{Host: host, Category: "Tomcat", Item: "实例发现",
			Result: "未发现 catalina.base（可能未部署 Tomcat 或为 jar 应用）", Level: SecInfo, Fixable: "no"})
		return
	}
	// 东方通/金蝶提示（走中间件加固，不在本工具范围）
	mwOut, _ := remoteRun(`pgrep -af 'com.tongweb|TongWeb|com.apusic|kingdee' 2>/dev/null | head -2; ss -lntH 2>/dev/null | grep -E ':(9060|6888|6900) ' | head -2`)
	if strings.TrimSpace(mwOut) != "" {
		r.Add(SecFinding{Host: host, Category: "Tomcat", Item: "国产中间件",
			Result:   "检测到东方通/金蝶进程或控制台端口(9060/6888/6900)",
			Evidence: strings.TrimSpace(firstLine(mwOut)), Level: SecInfo,
			Advice: "请走对应中间件加固工具（oneinstall enhance_middleware），本工具不处理", Fixable: "no"})
	}
	for _, base := range bases {
		checkOneTomcat(host, base, r)
	}
}

func checkOneTomcat(host, base string, r *SecReport) {
	sx, wx := base+"/conf/server.xml", base+"/conf/web.xml"

	// Server port 远程 shutdown
	out, _ := remoteRun(fmt.Sprintf(`grep -oE '<Server[^>]*port="[0-9-]+"' %s | head -1`, sq(sx)))
	if strings.Contains(out, `port="-1"`) {
		r.Add(SecFinding{Host: host, Category: "Tomcat", Item: base + " 远程 shutdown",
			Result: "已关闭(port=-1)", Level: SecInfo, Fixable: "no"})
	} else if strings.Contains(out, `port="`) {
		r.Add(SecFinding{Host: host, Category: "Tomcat", Item: base + " 远程 shutdown",
			Result: "未关闭（可远程停止实例）", Evidence: strings.TrimSpace(out), Level: SecHigh,
			Advice: `<Server port="-1">（harden tomcat fix）`, Fixable: "yes"})
	}

	// Connector server/allowTrace
	out, _ = remoteRun(fmt.Sprintf(`grep -cE '<Connector[^>]*(server=|allowTrace)' %s`, sq(sx)))
	if strings.TrimSpace(out) == "0" {
		r.Add(SecFinding{Host: host, Category: "Tomcat", Item: base + " Connector 标识",
			Result: "未隐藏 Apache-Coyote/未禁 TRACE", Level: SecMedium,
			Advice: `Connector 增加 server="egova" allowTrace="false"（harden tomcat fix）`, Fixable: "yes"})
	}

	// AJP
	out, _ = remoteRun(fmt.Sprintf(`grep -nE 'protocol="AJP' %s | head -1`, sq(sx)))
	if strings.TrimSpace(out) != "" {
		r.Add(SecFinding{Host: host, Category: "Tomcat", Item: base + " AJP 连接器",
			Result: "AJP 已启用（Ghostcat 历史漏洞）", Evidence: strings.TrimSpace(out),
			Level: SecHigh, Advice: "注释掉 AJP Connector（除非确有前端 AJP 需求）", Fixable: "yes"})
	}

	// listings
	out, _ = remoteRun(fmt.Sprintf(`grep -A2 '<param-name>listings</param-name>' %s 2>/dev/null | grep -c '<param-value>true</param-value>'`, sq(wx)))
	if strings.TrimSpace(out) != "0" {
		r.Add(SecFinding{Host: host, Category: "Tomcat", Item: base + " web.xml 目录列表",
			Result: "listings=true 可列目录", Level: SecHigh,
			Advice: "listings=false（harden tomcat fix）", Fixable: "yes"})
	}

	// 默认应用
	out, _ = remoteRun(fmt.Sprintf(`for a in manager host-manager examples docs; do [ -d %s ] && echo $a; done`, sq(base+"/webapps")))
	if strings.TrimSpace(out) == "" {
		r.Add(SecFinding{Host: host, Category: "Tomcat", Item: base + " 默认应用",
			Result: "未发现 manager/host-manager/examples/docs", Level: SecInfo, Fixable: "no"})
	} else {
		r.Add(SecFinding{Host: host, Category: "Tomcat", Item: base + " 默认应用",
			Result: "存在默认应用：" + strings.Join(strings.Fields(out), " "), Level: SecHigh,
			Advice: "隔离/移除默认应用（rm 或 webapps 外置），并核对 manager 口令", Fixable: "no"})
	}
}

// runTomcatFix tomcat 写修复（dry-run 出计划；--yes 执行 + xmllint 校验自动还原）。
func RunTomcatFix(host string, r *SecReport, yes bool) error {
	bases := tomcatBases()
	if len(bases) == 0 {
		r.Add(SecFinding{Host: host, Category: "Tomcat", Item: "实例发现",
			Result: "未发现 catalina.base（jar 应用，跳过 tomcat 加固）", Level: SecInfo, Fixable: "no"})
		return nil
	}
	type step struct {
		desc, cmd string
	}
	var steps []step
	var touched []string
	for _, base := range bases {
		sx, wx := base+"/conf/server.xml", base+"/conf/web.xml"
		touched = append(touched, sx, wx)
		// 1) Server port -> -1
		steps = append(steps, step{"Server port → -1: " + sx,
			fmt.Sprintf(`sed -i -E 's/(<Server[^>]*port=")[0-9]+(")/\1-1\2/' %s`, sq(sx))})
		// 2) Connector 加 server/allowTrace（仅修改 <Connector port="80xx" 协议行，幂等）
		steps = append(steps, step{"Connector 标识: " + sx,
			fmt.Sprintf(`sed -i -E 's/<Connector[[:space:]]+((?:[^>]*port="(80[0-9]{2}|443)")[^>]*)>/<Connector \1 server="egova" allowTrace="false">/' %s`, sq(sx))})
		// 3) AJP 注释
		steps = append(steps, step{"AJP 注释: " + sx,
			fmt.Sprintf(`sed -i -E 's|^([[:space:]]*)(<Connector[^>]*protocol="AJP.*)|\1<!-- \2 -->|' %s`, sq(sx))})
		// 4) listings=false
		steps = append(steps, step{"listings=false: " + wx,
			fmt.Sprintf(`sed -i '/<param-name>listings<\/param-name>/{n;s/<param-value>true<\/param-value>/<param-value>false<\/param-value>/}' %s`, sq(wx))})
	}

	if !yes {
		fmt.Printf("  [tomcat fix 计划] %s（%d 个实例）\n", host, len(bases))
		for _, s := range steps {
			fmt.Printf("    %s\n      $ %s\n", s.desc, truncate(s.cmd, 140))
		}
		fmt.Println("  （dry-run；确认后加 --yes 执行）")
		return nil
	}

	for _, f := range touched {
		if _, err := backupFile(host, f, r); err != nil {
			return err
		}
	}
	for _, s := range steps {
		if _, err := remoteRun(s.cmd); err != nil {
			return fmt.Errorf("tomcat fix %q 失败: %w", s.desc, err)
		}
	}
	// xmllint 校验（无 xmllint 视为通过），失败自动还原
	if verr := validateAndRollback(host,
		`command -v xmllint >/dev/null || exit 0; for f in `+quoted(touched)+`; do xmllint --noout "$f" 2>&1 || exit 1; done`,
		ManifestBackups(r), r); verr != nil {
		return verr
	}
	r.Add(SecFinding{Host: host, Category: "Tomcat", Item: "基线加固",
		Result:   fmt.Sprintf("%d 个实例已加固（重启后生效）", len(bases)),
		Evidence: fmt.Sprintf("备份 %d 项", len(r.Backups)), Level: SecInfo, Fixable: "no"})
	return nil
}

func quoted(paths []string) string {
	var out []string
	for _, p := range paths {
		out = append(out, sq(p))
	}
	return strings.Join(out, " ")
}
