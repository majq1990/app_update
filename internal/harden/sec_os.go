package harden

// sec_os.go —— 操作系统基线（对齐 oneinstall harden_os_baseline.sh）。
//
// check：账号口令（空口令/UID0/pwquality/PASS_MAX_DAYS/登录失败锁定）、SSH 五项、
//        会话（TMOUT/umask/core）、危险服务、auditd、关键文件权限。
// fix：幂等修复（pwquality/login.defs/limits/SSH 五项），
//      SSH 修复红线：无 /root/.ssh/authorized_keys 时拒绝；sshd -t 失败自动还原。

import (
	"fmt"
	"strings"
)

// runOSCheck OS 基线体检（主机级，只读）。
func RunOSCheck(host string, r *SecReport) {
	rec := func(level SecLevel, cat, item, result, evidence, advice, fixable string) {
		r.Add(SecFinding{Host: host, Category: cat, Item: item, Result: result,
			Evidence: evidence, Level: level, Advice: advice, Fixable: fixable})
	}
	ok := func(cat, item, result string) { rec(SecInfo, cat, item, result, "", "", "no") }

	// ---- 账号口令 ----
	out, _ := remoteRun(`awk -F: '($2 == ""){print $1}' /etc/shadow 2>/dev/null`)
	if s := strings.TrimSpace(out); s != "" {
		rec(SecCritical, "账号口令", "空口令账号", s, "/etc/shadow 空字段", "立即设置强口令或 passwd -l 锁定", "yes")
	} else {
		ok("账号口令", "空口令账号", "未发现")
	}
	out, _ = remoteRun(`awk -F: '($3 == 0 && $1 != "root"){print $1}' /etc/passwd`)
	if s := strings.TrimSpace(out); s != "" {
		rec(SecHigh, "账号口令", "UID=0 非 root 账号", s, "", "确认用途后删除或改 UID", "no")
	} else {
		ok("账号口令", "UID=0 账号", "仅 root")
	}
	minlen, minclass := "", ""
	out, _ = remoteRun(`grep -E '^\s*minlen\s*=' /etc/security/pwquality.conf 2>/dev/null | tail -1 | tr -dc '0-9'`)
	minlen = strings.TrimSpace(out)
	out, _ = remoteRun(`grep -E '^\s*minclass\s*=' /etc/security/pwquality.conf 2>/dev/null | tail -1 | tr -dc '0-9'`)
	minclass = strings.TrimSpace(out)
	if minlen != "" && lessThan(minlen, 10) {
		rec(SecMedium, "账号口令", "口令最小长度", "minlen="+minlen+"(<10)", "/etc/security/pwquality.conf",
			"minlen=10 minclass=3（harden os fix）", "yes")
	} else if minlen == "" {
		rec(SecMedium, "账号口令", "口令复杂度", "未配置 pwquality", "/etc/security/pwquality.conf",
			"minlen=10 minclass=3（harden os fix）", "yes")
	} else {
		ok("账号口令", "口令复杂度", "minlen="+minlen+" minclass="+defaultStr(minclass, "已配置"))
	}
	out, _ = remoteRun(`awk '/^\s*PASS_MAX_DAYS/{print $2}' /etc/login.defs 2>/dev/null | head -1`)
	if d := strings.TrimSpace(out); d == "" || d == "99999" || greater(d, 90) {
		rec(SecMedium, "账号口令", "口令有效期", "PASS_MAX_DAYS="+defaultStr(d, "未配置"), "/etc/login.defs",
			"PASS_MAX_DAYS=90（harden os fix）", "yes")
	} else {
		ok("账号口令", "口令有效期", "PASS_MAX_DAYS="+d)
	}
	out, _ = remoteRun(`grep -rlE 'pam_faillock|pam_tally2' /etc/pam.d/ 2>/dev/null | head -1`)
	if strings.TrimSpace(out) == "" {
		rec(SecMedium, "账号口令", "登录失败锁定", "未启用（可被在线爆破）", "/etc/pam.d/system-auth",
			"pam_faillock deny=5 unlock_time=600（参考产品手册，防锁死运维账号）", "no")
	} else {
		ok("账号口令", "登录失败锁定", "已启用")
	}

	// ---- SSH ----
	checkSSHKey := func(k string) string {
		out, _ = remoteRun(fmt.Sprintf(`awk -F'\\s+' 'tolower($1)=="%s"{print $2}' /etc/ssh/sshd_config 2>/dev/null | tail -1`, strings.ToLower(k)))
		return strings.ToLower(strings.TrimSpace(out))
	}
	if v := checkSSHKey("PermitRootLogin"); v == "yes" {
		rec(SecMedium, "SSH", "PermitRootLogin", "yes（root 可直接登录）", "/etc/ssh/sshd_config",
			"prohibit-password（harden os fix；改前必须确认有密钥）", "yes")
	} else {
		ok("SSH", "PermitRootLogin", defaultStr(v, "默认(prohibit-password)"))
	}
	if v := checkSSHKey("PasswordAuthentication"); v == "yes" {
		rec(SecMedium, "SSH", "PasswordAuthentication", "yes（口令登录开启）", "/etc/ssh/sshd_config",
			"改为 no（需先确保密钥可用；harden os fix 红线校验）", "yes")
	} else {
		ok("SSH", "PasswordAuthentication", defaultStr(v, "默认(yes)"))
	}
	if v := checkSSHKey("PermitEmptyPasswords"); v == "yes" {
		rec(SecHigh, "SSH", "PermitEmptyPasswords", "yes（空口令可登录）", "/etc/ssh/sshd_config",
			"必须 no（harden os fix）", "yes")
	} else {
		ok("SSH", "PermitEmptyPasswords", defaultStr(v, "默认(no)"))
	}
	if v := checkSSHKey("MaxAuthTries"); v != "" && greater(v, 6) {
		rec(SecLow, "SSH", "MaxAuthTries", v+"(>6)", "", "MaxAuthTries 6（harden os fix）", "yes")
	} else {
		ok("SSH", "MaxAuthTries", defaultStr(v, "默认6"))
	}

	// ---- 会话 ----
	out, _ = remoteRun(`grep -E '^\s*(export\s+)?TMOUT=' /etc/profile /etc/profile.d/*.sh 2>/dev/null | head -1 | tr -dc '0-9'`)
	if t := strings.TrimSpace(out); t == "" || greater(t, 900) {
		rec(SecLow, "会话", "TMOUT 自动注销", defaultStr(t, "未配置"), "/etc/profile.d/",
			"TMOUT=600（harden os fix）", "yes")
	} else {
		ok("会话", "TMOUT", t+"s")
	}
	out, _ = remoteRun(`grep -E '^\s*\*\s+soft\s+core' /etc/security/limits.conf 2>/dev/null | head -1`)
	if strings.TrimSpace(out) == "" {
		rec(SecLow, "会话", "core dump", "未关闭", "/etc/security/limits.conf",
			"* soft core 0 / * hard core 0（harden os fix）", "yes")
	} else {
		ok("会话", "core dump", "已限制")
	}

	// ---- 危险服务 ----
	out, _ = remoteRun(`systemctl is-active telnet.socket rsh.socket rlogin.socket vsftpd tftp 2>/dev/null | grep -cx 'active'`)
	if n := strings.TrimSpace(out); n != "0" {
		rec(SecHigh, "服务", "危险服务在运行", "telnet/rsh/vsftpd/tftp 有 active", "",
			"systemctl disable --now <服务>（改用 ssh/sftp）", "no")
	} else {
		ok("服务", "危险服务", "未运行")
	}

	// ---- 审计 ----
	out, _ = remoteRun(`systemctl is-active auditd 2>/dev/null`)
	if strings.TrimSpace(out) != "active" {
		rec(SecLow, "审计", "auditd", "未运行", "", "安装并启用 auditd + 基础规则（passwd/shadow/sudoers/sshd）", "no")
	} else {
		ok("审计", "auditd", "运行中")
	}

	// ---- 关键文件权限 ----
	out, _ = remoteRun(`stat -c '%a %n' /etc/shadow /etc/gshadow 2>/dev/null | awk '{m=sprintf("%04d",$1); if (m!="0000" && m!="0400" && m!="0640") print}'`)
	if s := strings.TrimSpace(out); s != "" {
		rec(SecMedium, "权限", "敏感文件权限过宽", s, "", "shadow/gshadow 收敛到 000/0400", "no")
	} else {
		ok("权限", "shadow/gshadow", "权限符合")
	}
}

func lessThan(a string, b int) bool {
	n := 0
	for _, c := range a {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n < b
}

func greater(a string, b int) bool {
	n := 0
	for _, c := range a {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n > b
}

func defaultStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// OSFixBlocks 幂等修复块（check 报告的 fixable=yes 项对应）。
const osFixBlocks = `
# --- pwquality（口令复杂度）---
grep -q 'minlen' /etc/security/pwquality.conf 2>/dev/null && sed -i -E 's/^\s*#*\s*minlen\s*=.*/minlen = 10/; s/^\s*#*\s*minclass\s*=.*/minclass = 3/' /etc/security/pwquality.conf || { echo 'minlen = 10'; echo 'minclass = 3'; } >> /etc/security/pwquality.conf
# --- login.defs（口令有效期）---
sed -i -E 's/^\s*PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS\t90/' /etc/login.defs
# --- limits（core dump）---
grep -qE '^\s*\*\s+soft\s+core\s+0' /etc/security/limits.conf || printf '* soft core 0\n* hard core 0\n' >> /etc/security/limits.conf
# --- profile（TMOUT）---
grep -qs 'TMOUT=600' /etc/profile.d/eops-session.sh || { echo 'export TMOUT=600' > /etc/profile.d/eops-session.sh; echo 'readonly TMOUT'; echo 'export TMOUT'; }
`

// SSHFixKeys SSH 加固五项（红线内执行）。
var SSHFixKeys = [][2]string{
	{"PermitRootLogin", "prohibit-password"},
	{"PermitEmptyPasswords", "no"},
	{"MaxAuthTries", "6"},
	{"X11Forwarding", "no"},
}

// SSHFixCmd 生成 sshd_config 幂等修复命令。
func SSHFixCmd(disablePassword bool) string {
	var b strings.Builder
	b.WriteString(`sshd=/etc/ssh/sshd_config; `)
	for _, kv := range SSHFixKeys {
		k, v := kv[0], kv[1]
		fmt.Fprintf(&b, `sed -i -E 's/^\s*#*\s*%s\s+.*/%s %s/I' $sshd; `, k, k, v)
		b.WriteString(`grep -qiE '^\s*` + k + `\s' $sshd || echo '` + k + ` ` + v + `' >> $sshd; `)
	}
	if disablePassword {
		b.WriteString(`sed -i -E 's/^\s*#*\s*PasswordAuthentication\s+.*/PasswordAuthentication no/I' $sshd; grep -qiE '^\s*PasswordAuthentication\s' $sshd || echo 'PasswordAuthentication no' >> $sshd; `)
	}
	b.WriteString(`sshd -t && echo SSH_OK || (cp -a /egova/security/backup/*/etc/ssh/sshd_config /etc/ssh/sshd_config 2>/dev/null; echo SSH_RESTORED)`)
	return b.String()
}

// runOSFix OS 幂等修复（dry-run 出计划；--yes 执行）。
func RunOSFix(host string, r *SecReport, yes, fixSSH bool) error {
	// 红线：无 /root/.ssh/authorized_keys 时拒绝改 SSH 登录方式
	out, _ := remoteRun(`test -s /root/.ssh/authorized_keys && echo yes || echo no`)
	hasKey := strings.TrimSpace(out) == "yes"
	if fixSSH && !hasKey {
		return fmt.Errorf("OS fix 红线：%s 无 /root/.ssh/authorized_keys，拒绝修改 SSH 登录方式（先确保密钥可登录）", host)
	}

	var steps []string
	steps = append(steps, "bash -c "+sq(osFixBlocks))
	if fixSSH {
		steps = append(steps, SSHFixCmd(true))
	}
	// 备份将修改的文件
	targets := []string{"/etc/security/pwquality.conf", "/etc/login.defs", "/etc/security/limits.conf", "/etc/ssh/sshd_config"}

	if !yes {
		fmt.Printf("  [os fix 计划] %s\n", host)
		for _, s := range steps {
			fmt.Printf("    $ %s\n", truncate(s, 150))
		}
		fmt.Printf("    备份: %v\n    （dry-run；确认后加 --yes 执行）\n", targets)
		return nil
	}

	for _, f := range targets {
		if _, err := backupFile(host, f, r); err != nil {
			return err
		}
	}
	for _, s := range steps {
		out, err := remoteRun(s)
		if err != nil {
			return fmt.Errorf("os fix 失败: %w", err)
		}
		if strings.Contains(out, "SSH_RESTORED") {
			return fmt.Errorf("sshd -t 失败已自动还原（备份 %s/%s）", BackupRoot, secBackupTS())
		}
	}
	if fixSSH {
		_, _ = remoteRun(`systemctl reload sshd 2>/dev/null || systemctl restart sshd 2>/dev/null || true`)
	}
	r.Add(SecFinding{Host: host, Category: "OS 基线", Item: "幂等修复",
		Result:   fmt.Sprintf("口令/会话/core/SSH 五项已收敛（fixSSH=%v）", fixSSH),
		Evidence: fmt.Sprintf("备份 %d 项", len(r.Backups)), Level: SecInfo, Fixable: "no"})
	return nil
}
