package harden

// secrun.go —— 安全任务的执行基础设施：远端执行、备份、回滚、幂等写入。
//
// 约定：
//   - 所有远端命令由本包构建（值强引用+路径白名单），调用方不拼 shell；
//   - 修改类动作先 hl_backup 等价备份到 /egova/security/backup/<ts>/，
//     并记录 manifest（原路径 → 备份路径），支持按清单回滚；
//   - fix 类动作默认 dry-run，CLI 层 --yes 才真正执行。

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecRunner 远端执行与脚本下发（sshx.Client / 测试假实现）。
type SecRunner interface {
	Run(cmd string) (string, error)
	RunWithStdin(cmd string, stdin []byte) (string, error)
}

// secRunner 当前任务绑定的远端（按主机循环时替换）。
var secRunner func(host string) (SecRunner, error)

// runnerOf 取当前主机的执行器。
func runnerOf(host string) (SecRunner, error) {
	if secRunner == nil {
		return nil, fmt.Errorf("secRunner 未绑定")
	}
	return secRunner(host)
}

// remoteRun 在当前主机执行只读命令（check 类全部走这里）。
func remoteRun(cmd string) (string, error) {
	rn, err := runnerOf(currentHost())
	if err != nil {
		return "", err
	}
	return rn.Run(cmd)
}

// currentHost 当前正在体检的主机。
var currentHostValue string

func currentHost() string { return currentHostValue }

// SetCurrentHost 绑定当前主机与执行器（CLI 层按主机循环调用）。
func SetCurrentHost(h string, fn func(string) (SecRunner, error)) {
	currentHostValue = h
	secRunner = fn
}

// BackupEntry 一条备份记录（manifest 行）。
// Created=true 表示该文件由本次修复新建，回滚时删除而非还原。
type BackupEntry struct {
	Host    string `json:"host,omitempty"`
	Origin  string `json:"origin"`
	Backup  string `json:"backup,omitempty"`
	Created bool   `json:"created,omitempty"`
}

// BackupRef 报告内的一条备份/新建引用（带主机，便于多主机 manifest 分组）。
type BackupRef struct {
	Host    string `json:"host"`
	Path    string `json:"path"`
	Created bool   `json:"created,omitempty"`
}

// BackupRoot 远端备份根目录：/egova/eops-sec-backup/<host>/<ts>/...
// （host 段用于 manifest 回滚时反查主机；CLI hostOfBackup 依赖该目录结构）。
const BackupRoot = "/egova/eops-sec-backup"

// ReportRoot 报告根目录。
const ReportRoot = "/egova/security/report"

// backupTS 当前任务的时间戳目录名。
var backupTS string

// secBackupTS 获取（或创建）本次任务的时间戳。
func secBackupTS() string {
	if backupTS == "" {
		backupTS = time.Now().Format("20060102-150405")
	}
	return backupTS
}

// backupFile 备份单个远端文件到任务目录，返回备份路径。
// 幂等：同一原文件只备份一次。
func backupFile(host, path string, r *SecReport) (string, error) {
	if !secPathOK(path) {
		return "", fmt.Errorf("路径非法: %q", path)
	}
	ts := secBackupTS()
	remote := fmt.Sprintf("%s/%s/%s%s", BackupRoot, host, ts, path)
	cmd := fmt.Sprintf(
		`test -f %s || exit 0; mkdir -p %s && cp -L -p %s %s && echo COPIED`,
		sq(path), sq(fmt.Sprintf("%s/%s/%s", BackupRoot, host, ts)+dirOf(path)),
		sq(path), sq(remote))
	out, err := remoteRun(cmd)
	if err != nil {
		return "", err
	}
	if !strings.Contains(out, "COPIED") {
		return "", nil // 文件不存在，无需备份
	}
	r.Backups = append(r.Backups, BackupRef{Host: host, Path: remote})
	return remote, nil
}

func dirOf(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

// secPathOK 远端路径白名单：绝对路径、无元字符、无 .. 段。
func secPathOK(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\n\r\t'\"`$;&|<>(){}\\") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// sq 单引号强引用。
func sq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// RollbackCommand 按备份清单生成回滚命令（cp -a 备份 → 原路径；新建文件 rm -f）。
func RollbackCommand(backups []BackupEntry) (string, error) {
	if len(backups) == 0 {
		return "", fmt.Errorf("备份清单为空，无可回滚项")
	}
	var parts []string
	for _, b := range backups {
		if b.Created {
			if !secPathOK(b.Origin) {
				return "", fmt.Errorf("回滚清单含非法路径: %q", b.Origin)
			}
			parts = append(parts, fmt.Sprintf("rm -f %s", sq(b.Origin)))
			continue
		}
		if b.Backup == "" {
			return "", fmt.Errorf("回滚项缺少备份文件: %q", b.Origin)
		}
		if !secPathOK(b.Origin) || !secPathOK(b.Backup) {
			return "", fmt.Errorf("回滚清单含非法路径: %q", b.Origin)
		}
		parts = append(parts, fmt.Sprintf("cp -f %s %s", sq(b.Backup), sq(b.Origin)))
	}
	return "set -e; " + strings.Join(parts, " && ") + " && echo ROLLBACK_OK", nil
}

// validateAndRollback 校验失败自动还原（nginx -t / sshd -t / xmllint）。
// validator 输出包含 "failed"/"error"/"错误" 视为失败。
func validateAndRollback(host string, validator string, backups []BackupEntry, r *SecReport) error {
	if validator == "" {
		return nil
	}
	out, err := remoteRun(validator)
	if err == nil && !strings.Contains(strings.ToLower(out), "fail") &&
		!strings.Contains(strings.ToLower(out), "error") {
		return nil
	}
	rb, rberr := RollbackCommand(backups)
	if rberr != nil {
		return fmt.Errorf("校验失败且回滚失败: %v / %v", err, rberr)
	}
	out2, err2 := remoteRun(rb)
	if err2 != nil {
		return fmt.Errorf("校验失败，自动还原失败: %v（备份仍在 %s/%s）", err2, BackupRoot, secBackupTS())
	}
	sort.SliceStable(r.Backups, func(i, j int) bool { return r.Backups[i].Path < r.Backups[j].Path })
	r.Add(SecFinding{Host: host, Category: "回滚", Item: "校验失败自动还原",
		Result: strings.TrimSpace(firstLine(out2)), Level: SecInfo, Fixable: "no"})
	return fmt.Errorf("校验失败已自动还原（备份 %s/%s）：%s", BackupRoot, secBackupTS(), strings.TrimSpace(firstLine(out)))
}

// ensureBlock 幂等配置块写入（等价 harden_lib 的幂等配置块）：BEGIN/END 标记之间内容不存在则追加。
// 注意：内容必须经 printf 输出，不能把单引号字符串当命令执行。
func ensureBlock(path, marker, content string) (string, error) {
	if !secPathOK(path) || strings.ContainsAny(marker, "'") {
		return "", fmt.Errorf("参数非法: %q / %q", path, marker)
	}
	block := "# BEGIN " + marker + "\n" + content + "\n# END " + marker + "\n"
	return fmt.Sprintf(
		"grep -qF %s %s 2>/dev/null || printf '%%s' %s >> %s",
		sq("# BEGIN "+marker), sq(path), sq(block), sq(path)), nil
}
