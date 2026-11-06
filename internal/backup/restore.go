package backup

// 备份恢复（backup restore）：把现场 eops-*.tar.gz 应用备份解压回 web_path。
//
// 安全口径与 backup.go 一致：所有进入远端命令的值都经过 quote() 强引用与
// pathOK 白名单校验；备份包必须是 backup.root 目录下、本工具生成的
// eops-*.tar.gz，绝不接受任意外部文件。
//
// 恢复流程（命令构建集中在本文件，执行编排在 cmd 层）：
//  1. 停应用（该主机 stop_cmd）
//  2. 变更前自动备份当前 web_path → <root>/pre-restore-<ts>.tar.gz（复用 TarCommand）
//  3. tar -xzf <备份包> -C <web_path>（覆盖式，不删运行期新增文件）
//  4. chown -R user:group web_path
//  5. 启应用（该主机 start_cmd）
//  6. 健康检查（远端只读探测：check_uri 用 curl，否则 /dev/tcp 探测端口）

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
)

// 恢复计划中的步骤标识（cmd 层按 Key 识别特殊步骤：变更前备份需解析校验输出）。
const (
	StepStop      = "stop"
	StepPreBackup = "prebackup"
	StepRestore   = "restore"
	StepChown     = "chown"
	StepStart     = "start"
)

// RestoreStep 一步恢复动作。
type RestoreStep struct {
	Key     string
	Name    string
	Command string
}

// RestorePlan 一次应用恢复的完整计划（dry-run 展示与执行共用，保证"看到的=执行的"）。
type RestorePlan struct {
	App           string
	Host          string
	WebPath       string
	Package       string
	PreBackup     string
	Steps         []RestoreStep
	HealthEnabled bool
	HealthCommand string
}

// ValidateRestorePackage 校验恢复包：必须位于 backup.root 下且为 eops-*.tar.gz。
func ValidateRestorePackage(root, file string) error {
	root = strings.TrimRight(strings.TrimSpace(root), "/")
	if !pathOK(root) {
		return fmt.Errorf("备份根目录非法: %q", root)
	}
	if !pathOK(file) {
		return fmt.Errorf("备份包路径非法: %q", file)
	}
	if !strings.HasPrefix(file, root+"/") {
		return fmt.Errorf("备份包必须位于备份根目录 %s 下: %q", root, file)
	}
	base := path.Base(file)
	if !strings.HasPrefix(base, config.BackupFilePrefix) || !strings.HasSuffix(base, ".tar.gz") {
		return fmt.Errorf("备份包必须是 %s*.tar.gz: %q", config.BackupFilePrefix, base)
	}
	return nil
}

// FindRestoreTarget 按应用名 + 备份包文件名反查恢复目标（只接受 app 类目标）。
// 文件名前缀 eops-<slug>-<host>- 与备份生成同源，避免恢复包与主机错配。
func FindRestoreTarget(targets []Target, appName, file string) (Target, bool) {
	base := path.Base(file)
	for _, t := range targets {
		if t.Kind != KindApp || t.Name != appName {
			continue
		}
		if strings.HasPrefix(base, TargetPrefix(t)) {
			return t, true
		}
	}
	return Target{}, false
}

// ServiceCommand 校验收起自配置的 start_cmd/stop_cmd（命令字段本身允许复杂语法，
// 只拒绝空值与控制字符，危险模式由 config.ShellSafetyIssues 统一拦截）。
func ServiceCommand(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("启停命令为空")
	}
	if strings.ContainsAny(raw, "\x00\n\r") {
		return "", fmt.Errorf("启停命令含控制字符，拒绝执行: %q", raw)
	}
	return raw, nil
}

// PreRestorePath 变更前自动备份路径：<root>/pre-restore-<ts>.tar.gz。
func PreRestorePath(root string, now time.Time) (string, error) {
	root = strings.TrimRight(strings.TrimSpace(root), "/")
	if !pathOK(root) {
		return "", fmt.Errorf("备份根目录非法: %q", root)
	}
	p := root + "/pre-restore-" + now.Format("20060102-150405") + ".tar.gz"
	if !pathOK(p) {
		return "", fmt.Errorf("变更前备份路径非法: %q", p)
	}
	return p, nil
}

// RestoreCommand 构建解压恢复命令：tar -xzf <备份包> -C <web_path>（覆盖式）。
func RestoreCommand(file, dest string) (string, error) {
	if !pathOK(file) {
		return "", fmt.Errorf("备份包路径非法: %q", file)
	}
	base := path.Base(file)
	if !strings.HasPrefix(base, config.BackupFilePrefix) || !strings.HasSuffix(base, ".tar.gz") {
		return "", fmt.Errorf("备份包必须是 %s*.tar.gz: %q", config.BackupFilePrefix, base)
	}
	dest = strings.TrimRight(dest, "/")
	if !pathOK(dest) {
		return "", fmt.Errorf("恢复目标路径非法: %q", dest)
	}
	fQ, err := quote(file)
	if err != nil {
		return "", err
	}
	dQ, err := quote(dest)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tar -xzf %s -C %s", fQ, dQ), nil
}

// ChownCommand 构建属主修正命令：chown -R <user>[:<group>] <web_path>。
func ChownCommand(dest, user, group string) (string, error) {
	dest = strings.TrimRight(dest, "/")
	if !pathOK(dest) {
		return "", fmt.Errorf("恢复目标路径非法: %q", dest)
	}
	if !ownerIdentOK(user) {
		return "", fmt.Errorf("属主用户非法: %q", user)
	}
	owner := user
	if strings.TrimSpace(group) != "" {
		if !ownerIdentOK(group) {
			return "", fmt.Errorf("属主属组非法: %q", group)
		}
		owner = user + ":" + group
	}
	oQ, err := quote(owner)
	if err != nil {
		return "", err
	}
	dQ, err := quote(dest)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("chown -R %s %s", oQ, dQ), nil
}

// ownerIdentOK 属主/属组白名单：字母数字 . _ -（与现场 user/group 命名一致）。
func ownerIdentOK(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// HealthProbeCommand 构建远端只读健康探测命令：
//   - health_mode: none → 跳过；
//   - check_uri 有值 → curl 访问 http://127.0.0.1:<port><uri>（URL 整体强引用）；
//   - 否则 service_port>0 → bash /dev/tcp 端口探测；
//   - 都没有 → 跳过。
func HealthProbeCommand(h config.Host) (string, bool, error) {
	if h.HealthMode == "none" {
		return "", false, nil
	}
	if strings.TrimSpace(h.CheckURI) != "" {
		if h.ServicePort < 1 || h.ServicePort > 65535 {
			return "", false, fmt.Errorf("健康检查端口非法: %d", h.ServicePort)
		}
		if !strings.HasPrefix(h.CheckURI, "/") || strings.ContainsAny(h.CheckURI, "\"'`;$&|<>\\\n\r\t {}()") {
			return "", false, fmt.Errorf("健康检查 URI 非法: %q", h.CheckURI)
		}
		url := fmt.Sprintf("http://127.0.0.1:%d%s", h.ServicePort, h.CheckURI)
		q, err := quote(url)
		if err != nil {
			return "", false, err
		}
		return "curl -fsS -o /dev/null -m 10 " + q, true, nil
	}
	if h.ServicePort > 0 {
		if h.ServicePort > 65535 {
			return "", false, fmt.Errorf("健康检查端口非法: %d", h.ServicePort)
		}
		return fmt.Sprintf("timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/%d'", h.ServicePort), true, nil
	}
	return "", false, nil
}

// BuildRestorePlan 为一个应用目标构建恢复计划。
func BuildRestorePlan(root string, t Target, file string, now time.Time) (*RestorePlan, error) {
	if t.Kind != KindApp {
		return nil, fmt.Errorf("只有应用目录备份支持恢复（当前目标类型 %s）", t.Kind)
	}
	if err := ValidateRestorePackage(root, file); err != nil {
		return nil, err
	}
	if strings.TrimSpace(t.Path) == "" {
		return nil, fmt.Errorf("应用 %s 的目标主机未配置 web_path", t.Name)
	}

	stopCmd, err := ServiceCommand(t.Host.StopCmd)
	if err != nil {
		return nil, fmt.Errorf("%s@%s 停止命令不可用: %w", t.Name, t.Host.Host, err)
	}
	pre, err := PreRestorePath(root, now)
	if err != nil {
		return nil, err
	}
	preCmd, err := TarCommand(pre, t.Path, t.Exclude)
	if err != nil {
		return nil, fmt.Errorf("变更前备份命令构建失败: %w", err)
	}
	restoreCmd, err := RestoreCommand(file, t.Path)
	if err != nil {
		return nil, err
	}
	chownCmd, err := ChownCommand(t.Path, t.Host.User, t.Host.Group)
	if err != nil {
		return nil, err
	}
	startCmd, err := ServiceCommand(t.Host.StartCmd)
	if err != nil {
		return nil, fmt.Errorf("%s@%s 启动命令不可用: %w", t.Name, t.Host.Host, err)
	}
	healthCmd, healthOn, err := HealthProbeCommand(t.Host)
	if err != nil {
		return nil, err
	}

	return &RestorePlan{
		App:       t.Name,
		Host:      t.Host.Host,
		WebPath:   strings.TrimRight(t.Path, "/"),
		Package:   file,
		PreBackup: pre,
		Steps: []RestoreStep{
			{Key: StepStop, Name: "停止应用", Command: stopCmd},
			{Key: StepPreBackup, Name: "变更前自动备份", Command: preCmd},
			{Key: StepRestore, Name: "解压恢复", Command: restoreCmd},
			{Key: StepChown, Name: "修正属主", Command: chownCmd},
			{Key: StepStart, Name: "启动应用", Command: startCmd},
		},
		HealthEnabled: healthOn,
		HealthCommand: healthCmd,
	}, nil
}

// Text 计划文案（dry-run 与执行前展示；每步都打印将执行的完整命令）。
func (p *RestorePlan) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "恢复计划：应用 %s @%s\n", p.App, p.Host)
	fmt.Fprintf(&b, "  备份包    : %s\n", p.Package)
	fmt.Fprintf(&b, "  目标目录  : %s\n", p.WebPath)
	fmt.Fprintf(&b, "  变更前备份: %s\n", p.PreBackup)
	b.WriteString("  步骤:\n")
	for i, s := range p.Steps {
		fmt.Fprintf(&b, "    %d. %s: %s\n", i+1, s.Name, s.Command)
	}
	if p.HealthEnabled {
		fmt.Fprintf(&b, "    %d. 健康检查: %s\n", len(p.Steps)+1, p.HealthCommand)
	} else {
		fmt.Fprintf(&b, "    %d. 健康检查: 未配置 check_uri 与服务端口（或 health_mode=none），跳过\n", len(p.Steps)+1)
	}
	return b.String()
}
