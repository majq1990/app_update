// Package depsec 三方依赖安全检查（只读）。
//
// 资产（扫描脚本、版本判定脚本、安全版本清单）随二进制内嵌，运行时不依赖现场已有文件。
// 口径与 oneinstall_v2 安全工具箱一致：
//   - 中间件/独立软件：可联网升级，无外网用清单内中国大陆地址
//   - 代码内 jar：只登记问题，要求提单由研发更新（工具不下载、不替换）
//   - 全部为只读操作：脚本只做 find/unzip -l/--version/ps 等读取，只写报告文件
package depsec

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed assets/*
var assets embed.FS

// RemoteDir 远端工作目录（存放脚本与清单，报告也落这里）。
const RemoteDir = "/tmp/eops_depsec"

// Asset 一个内嵌资产。
type Asset struct {
	Name string // 目标文件名
	Dir  string // 内嵌子路径
	Mode os.FileMode
}

// Assets 需要下发到远端的文件清单。
var Assets = []Asset{
	{Name: "scan_secure_deps.sh", Dir: "assets/scan_secure_deps.sh", Mode: 0o755},
	{Name: "query_secure_version.sh", Dir: "assets/query_secure_version.sh", Mode: 0o755},
	{Name: "fetch_secure_artifact.sh", Dir: "assets/fetch_secure_artifact.sh", Mode: 0o755},
	{Name: "conf/secure-versions.flat", Dir: "assets/secure-versions.flat", Mode: 0o644},
}

// Read 读取内嵌资产内容。
func Read(path string) ([]byte, error) {
	return assets.ReadFile(path)
}

// Materialize 把资产写到本地目录，返回用到的文件路径（供 sshx.Upload 使用）。
func Materialize(dir string) (map[string]string, error) {
	out := map[string]string{}
	for _, a := range Assets {
		b, err := Read(a.Dir)
		if err != nil {
			return nil, fmt.Errorf("读取内嵌资产 %s: %w", a.Dir, err)
		}
		p := filepath.Join(dir, filepath.FromSlash(a.Name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, b, a.Mode); err != nil {
			return nil, err
		}
		out[a.Name] = p
	}
	return out, nil
}

// Summary 解析报告结论行。
type Summary struct {
	High   int // 高危/需处理
	Review int // 待复核
	OK     int // 正常
	Raw    string
}

var summaryRe = regexp.MustCompile(`结论：高危/需处理 \*\*(\d+)\*\* 项，待复核 (\d+) 项，正常 (\d+) 项`)

// ParseSummary 从报告正文里取结论统计。
func ParseSummary(report string) Summary {
	m := summaryRe.FindStringSubmatch(report)
	s := Summary{}
	if len(m) == 4 {
		fmt.Sscanf(m[1], "%d", &s.High)
		fmt.Sscanf(m[2], "%d", &s.Review)
		fmt.Sscanf(m[3], "%d", &s.OK)
	}
	for _, ln := range strings.Split(report, "\n") {
		if strings.HasPrefix(ln, "- 结论：") {
			s.Raw = strings.TrimSpace(ln)
			break
		}
	}
	return s
}

// FlatCount 安全版本清单条目数（去掉注释与空行）。
func FlatCount() int {
	b, err := Read("assets/secure-versions.flat")
	if err != nil {
		return 0
	}
	n := 0
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) != "" && !strings.HasPrefix(ln, "#") {
			n++
		}
	}
	return n
}

// RCMarker 包装命令时输出的退出码标记（SSH 对非零退出返回 error，需显式区分）。
const RCMarker = "__EOPS_DEP_SEC_RC__="

// Wrap 把命令包成恒定退出 0，并把真实退出码打到标记行。
// 脚本语义：0=无高危、1=有需处理、2=清单缺失、5=jar 拒绝下载，都属正常结论。
func Wrap(cmd string) string {
	return fmt.Sprintf("set +e; { %s; }; __rc=$?; echo \"%s$__rc\"; exit 0", cmd, RCMarker)
}

// SplitRC 从输出中剥离标记行，返回正文与真实退出码。
func SplitRC(out string) (string, int, bool) {
	rc := 0
	found := false
	var keep []string
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, RCMarker) {
			fmt.Sscanf(strings.TrimPrefix(ln, RCMarker), "%d", &rc)
			found = true
			continue
		}
		keep = append(keep, ln)
	}
	return strings.Join(keep, "\n"), rc, found
}

// ScanCommand 生成远端只读扫描命令（报告落 RemoteDir）。
func ScanCommand(extraDirs string, embedded bool) string {
	args := "local --out " + RemoteDir
	if extraDirs != "" {
		args += " --dirs " + shellQuote(extraDirs)
	}
	if !embedded {
		args += " --no-embedded"
	}
	return fmt.Sprintf("cd %s && bash scan_secure_deps.sh %s", RemoteDir, args)
}

// QueryCommand 生成单组件判定命令。
func QueryCommand(target string) string {
	return fmt.Sprintf("cd %s && bash query_secure_version.sh %s", RemoteDir, shellQuote(target))
}

// FetchCommand 生成地址查询/取件命令（download=false 时只打印地址）。
func FetchCommand(target string, download bool) string {
	if download {
		return fmt.Sprintf("cd %s && bash fetch_secure_artifact.sh %s --download %s/artifacts",
			RemoteDir, shellQuote(target), RemoteDir)
	}
	return fmt.Sprintf("cd %s && bash fetch_secure_artifact.sh %s", RemoteDir, shellQuote(target))
}

// shellQuote 单引号包裹，内部单引号转义。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
