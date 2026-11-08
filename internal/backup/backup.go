// Package backup 实现「备份运维」：现场留包（应用目录 / 支持软件数据目录 / MySQL 逻辑备份）、
// 完整性校验、保留期清理与台账导出。
//
// 设计口径（与统一运维工具规划一致）：
//   - 备份产物只留现场（默认 /egova/backup），不自动拉回中心；
//   - 工具负责执行、校验、保留期清理、台账导出，台账再交给上层推送项目管理；
//   - 口令不进配置、不进命令行：MySQL 凭据由现场文件（--defaults-extra-file / 默认读取）持有。
//
// 安全口径：远端命令由本包统一构建，凡进入命令的值都经过 quote() 强引用与白名单校验；
// 文件名统一 eops- 前缀，prune 只处理本工具产物，绝不误删现场其他文件。
package backup

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
)

// Kind 备份目标类别。
type Kind string

const (
	KindApp   Kind = "app"   // 应用部署目录打包
	KindDir   Kind = "dir"   // 支持软件指定目录打包
	KindMySQL Kind = "mysql" // mysqldump 逻辑备份
	KindDM    Kind = "dm"    // 达梦 dexp 逻辑备份
)

// Target 一个备份目标（应用单主机 / 支持软件单主机单路径 / 数据库单主机）。
type Target struct {
	Kind    Kind
	Name    string // 显示名（应用名 / 支持软件名）
	Host    config.Host
	Path    string   // app/dir：源绝对路径；mysql：空
	Bases   []string // mysql：库名列表；dm：单元素模式名
	Exclude []string // app/dir：相对 Path 的排除通配（不含 basename 前缀，构建时补）
	Slug    string   // 文件名中的稳定标识（应用名/支持软件名+目录名）
}

// baseExcludes 任何目录打包都不带的东西：日志与更新期备份目录。
var baseExcludes = []string{"logs/*", "log/*", "backups/*", "*.log"}

// Targets 从配置展开全部备份目标。
//   - webs：每个应用在每个主机群组各一个目录目标（web_path）；
//   - supports：BackupPaths 逐路径展开（redis 的 dump.rdb、nginx 的 conf 等）；
//   - mysql：配了 backup.databases 时，在 mysql 支持软件主机的每个主机上各一个库目标；
//   - dm：配了 backup.dm_schema 时，在达梦支持软件主机的每个主机上各一个模式目标。
func Targets(c *config.Config) []Target {
	var out []Target
	seen := map[string]bool{} // 同主机同路径只备一次（应用跨群组常见）

	for i := range c.Webs {
		app := &c.Webs[i]
		ex := append([]string{}, app.ExcludePaths...)
		if c.Backup != nil {
			ex = append(ex, c.Backup.Exclude...)
		}
		ex = append(ex, baseExcludes...)
		if ld := strings.TrimSpace(app.LogDir); ld != "" {
			ex = append(ex, strings.Trim(ld, "/")+"/*")
		}
		for _, group := range []string{config.GroupMaster, config.GroupUpdate, config.GroupStatic} {
			for _, h := range app.GroupHosts(group) {
				if h.Host == "" || strings.TrimSpace(h.WebPath) == "" {
					continue
				}
				key := h.Host + "\x00" + h.WebPath
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, Target{
					Kind: KindApp, Name: app.Web, Host: h,
					Path: h.WebPath, Exclude: dedup(ex), Slug: app.Web,
				})
			}
		}
	}

	for i := range c.Supports {
		s := &c.Supports[i]
		name := s.Name
		if name == "" {
			name = s.Kind
		}
		for _, h := range s.Hosts {
			if h.Host == "" {
				continue
			}
			for _, p := range s.BackupPaths {
				p = strings.TrimRight(strings.TrimSpace(p), "/")
				if p == "" {
					continue
				}
				key := h.Host + "\x00" + p
				if seen[key] {
					continue
				}
				seen[key] = true
				slug := slugFor(name, s.Kind)
				if b := path.Base(p); b != "" && b != "/" && b != "." {
					slug = slug + "-" + b
				}
				out = append(out, Target{
					Kind: KindDir, Name: name, Host: h,
					Path: p, Slug: slug,
				})
			}
		}
	}

	if c.Backup != nil && len(c.Backup.Databases) > 0 {
		for i := range c.Supports {
			s := &c.Supports[i]
			if s.Kind != "mysql" {
				continue
			}
			name := s.Name
			if name == "" {
				name = "mysql"
			}
			for _, h := range s.Hosts {
				if h.Host == "" {
					continue
				}
				key := h.Host + "\x00mysql"
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, Target{
					Kind: KindMySQL, Name: name, Host: h,
					Bases: append([]string{}, c.Backup.Databases...),
					Slug:  slugFor(name, "mysql"),
				})
			}
		}
	}

	// dm：配了 backup.dm_schema 时，在达梦支持软件主机的每个主机上各一个模式目标
	if c.Backup != nil && c.Backup.DMSchema != "" {
		for i := range c.Supports {
			s := &c.Supports[i]
			if s.Kind != "dm" {
				continue
			}
			name := s.Name
			if name == "" {
				name = "dm"
			}
			for _, h := range s.Hosts {
				if h.Host == "" {
					continue
				}
				key := h.Host + "\x00dm"
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, Target{
					Kind: KindDM, Name: name, Host: h,
					Bases: []string{c.Backup.DMSchema},
					Slug:  slugFor(name, "dm"),
				})
			}
		}
	}
	return out
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// Slugify 把名称变成文件名安全片段：只留字母数字._-，其余替换为 -。
// 全部为非 ASCII（如纯中文名）时返回空串，由调用方用 slugFor 回落。
func Slugify(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-.")
}

// slugFor 文件名片段：name 无法产出 ASCII 片段时回落 fallback，再回落 target。
func slugFor(name, fallback string) string {
	if s := Slugify(name); s != "" {
		return s
	}
	if s := Slugify(fallback); s != "" {
		return s
	}
	return "target"
}

// DayDir 备份落盘的日期子目录。
func DayDir(root string, now time.Time) string {
	return strings.TrimRight(root, "/") + "/" + now.Format("2006-01-02")
}

// TargetPrefix 文件名前缀：eops-<slug>-<host>-。
// 台账反查与 prune 白名单都用它，保证「生成的名字」与「识别的名字」同源。
func TargetPrefix(t Target) string {
	return config.BackupFilePrefix + slugFor(t.Slug, string(t.Kind)) + "-" + slugFor(t.Host.Host, "host") + "-"
}

// ArchiveName 单次备份的文件名：eops-<slug>-<host>-<HHMMSS>.tar.gz|.sql.gz。
// 带时分秒避免同日多次执行互相覆盖。
func ArchiveName(t Target, now time.Time) string {
	ext := ".tar.gz"
	switch t.Kind {
	case KindMySQL:
		ext = ".sql.gz"
	case KindDM:
		ext = ".dmp.gz"
	}
	return TargetPrefix(t) + now.Format("150405") + ext
}

// ArchivePath 备份文件绝对路径。
func ArchivePath(root string, t Target, now time.Time) string {
	return DayDir(root, now) + "/" + ArchiveName(t, now)
}

// quote 单引号强引用 + 控制字符拒绝。所有进入远端命令的值都必须过这里。
func quote(s string) (string, error) {
	if strings.ContainsAny(s, "\x00\n\r") {
		return "", fmt.Errorf("值含控制字符，拒绝执行: %q", s)
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'", nil
}

// pathOK 远端路径白名单：绝对路径、无 shell 元字符、无 .. 段。
func pathOK(p string) bool {
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

// TarCommand 构建目录打包命令：先写 .part 再原子 mv，产出 sha256 与字节数。
// 输出行格式：<sha256>  <path>\n<bytes>
func TarCommand(dest, src string, excludes []string) (string, error) {
	if !pathOK(dest) {
		return "", fmt.Errorf("备份目标路径非法: %q", dest)
	}
	if !pathOK(strings.TrimRight(src, "/")) {
		return "", fmt.Errorf("源路径非法: %q", src)
	}
	src = strings.TrimRight(src, "/")
	parent := path.Dir(src)
	base := path.Base(src)
	if parent == "." || base == "" || base == "/" {
		return "", fmt.Errorf("源路径必须是具体目录: %q", src)
	}
	dirQ, err := quote(path.Dir(dest))
	if err != nil {
		return "", err
	}
	destQ, err := quote(dest)
	if err != nil {
		return "", err
	}
	partQ, err := quote(dest + ".part")
	if err != nil {
		return "", err
	}
	parentQ, err := quote(parent)
	if err != nil {
		return "", err
	}
	baseQ, err := quote(base)
	if err != nil {
		return "", err
	}
	var opts []string
	for _, ex := range excludes {
		ex = strings.TrimSpace(ex)
		if ex == "" {
			continue
		}
		pat, err := quote(base + "/" + strings.TrimPrefix(ex, "/"))
		if err != nil {
			return "", err
		}
		opts = append(opts, "--exclude="+pat)
	}
	return fmt.Sprintf(
		"set -o pipefail; mkdir -p %s && tar czf %s -C %s %s %s && mv -f %s %s && sha256sum %s && stat -c %%s %s",
		dirQ, partQ, parentQ, strings.Join(opts, " "), baseQ,
		partQ, destQ, destQ, destQ,
	), nil
}

// DumpCommand 构建 mysqldump 命令（库级逻辑备份，单事务一致性快照）。
// 口令不进命令：凭据来自 defaultsFile（--defaults-extra-file）或 mysqldump 默认读取。
func DumpCommand(dest string, dbs []string, user, defaultsFile string) (string, error) {
	if !pathOK(dest) {
		return "", fmt.Errorf("备份目标路径非法: %q", dest)
	}
	if len(dbs) == 0 {
		return "", fmt.Errorf("库名为空")
	}
	if !sqlIdentOK(user) {
		return "", fmt.Errorf("mysqldump 用户非法: %q", user)
	}
	userQ, err := quote(user)
	if err != nil {
		return "", err
	}
	var credOpt string
	if defaultsFile != "" {
		if !pathOK(defaultsFile) {
			return "", fmt.Errorf("凭据文件路径非法: %q", defaultsFile)
		}
		fQ, err := quote(defaultsFile)
		if err != nil {
			return "", err
		}
		credOpt = " --defaults-extra-file=" + fQ
	}
	var dbArgs []string
	for _, db := range dbs {
		if !sqlIdentOK(db) {
			return "", fmt.Errorf("库名非法: %q", db)
		}
		q, err := quote(db)
		if err != nil {
			return "", err
		}
		dbArgs = append(dbArgs, q)
	}
	dirQ, err := quote(path.Dir(dest))
	if err != nil {
		return "", err
	}
	destQ, err := quote(dest)
	if err != nil {
		return "", err
	}
	partQ, err := quote(dest + ".part")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"set -o pipefail; mkdir -p %s && mysqldump --single-transaction --quick --routines --triggers --events "+
			"--default-character-set=utf8mb4%s -u %s --databases %s | gzip -1 > %s && mv -f %s %s && sha256sum %s && stat -c %%s %s",
		dirQ, credOpt, userQ, strings.Join(dbArgs, " "), partQ,
		partQ, destQ, destQ, destQ,
	), nil
}

// DMCommand 构建达梦 dexp 命令（SCHEMAS 级逻辑备份，产物 gzip 压缩）。
// 口令不进命令行：凭据从现场文件（credFile，内容一行 USER/密码@host:port）读入
// 临时 PARFILE（umask 077，执行完即删），ps 与历史都看不到口令。
// 成功判定用 rc 与产物双重校验：dexp 个别错误 rc=0，必须看 .dmp 非空。
func DMCommand(dest, schema, credFile string) (string, error) {
	if !pathOK(dest) {
		return "", fmt.Errorf("备份目标路径非法: %q", dest)
	}
	if !sqlIdentOK(schema) {
		return "", fmt.Errorf("达梦模式名非法: %q", schema)
	}
	if !pathOK(credFile) {
		return "", fmt.Errorf("凭据文件路径非法: %q", credFile)
	}
	dirQ, err := quote(path.Dir(dest))
	if err != nil {
		return "", err
	}
	base := path.Base(dest) // eops-<slug>-<host>-150405.dmp.gz
	dmp := strings.TrimSuffix(base, ".gz")
	logName := strings.TrimSuffix(base, ".dmp.gz") + ".log"
	partQ, err := quote(dest + ".par")
	if err != nil {
		return "", err
	}
	credQ, err := quote(credFile)
	if err != nil {
		return "", err
	}
	dmpQ, err := quote(dmp)
	if err != nil {
		return "", err
	}
	destQ, err := quote(dest)
	if err != nil {
		return "", err
	}
	// dexp 产物落 DIRECTORY（已 cd 进该目录，FILE 用相对名）；成功后 gzip -1 得最终 .dmp.gz。
	// printf 的 %s 参数不经过 shell 二次解释，PARFILE 内的值用原始名（不带 shell 引号）；
	// schema 已过 sqlIdentOK 白名单，dmp/log/dir 为本工具自构文件名，$cred 为运行时变量。
	return fmt.Sprintf(
		"set -o pipefail; mkdir -p %s && cd %s && umask 077 && "+
			"cred=$(cat %s) || exit 2; "+
			"printf 'FILE=%s\\nLOG=%s\\nSCHEMAS=%s\\nDIRECTORY=%s\\nUSERID=%s\\n' > %s && "+
			"dexp PARFILE=%s >/dev/null 2>&1; rc=$?; rm -f %s; "+
			"if [ $rc -ne 0 ] || [ ! -s %s ]; then echo 达梦导出失败 rc=$rc >&2; exit ${rc:-1}; fi; "+
			"gzip -1 -f %s && sha256sum %s && stat -c %%s %s",
		dirQ, dirQ, credQ,
		dmp, logName, schema, path.Dir(dest), "$cred",
		partQ, partQ, partQ, dmpQ, dmpQ, destQ, destQ,
	), nil
}

// sqlIdentOK 库名/用户名白名单（与 config 校验口径一致）。
func sqlIdentOK(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '$' || r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

// VerifyCommand 校验命令：gzip 完整性 → tar 可枚举（仅 .tar.gz）→ sha256 → 字节数。
func VerifyCommand(file string) (string, error) {
	if !pathOK(file) {
		return "", fmt.Errorf("备份文件路径非法: %q", file)
	}
	fQ, err := quote(file)
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(file, ".tar.gz") {
		return fmt.Sprintf("gzip -t %s && tar -tzf %s >/dev/null && sha256sum %s && stat -c %%s %s",
			fQ, fQ, fQ, fQ), nil
	}
	return fmt.Sprintf("gzip -t %s && sha256sum %s && stat -c %%s %s", fQ, fQ, fQ), nil
}

// VerifyResult 单个备份文件的校验结果。
type VerifyResult struct {
	File   string
	SHA256 string
	Bytes  int64
	OK     bool
	Err    string
}

// ParseVerify 解析 VerifyCommand 输出（sha256sum 行 + stat 行）。
func ParseVerify(file, out string) VerifyResult {
	res := VerifyResult{File: file}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if i := strings.IndexByte(ln, ' '); i == 64 && isHex(ln[:64]) {
			res.SHA256 = ln[:64]
			continue
		}
		if n, err := parseInt(ln); err == nil {
			res.Bytes = n
		}
	}
	res.OK = res.SHA256 != "" && res.Bytes > 0
	if !res.OK {
		res.Err = "输出缺少 sha256 或大小为 0: " + strings.TrimSpace(out)
	}
	return res
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func parseInt(s string) (int64, error) {
	var n int64
	if s == "" {
		return 0, fmt.Errorf("空值")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("非数字: %q", s)
		}
		n = n*10 + int64(r-'0')
	}
	return n, nil
}

// ListCommand 列出本工具产物（eops- 前缀），字段：mtime|size|path。
func ListCommand(root string) (string, error) {
	if !pathOK(strings.TrimRight(root, "/")) {
		return "", fmt.Errorf("备份根目录非法: %q", root)
	}
	rQ, err := quote(strings.TrimRight(root, "/"))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"find %s -type f \\( -name '%star.gz' -o -name '%ssql.gz' \\) -printf '%%T@|%%s|%%p\\n' 2>/dev/null | sort",
		rQ, config.BackupFilePrefix, config.BackupFilePrefix), nil
}

// PruneListCommand 列出超过保留期的本工具产物（只列不删，删除由 Go 侧逐条执行）。
func PruneListCommand(root string, keepDays int) (string, error) {
	if !pathOK(strings.TrimRight(root, "/")) {
		return "", fmt.Errorf("备份根目录非法: %q", root)
	}
	if keepDays < 1 {
		keepDays = config.BackupKeepDaysDefault
	}
	rQ, err := quote(strings.TrimRight(root, "/"))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"find %s -type f \\( -name '%star.gz' -o -name '%ssql.gz' \\) -mtime +%d -print 2>/dev/null | sort",
		rQ, config.BackupFilePrefix, config.BackupFilePrefix, keepDays), nil
}

// RegisterBackupDirCommand 把备份根目录幂等登记进 zabbix agent 的备份目录监控清单
// （/etc/zabbix/zabbix_agentd.d/backup_dirs.txt，见 FAQ wiki《通过 zabbix监控备份目录》）。
// agent 未安装（目录不存在）时静默跳过，不制造多余文件。
func RegisterBackupDirCommand(root string) (string, error) {
	r := strings.TrimRight(root, "/")
	if !pathOK(r) {
		return "", fmt.Errorf("备份根目录非法: %q", root)
	}
	rQ, err := quote(r)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"d=/etc/zabbix/zabbix_agentd.d; if [ -d \"$d\" ]; then f=\"$d/backup_dirs.txt\"; touch \"$f\"; "+
			"grep -qxF %s \"$f\" 2>/dev/null || echo %s >> \"$f\"; echo REGISTERED; else echo NO_AGENT; fi",
		rQ, rQ), nil
}

// ParseRegisterResult 解析登记命令输出（REGISTERED=已登记，其余视为 agent 未装）。
func ParseRegisterResult(out string) bool {
	return strings.Contains(out, "REGISTERED")
}

// StoredFile 现场已有的一份备份。
type StoredFile struct {
	Path    string
	Bytes   int64
	ModTime time.Time
}

// ParseList 解析 ListCommand 输出。
func ParseList(out string) []StoredFile {
	var files []StoredFile
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		parts := strings.SplitN(ln, "|", 3)
		if len(parts) != 3 {
			continue
		}
		sec, err := parseFloat(parts[0])
		if err != nil {
			continue
		}
		size, err := parseInt(parts[1])
		if err != nil {
			continue
		}
		files = append(files, StoredFile{
			Path:    parts[2],
			Bytes:   size,
			ModTime: time.Unix(int64(sec), 0),
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}

// ParseLines 解析纯路径清单（PruneListCommand 输出）。
func ParseLines(out string) []string {
	var paths []string
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		if ln = strings.TrimSpace(ln); ln != "" && strings.HasPrefix(ln, "/") {
			paths = append(paths, ln)
		}
	}
	sort.Strings(paths)
	return paths
}

// RemoveCommand 删除一个备份文件（路径必须过白名单，且必须是本工具产物命名）。
func RemoveCommand(file string) (string, error) {
	if !pathOK(file) {
		return "", fmt.Errorf("备份文件路径非法: %q", file)
	}
	base := path.Base(file)
	if !strings.HasPrefix(base, config.BackupFilePrefix) || !(strings.HasSuffix(base, ".tar.gz") || strings.HasSuffix(base, ".sql.gz")) {
		return "", fmt.Errorf("拒绝删除非本工具产物: %q", file)
	}
	fQ, err := quote(file)
	if err != nil {
		return "", err
	}
	return "rm -f " + fQ, nil
}

func parseFloat(s string) (float64, error) {
	var whole, frac int64
	var seenDot bool
	var div float64 = 1
	if s == "" {
		return 0, fmt.Errorf("空值")
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			if seenDot {
				frac = frac*10 + int64(r-'0')
				div *= 10
			} else {
				whole = whole*10 + int64(r-'0')
			}
		case r == '.' && !seenDot:
			seenDot = true
		default:
			return 0, fmt.Errorf("非数字: %q", s)
		}
	}
	return float64(whole) + float64(frac)/div, nil
}
