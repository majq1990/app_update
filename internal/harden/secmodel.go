package harden

// secmodel.go —— oneinstall_v2 安全工具箱（2026-11-12 改造）对齐的核心模型。
//
// 范围：只做「非代码类」修复与拦截；SQL 注入/XSS/越权逻辑/上传校验/加解密改造
// 与组件升级不在本包范围（对应清单「三、设计约定 6」）。
//
// 与清单约定的对齐：
//   - 双模式：check（只读体检）/ fix（写修复，一律 dry-run 默认、--yes 才执行）；
//   - 报告：四级（critical/high/medium/low/info）+ findings.tsv 等价导出；
//   - 备份：修改前逐文件备份，记录 manifest；nginx/tomcat 支持回滚；
//   - 校验后生效：nginx -t / sshd -t / xmllint 失败自动还原；
//   - 红线：无密钥不改 SSH 登录方式；数据库只读；拦截链可整链回退。

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// SecLevel 安全等级（与 harden_lib.sh 的 高危/中危/低危/信息 对齐）。
type SecLevel string

const (
	SecCritical SecLevel = "critical" // 高危
	SecHigh     SecLevel = "high"     // 高危（介于 critical 与 medium 的实现细分，展示归高危）
	SecMedium   SecLevel = "medium"   // 中危
	SecLow      SecLevel = "low"      // 低危
	SecInfo     SecLevel = "info"     // 信息
)

// rankSec 等级排序。
func rankSec(l SecLevel) int {
	switch l {
	case SecCritical:
		return 4
	case SecHigh:
		return 3
	case SecMedium:
		return 2
	case SecLow:
		return 1
	default:
		return 0
	}
}

// SecLabel 中文等级（与 oneinstall 输出口径一致）。
func SecLabel(l SecLevel) string {
	switch l {
	case SecCritical, SecHigh:
		return "高危"
	case SecMedium:
		return "中危"
	case SecLow:
		return "低危"
	default:
		return "信息"
	}
}

// SecFinding 一次安全体检的单条结论。
type SecFinding struct {
	Host     string   `json:"host"`
	Category string   `json:"category"` // 分类（账号口令/未授权访问/Nginx/Tomcat/数据库/容器/拦截…）
	Item     string   `json:"item"`     // 检查项
	Result   string   `json:"result"`   // 结果描述
	Evidence string   `json:"evidence"` // 证据（路径/值，最多几条）
	Level    SecLevel `json:"level"`    // 等级
	Advice   string   `json:"advice"`   // 整改建议
	Fixable  string   `json:"fixable"`  // yes=fix 可自动 / no=人工 / sql=进 remediation.sql
}

// SecReport 一次安全任务的完整报告（findings.tsv + report.md 等价物）。
type SecReport struct {
	Tool        string         `json:"tool"` // exposure|nginx|tomcat|os|network|db|appconfig
	GeneratedAt string         `json:"generated_at"`
	Hosts       []string       `json:"hosts"`
	Findings    []SecFinding   `json:"findings"`
	Summary     map[string]int `json:"summary"`               // level → count
	Backups     []string       `json:"backups,omitempty"`     // 修改类任务产生的备份路径
	Remediation string         `json:"remediation,omitempty"` // DB 任务生成的整改 SQL

	errorList []string // 执行错误（不序列化，终端展示用）
}

// NewSecReport 构造空报告。
func NewSecReport(tool string, hosts []string, now time.Time) *SecReport {
	return &SecReport{
		Tool:        tool,
		GeneratedAt: now.Format(time.RFC3339),
		Hosts:       hosts,
		Findings:    make([]SecFinding, 0, 32),
		Summary:     map[string]int{},
	}
}

// Add 记录一条发现并累加计数。
func (r *SecReport) Add(f SecFinding) {
	r.Findings = append(r.Findings, f)
	r.Summary[string(f.Level)]++
}

// SortFindings 按等级降序、分类+条目稳定排序。
func (r *SecReport) SortFindings() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if rankSec(a.Level) != rankSec(b.Level) {
			return rankSec(a.Level) > rankSec(b.Level)
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Item < b.Item
	})
}

// TSV findings.tsv 等价输出（level\tcategory\titem\tresult\tevidence\tadvice\tfixable）。
func (r *SecReport) TSV() string {
	var b strings.Builder
	b.WriteString("level\tcategory\titem\tresult\tevidence\tadvice\tfixable\n")
	for _, f := range r.Findings {
		b.WriteString(SecLabel(f.Level) + "\t" +
			cleanTSV(f.Category) + "\t" + cleanTSV(f.Item) + "\t" +
			cleanTSV(f.Result) + "\t" + cleanTSV(f.Evidence) + "\t" +
			cleanTSV(f.Advice) + "\t" + f.Fixable + "\n")
	}
	return b.String()
}

func cleanTSV(s string) string {
	s = strings.ReplaceAll(s, "\t", "  ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// CountBy 统计某分类的各级数量（报告文案用）。
func (r *SecReport) CountBy(category string) (critical, medium, low int) {
	for _, f := range r.Findings {
		if category != "all" && f.Category != category {
			continue
		}
		switch f.Level {
		case SecCritical, SecHigh:
			critical++
		case SecMedium:
			medium++
		case SecLow:
			low++
		}
	}
	return
}

// HasBlocking 判断是否存在需要立即处置的高危项。
func (r *SecReport) HasBlocking() bool {
	for _, f := range r.Findings {
		if f.Level == SecCritical || f.Level == SecHigh {
			return true
		}
	}
	return false
}

// GapRow 对照表一行（harden sec gap 输出）。
type GapRow struct {
	Tool       string `json:"tool"`       // oneinstall 工具
	Capability string `json:"capability"` // 能力
	Status     string `json:"status"`     // covered / partial / missing / missing→covered
	Note       string `json:"note"`       // eops 实现位置/入口
}

// GapTable 返回与清单「四、1」对应的差距表（代码内单一事实源）。
func GapTable() []GapRow {
	return []GapRow{
		{Tool: "enhance_port/expose_port", Capability: "高危端口限源（iptables+ipset）", Status: "partial", Note: "harden network guard fix（EGOVA-SEC-GUARD 链，实现⑥④合并覆盖高危端口部分）"},
		{Tool: "scan_exposure(端口/暴露面部分)", Capability: "监听采集+高危字典比对", Status: "partial", Note: "inspect ports-exposure（0.0.0.0 监听比对内置 9 项字典）；eops harden exposure check 扩到 29 项全字典"},
		{Tool: "scan_exposure(未授权探测)", Capability: "Redis/ES/Nacos/ZK/Docker/MinIO/manager/Actuator/Swagger", Status: "missing→covered", Note: "eops harden exposure check（sec_exposure.go，回环主动探测）"},
		{Tool: "add_security_agent", Capability: "内置超级用户登录禁用", Status: "partial", Note: "inspect 无此项；harden appconfig check 检 egova.security.agent 开关（fix 属代码/平台配置，只提示）"},
		{Tool: "scan_egova_service", Capability: "违禁服务/WAF/加固状态扫描", Status: "partial", Note: "inspect ac-security-port（auto-check 资产）+ nginx/tomcat 基线覆盖大部分；fscan 网段扫描不做（侵入性）"},
		{Tool: "scan_weak_password", Capability: "数据库人员弱口令扫描", Status: "missing", Note: "延后：依赖 DB 凭据方案（与 admin-users 同批）"},
		{Tool: "scan_vulnerable_jar", Capability: "高危 jar 扫描", Status: "covered", Note: "inspect ac-vulnerable-jar（auto-check 资产，按应用目录）"},
		{Tool: "check_safe_config", Capability: "产品安全配置开关体检", Status: "covered", Note: "eops harden appconfig check/fix（sec_appconfig.go，8 类规则对齐 scan_re 全集）"},
		{Tool: "enhance_middleware", Capability: "东方通/金蝶中间件加固", Status: "missing", Note: "延后：现场无东方通/金蝶环境；检测点已并入 tomcat 基线（9060/6888/6900 提示）"},
		{Tool: "cn_whitelist", Capability: "中国 IP 白名单", Status: "missing", Note: "延后：境外拦截属网络策略决策，需用户拍板白名单口径（可用 network guard 的 ipset 机制承载）"},
		{Tool: "fastjson", Capability: "fastjson 扫描/启动配置", Status: "partial", Note: "inspect ac-vulnerable-jar 覆盖检测；启动配置处理延后到 harden apply（改启动参数需重启）"},
		{Tool: "harden_nginx(新增)", Capability: "nginx 基线 check/fix/rollback", Status: "missing→covered", Note: "eops harden nginx check|fix|rollback（sec_nginx.go）"},
		{Tool: "harden_tomcat(新增)", Capability: "tomcat 基线 check/fix/rollback", Status: "missing→covered", Note: "eops harden tomcat check|fix|rollback（sec_tomcat.go）"},
		{Tool: "harden_app_config(新增)", Capability: "应用配置体检+受限 apply", Status: "missing→covered", Note: "eops harden appconfig check|fix（sec_appconfig.go，--apply 仅写 Swagger/Actuator/错误页）"},
		{Tool: "harden_os_baseline(新增)", Capability: "系统基线 check/幂等 fix", Status: "partial→covered", Note: "eops harden os check|fix（sec_os.go；eops 原有 inspect ssh-policy/空口令/UID0 并入为子集）"},
		{Tool: "harden_network_guard(新增)", Capability: "docker 收敛/恶意IP封禁/cron", Status: "missing→covered", Note: "eops harden network docker|guard|ban|unban|status|install-cron（sec_network.go）"},
		{Tool: "harden_db_baseline(新增)", Capability: "DB 只读体检+remediation.sql", Status: "missing→covered", Note: "eops harden db check（sec_db.go，MySQL/达梦/金仓·瀚高；凭据走配置/现场输入，不落盘）"},
		{Tool: "harden_lib.sh", Capability: "统一报告/备份/探测", Status: "covered", Note: "SecReport/TSV/备份 manifest（secmodel.go+secfix.go）"},
	}
}

// Text 终端摘要（按主机分组、级别降序）。
func (r *SecReport) Text(w io.Writer) {
	fmt.Fprintf(w, "安全体检 %s（%s）\n", r.Tool, r.GeneratedAt)
	fmt.Fprintf(w, "主机 %d 台，检出 %d 项\n", len(r.Hosts), len(r.Findings))
	cur := ""
	for _, f := range r.Findings {
		if f.Host != cur {
			cur = f.Host
			fmt.Fprintf(w, "\n主机 %s：\n", cur)
		}
		fmt.Fprintf(w, "  %s %-14s %-22s %s\n", SecLabel(f.Level), "["+f.Category+"]", f.Item, f.Result)
		if f.Evidence != "" {
			fmt.Fprintf(w, "        证据：%s\n", f.Evidence)
		}
		fmt.Fprintf(w, "        建议：%s（%s）\n", f.Advice, fixHint(f.Fixable))
	}
	c, m, l := r.CountBy("all")
	fmt.Fprintf(w, "\n汇总：高危 %d / 中危 %d / 低危 %d；执行错误 %d\n", c, m, l, len(r.errorList))
	for _, e := range r.errorList {
		fmt.Fprintln(w, "  ⚠️", e)
	}
	if r.HasBlocking() {
		fmt.Fprintln(w, "❗存在高危项，建议尽快处置（可用 fix 的 dry-run 预览修复动作）")
	}
}

func fixHint(fixable string) string {
	switch fixable {
	case "yes":
		return "fix 可自动修复"
	case "sql":
		return "进 remediation.sql（DB 域）"
	default:
		return "需人工处理"
	}
}

// JSON åºååï¼ä¸¤ç©ºæ ¼ç¼©è¿ï¼ã
func (r *SecReport) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// SetErrors 记录执行错误（不进 JSON，终端展示用）。
func (r *SecReport) SetErrors(e []string) { r.errorList = e }

// Errors 返回执行错误。
func (r *SecReport) Errors() []string { return r.errorList }

// AddError 追加一条执行错误。
func (r *SecReport) AddError(err string) { r.errorList = append(r.errorList, err) }
