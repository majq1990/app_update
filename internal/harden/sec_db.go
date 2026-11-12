package harden

// sec_db.go —— 数据库安全基线只读体检（对齐 oneinstall harden_db_baseline.sh）。
//
// 支持 MySQL / 达梦 DM / 人大金仓 KingbaseES / 瀚高 HighGo。
// 只读：不执行任何 DDL/DML；整改 SQL 仅写入报告（remediation.sql），由人工核对执行。
//
// 凭据红线：
//   - 口令只从调用方（CLI 环境变量）传入，本包不打印、不落盘；
//   - 远端通过 0600 临时凭据文件（MySQL/PG）或 stdin（DM disql）传给客户端，
//     不出现在 ps 可见的命令行参数中，脚本结束 trap 删除。

import (
	"fmt"
	"strconv"
	"strings"
)

// DBOptions 数据库连接参数（Password 不参与 JSON 序列化，也不进日志）。
type DBOptions struct {
	Type     string `json:"type"` // mysql|dm|kingbase|highgo
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Name     string `json:"name,omitempty"`
	Password string `json:"-"`
}

// NormalizeDB 补默认值（端口按类型）。
func NormalizeDB(o DBOptions) DBOptions {
	o.Type = strings.ToLower(strings.TrimSpace(o.Type))
	if o.Host == "" {
		o.Host = "127.0.0.1"
	}
	if o.Port == "" {
		switch o.Type {
		case "mysql":
			o.Port = "3306"
		case "dm":
			o.Port = "5236"
		case "kingbase":
			o.Port = "54321"
		case "highgo":
			o.Port = "5866"
		}
	}
	if o.User == "" {
		switch o.Type {
		case "mysql":
			o.User = "root"
		case "dm":
			o.User = "SYSDBA"
		case "kingbase":
			o.User = "system"
		case "highgo":
			o.User = "highgo"
		}
	}
	return o
}

// ValidateDB 参数校验。
func ValidateDB(o DBOptions) error {
	switch o.Type {
	case "mysql", "dm", "kingbase", "highgo":
	default:
		return fmt.Errorf("不支持的数据库类型: %q（可选 mysql|dm|kingbase|highgo）", o.Type)
	}
	if o.Host == "" || o.User == "" || o.Port == "" {
		return fmt.Errorf("db host/port/user 不能为空")
	}
	if _, err := strconv.Atoi(o.Port); err != nil {
		return fmt.Errorf("db port 非数字: %q", o.Port)
	}
	return nil
}

// dbScript 生成远端只读体检脚本（按类型）。
func dbScript(o DBOptions) string {
	switch o.Type {
	case "mysql":
		return fmt.Sprintf(`set -u
umask 077
U=%s
PW=%s
command -v mysql >/dev/null 2>&1 || { echo "##NOCLIENT"; echo "##END"; exit 0; }
CNF=$(mktemp /tmp/.eops_db.XXXXXX) || exit 1
trap 'rm -f "$CNF"' EXIT
printf '[client]\nuser=%%s\npassword=%%s\n' "$U" "$PW" > "$CNF"
M="mysql --defaults-extra-file=$CNF -h %s -P %s -N -B --default-character-set=utf8"
echo "##VER"; $M -e "SELECT VERSION();" 2>/dev/null
echo "##USERS"; $M -e "SELECT user,host,plugin,IF(authentication_string IS NULL OR authentication_string='','EMPTY','SET') FROM mysql.user;" 2>/dev/null
echo "##LOCALINFILE"; $M -e "SELECT @@local_infile;" 2>/dev/null
echo "##SECUREFILE"; $M -e "SELECT IFNULL(@@secure_file_priv,'');" 2>/dev/null
echo "##GENERALLOG"; $M -e "SELECT @@general_log;" 2>/dev/null
echo "##SLOWLOG"; $M -e "SELECT @@slow_query_log;" 2>/dev/null
echo "##VALIDATEPWD"; $M -e "SELECT COUNT(*) FROM information_schema.plugins WHERE plugin_name LIKE 'validate_password%%' AND plugin_status='ACTIVE';" 2>/dev/null
echo "##END"
`, sq(o.User), sq(o.Password), sq(o.Host), sq(o.Port))

	case "dm":
		return fmt.Sprintf(`set -u
umask 077
U=%s
PW=%s
H=%s
PT=%s
command -v disql >/dev/null 2>&1 || { echo "##NOCLIENT"; echo "##END"; exit 0; }
runq() { printf 'conn %%s/%%s@%%s:%%s\n%%s\nexit\n' "$U" "$PW" "$H" "$PT" "$1" | disql -S 2>/dev/null; }
echo "##VER"; runq "select banner from v\$version;"
echo "##USERS"; runq "select username from dba_users where account_status='OPEN';"
echo "##PWDPOLICY"; runq "select para_value from v\$dm_ini where para_name='PWD_POLICY';"
echo "##AUDIT"; runq "select para_value from v\$dm_ini where para_name='ENABLE_AUDIT';"
echo "##END"
`, sq(o.User), sq(o.Password), sq(o.Host), sq(o.Port))

	default: // kingbase / highgo
		return fmt.Sprintf(`set -u
umask 077
U=%s
PW=%s
DB=%s
PG=""
for c in psql ksql; do command -v "$c" >/dev/null 2>&1 && { PG="$c"; break; }; done
[ -n "$PG" ] || { echo "##NOCLIENT"; echo "##END"; exit 0; }
PF=$(mktemp /tmp/.eops_pg.XXXXXX) || exit 1
trap 'rm -f "$PF"' EXIT
printf '%%s:%%s:%%s:%%s:%%s\n' %s %s %s "$U" "$PW" > "$PF"
chmod 600 "$PF"
export PGPASSFILE="$PF"
Q="$PG -h %s -p %s -U %s -d $DB -w -A -t -F |"
echo "##VER"; $Q -c "select version();" 2>/dev/null
echo "##ROLES"; $Q -c "select rolname,rolcanlogin,rolsuper from pg_roles;" 2>/dev/null
echo "##PWENC"; $Q -c "show password_encryption;" 2>/dev/null
echo "##LOGCONN"; $Q -c "show log_connections;" 2>/dev/null
echo "##LOGSTMT"; $Q -c "show log_statement;" 2>/dev/null
echo "##HBA"
for f in $(find / -maxdepth 5 -name pg_hba.conf -type f 2>/dev/null | head -3); do
  grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -E '[[:space:]]trust[[:space:]]*$' | head -3 | sed "s#^#$f: #"
done
echo "##END"
`, sq(o.User), sq(o.Password), sq(derefOr(o.Name, "postgres")),
			sq(o.Host), sq(o.Port), sq(o.Name),
			sq(o.Host), sq(o.Port), sq(o.User))
	}
}

func derefOr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func addRemediation(r *SecReport, sql string) {
	if r.Remediation == "" {
		r.Remediation = "-- 数据库整改 SQL（请逐条核对后执行）\n"
	}
	r.Remediation += sql + "\n"
}

// RunDBCheck 数据库只读体检。
func RunDBCheck(host string, o DBOptions, r *SecReport) error {
	o = NormalizeDB(o)
	if err := ValidateDB(o); err != nil {
		return err
	}
	out, err := remoteRun(dbScript(o))
	if err != nil {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "连接体检",
			Result: "执行失败: " + err.Error(), Level: SecLow, Fixable: "no"})
		return nil
	}
	sec := appCfgSections(out)
	if len(sec["NOCLIENT"]) > 0 {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "客户端缺失",
			Result: "目标机未安装对应客户端(" + o.Type + ")", Level: SecMedium,
			Advice: "安装客户端后复检，或按 remediation.sql 人工核对", Fixable: "no"})
		return nil
	}
	if len(sec["VER"]) == 0 {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "连接失败",
			Result: "未取到版本信息（口令错误/账号无权限/端口不通）", Level: SecLow,
			Advice: "核对连接参数与账号权限", Fixable: "no"})
		return nil
	}
	r.Add(SecFinding{Host: host, Category: "数据库", Item: "版本",
		Result: strings.TrimSpace(strings.Join(sec["VER"], " ")), Level: SecInfo, Fixable: "no"})

	switch o.Type {
	case "mysql":
		dbFindMySQL(host, sec, r)
	case "dm":
		dbFindDM(host, sec, r)
	default:
		dbFindPG(host, sec, r)
	}
	return nil
}

func dbFindMySQL(host string, sec map[string][]string, r *SecReport) {
	var empty, anon, rootPct, wild []string
	for _, ln := range sec["USERS"] {
		f := strings.Split(ln, "\t")
		if len(f) < 4 {
			continue
		}
		user, h, state := f[0], f[1], f[3]
		if user == "" {
			anon = append(anon, h)
			continue
		}
		if state == "EMPTY" && h != "localhost" {
			empty = append(empty, user+"@"+h)
		}
		if user == "root" && h == "%" {
			rootPct = append(rootPct, "root@%")
		}
		if user != "root" && h == "%" {
			wild = append(wild, user+"@%")
		}
	}
	if len(empty) > 0 {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "存在空口令账号",
			Result: strings.Join(empty, ", "), Level: SecHigh,
			Advice: "ALTER USER ... IDENTIFIED BY '<强口令>';（见 remediation.sql）", Fixable: "sql"})
		for _, u := range empty {
			i := strings.LastIndex(u, "@")
			if i > 0 {
				addRemediation(r, fmt.Sprintf("ALTER USER '%s'@'%s' IDENTIFIED BY '<强口令>';", u[:i], u[i+1:]))
			}
		}
	}
	if len(anon) > 0 {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "存在匿名账号",
			Result: strings.Join(anon, ", "), Level: SecHigh,
			Advice: "DROP USER ''@'<host>';", Fixable: "sql"})
		for _, h := range anon {
			addRemediation(r, fmt.Sprintf("DROP USER ''@'%s';", h))
		}
	}
	if len(rootPct) > 0 {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "root 允许任意来源登录",
			Result: "root@%", Level: SecHigh,
			Advice: "DROP USER 'root'@'%'; 或收敛为具体应用服务器", Fixable: "sql"})
		addRemediation(r, "DROP USER IF EXISTS 'root'@'%';")
	}
	if len(wild) > 0 {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "业务账号使用 % 通配来源",
			Result: strings.Join(wild, ", "), Level: SecMedium,
			Advice: "收敛为具体应用服务器 IP/网段", Fixable: "sql"})
	}

	at := func(k string) string {
		if v := sec[k]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	if at("LOCALINFILE") == "1" {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "local_infile 开启",
			Result: "可被利用读取服务器任意文件", Level: SecMedium,
			Advice: "SET GLOBAL local_infile=0; 并在 my.cnf 固化", Fixable: "sql"})
		addRemediation(r, "SET GLOBAL local_infile=0;")
	}
	if v := at("SECUREFILE"); v == "" || strings.EqualFold(v, "NULL") {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "secure_file_priv 为空",
			Result: "允许任意路径导入导出", Level: SecMedium,
			Advice: "my.cnf: secure_file_priv=/var/lib/mysql-files", Fixable: "no"})
	}
	if at("GENERALLOG") == "1" {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "general_log 开启",
			Result: "记录全部SQL，含明文口令", Level: SecLow,
			Advice: "SET GLOBAL general_log=0;（排障时临时开启）", Fixable: "sql"})
		addRemediation(r, "SET GLOBAL general_log=0;")
	}
	if v := at("SLOWLOG"); v != "1" {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "慢查询日志未开启",
			Result: "不利于审计与性能排查", Level: SecLow,
			Advice: "slow_query_log=ON, long_query_time=2", Fixable: "sql"})
		addRemediation(r, "SET GLOBAL slow_query_log=ON;")
	}
	if v := at("VALIDATEPWD"); v == "0" || v == "" {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "未启用口令复杂度插件",
			Result: "validate_password 未安装/未启用", Level: SecMedium,
			Advice:  "INSTALL PLUGIN validate_password SONAME 'validate_password.so'; policy=MEDIUM",
			Fixable: "sql"})
		addRemediation(r, "INSTALL PLUGIN validate_password SONAME 'validate_password.so';")
		addRemediation(r, "SET GLOBAL validate_password.policy=MEDIUM;")
		addRemediation(r, "SET GLOBAL validate_password.length=10;")
	}
}

func dbFindDM(host string, sec map[string][]string, r *SecReport) {
	if users := sec["USERS"]; len(users) > 0 {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "启用账号",
			Result: strings.Join(users, ", "), Level: SecInfo,
			Advice: "确认业务必需，其余锁定", Fixable: "no"})
	}
	policy := firstDigits(sec["PWDPOLICY"])
	if policy == "" || policy == "0" {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "达梦口令复杂度策略未开启",
			Result: "PWD_POLICY=" + orDash(policy), Level: SecMedium,
			Advice: "SP_SET_PARA_VALUE(1,'PWD_POLICY',7);", Fixable: "sql"})
		addRemediation(r, "SP_SET_PARA_VALUE(1,'PWD_POLICY',7);")
	}
	if audit := firstDigits(sec["AUDIT"]); audit != "1" {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "达梦审计未开启",
			Result: "ENABLE_AUDIT=" + orDash(audit), Level: SecMedium,
			Advice: "SP_SET_PARA_VALUE(1,'ENABLE_AUDIT',1);", Fixable: "sql"})
		addRemediation(r, "SP_SET_PARA_VALUE(1,'ENABLE_AUDIT',1);")
	}
	r.Add(SecFinding{Host: host, Category: "数据库", Item: "默认口令",
		Result: "请确认 SYSDBA 口令已修改(默认 SYSDBA)", Level: SecLow,
		Advice: `ALTER USER SYSDBA IDENTIFIED BY "<强口令>";`, Fixable: "sql"})
	addRemediation(r, `ALTER USER SYSDBA IDENTIFIED BY "<强口令>";`)
}

func dbFindPG(host string, sec map[string][]string, r *SecReport) {
	var supers []string
	for _, ln := range sec["ROLES"] {
		f := strings.Split(ln, "|")
		if len(f) >= 3 && strings.HasPrefix(strings.ToLower(strings.TrimSpace(f[2])), "t") {
			supers = append(supers, strings.TrimSpace(f[0]))
		}
	}
	if len(supers) > 0 {
		rl := strings.Join(supers, ", ")
		lv := SecInfo
		adv := ""
		if !onlyDefaults(supers) {
			lv = SecMedium
			adv = "按最小权限拆分业务账号"
		}
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "超级用户",
			Result: rl, Level: lv, Advice: adv, Fixable: "no"})
	}
	if enc := strings.ToLower(strings.TrimSpace(strings.Join(sec["PWENC"], " "))); enc == "md5" {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "口令加密方式为 md5",
			Result: "易被离线破解", Level: SecMedium,
			Advice: "password_encryption=scram-sha-256 并重置账号口令", Fixable: "no"})
	}
	conn := strings.ToLower(strings.TrimSpace(strings.Join(sec["LOGCONN"], " ")))
	stmt := strings.ToLower(strings.TrimSpace(strings.Join(sec["LOGSTMT"], " ")))
	if conn != "on" && stmt == "none" {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "登录/SQL 审计未开启",
			Result: "log_connections=" + orDash(conn) + " log_statement=" + orDash(stmt), Level: SecLow,
			Advice: "postgresql.conf: log_connections=on, log_statement=ddl", Fixable: "no"})
	}
	if hba := sec["HBA"]; len(hba) > 0 {
		r.Add(SecFinding{Host: host, Category: "数据库", Item: "pg_hba.conf 存在 trust 规则",
			Result: "任意来源可免密登录", Evidence: evidenceOf(hba, 3), Level: SecHigh,
			Advice: "改为 scram-sha-256 并 reload", Fixable: "no"})
	}
	r.Add(SecFinding{Host: host, Category: "数据库", Item: "默认口令",
		Result: "请确认 postgres/system/highgo 口令已修改", Level: SecLow,
		Advice: "ALTER USER <user> WITH PASSWORD '<强口令>';", Fixable: "sql"})
	addRemediation(r, "ALTER USER <user> WITH PASSWORD '<强口令>';")
}

func onlyDefaults(users []string) bool {
	ok := map[string]bool{"postgres": true, "system": true, "highgo": true, "sso_super": true}
	for _, u := range users {
		if !ok[u] {
			return false
		}
	}
	return true
}

func firstDigits(lines []string) string {
	for _, ln := range lines {
		var b strings.Builder
		for _, c := range ln {
			if c >= '0' && c <= '9' {
				b.WriteRune(c)
			}
		}
		if b.Len() > 0 {
			return b.String()
		}
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
