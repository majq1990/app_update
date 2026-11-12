package harden

// sec_db_appconfig_test.go —— 应用配置与数据库体检的纯函数/假远端测试。

import (
	"strings"
	"testing"
	"time"
)

func TestAppCfgSections(t *testing.T) {
	out := `##ACTUATOR
/a.properties:2:management.endpoints.web.exposure.include=*
##END
##REDIS
/etc/redis.conf:requirepass:0
##END
`
	sec := appCfgSections(out)
	if len(sec["ACTUATOR"]) != 1 {
		t.Fatalf("ACTUATOR 解析错误: %#v", sec)
	}
	if !strings.Contains(sec["ACTUATOR"][0], "exposure.include") {
		t.Fatalf("ACTUATOR 内容错误: %q", sec["ACTUATOR"][0])
	}
	if len(sec["REDIS"]) != 1 {
		t.Fatalf("REDIS 解析错误: %#v", sec)
	}
}

func TestRunAppConfigCheck(t *testing.T) {
	fr := fakeSecRunner{byFrag: map[string]string{"scan()": `##ACTUATOR
/egova/app/conf/a.properties:2:management.endpoints.web.exposure.include=*
##END
##SWAGGER
/egova/app/conf/a.properties:4:swagger.enable=true
##END
##ERRORPAGE
/egova/app/conf/a.properties:6:server.error.include-stacktrace=always
##END
##PASSWORD
/egova/app/conf/a.properties:7:spring.datasource.password=Passw0rd123
##END
##COOKIE
##END
##SWITCH
##END
##AGENT
##END
##MWAUTH
/egova/app/conf/a.properties:9:nacos.core.auth.enabled=false
##END
##REDIS
/etc/redis.conf:requirepass:0
/etc/redis.conf:bind:bind 0.0.0.0
##END
`}}
	withFakeHost(t, "10.0.0.9", fr)
	r := NewSecReport("appconfig", []string{"10.0.0.9"}, time.Now())
	RunAppConfigCheck("10.0.0.9", r)

	if r.Summary["high"] < 4 {
		t.Fatalf("应有 Actuator/Swagger/明文口令/中间件 4 项高危，实际 %d：%+v", r.Summary["high"], r.Findings)
	}
	if r.Summary["medium"] < 2 {
		t.Fatalf("应有错误页/Redis bind 2 项中危，实际 %d", r.Summary["medium"])
	}
	found := false
	for _, f := range r.Findings {
		if f.Item == "疑似明文口令" && !strings.Contains(f.Evidence, "Passw0rd123") {
			t.Fatalf("明文口令证据丢失: %+v", f)
		}
		if f.Item == "疑似明文口令" {
			found = true
		}
	}
	if !found {
		t.Fatal("未检出明文口令")
	}
}

func TestRunAppConfigFixDryRun(t *testing.T) {
	fr := fakeSecRunner{byFrag: map[string]string{"scan()": `##SWAGGER
/egova/app/conf/a.properties:4:swagger.enable=true
##END
##END
`}}
	withFakeHost(t, "10.0.0.9", fr)
	r := NewSecReport("appconfig", []string{"10.0.0.9"}, time.Now())
	out := captureStdout(func() { _ = RunAppConfigFix("10.0.0.9", r, false) })

	if !strings.Contains(out, "appconfig fix 计划") {
		t.Fatalf("dry-run 应打印计划: %s", out)
	}
	if len(r.Backups) != 0 {
		t.Fatalf("dry-run 不应产生备份: %v", r.Backups)
	}
}

func TestAppCfgFixFiles(t *testing.T) {
	sec := map[string][]string{
		"ACTUATOR":  {"/a.properties:2:x=*", "/b.yml:3:y=1"},
		"SWAGGER":   {"/a.properties:4:swagger.enable=true"},
		"ERRORPAGE": {},
	}
	files := appCfgFixFiles(sec)
	if len(files) != 2 {
		t.Fatalf("应去重为 2 个文件，实际 %v", files)
	}
}

func TestDBFindMySQL(t *testing.T) {
	sec := map[string][]string{
		"USERS": {
			"root\t%\tmysql_native_password\tEMPTY",
			"app\t%\tmysql_native_password\tSET",
			"\tlocalhost\t\tEMPTY",
		},
		"LOCALINFILE": {"1"},
		"SECUREFILE":  {""},
		"GENERALLOG":  {"0"},
		"SLOWLOG":     {"0"},
		"VALIDATEPWD": {"0"},
	}
	r := NewSecReport("db", nil, time.Now())
	dbFindMySQL("h1", sec, r)

	if r.Summary["high"] < 3 {
		t.Fatalf("空口令/匿名/root@%% 应各有高危，实际 %d：%+v", r.Summary["high"], r.Findings)
	}
	for _, want := range []string{
		"ALTER USER 'root'@'%' IDENTIFIED BY '<强口令>';",
		"DROP USER IF EXISTS 'root'@'%';",
		"SET GLOBAL local_infile=0;",
		"INSTALL PLUGIN validate_password",
	} {
		if !strings.Contains(r.Remediation, want) {
			t.Fatalf("remediation 缺少 %q：\n%s", want, r.Remediation)
		}
	}
}

func TestDBFindPGTrust(t *testing.T) {
	sec := map[string][]string{
		"ROLES":   {"postgres|t|t", "biz|t|f"},
		"PWENC":   {"md5"},
		"LOGCONN": {"off"},
		"LOGSTMT": {"none"},
		"HBA":     {"/var/lib/pgsql/data/pg_hba.conf: host all all 0.0.0.0/0 trust"},
	}
	r := NewSecReport("db", nil, time.Now())
	dbFindPG("h2", sec, r)

	if r.Summary["high"] < 1 {
		t.Fatalf("pg_hba trust 应判高危：%+v", r.Findings)
	}
	if r.Summary["medium"] < 1 {
		t.Fatalf("md5 口令应判中危：%+v", r.Findings)
	}
}

func TestNormalizeAndValidateDB(t *testing.T) {
	o := NormalizeDB(DBOptions{Type: "MySQL"})
	if o.Type != "mysql" || o.Port != "3306" || o.User != "root" || o.Host != "127.0.0.1" {
		t.Fatalf("默认值错误: %+v", o)
	}
	if err := ValidateDB(o); err != nil {
		t.Fatalf("默认参数应合法: %v", err)
	}
	if err := ValidateDB(DBOptions{Type: "oracle", Host: "h", Port: "1521", User: "u"}); err == nil {
		t.Fatal("不支持的数据库类型应报错")
	}
	if err := ValidateDB(DBOptions{Type: "mysql", Host: "h", Port: "abc", User: "u"}); err == nil {
		t.Fatal("非法端口应报错")
	}
}
