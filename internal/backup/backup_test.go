package backup

import (
	"strings"
	"testing"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
)

func cfgWith(backup *config.Backup, webs []config.App, sup []config.Support) *config.Config {
	return &config.Config{Backup: backup, Webs: webs, Supports: sup}
}

func TestTargetsAppDedupAndExclude(t *testing.T) {
	app := config.App{
		Web: "eurbanpro", MiddleType: "jar", LogDir: "log",
		ExcludePaths: []string{"tilemap/"},
		Master:       []config.Host{{Host: "10.0.0.1", WebPath: "/egova/apps/eurbanpro"}},
		Update:       []config.Host{{Host: "10.0.0.1", WebPath: "/egova/apps/eurbanpro"}},
	}
	c := cfgWith(&config.Backup{Exclude: []string{"tmp/"}}, []config.App{app}, nil)
	ts := Targets(c)
	if len(ts) != 1 {
		t.Fatalf("同主机同路径应只出 1 个目标，实际 %d: %+v", len(ts), ts)
	}
	if ts[0].Kind != KindApp || ts[0].Path != "/egova/apps/eurbanpro" {
		t.Fatalf("目标不正确: %+v", ts[0])
	}
	joined := strings.Join(ts[0].Exclude, ",")
	for _, want := range []string{"tilemap/", "tmp/", "log/*", "logs/*", "backups/*"} {
		if !strings.Contains(joined, want) {
			t.Errorf("排除项缺少 %q，实际 %v", want, ts[0].Exclude)
		}
	}
}

func TestTargetsSupportPathsAndMySQL(t *testing.T) {
	sup := []config.Support{
		{Kind: "redis", Name: "缓存", Hosts: []config.Host{{Host: "10.0.0.2"}},
			BackupPaths: []string{"/egova/apps/redis/data/dump.rdb"}},
		{Kind: "mysql", Hosts: []config.Host{{Host: "10.0.0.3"}, {Host: "10.0.0.4"}}},
	}
	c := cfgWith(&config.Backup{Databases: []string{"eurbanpro"}}, nil, sup)
	ts := Targets(c)

	var dirs int
	dirTargets := map[string]string{}
	for _, x := range ts {
		if x.Kind == KindDir {
			dirs++
			dirTargets[x.Host.Host] = x.Slug
		}
	}
	if dirs != 1 {
		t.Fatalf("期望 1 个目录目标，实际 %d", dirs)
	}
	if _, ok := dirTargets["10.0.0.2"]; !ok {
		t.Fatalf("目录目标主机不对: %v", dirTargets)
	}

	var mysqls int
	for _, x := range ts {
		if x.Kind == KindMySQL {
			mysqls++
		}
	}
	if mysqls != 2 {
		t.Fatalf("mysql 目标应为主机数 2，实际 %d", mysqls)
	}
}

func TestTargetsNoDatabasesNoMySQLTarget(t *testing.T) {
	sup := []config.Support{{Kind: "mysql", Hosts: []config.Host{{Host: "10.0.0.3"}}}}
	ts := Targets(cfgWith(&config.Backup{}, nil, sup))
	for _, x := range ts {
		if x.Kind == KindMySQL {
			t.Fatalf("未配 databases 不应产生 mysql 目标")
		}
	}
}

func TestArchiveNameAndPath(t *testing.T) {
	now := time.Date(2026, 11, 6, 10, 15, 30, 0, time.UTC)
	appt := Target{Kind: KindApp, Name: "eUrban MIS", Slug: "eUrban MIS",
		Host: config.Host{Host: "10.0.0.1"}}
	got := ArchiveName(appt, now)
	if got != "eops-eUrban-MIS-10.0.0.1-101530.tar.gz" {
		t.Fatalf("文件名不合规: %q", got)
	}
	db := Target{Kind: KindMySQL, Slug: "mysql", Host: config.Host{Host: "10.0.0.3"}}
	if n := ArchiveName(db, now); !strings.HasSuffix(n, ".sql.gz") {
		t.Fatalf("数据库备份扩展名应为 .sql.gz: %q", n)
	}
	p := ArchivePath("/egova/backup/", appt, now)
	if p != "/egova/backup/2026-11-06/eops-eUrban-MIS-10.0.0.1-101530.tar.gz" {
		t.Fatalf("路径不合规: %q", p)
	}
}

func TestTarCommandRejectsInjection(t *testing.T) {
	bad := []string{
		"/egova/backup/2026-11-06/eops-a.tar.gz; rm -rf /",
		"/egova/backup/../etc/passwd",
		"/egova/backup/'quote.tar.gz",
		"/egova/backup/$(whoami).tar.gz",
	}
	for _, dest := range bad {
		if _, err := TarCommand(dest, "/egova/apps/x", nil); err == nil {
			t.Errorf("恶意目标路径应被拒绝: %q", dest)
		}
	}
	if _, err := TarCommand("/egova/backup/a.tar.gz", "/egova/apps/x;ls", nil); err == nil {
		t.Error("恶意源路径应被拒绝")
	}
}

func TestTarCommandShape(t *testing.T) {
	cmd, err := TarCommand("/egova/backup/2026-11-06/eops-x-10.0.0.1.tar.gz",
		"/egova/apps/x/", []string{"logs/*", "backups/*"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"tar czf '/egova/backup/2026-11-06/eops-x-10.0.0.1.tar.gz.part'",
		"-C '/egova/apps'",
		"--exclude='x/logs/*'",
		"--exclude='x/backups/*'",
		"'x'",
		"mv -f '/egova/backup/2026-11-06/eops-x-10.0.0.1.tar.gz.part'",
		"sha256sum",
		"stat -c %s",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("命令缺少 %q\n实际: %s", want, cmd)
		}
	}
	if strings.Contains(cmd, "x//") {
		t.Errorf("路径出现重复斜杠: %s", cmd)
	}
}

func TestDumpCommand(t *testing.T) {
	if _, err := DumpCommand("/egova/backup/x.sql.gz", []string{"a;rm -rf /"}, "root", ""); err == nil {
		t.Fatal("非法库名应被拒绝")
	}
	if _, err := DumpCommand("/egova/backup/x.sql.gz", []string{"eurbanpro"}, "root;ls", ""); err == nil {
		t.Fatal("非法用户应被拒绝")
	}
	cmd, err := DumpCommand("/egova/backup/2026-11-06/eops-mysql-10.0.0.3-101530.sql.gz",
		[]string{"eurbanpro", "evaluation"}, "root", "/root/.my.cnf")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"mysqldump --single-transaction --quick --routines --triggers --events",
		"--defaults-extra-file='/root/.my.cnf'",
		"-u 'root'",
		"--databases 'eurbanpro' 'evaluation'",
		"| gzip -1 >",
		"set -o pipefail",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("mysqldump 命令缺少 %q\n实际: %s", want, cmd)
		}
	}
}

func TestVerifyCommandByExtension(t *testing.T) {
	tarCmd, err := VerifyCommand("/egova/backup/a.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tarCmd, "tar -tzf") || !strings.Contains(tarCmd, "gzip -t") {
		t.Errorf("tar.gz 校验应同时验 gzip 与 tar: %s", tarCmd)
	}
	sqlCmd, err := VerifyCommand("/egova/backup/a.sql.gz")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sqlCmd, "tar -tzf") {
		t.Errorf("sql.gz 不应做 tar 枚举: %s", sqlCmd)
	}
}

func TestParseVerify(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	out := hash + "  /egova/backup/a.tar.gz\n12345\n"
	res := ParseVerify("/egova/backup/a.tar.gz", out)
	if !res.OK || res.SHA256 != hash || res.Bytes != 12345 {
		t.Fatalf("解析失败: %+v", res)
	}
	bad := ParseVerify("/egova/backup/a.tar.gz", "12345")
	if bad.OK || bad.Err == "" {
		t.Fatalf("无 sha256 应判失败: %+v", bad)
	}
}

func TestParseListAndLines(t *testing.T) {
	out := "1762435200.000|1048576|/egova/backup/2026-11-06/eops-a-10.0.0.1-101530.tar.gz\n" +
		"\n" +
		"1762435300.5|2048|/egova/backup/2026-11-06/eops-b-10.0.0.1-101600.sql.gz\n"
	files := ParseList(out)
	if len(files) != 2 {
		t.Fatalf("应解析 2 份，实际 %d: %+v", len(files), files)
	}
	if files[0].Bytes != 1048576 || files[1].Bytes != 2048 {
		t.Fatalf("字节数解析错误: %+v", files)
	}
	if files[0].ModTime.Year() < 2020 {
		t.Fatalf("mtime 解析错误: %v", files[0].ModTime)
	}

	lines := ParseLines("/egova/backup/a.tar.gz\nnot-a-path\n/egova/backup/b.sql.gz\n")
	if len(lines) != 2 || lines[0] != "/egova/backup/a.tar.gz" {
		t.Fatalf("路径清单解析错误: %v", lines)
	}
}

func TestSlugFallbackForChineseNames(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	sup := []config.Support{
		{Kind: "redis", Name: "缓存", Hosts: []config.Host{{Host: "10.0.0.2"}},
			BackupPaths: []string{"/egova/apps/redis/data/dump.rdb"}},
		{Kind: "mysql", Name: "业务库", Hosts: []config.Host{{Host: "10.0.0.3"}}},
	}
	c := cfgWith(&config.Backup{Databases: []string{"eurbanpro"}}, nil, sup)
	ts := Targets(c)
	byKind := map[Kind]Target{}
	for _, x := range ts {
		byKind[x.Kind] = x
	}
	if got := ArchiveName(byKind[KindDir], now); got != "eops-redis-dump.rdb-10.0.0.2-120000.tar.gz" {
		t.Errorf("目录目标文件名未回落 kind: %q", got)
	}
	if got := ArchiveName(byKind[KindMySQL], now); got != "eops-mysql-10.0.0.3-120000.sql.gz" {
		t.Errorf("数据库目标文件名未回落 kind: %q", got)
	}
}

func TestRemoveCommandGuards(t *testing.T) {
	if _, err := RemoveCommand("/egova/backup/other.tar.gz"); err == nil {
		t.Error("非 eops- 产物应拒绝删除")
	}
	if _, err := RemoveCommand("/egova/backup/eops-a-10.0.0.1-101530.tar.gz;rm -rf /"); err == nil {
		t.Error("带元字符的路径应拒绝")
	}
	cmd, err := RemoveCommand("/egova/backup/2026-11-06/eops-a-10.0.0.1-101530.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cmd, "rm -f '") {
		t.Fatalf("删除命令应带引号: %s", cmd)
	}
}

func TestBuildLedgerMapping(t *testing.T) {
	now := time.Date(2026, 11, 6, 11, 0, 0, 0, time.UTC)
	targets := []Target{
		{Kind: KindApp, Name: "eurbanpro", Slug: "eurbanpro", Host: config.Host{Host: "10.0.0.1"}},
		{Kind: KindMySQL, Name: "mysql", Slug: "mysql", Host: config.Host{Host: "10.0.0.3"}},
	}
	files := []StoredFile{
		{Path: "/egova/backup/2026-11-06/eops-eurbanpro-10.0.0.1-101530.tar.gz", Bytes: 100, ModTime: now},
		{Path: "/egova/backup/2026-11-06/eops-mysql-10.0.0.3-101600.sql.gz", Bytes: 200, ModTime: now},
		{Path: "/egova/backup/2026-11-06/manual.tar.gz", Bytes: 300, ModTime: now},
	}
	verified := map[string]VerifyResult{
		files[0].Path: {File: files[0].Path, SHA256: strings.Repeat("cd", 32), Bytes: 100, OK: true},
	}
	led := BuildLedger("/egova/backup", 14, targets, files, verified, now)
	if len(led.Entries) != 3 {
		t.Fatalf("条目数应为 3，实际 %d", len(led.Entries))
	}
	byFile := map[string]LedgerEntry{}
	for _, e := range led.Entries {
		byFile[e.File] = e
	}
	a := byFile[files[0].Path]
	if a.Target != "eurbanpro" || a.Host != "10.0.0.1" || a.Kind != "app" || !a.Verified {
		t.Fatalf("应用条目映射错误: %+v", a)
	}
	m := byFile[files[1].Path]
	if m.Target != "mysql" || m.Host != "10.0.0.3" || m.Kind != "mysql" {
		t.Fatalf("mysql 条目映射错误: %+v", m)
	}
	u := byFile[files[2].Path]
	if u.Kind != "unknown" || u.Target != "" {
		t.Fatalf("非本工具产物应标 unknown: %+v", u)
	}
	if !strings.Contains(led.Summary(), "共 3 份") {
		t.Fatalf("摘要文案异常: %s", led.Summary())
	}
}

func TestRegisterBackupDirCommand(t *testing.T) {
	if _, err := RegisterBackupDirCommand("/egova/backup;rm -rf /"); err == nil {
		t.Fatal("含元字符的备份根目录应被拒绝")
	}
	cmd, err := RegisterBackupDirCommand("/egova/backup/")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/etc/zabbix/zabbix_agentd.d", "backup_dirs.txt",
		"grep -qxF '/egova/backup'", "echo '/egova/backup'", "NO_AGENT",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("登记命令缺少 %q\n实际: %s", want, cmd)
		}
	}
	if !ParseRegisterResult("REGISTERED\n") {
		t.Error("REGISTERED 应判为已登记")
	}
	if ParseRegisterResult("NO_AGENT\n") {
		t.Error("NO_AGENT 不应判为已登记")
	}
}

func TestBackupValidation(t *testing.T) {
	base := func(b *config.Backup) *config.Config {
		return &config.Config{
			Global: config.Global{AnsibleUser: "root", AnsibleSSHPort: 22},
			Webs: []config.App{{
				Web: "a", MiddleType: "jar", RetainedConfigFile: []string{"x"},
				Master: []config.Host{{Host: "10.0.0.1", WebPath: "/egova/a"}},
			}},
			Supports: nil,
			Backup:   b,
		}
	}
	cases := []struct {
		name string
		b    *config.Backup
		want string
	}{
		{"相对 root", &config.Backup{Root: "backup"}, "root 必须是绝对路径"},
		{"非法库名", &config.Backup{Databases: []string{"a;rm"}}, "databases 含非法库名"},
		{"库名有 mysql 段缺失", &config.Backup{Databases: []string{"a"}}, "没有 mysql 类型的 supports 段"},
		{"非法凭据文件", &config.Backup{DumpDefaultsFile: "/root/.my.cnf;ls"}, "dump_defaults_file"},
		{"负保留期", &config.Backup{KeepDays: -1}, "keep_days 不能为负"},
	}
	for _, c := range cases {
		issues := base(c.b).Validate()
		found := false
		for _, is := range issues {
			if strings.Contains(is.Msg, c.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: 期望命中 %q，实际 %+v", c.name, c.want, issues)
		}
	}
}
