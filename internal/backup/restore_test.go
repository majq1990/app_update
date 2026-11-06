package backup

import (
	"strings"
	"testing"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
)

const restoreGoodFile = "/egova/backup/2026-11-07/eops-eurbanpro-10.0.0.1-101530.tar.gz"

func restoreTestTarget() Target {
	return Target{
		Kind: KindApp, Name: "eurbanpro", Slug: "eurbanpro",
		Path: "/egova/apps/eurbanpro",
		Host: config.Host{
			Host: "10.0.0.1", WebPath: "/egova/apps/eurbanpro",
			User: "egova", Group: "egova",
			ServicePort: 8080, CheckURI: "/eurbanpro-api/free/status",
			StartCmd: "systemctl start eurbanpro",
			StopCmd:  "systemctl stop eurbanpro",
		},
		Exclude: []string{"logs/*"},
	}
}

func TestValidateRestorePackage(t *testing.T) {
	root := "/egova/backup"
	if err := ValidateRestorePackage(root, restoreGoodFile); err != nil {
		t.Fatalf("合法备份包被拒绝: %v", err)
	}
	if err := ValidateRestorePackage("/egova/backup/", restoreGoodFile); err != nil {
		t.Fatalf("根目录带尾斜杠应等价: %v", err)
	}
	bad := map[string]string{
		"不在备份根目录下":  "/etc/eops-eurbanpro-10.0.0.1-101530.tar.gz",
		"同前缀兄弟目录":   "/egova/backupX/eops-eurbanpro-10.0.0.1-101530.tar.gz",
		"非本工具前缀":    "/egova/backup/2026-11-07/manual.tar.gz",
		"扩展名不对":     "/egova/backup/2026-11-07/eops-eurbanpro-10.0.0.1-101530.sql.gz",
		"路径穿越":      "/egova/backup/../etc/eops-x.tar.gz",
		"shell 元字符": "/egova/backup/eops-x.tar.gz;rm -rf /",
	}
	for name, file := range bad {
		if err := ValidateRestorePackage(root, file); err == nil {
			t.Errorf("%s: 应拒绝 %q", name, file)
		}
	}
}

func TestRestoreCommandBuilders(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	plan, err := BuildRestorePlan("/egova/backup", restoreTestTarget(), restoreGoodFile, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != 5 {
		t.Fatalf("步骤数应为 5，实际 %d", len(plan.Steps))
	}
	wantKeys := []string{StepStop, StepPreBackup, StepRestore, StepChown, StepStart}
	for i, k := range wantKeys {
		if plan.Steps[i].Key != k {
			t.Errorf("第 %d 步 key 应为 %s，实际 %s", i+1, k, plan.Steps[i].Key)
		}
	}
	if plan.Steps[0].Command != "systemctl stop eurbanpro" {
		t.Errorf("停止命令异常: %s", plan.Steps[0].Command)
	}
	if plan.Steps[4].Command != "systemctl start eurbanpro" {
		t.Errorf("启动命令异常: %s", plan.Steps[4].Command)
	}
	if plan.PreBackup != "/egova/backup/pre-restore-20261107-120000.tar.gz" {
		t.Errorf("变更前备份路径异常: %s", plan.PreBackup)
	}
	pre := plan.Steps[1].Command
	for _, want := range []string{
		"tar czf '/egova/backup/pre-restore-20261107-120000.tar.gz.part'",
		"-C '/egova/apps'",
		"--exclude='eurbanpro/logs/*'",
	} {
		if !strings.Contains(pre, want) {
			t.Errorf("变更前备份命令缺少 %q\n实际: %s", want, pre)
		}
	}
	wantRestore := "tar -xzf '" + restoreGoodFile + "' -C '/egova/apps/eurbanpro'"
	if plan.Steps[2].Command != wantRestore {
		t.Errorf("恢复命令异常:\n期望: %s\n实际: %s", wantRestore, plan.Steps[2].Command)
	}
	if plan.Steps[3].Command != "chown -R 'egova:egova' '/egova/apps/eurbanpro'" {
		t.Errorf("属主命令异常: %s", plan.Steps[3].Command)
	}
	if !plan.HealthEnabled {
		t.Fatal("配了 check_uri 应启用健康检查")
	}
	for _, want := range []string{"curl -fsS", "'http://127.0.0.1:8080/eurbanpro-api/free/status'"} {
		if !strings.Contains(plan.HealthCommand, want) {
			t.Errorf("健康检查命令缺少 %q\n实际: %s", want, plan.HealthCommand)
		}
	}
}

func TestBuildRestorePlanRejectsBadPackage(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	if _, err := BuildRestorePlan("/egova/backup", restoreTestTarget(),
		"/egova/backup/2026-11-07/manual.tar.gz", now); err == nil {
		t.Fatal("非 eops-*.tar.gz 应拒绝构建计划")
	}
	if _, err := BuildRestorePlan("/egova/backup", restoreTestTarget(),
		"/etc/eops-x.tar.gz", now); err == nil {
		t.Fatal("备份根目录之外的包应拒绝")
	}
}

func TestRestorePlanText(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	plan, err := BuildRestorePlan("/egova/backup", restoreTestTarget(), restoreGoodFile, now)
	if err != nil {
		t.Fatal(err)
	}
	text := plan.Text()
	for _, want := range []string{
		"恢复计划：应用 eurbanpro @10.0.0.1",
		restoreGoodFile,
		"/egova/backup/pre-restore-20261107-120000.tar.gz",
		"停止应用",
		"变更前自动备份",
		"解压恢复",
		"修正属主",
		"启动应用",
		"健康检查",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("计划文案缺少 %q\n实际:\n%s", want, text)
		}
	}
}

func TestRestorePlanTextSkipHealth(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	tg := restoreTestTarget()
	tg.Host.CheckURI = ""
	tg.Host.ServicePort = 0
	plan, err := BuildRestorePlan("/egova/backup", tg, restoreGoodFile, now)
	if err != nil {
		t.Fatal(err)
	}
	if plan.HealthEnabled {
		t.Fatal("无 URI 与端口时不应启用健康检查")
	}
	if !strings.Contains(plan.Text(), "跳过") {
		t.Errorf("计划文案应注明跳过健康检查:\n%s", plan.Text())
	}
}

func TestFindRestoreTarget(t *testing.T) {
	targets := []Target{restoreTestTarget()}
	if _, ok := FindRestoreTarget(targets, "eurbanpro", restoreGoodFile); !ok {
		t.Fatal("应匹配到应用主机")
	}
	if _, ok := FindRestoreTarget(targets, "other", restoreGoodFile); ok {
		t.Fatal("应用名不匹配不应命中")
	}
	if _, ok := FindRestoreTarget(targets, "eurbanpro",
		"/egova/backup/2026-11-07/eops-eurbanpro-10.0.0.9-101530.tar.gz"); ok {
		t.Fatal("备份包主机与应用主机不一致不应命中")
	}
}

func TestChownCommandGuards(t *testing.T) {
	cmd, err := ChownCommand("/egova/apps/x", "egova", "")
	if err != nil {
		t.Fatal(err)
	}
	if cmd != "chown -R 'egova' '/egova/apps/x'" {
		t.Errorf("单属主命令异常: %s", cmd)
	}
	if _, err := ChownCommand("/egova/apps/x", "egova;rm", ""); err == nil {
		t.Error("非法属主应拒绝")
	}
	if _, err := ChownCommand("/egova/apps/x", "egova", "a b"); err == nil {
		t.Error("非法属组应拒绝")
	}
	if _, err := ChownCommand("/egova/apps/x;ls", "egova", ""); err == nil {
		t.Error("非法目标路径应拒绝")
	}
}

func TestServiceCommandGuards(t *testing.T) {
	if _, err := ServiceCommand(""); err == nil {
		t.Error("空命令应拒绝")
	}
	if _, err := ServiceCommand("systemctl stop x\nrm -rf /"); err == nil {
		t.Error("含换行的命令应拒绝")
	}
	cmd, err := ServiceCommand("systemctl stop x")
	if err != nil || cmd != "systemctl stop x" {
		t.Fatalf("合法命令应原样返回: %q %v", cmd, err)
	}
}

func TestHealthProbeCommandVariants(t *testing.T) {
	cmd, on, err := HealthProbeCommand(config.Host{
		ServicePort: 9000, CheckURI: "/api/check",
	})
	if err != nil || !on || !strings.Contains(cmd, "curl -fsS") {
		t.Fatalf("check_uri 应走 curl: %q on=%v err=%v", cmd, on, err)
	}
	cmd, on, err = HealthProbeCommand(config.Host{ServicePort: 9000})
	if err != nil || !on || !strings.Contains(cmd, "/dev/tcp/127.0.0.1/9000") {
		t.Fatalf("无 URI 应走 /dev/tcp: %q on=%v err=%v", cmd, on, err)
	}
	if _, on, err := HealthProbeCommand(config.Host{ServicePort: 9000, HealthMode: "none"}); on || err != nil {
		t.Fatalf("health_mode=none 应跳过: on=%v err=%v", on, err)
	}
	if _, _, err := HealthProbeCommand(config.Host{ServicePort: 9000, CheckURI: "/a;rm -rf /"}); err == nil {
		t.Fatal("非法 check_uri 应拒绝")
	}
}
