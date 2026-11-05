package logs

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
)

// fakeRotater 假远端探测。
type fakeRotater struct {
	files   map[string]string   // 存在的文件路径 → 内容（空串=存在无内容）
	cmdOut  map[string]string   // Run 命令 → 输出
	cmdErr  map[string]error
}

func (f fakeRotater) TestFile(p string) bool {
	_, ok := f.files[p]
	return ok
}
func (f fakeRotater) ReadFile(p string) (string, error) {
	if s, ok := f.files[p]; ok {
		return s, nil
	}
	return "", fmt.Errorf("not exist: %s", p)
}
func (f fakeRotater) Run(cmd string) (string, error) {
	if e, ok := f.cmdErr[cmd]; ok {
		return f.cmdOut[cmd], e
	}
	return f.cmdOut[cmd], nil
}

func mkTarget(kind Kind, kindRaw, name string, dirs ...string) Target {
	return Target{Kind: kind, KindRaw: kindRaw, Name: name,
		Host: config.Host{Host: "10.0.0.1"}, LogDirs: dirs, KeepDays: 30}
}

func TestRotateCheckNoFragment(t *testing.T) {
	rt := fakeRotater{files: map[string]string{}}
	tg := mkTarget(KindApp, "jar", "usercenter", "/egova/apps/basic/usercenter/logs")
	files := []LogFile{{Abs: "/egova/apps/basic/usercenter/logs/app.log", Dir: tg.LogDirs[0], Rel: "app.log", Size: 100 << 20, Mtime: time.Now()}}
	res := RunRotateCheck(rt, tg, files, RotateCheckOptions{})
	if !hasFinding(res, "high", "无 logrotate 配置") {
		t.Errorf("缺配置应报 high:\n%v", res.Findings)
	}
}

func TestRotateCheckNoFragmentNoLogs(t *testing.T) {
	// 没配 log_dir 的应用（LogDirs 空）或目录无日志：不算问题
	rt := fakeRotater{files: map[string]string{}}
	tg := mkTarget(KindApp, "jar", "gis") // 无 LogDirs
	res := RunRotateCheck(rt, tg, nil, RotateCheckOptions{})
	for _, f := range res.Findings {
		if f.Severity == "high" || f.Severity == "medium" {
			t.Errorf("无日志目标不应报问题: %+v", f)
		}
	}
}

func TestRotateCheckFragmentOk(t *testing.T) {
	tg := mkTarget(KindApp, "jar", "usercenter", "/egova/apps/basic/usercenter/logs")
	frag := "/etc/logrotate.d/usercenter"
	rt := fakeRotater{
		files: map[string]string{frag: "/egova/apps/basic/usercenter/logs/*.log {\n weekly\n}\n"},
		cmdOut: map[string]string{"logrotate -d " + frag + " 2>&1": "considering log /egova/.../app.log\nlog needs rotating"},
	}
	files := []LogFile{{Abs: tg.LogDirs[0] + "/app.log", Dir: tg.LogDirs[0], Rel: "app.log", Size: 10 << 20, Mtime: time.Now()}}
	res := RunRotateCheck(rt, tg, files, RotateCheckOptions{})
	if hasFinding(res, "high", "") {
		t.Errorf("正常场景不应报 high:\n%v", res.Findings)
	}
	if !hasFinding(res, "info", "已有 logrotate 配置") {
		t.Error("应有 info 提示已有配置")
	}
}

func TestRotateCheckSyntaxError(t *testing.T) {
	tg := mkTarget(KindSupport, "mysql", "mysql", "/egova/apps/mysql/data")
	frag := "/etc/logrotate.d/mysql"
	rt := fakeRotater{
		files: map[string]string{frag: "bad {"},
		cmdOut: map[string]string{"logrotate -d " + frag + " 2>&1": "error: /etc/logrotate.d/mysql:2 unexpected }\n"},
	}
	res := RunRotateCheck(rt, tg, nil, RotateCheckOptions{})
	if !hasFinding(res, "high", "语法错误") {
		t.Errorf("语法错误应报 high:\n%v", res.Findings)
	}
}

func TestRotateCheckDrift(t *testing.T) {
	// 配置存在但没覆盖目标的日志目录（目录改过/配置是别的应用的）
	tg := mkTarget(KindApp, "jar", "usercenter", "/egova/apps/basic/usercenter/logs")
	frag := "/etc/logrotate.d/usercenter"
	rt := fakeRotater{
		files: map[string]string{frag: "/some/other/path/*.log {\n weekly\n}\n"},
		cmdOut: map[string]string{"logrotate -d " + frag + " 2>&1": "ok"},
	}
	res := RunRotateCheck(rt, tg, nil, RotateCheckOptions{})
	if !hasFinding(res, "medium", "未覆盖日志目录") {
		t.Errorf("配置漂移应报 medium:\n%v", res.Findings)
	}
}

func TestRotateCheckBigFile(t *testing.T) {
	rt := fakeRotater{files: map[string]string{}}
	tg := mkTarget(KindApp, "tomcat", "gis", "/egova/apps/basic/gis/WEB-INF/logs")
	files := []LogFile{
		{Abs: "/egova/apps/basic/gis/WEB-INF/logs/catalina.out", Dir: tg.LogDirs[0], Rel: "catalina.out", Size: 3 << 30, Mtime: time.Now()},
	}
	res := RunRotateCheck(rt, tg, files, RotateCheckOptions{})
	if !hasFinding(res, "high", "未切割大文件") {
		t.Errorf("3G catalina.out 应报 high:\n%v", res.Findings)
	}
}

func TestRotateCheckGrowth(t *testing.T) {
	// 近 7 天写了 500MB → 约 71MB/天，30 天 ~2.1G > 1G 阈值/30=33MB → 应报 medium
	rt := fakeRotater{files: map[string]string{}}
	tg := mkTarget(KindApp, "jar", "uc", "/egova/apps/uc/logs")
	now := time.Now()
	var files []LogFile
	for i := 0; i < 5; i++ {
		files = append(files, LogFile{Abs: fmt.Sprintf("/egova/apps/uc/logs/app.%d.log", i),
			Dir: tg.LogDirs[0], Rel: fmt.Sprintf("app.%d.log", i), Size: 100 << 20, Mtime: now.Add(-time.Duration(i) * 24 * time.Hour)})
	}
	res := RunRotateCheck(rt, tg, files, RotateCheckOptions{})
	if !hasFinding(res, "medium", "新增") {
		t.Errorf("高增长应报 medium:\n%v", res.Findings)
	}
}

func TestRotateFragmentName(t *testing.T) {
	if got := RotateFragmentName(mkTarget(KindApp, "jar", "usercenter")); got != "usercenter" {
		t.Errorf("应用片段名 = %q", got)
	}
	if got := RotateFragmentName(mkTarget(KindSupport, "mysql", "MySQL库")); got != "mysql" {
		t.Errorf("支持软件片段名应以 kind 命名 = %q", got)
	}
}

func TestRotateTemplate(t *testing.T) {
	tg := mkTarget(KindApp, "tomcat", "gis", "/egova/apps/basic/gis/WEB-INF/logs")
	tpl := RotateTemplate(tg)
	for _, want := range []string{"/egova/apps/basic/gis/WEB-INF/logs/*.log", "*.out", "copytruncate", "weekly", "rotate 8", "dateext", "missingok"} {
		if !strings.Contains(tpl, want) {
			t.Errorf("模板缺少 %q:\n%s", want, tpl)
		}
	}
	// jar 应用不含 .out
	jar := mkTarget(KindApp, "jar", "uc", "/egova/apps/uc/logs")
	if strings.Contains(RotateTemplate(jar), "*.out") {
		t.Error("jar 应用模板不应有 *.out")
	}
}

func hasFinding(res RotateCheckResult, sev, sub string) bool {
	for _, f := range res.Findings {
		if f.Severity == sev && strings.Contains(f.Msg, sub) {
			return true
		}
	}
	return false
}
