package logs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/majq1990/app-updater-go/internal/config"
)

// fakeRunner 假远端执行器：本地文件系统 + LineTime 时间窗过滤（等价远端 awk 行为）。
type fakeRunner struct{ root string }

func (f fakeRunner) ExtractLines(abs string, from, to time.Time) (string, error) {
	p := filepath.Join(f.root, filepath.FromSlash(abs))
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", os.ErrNotExist
		}
		return "", err
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		if ts, ok := LineTime(ln); ok {
			if !ts.Before(from) && ts.Before(to) {
				out = append(out, ln)
			}
		}
	}
	return strings.Join(out, "\n"), nil
}

func (f fakeRunner) ReadTail(abs string, n int) (string, error) {
	p := filepath.Join(f.root, filepath.FromSlash(abs))
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", os.ErrNotExist
		}
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n"), nil
}

func (f fakeRunner) FileSize(abs string) (int64, error) {
	st, err := os.Stat(filepath.Join(f.root, filepath.FromSlash(abs)))
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

const gatherLog = `2026-11-05 08:00:00 INFO start ok
2026-11-05 08:30:00 ERROR db timeout
java.sql.SQLTimeoutException: wait 30s
	at com.foo.Bar.run(Bar.java:1)
2026-11-05 09:00:00 INFO recovered
2026-10-01 08:30:00 ERROR very old should not gather
`

func TestGatherFilesWindowAndCount(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	p := filepath.Join(root, "app", "logs", "app.log")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(gatherLog), 0o644); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 5, 10, 0, 0, 0, time.Local)
	tg := Target{Kind: KindApp, Name: "app", KindRaw: "jar",
		Host:     config.Host{Host: "10.0.0.1"},
		LogDirs:  []string{"/app/logs"},
		KeepDays: 30,
	}
	files := []LogFile{{Abs: "/app/logs/app.log", Dir: "/app/logs", Rel: "app.log", Size: int64(len(gatherLog))}}

	r := fakeRunner{root}
	res := GatherFiles(r, files, []Target{tg}, GatherOptions{
		Window:  4 * time.Hour, // [06:00, 10:00)
		OutDir:  out,
		MaxBytes: 1 << 20,
	}, now)

	if len(res.Errs) != 0 {
		t.Fatalf("errs: %v", res.Errs)
	}
	if len(res.Files) != 1 {
		t.Fatalf("files = %d, want 1", len(res.Files))
	}
	gf := res.Files[0]
	// ERROR 行 + Exception 堆栈行都在窗口内（跟随上一行归属）
	if gf.Errors == 0 {
		t.Error("ERROR 计数应 > 0")
	}
	b, _ := os.ReadFile(gf.LocalPath)
	if strings.Contains(string(b), "very old") {
		t.Error("窗口外旧日志被拉取")
	}
	if !strings.Contains(string(b), "db timeout") {
		t.Error("窗口内 ERROR 未被拉取")
	}
	if res.TotalErrors != gf.Errors {
		t.Errorf("TotalErrors 与文件计数不一致")
	}
	if got := res.Summarize(); !strings.Contains(got, "1 个日志文件") {
		t.Errorf("摘要异常: %s", got)
	}
}

func TestGatherCatalinaTail(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	var lines []string
	for i := 0; i < 500; i++ {
		lines = append(lines, fmt.Sprintf("line-%03d some output", i))
	}
	p := filepath.Join(root, "tomcat", "logs", "catalina.out")
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o644)

	tg := Target{Kind: KindApp, Name: "gis", KindRaw: "tomcat",
		Host: config.Host{Host: "10.0.0.2"}, LogDirs: []string{"/tomcat/logs"}, KeepDays: 30}
	files := []LogFile{{Abs: "/tomcat/logs/catalina.out", Dir: "/tomcat/logs", Rel: "catalina.out"}}

	res := GatherFiles(fakeRunner{root}, files, []Target{tg}, GatherOptions{
		Window: 4 * time.Hour, OutDir: out, TailLines: 50,
	}, time.Now())

	if len(res.Files) != 1 || !res.Files[0].NoTS {
		t.Fatalf("catalina.out 应走 tail fallback: %+v", res.Files)
	}
	b, _ := os.ReadFile(res.Files[0].LocalPath)
	if !strings.Contains(string(b), "line-499") {
		t.Error("tail 未取到末尾行")
	}
	if strings.Contains(string(b), "line-400") {
		t.Error("tail 行数超限（应只有 50 行）")
	}
}

func TestGatherMaxBytesTruncates(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	var lines []string
	for i := 0; i < 100; i++ {
		lines = append(lines, "2026-11-05 08:00:00 ERROR blahblahblah")
	}
	p := filepath.Join(root, "app", "logs", "app.log")
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o644)

	tg := Target{Kind: KindApp, Name: "app", KindRaw: "jar",
		Host: config.Host{Host: "h"}, LogDirs: []string{"/app/logs"}}
	files := []LogFile{{Abs: "/app/logs/app.log", Dir: "/app/logs", Rel: "app.log"}}

	res := GatherFiles(fakeRunner{root}, files, []Target{tg}, GatherOptions{
		Window: 24 * time.Hour, OutDir: out, MaxBytes: 100,
	}, time.Now())
	if len(res.Files) != 1 {
		t.Fatalf("files=%d", len(res.Files))
	}
	if !res.Files[0].Truncated || res.Files[0].Bytes != 100 {
		t.Errorf("截断标记/大小错误: %+v", res.Files[0])
	}
}

func TestGatherWhitelistSkip(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	p := filepath.Join(root, "mysql", "data", "mysql-bin.000042")
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte("binlog"), 0o644)

	tg := Target{Kind: KindSupport, KindRaw: "mysql", Name: "mysql",
		Host: config.Host{Host: "h"}, LogDirs: []string{"/mysql/data"}, KeepDays: 15}
	files := []LogFile{{Abs: "/mysql/data/mysql-bin.000042", Dir: "/mysql/data", Rel: "mysql-bin.000042"}}

	res := GatherFiles(fakeRunner{root}, files, []Target{tg}, GatherOptions{
		Window: time.Hour, OutDir: out,
	}, time.Now())
	if len(res.Files) != 0 {
		t.Errorf("binlog 白名单外不应被拉取: %+v", res.Files)
	}
}

func TestBuildAwkScript(t *testing.T) {
	from := time.Date(2026, 11, 5, 6, 0, 0, 0, time.UTC)
	to := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	s := BuildAwkScript(from, to)
	if !strings.Contains(s, fmt.Sprintf("-v F=%d", from.Unix())) || !strings.Contains(s, fmt.Sprintf("-v T=%d", to.Unix())) {
		t.Errorf("awk 脚本 epoch 注入错误:\n%s", s)
	}
	if !strings.Contains(s, "mktime") {
		t.Error("awk 脚本缺时间解析")
	}
}

func TestLineTime(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
	}{
		{"2026-11-05 08:30:00 ERROR x", true},
		{"2026/11/05 08:30:00 warn", true},
		{"[05/Nov/2026:08:30:00 +0800] GET /", true},
		{"no timestamp here", false},
	}
	for _, c := range cases {
		if _, ok := LineTime(c.line); ok != c.ok {
			t.Errorf("LineTime(%q) ok=%v, want %v", c.line, ok, c.ok)
		}
	}
}
