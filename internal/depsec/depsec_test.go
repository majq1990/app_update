package depsec

import (
	"os"
	"strings"
	"testing"
)

func TestParseSummary(t *testing.T) {
	rep := "# 三方依赖安全检查报告\n\n- 主机：node3\n- 结论：高危/需处理 **68** 项，待复核 7 项，正常 162 项，其他 0 项\n\n| 类别 |"
	s := ParseSummary(rep)
	if s.High != 68 || s.Review != 7 || s.OK != 162 {
		t.Fatalf("解析结果不符: %+v", s)
	}
	if s.Raw == "" {
		t.Fatal("Raw 应保留结论行")
	}
}

func TestParseSummaryEmpty(t *testing.T) {
	s := ParseSummary("no summary here")
	if s.High != 0 || s.Review != 0 || s.OK != 0 {
		t.Fatalf("无结论行时应全 0: %+v", s)
	}
}

func TestSplitRC(t *testing.T) {
	out := "第一行\n" + RCMarker + "1\n第三行\n"
	body, rc, ok := SplitRC(out)
	if !ok || rc != 1 {
		t.Fatalf("rc 解析失败: rc=%d ok=%v", rc, ok)
	}
	if strings.Contains(body, RCMarker) {
		t.Fatal("正文不应保留标记行")
	}
	if !strings.Contains(body, "第一行") || !strings.Contains(body, "第三行") {
		t.Fatalf("正文被破坏: %q", body)
	}
}

func TestWrapConstantExit(t *testing.T) {
	cmd := Wrap("bash x.sh")
	if !strings.Contains(cmd, "exit 0") || !strings.Contains(cmd, RCMarker) {
		t.Fatalf("Wrap 应恒定退出并打标记: %s", cmd)
	}
}

func TestMaterializeAndFlatCount(t *testing.T) {
	dir := t.TempDir()
	files, err := Materialize(dir)
	if err != nil {
		t.Fatalf("Materialize 失败: %v", err)
	}
	for _, name := range []string{"scan_secure_deps.sh", "query_secure_version.sh", "fetch_secure_artifact.sh", "conf/secure-versions.flat"} {
		p, ok := files[name]
		if !ok {
			t.Fatalf("缺少资产 %s", name)
		}
		st, err := os.Stat(p)
		if err != nil || st.Size() == 0 {
			t.Fatalf("资产 %s 落盘异常: %v", name, err)
		}
	}
	if n := FlatCount(); n < 80 {
		t.Fatalf("清单条目数异常: %d", n)
	}
}

func TestCommandsQuoted(t *testing.T) {
	c := QueryCommand("a b'c")
	if !strings.Contains(c, "query_secure_version.sh") || !strings.Contains(c, `'\''`) {
		t.Fatalf("单引号未转义: %s", c)
	}
	f := FetchCommand("redis", true)
	if !strings.Contains(f, "--download") || !strings.Contains(f, "artifacts") {
		t.Fatalf("fetch 命令不符: %s", f)
	}
}
