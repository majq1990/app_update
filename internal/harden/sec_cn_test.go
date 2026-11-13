package harden

import (
	"strings"
	"testing"
	"time"
)

func TestCNEnableScript(t *testing.T) {
	allow, err := cnAllowList([]string{"43.163.81.173/32", "172.21.133.0/24", "bad;rm -rf /", "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if len(allow) != 3 {
		t.Fatalf("非法 CIDR 应被过滤: %v", allow)
	}
	script, err := cnEnableScript(allow)
	if err != nil {
		t.Fatalf("应能生成脚本: %v", err)
	}
	for _, want := range []string{
		"ipset create egova-cn-nets",
		"EOFCN",
		"CN_SET_TOO_SMALL",
		"iptables -A EGOVA-CN-GUARD -j DROP",
		"-m set --match-set egova-cn-allow src -j RETURN",
		"-m set --match-set egova-cn-nets src -j RETURN",
		"iptables -I INPUT 1 -j EGOVA-CN-GUARD",
		"DOCKER-USER",
		"CN_ENABLED=",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("脚本缺少 %q", want)
		}
	}
	if strings.Contains(script, "bad;rm") {
		t.Fatal("非法 CIDR 不应进入脚本")
	}
}

func TestCNCIDRsCount(t *testing.T) {
	n := len(cnCIDRs())
	if n < cnMinEntries {
		t.Fatalf("内置中国网段过少: %d", n)
	}
}

func TestParseBadIPs(t *testing.T) {
	out := "520 203.0.113.99\n" +
		"find: permission denied\n" + // 非数字开头，必须忽略
		"30 198.51.100.7\n" +
		"25 203.0.113.99\n" + // 重复
		"x 8.8.8.8\n" +
		"40 not-an-ip\n"
	ips := parseBadIPs(out)
	if len(ips) != 2 {
		t.Fatalf("应解析出 2 个合法 IP，实际 %v", ips)
	}
	if ips[0] != "203.0.113.99" || ips[1] != "198.51.100.7" {
		t.Fatalf("解析结果/顺序错误: %v", ips)
	}
}

func TestPublishedHostPorts(t *testing.T) {
	got := publishedHostPorts("0.0.0.0:8848->8848/tcp, 0.0.0.0:2379-2380->2379-2380/tcp, 127.0.0.1:9999->9999/tcp")
	want := []string{"8848", "2379", "2380"}
	if len(got) != len(want) {
		t.Fatalf("端口解析错误: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("端口解析错误: %v", got)
		}
	}
}

func TestFixesSkipWithoutInstances(t *testing.T) {
	fr := fakeSecRunner{}
	withFakeHost(t, "h1", fr)
	r := NewSecReport("fix", []string{"h1"}, time.Now())
	if err := RunTomcatFix("h1", r, true); err != nil {
		t.Fatalf("无 tomcat 实例应跳过而不是报错: %v", err)
	}
	if err := RunNginxFix("h1", r, true); err != nil {
		t.Fatalf("无 nginx 应跳过而不是报错: %v", err)
	}
}
