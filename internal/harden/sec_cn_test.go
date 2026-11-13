package harden

import (
	"strings"
	"testing"
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
