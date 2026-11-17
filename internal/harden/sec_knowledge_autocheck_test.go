package harden

import (
	"strings"
	"testing"
)

const testVulnJarJSON = `some progress line
 {"vulnerable_jar_check": {"vulnerable_jars": [
   {"jar_path": "/egova/apps/a/fastjson-1.2.62.jar", "jar_filename": "fastjson-1.2.62.jar",
    "jar_name": "fastjson", "current_version": "1.2.62", "minimum_safe_version": "1.2.83"}
 ], "scan_summary": {"total_vulnerabilities": 1}}, "scan_time": "2026-11-17 00:00:00"}`

func TestParseVulnJarAutocheck(t *testing.T) {
	items, warn, err := ParseVulnJarAutocheck([]byte(testVulnJarJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if warn != "" {
		t.Fatalf("unexpected warn: %s", warn)
	}
	if len(items) != 1 || items[0].Short != "fastjson" || items[0].Version != "1.2.62" {
		t.Fatalf("items: %+v", items)
	}
}

const testInspectReport = `{"results": [{"check": "ac-vulnerable-jar",
 "metrics": [{"name": "vulnerable_jars", "value": "3"}]}]}`

func TestParseVulnJarInspectReport(t *testing.T) {
	items, warn, err := ParseVulnJarAutocheck([]byte(testInspectReport))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(items) != 0 || !strings.Contains(warn, "3") {
		t.Fatalf("items=%v warn=%q", items, warn)
	}
}

const testPortJSON = `{"basic": {}, "topics": {
 "01:port_security_checks": [{"01:ipset_egova_vpc_nets_status::X": "YES",
   "02:ipset_egova_local_ports_status::X": "YES",
   "03:ipset_egova_expose_ports_status::X": "NO",
   "04:vpc_access_rule::X": "YES",
   "05:exposed_ports_rule::X": "YES",
   "06:local_ports_config::X": "YES",
   "07:default_drop_rule::X": "NO",
   "08:ipset_services_enabled::X": "YES",
   "09:firewalld_disabled::X": "YES",
   "06:vpc_nets_count::X": "5"}],
 "02:port_security_details": [{"01:vpc_networks::X": "172.21.133.0/24",
   "02:local_ports::X": "3306,8080", "03:exposed_ports::X": "8080"}]}}`

func TestParsePortTopics(t *testing.T) {
	m, err := ParsePortTopics([]byte(testPortJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m["ipset_egova_expose_ports_status"] != "NO" {
		t.Fatalf("expose: %v", m)
	}
	if m["vpc_nets_count"] != "5" || m["exposed_ports"] != "8080" {
		t.Fatalf("details: %v", m)
	}
}

func TestDepAutocheckVerdict(t *testing.T) {
	r := NewSecReport("knowledge", []string{"h1"}, testNow())
	items := []JarHit{{Path: "/x/fastjson-1.2.62.jar", Short: "fastjson", Version: "1.2.62"}}
	RunKnowledgeDepAutocheck("h1", items, KnowledgeDepOptions{}, r)
	if len(r.Findings) != 1 || r.Findings[0].Level != SecCritical {
		t.Fatalf("findings: %+v", r.Findings)
	}
}
