package config

// 新增配置段（backup / monitor）的 YAML 往返测试：
// 这两段是 v1.4–v1.6 新增、会进远端命令的数据源，必须保证
// 「写出去 → 读回来」字段不丢、默认值回落正确。

import (
	"path/filepath"
	"testing"
)

func TestYAMLRoundTripBackupAndMonitor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	src := &Config{
		Global: Global{AnsibleUser: "root", AnsibleSSHPort: 22},
		Webs: []App{{
			Web: "a", MiddleType: "jar", RetainedConfigFile: []string{"x"},
			Master: []Host{{Host: "10.0.0.1", WebPath: "/egova/a"}},
		}},
		Supports: []Support{{
			Kind: "mysql", Hosts: []Host{{Host: "10.0.0.3"}},
		}, {
			Kind: "redis", BackupPaths: []string{"/egova/apps/redis/data/dump.rdb"},
			Hosts: []Host{{Host: "10.0.0.3"}},
		}},
		Backup: &Backup{
			Root: "/egova/backup", KeepDays: 7,
			Databases: []string{"eurbanpro"}, DumpUser: "backup",
			DumpDefaultsFile: "/root/.my.cnf", Exclude: []string{"tmp/"},
		},
		Monitor: &Monitor{
			Server: "zbx.example.com", ServerPort: 7001,
			AgentPort: 9000, ProxyPort: 9001, YumPort: 8080,
			ProxyHosts: []Host{{Host: "10.0.0.9"}},
			AgentHosts: []Host{{Host: "10.0.0.1"}},
			PSKFile:    "/etc/zabbix/zabbix_agentd.psk",
		},
	}
	if err := src.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Backup == nil || got.Backup.Root != "/egova/backup" || got.Backup.KeepDays != 7 ||
		len(got.Backup.Databases) != 1 || got.Backup.DumpUser != "backup" ||
		got.Backup.DumpDefaultsFile != "/root/.my.cnf" || len(got.Backup.Exclude) != 1 {
		t.Fatalf("backup 段往返丢字段: %+v", got.Backup)
	}
	if got.Monitor == nil || got.Monitor.Server != "zbx.example.com" ||
		got.Monitor.AgentPort != 9000 || got.Monitor.ProxyPort != 9001 ||
		len(got.Monitor.ProxyHosts) != 1 || len(got.Monitor.AgentHosts) != 1 ||
		got.Monitor.PSKFile != "/etc/zabbix/zabbix_agentd.psk" {
		t.Fatalf("monitor 段往返丢字段: %+v", got.Monitor)
	}
	if s := got.SupportByKind("redis"); s == nil || len(s.BackupPaths) != 1 {
		t.Fatalf("supports.backup_paths 往返丢失: %+v", s)
	}
}

func TestEffectiveDefaults(t *testing.T) {
	var b *Backup
	if b.EffectiveRoot() != BackupRootDefault || b.EffectiveKeepDays() != BackupKeepDaysDefault ||
		b.EffectiveDumpUser() != "root" {
		t.Fatal("backup 默认值回落错误")
	}
	var m *Monitor
	if m.EffectiveServer() != MonitorServerDefault || m.EffectiveServerPort() != 7001 ||
		m.EffectiveAgentPort() != 9000 || m.EffectiveProxyPort() != 9001 ||
		m.EffectiveYumPort() != 8080 || m.EffectiveAgentConf() != MonitorAgentConfDefault ||
		m.EffectivePluginDir() != MonitorPluginDirDefault ||
		m.EffectiveScriptDir() != MonitorScriptDirDefault ||
		m.EffectivePSKFile() != MonitorPSKFileDefault {
		t.Fatal("monitor 默认值回落错误")
	}
	// 负保留期按 1 处理
	if (&Backup{KeepDays: -5}).EffectiveKeepDays() != 1 {
		t.Fatal("负 keep_days 应回落为 1")
	}
}
