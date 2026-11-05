package logs

// 矩阵软件清理模式测试：信创《拉包打包矩阵》各 kind 的白名单命中/保护。
import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/majq1990/app-updater-go/internal/config"
)

func yamlUnmarshal(c *config.Config) error {
	return yaml.Unmarshal([]byte(`
ansible_user: root
supports:
  - kind: PostgreSQL
    log_dirs: [/egova/pgsql/log]
    hosts: [{host: 10.0.0.1}]
  - kind: pg
    log_dirs: [/egova/pgsql/log]
    hosts: [{host: 10.0.0.2}]
`), c)
}

func matrixTarget(kind string) Target {
	return Target{Kind: KindSupport, KindRaw: kind, Name: kind,
		Host: config.Host{Host: "h"}, LogDirs: []string{"/x"}, KeepDays: 15}
}

func TestMatrixCleanPatterns(t *testing.T) {
	cases := []struct {
		kind  string
		file  string // 相对路径
		hit   bool
		note  string
	}{
		// PostgreSQL：pg_log 命中；WAL/数据文件绝不删
		{"postgres", "postgresql-2026-11-05_000000.log", true, "pg 标准日志"},
		{"postgres", "pg_wal/000000010000000000000001", false, "WAL 绝不删"},
		{"postgres", "base/16384/2619", false, "数据文件绝不删"},
		// Kafka
		{"kafka", "server.log.1", true, "滚动日志"},
		{"kafka", "kafka-request.log", true, "request 日志"},
		{"kafka", "00000000000000000000.index", false, "segment 索引绝不删"},
		{"kafka", "00000000000000000000.log", true, "注：kafka 数据 segment 也叫 .log——目录是 data 根，需靠 exclude_patterns 排除（文档已注明）"},
		// Elasticsearch：慢日志 json 与滚动
		{"elasticsearch", "gc.log.03", true, "GC 日志滚动"},
		{"elasticsearch", "xxx_index_indexing_slowlog.json", true, "索引慢日志"},
		{"elasticsearch", "xxx-2026.11.05.slowlog.json", false, "日期命名但不在模式内——留待模式收敛"},
		// ZooKeeper
		{"zookeeper", "zookeeper-server.log", true, ""},
		{"zookeeper", "version-2/log.1", false, "txnlog 目录保护（transaction.log* 只匹配根级）"},
		// TDengine
		{"tdengine", "taosdlog.0", true, "按序滚动"},
		{"tdengine", "taosdlog", true, "当前日志"},
		// Nacos / MinIO / Docker / ProxySQL / OnlyOffice
		{"nacos", "nacos.log", true, ""},
		{"nacos", "rotated-2026-11-05.log", true, ""},
		{"minio", "minio-2026-11-05.log", true, ""},
		{"docker", "abc123def--json.log", true, "json-file 日志"},
		{"proxysql", "proxysql.log.00000001", true, ""},
		{"onlyoffice", "converterout.log", true, ""},
	}
	for _, tc := range cases {
		tg := matrixTarget(tc.kind)
		got := tg.Candidate(LogFile{Dir: "/x", Rel: tc.file})
		if got != tc.hit {
			t.Errorf("[%s] %s 命中=%v, want %v（%s）", tc.kind, tc.file, got, tc.hit, tc.note)
		}
	}
}

// 别名归一后目标行为一致（postgresql 与 postgres 同一白名单）。
func TestAliasKindSameBehavior(t *testing.T) {
	c := &config.Config{}
	if err := yamlUnmarshal(c); err != nil {
		t.Fatal(err)
	}
	c.Normalize()
	ts := Targets(c)
	var pgCount int
	for _, x := range ts {
		if x.KindRaw == "postgres" {
			pgCount++
		}
	}
	if pgCount != 2 { // PostgreSQL + pg 两段归一后都是 postgres，但仍是两段（去重属 validate 责任）
		t.Fatalf("postgres 目标数 = %d", pgCount)
	}
	// 两段的白名单行为一致
	var first Target
	for _, x := range ts {
		if x.KindRaw == "postgres" {
			first = x
			break
		}
	}
	if !first.Candidate(LogFile{Dir: "/x", Rel: "postgresql-2026-11-05_000000.log"}) {
		t.Error("postgres 白名单不命中")
	}
}
