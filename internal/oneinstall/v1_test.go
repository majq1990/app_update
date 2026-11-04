package oneinstall

import (
	"testing"

	"github.com/majq1990/app-updater-go/internal/config"
)

// 对齐 oneops shell/tools/init_hosts_from_oneinstall.sh 消费的字段约定。
const sampleV1Conf = `
# 注释行应被忽略
devops_ssh_user=egova
devops_ssh_port=2222
devops_ssh_key=/root/.ssh/deploy_rsa
IP_WEB_MIS=10.1.1.11
IP_WEB_GIS=10.1.1.12
IP_WEB_GIS1=10.1.1.13
IP_WEB_REDIS=10.1.1.14
IP_DB_BIZ=10.1.1.21
IP_DB_BIZ1=10.1.1.22
IP_DB_STAT=10.1.1.23
IP_PROXY=10.1.1.99
`

func TestParseInstallMultiConf(t *testing.T) {
	conf, err := ParseInstallMultiConf([]byte(sampleV1Conf))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if conf["IP_WEB_MIS"] != "10.1.1.11" || conf["devops_ssh_port"] != "2222" {
		t.Fatalf("解析错误: %+v", conf)
	}
	if _, ok := conf["IP_WEB_GIS1"]; !ok {
		t.Fatalf("编号节点键丢失")
	}
	if _, isComment := conf["# 注释行应被忽略"]; isComment {
		t.Fatalf("注释行不应产生键")
	}
}

func TestConvertV1(t *testing.T) {
	conf, err := ParseInstallMultiConf([]byte(sampleV1Conf))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, notes, err := ConvertV1(conf)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	// 全局 SSH 参数来自 devops_*
	if cfg.AnsibleUser != "egova" || cfg.AnsibleSSHPort != 2222 {
		t.Fatalf("全局参数错误: %+v", cfg.Global)
	}

	// eUrbanMIS：主节点
	mis := cfg.AppByName("eUrbanMIS")
	if mis == nil || mis.MiddleType != "tomcat" {
		t.Fatalf("eUrbanMIS 缺失或类型错误")
	}
	if len(mis.Master) != 1 || mis.Master[0].Host != "10.1.1.11" {
		t.Fatalf("MIS master 错误: %+v", mis.Master)
	}
	if mis.Master[0].WebPath != "/egova/web/eUrbanMIS" ||
		mis.Master[0].StartCmd != "systemctl start tomcat-MIS" ||
		mis.Master[0].CheckURI != "/eUrbanMIS/main.htm" {
		t.Fatalf("MIS 约定字段错误: %+v", mis.Master[0])
	}

	// eUrbanGIS：主 + 编号备节点 → update
	gis := cfg.AppByName("eUrbanGIS")
	if gis == nil || len(gis.Master) != 1 || gis.Master[0].Host != "10.1.1.12" {
		t.Fatalf("GIS master 错误: %+v", gis)
	}
	if len(gis.Update) != 1 || gis.Update[0].Host != "10.1.1.13" {
		t.Fatalf("GIS 编号备节点→update 映射错误: %+v", gis.Update)
	}

	// IP_WEB_REDIS / IP_DB_* / IP_PROXY 不生成应用
	if cfg.AppByName("REDIS") != nil || cfg.AppByName("BIZ") != nil {
		t.Fatalf("基础设施键不应生成应用")
	}
	if len(cfg.Webs) != 2 {
		t.Fatalf("应只生成 MIS+GIS 两个应用: %d", len(cfg.Webs))
	}

	// v1 无端口信息：master 端口应为 0，校验必须报错提示补填
	if gis.Master[0].ServicePort != 0 {
		t.Fatalf("v1 端口应为 0: %d", gis.Master[0].ServicePort)
	}
	if iss := cfg.Validate(); !config.HasError(iss) {
		t.Fatalf("v1 初稿端口缺失应触发 error 提示补填")
	}
	if len(notes) == 0 {
		t.Fatalf("应有转换器 notes")
	}
}
