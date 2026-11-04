package oneinstall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/majq1990/app-updater-go/internal/config"
)

// 用从 8.160.174.228 拉取的真实 inventory 做夹具（部署完成后的终态快照，断言须状态无关）。
func loadRealInventory(t *testing.T) Inventory {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "oneinstall")
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Skipf("缺少真实夹具 %s: %v", name, err)
		}
		return b
	}
	return Inventory{
		Hosts:           read("hosts.yml"),
		MultiServer:     read("eurbanpro_multi_server.yml"),
		MultiServerBase: read("multi_server.yml"),
		Metadata:        read("metadata.yml"),
	}
}

// 合成夹具：验证 success 过滤 / WAR 单元命名 / IM 跳过语义（确定性，不依赖线上部署进度）。
const syntheticMetadata = `
service:
  eUrbanUMA:
    eUrbanUMA_1:
      name: 运管服
      biz_type: UMA
      server_port: 8081
      base_path: /egova/web
      status: success
      host: n1
      ip: 10.0.0.1
  warPending:
    warPending_1:
      server_port: 8082
      base_path: /egova/web
      status: undeployed
      host: n1
      ip: 10.0.0.1
  warNoBiz:
    warNoBiz_1:
      server_port: 8083
      base_path: /egova/web
      status: success
      host: n1
      ip: 10.0.0.1
microservice:
  IM:
    IM_1:
      server_port: 16030
      base_path: /egova/apps/basic/IM
      status: success
      host: n1
      ip: 10.0.0.1
  jarApp:
    jarApp_1:
      server_port: 16000
      base_path: /egova/apps/basic/jarApp
      status: success
      host: n2
      ip: 10.0.0.2
  jarMulti:
    jarMulti_1:
      server_port: 16001
      base_path: /egova/apps/basic/jarMulti
      status: success
      host: n2
      ip: 10.0.0.2
  jarDup:
    jarDup_1:
      server_port: 16002
      base_path: /egova/apps/basic/jarDup
      status: success
      host: n2
      ip: 10.0.0.2
    jarDup_2:
      server_port: 16002
      base_path: /egova/apps/basic/jarDup
      status: success
      host: n1
      ip: 10.0.0.1
  jarSame:
    jarSame_1:
      server_port: 16003
      base_path: /egova/apps/basic/jarSame
      status: success
      host: n1
      ip: 10.0.0.1
    jarSame_2:
      server_port: 16004
      base_path: /egova/apps/basic/jarSame
      status: success
      host: n1
      ip: 10.0.0.1
`

const syntheticHosts = `
all:
  hosts:
    n1:
      ansible_ssh_host: 10.0.0.1
      ansible_ssh_port: "22"
    n2:
      ansible_ssh_host: 10.0.0.2
      ansible_ssh_port: "2222"
`

const syntheticMulti = `
ip_web_a:
  name: A
  modules:
    - type: service
      sub_type: warApp
    - type: service
      sub_type: warPending
    - type: microservice
      sub_type: jarApp
  hosts:
    master: n2
    slave: n1
ip_web_b:
  name: B
  modules:
    - type: service
      sub_type: warNoBiz
  hosts:
    master: n1
    slave: []
ip_web_c:
  name: C
  modules:
    - type: microservice
      sub_type: jarMulti
  hosts:
    master: n2
    slave:
      - n1
ip_web_jardup:
  name: D
  modules:
    - type: microservice
      sub_type: jarDup
  hosts:
    master: n2
    slave: []
ip_web_jarsame:
  name: E
  modules:
    - type: microservice
      sub_type: jarSame
  hosts:
    master: n1
    slave: []
`

func syntheticInventory() Inventory {
	return Inventory{
		Hosts:       []byte(syntheticHosts),
		MultiServer: []byte(syntheticMulti),
		Metadata:    []byte(syntheticMetadata),
	}
}

// 默认只收 success；--include-undeployed 全收；slave→update 映射；WAR 单元命名；IM 跳过。
func TestConvertSyntheticFilterAndMapping(t *testing.T) {
	inv := syntheticInventory()

	def, notes, err := Convert(inv, Options{})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	// success: warApp + warNoBiz + jarApp + jarMulti + jarDup + jarSame；IM 跳过、warPending undeployed
	if len(def.Webs) != 6 {
		t.Fatalf("默认应收 6 个应用（IM 跳过、undeployed 过滤）, got %d: %+v", len(def.Webs), def.Webs)
	}
	if def.AppByName("warPending") != nil {
		t.Fatalf("undeployed 应用不应出现")
	}
	if def.AppByName("IM") != nil {
		t.Fatalf("IM（docker-compose 多进程）应跳过")
	}

	all, _, err := Convert(inv, Options{IncludeUndeployed: true})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(all.Webs) != 7 {
		t.Fatalf("全量应收 7 个应用（IM 仍跳过）, got %d", len(all.Webs))
	}

	// WAR：unit = tomcat-<biz_type>，保留配置对齐 tomcat_app role 模板清单
	//（eUrbanUMA 在 role 扩展清单内，应有 5 个保留配置）
	war := def.AppByName("eUrbanUMA")
	if war == nil || war.MiddleType != "tomcat" {
		t.Fatalf("eUrbanUMA 缺失或类型错误")
	}
	if war.Master[0].StartCmd != "systemctl start tomcat-UMA" ||
		war.Master[0].StopCmd != "systemctl stop tomcat-UMA" {
		t.Fatalf("WAR unit 命名错误: %s / %s", war.Master[0].StartCmd, war.Master[0].StopCmd)
	}
	wantRetained := []string{
		"WEB-INF/classes/jdbc.properties", "WEB-INF/classes/redis.properties",
		"WEB-INF/classes/timeseries.properties", "WEB-INF/classes/postgres.properties",
		"WEB-INF/classes/kafka.properties",
	}
	if len(war.RetainedConfigFile) != len(wantRetained) {
		t.Fatalf("WAR 保留配置错误: %v", war.RetainedConfigFile)
	}
	for i, f := range wantRetained {
		if war.RetainedConfigFile[i] != f {
			t.Fatalf("WAR 保留配置[%d]错误: %s", i, war.RetainedConfigFile[i])
		}
	}

	// 缺 biz_type 的 WAR：按应用名回退并提示
	noBiz := def.AppByName("warNoBiz")
	if noBiz == nil || noBiz.Master[0].StartCmd != "systemctl start warNoBiz" {
		t.Fatalf("缺 biz_type 回退错误: %+v", noBiz)
	}
	foundBizWarn := false
	for _, n := range notes {
		if n.Where == "metadata>warNoBiz" && strings.Contains(n.Msg, "biz_type") {
			foundBizWarn = true
		}
	}
	if !foundBizWarn {
		t.Fatalf("缺 biz_type 应有 warn 提示: %+v", notes)
	}

	jar := def.AppByName("jarApp")
	if jar == nil {
		t.Fatalf("jarApp 缺失")
	}
	// 旧版标量 slave 写法（master=n2/10.0.0.2，slave=n1/10.0.0.1）
	if len(jar.Update) != 1 || jar.Update[0].Host != "10.0.0.1" {
		t.Fatalf("slave→update 映射错误: %+v", jar.Update)
	}
	if jar.Update[0].SSHPort != 22 {
		t.Fatalf("slave SSH 端口错误: %d", jar.Update[0].SSHPort)
	}
	if len(jar.Master) != 1 || jar.Master[0].Host != "10.0.0.2" {
		t.Fatalf("jarApp master 错误: %+v", jar.Master)
	}
	if !strings.HasPrefix(jar.Master[0].StartCmd, "systemctl start jarApp") {
		t.Fatalf("unit 命名错误: %s", jar.Master[0].StartCmd)
	}

	// 新版列表 slave：备节点逐台进入 update 群组
	jm := def.AppByName("jarMulti")
	if jm == nil {
		t.Fatalf("jarMulti 缺失")
	}
	if len(jm.Update) != 1 || jm.Update[0].Host != "10.0.0.1" {
		t.Fatalf("备节点映射错误: %+v", jm.Update)
	}
	if len(jm.Master) != 1 || jm.Master[0].Host != "10.0.0.2" {
		t.Fatalf("jarMulti master 错误: %+v", jm.Master)
	}
	// 空列表 slave（新版写法）：不生成 update
	nb := def.AppByName("warNoBiz")
	if nb == nil || len(nb.Update) != 0 {
		t.Fatalf("slave:[] 不应生成 update 群组: %+v", nb)
	}

	// 多实例应用（跨机主备）：合并为一个 App，单元名 = sub_type（实机验证），主→master 从→update
	dup := def.AppByName("jarDup")
	if dup == nil {
		t.Fatalf("jarDup 缺失")
	}
	if len(dup.Master) != 1 || dup.Master[0].Host != "10.0.0.2" ||
		dup.Master[0].StartCmd != "systemctl start jarDup" {
		t.Fatalf("多实例 master 错误: %+v", dup.Master)
	}
	if len(dup.Update) != 1 || dup.Update[0].Host != "10.0.0.1" ||
		dup.Update[0].StartCmd != "systemctl start jarDup" {
		t.Fatalf("多实例 update 错误: %+v", dup.Update)
	}
	wantDupRetained := []string{"jarDup.env", "application.properties"}
	if len(dup.RetainedConfigFile) != len(wantDupRetained) {
		t.Fatalf("多实例保留配置错误: %v", dup.RetainedConfigFile)
	}
	for i, f := range wantDupRetained {
		if dup.RetainedConfigFile[i] != f {
			t.Fatalf("保留配置[%d]错误: %s", i, dup.RetainedConfigFile[i])
		}
	}

	// 同机多实例：单元名才需要 sub_type_N 区分
	same := def.AppByName("jarSame")
	if same == nil {
		t.Fatalf("jarSame 缺失")
	}
	if len(same.Master) != 1 || !strings.Contains(same.Master[0].StartCmd, "jarSame_1") {
		t.Fatalf("同机多实例 master 单元名错误: %+v", same.Master)
	}
	if len(same.Update) != 1 || !strings.Contains(same.Update[0].StartCmd, "jarSame_2") {
		t.Fatalf("同机多实例 update 单元名错误: %+v", same.Update)
	}

	if iss := def.Validate(); config.HasError(iss) {
		t.Fatalf("合成配置自检失败: %+v", iss)
	}
}

// 真实夹具：结构映射断言（不依赖部署进度）。
func TestConvertRealInventoryStructure(t *testing.T) {
	cfg, notes, err := Convert(loadRealInventory(t), Options{IncludeUndeployed: true})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	gis := cfg.AppByName("eUrbanGIS")
	if gis == nil {
		t.Fatalf("缺少 eUrbanGIS")
	}
	if gis.MiddleType != "tomcat" {
		t.Fatalf("eUrbanGIS 应为 tomcat, got %s", gis.MiddleType)
	}
	if len(gis.Master) != 1 || gis.Master[0].Host != "172.21.133.222" {
		t.Fatalf("eUrbanGIS master 不符: %+v", gis.Master)
	}
	if gis.Master[0].WebPath != "/egova/web/eUrbanGIS" {
		t.Fatalf("WAR 路径拼接错误: %s", gis.Master[0].WebPath)
	}
	if gis.Master[0].ServicePort != 8085 {
		t.Fatalf("端口错误: %d", gis.Master[0].ServicePort)
	}
	// 实机核对（node2 上为 tomcat-GIS.service）：WAR unit = tomcat-<biz_type>
	if gis.Master[0].StartCmd != "systemctl start tomcat-GIS" {
		t.Fatalf("启动命令错误: %s", gis.Master[0].StartCmd)
	}
	if gis.Master[0].CheckURI != "/eUrbanGIS/" {
		t.Fatalf("WAR check_uri 错误（应为上下文根）: %s", gis.Master[0].CheckURI)
	}
	// GIS 不在 MIS/UMA/MF/SG 扩展清单：只有 jdbc/redis 两个保留配置
	if len(gis.RetainedConfigFile) != 2 ||
		gis.RetainedConfigFile[0] != "WEB-INF/classes/jdbc.properties" {
		t.Fatalf("WAR 保留配置错误: %v", gis.RetainedConfigFile)
	}
	// WAR 自动配置 liquibase 排除（备节点不推 + 更新时自动清理）
	if len(gis.MasterExclusiveFiles) != 2 ||
		gis.MasterExclusiveFiles[0] != "egova-liquibase-*.jar" ||
		gis.MasterExclusiveFiles[1] != "liquibase-core-*.jar" {
		t.Fatalf("WAR 应自动配置 liquibase 排除: %v", gis.MasterExclusiveFiles)
	}
	// eUrbanGIS 自动排除 tilemap（切片缓存体积巨大，不备份不更新）
	if len(gis.ExcludePaths) != 1 || gis.ExcludePaths[0] != "tilemap/" {
		t.Fatalf("eUrbanGIS 应自动排除 tilemap/: %v", gis.ExcludePaths)
	}
	// 其他 WAR 不应带 tilemap 排除
	if uma := cfg.AppByName("eUrbanUMA"); uma != nil && len(uma.ExcludePaths) != 0 {
		t.Fatalf("eUrbanUMA 不应有 exclude_paths: %v", uma.ExcludePaths)
	}

	ep := cfg.AppByName("eurbanpro")
	if ep == nil || ep.MiddleType != "jar" {
		t.Fatalf("eurbanpro 缺失或类型错误: %+v", ep)
	}
	if ep.Master[0].WebPath != "/egova/apps/basic/eurbanpro" {
		t.Fatalf("JAR 路径错误: %s", ep.Master[0].WebPath)
	}
	if ep.Master[0].StartCmd != "systemctl start eurbanpro" {
		t.Fatalf("JAR 启动命令错误: %s", ep.Master[0].StartCmd)
	}
	if len(ep.RetainedConfigFile) != 2 || ep.RetainedConfigFile[0] != "eurbanpro.env" {
		t.Fatalf("JAR 保留配置错误: %v", ep.RetainedConfigFile)
	}
	// 一键部署标准健康检查地址（核心 Java 服务 backend 探针，现场实测 200）
	if ep.Master[0].CheckURI != "/eurbanpro-api/free/sysconfig/get-all-free-config" {
		t.Fatalf("JAR 标准 check_uri 错误: %q", ep.Master[0].CheckURI)
	}
	if ep.Master[0].User != "egova" || ep.Master[0].Group != "egova" {
		t.Fatalf("属主错误: %+v", ep.Master[0])
	}

	// IM（docker-compose 多进程）必须跳过且给出提示
	if cfg.AppByName("IM") != nil {
		t.Fatalf("IM 应跳过（无 systemd 单元）")
	}

	// 双实例应用（usercenter 主备）：合并为一个 App（主→master，从→update）；
	// 实机验证：跨机主备两台的 systemd 单元与 EnvironmentFile 都叫 usercenter（不带 _N）
	uc := cfg.AppByName("usercenter")
	if uc == nil {
		t.Fatalf("usercenter 缺失")
	}
	if len(uc.Master) != 1 || uc.Master[0].Host != "172.21.133.222" {
		t.Fatalf("usercenter master 不符（应为 node2 主实例）: %+v", uc.Master)
	}
	if uc.Master[0].StartCmd != "systemctl start usercenter" {
		t.Fatalf("usercenter 单元名错误（实机为 usercenter）: %s", uc.Master[0].StartCmd)
	}
	if uc.Master[0].CheckURI != "/usercenter-api/free/application/check" {
		t.Fatalf("usercenter 标准 check_uri 错误: %q", uc.Master[0].CheckURI)
	}
	if len(uc.Update) != 1 || !strings.Contains(uc.Update[0].Remark, "(slave)") {
		t.Fatalf("usercenter 从实例应进 update 群组: %+v", uc.Update)
	}
	wantUcRetained := map[string]bool{"usercenter.env": true, "application.properties": true}
	if len(uc.RetainedConfigFile) != len(wantUcRetained) {
		t.Fatalf("双实例保留配置应合并为 usercenter.env + application.properties: %v", uc.RetainedConfigFile)
	}
	for _, f := range uc.RetainedConfigFile {
		if !wantUcRetained[f] {
			t.Fatalf("保留配置含意外项: %v", uc.RetainedConfigFile)
		}
	}

	foundIMNote := false
	for _, n := range notes {
		if strings.Contains(n.Msg, "IM") && strings.Contains(n.Msg, "docker-compose") {
			foundIMNote = true
		}
	}
	if !foundIMNote {
		t.Fatalf("IM 跳过应有说明: %+v", notes)
	}

	if iss := cfg.Validate(); config.HasError(iss) {
		t.Fatalf("生成配置自检失败: %+v", iss)
	}
}

// 真实夹具：默认模式结果必须是全量模式的子集，且跳过数一致。
func TestConvertRealInventoryDefaultSubset(t *testing.T) {
	inv := loadRealInventory(t)
	all, _, err := Convert(inv, Options{IncludeUndeployed: true})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	def, notes, err := Convert(inv, Options{})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(def.Webs) > len(all.Webs) {
		t.Fatalf("默认结果(%d)不应多于全量(%d)", len(def.Webs), len(all.Webs))
	}
	if len(def.Webs) < len(all.Webs) {
		found := false
		for _, n := range notes {
			if strings.Contains(n.Msg, "undeployed") {
				found = true
			}
		}
		if !found {
			t.Fatalf("过滤生效时必须给出 undeployed 提示, notes=%+v", notes)
		}
	}
	// 校验 metadata 解析通道没有被 flexInt/空键问题卡死
	var probe map[string]interface{}
	if err := yaml.Unmarshal([]byte(`a: 1`), &probe); err != nil {
		t.Fatalf("yaml 通道异常: %v", err)
	}
}
