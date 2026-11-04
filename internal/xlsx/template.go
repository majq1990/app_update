// Package xlsx 负责 Excel 配置模板的生成、导入与反向导出。
// 工作簿布局：全局设置 / 应用清单 / 主机清单 / 填写说明 四个 sheet。
package xlsx

import (
	"strings"

	"github.com/xuri/excelize/v2"
)

// Sheet 名称常量，导入与导出共用，防止漂移。
const (
	SheetGlobal = "全局设置"
	SheetApps   = "应用清单"
	SheetHosts  = "主机清单"
	SheetNotes  = "填写说明"
)

// 示例行前缀：导入时自动忽略。
const ExamplePrefix = "示例-"

var (
	hdrFill = excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"1F4E79"}}
	hdrFont = &excelize.Font{Bold: true, Color: "FFFFFF", Size: 11}
	exFill  = excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"F2F2F2"}}
	keyFill = excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"DDEBF7"}}
	border  = []excelize.Border{
		{Type: "left", Style: 1, Color: "BFBFBF"}, {Type: "right", Style: 1, Color: "BFBFBF"},
		{Type: "top", Style: 1, Color: "BFBFBF"}, {Type: "bottom", Style: 1, Color: "BFBFBF"},
	}
	center  = &excelize.Alignment{Horizontal: "center", Vertical: "center", WrapText: true}
	wrapTop = &excelize.Alignment{Vertical: "center", WrapText: true}
)

// appColumns / hostColumns 两张明细表的列布局。
var appColumns = []struct {
	title string
	width float64
}{
	{"应用名称", 20}, {"中间件类型", 13}, {"应用日志目录(相对部署路径)", 26},
	{"保留配置文件(相对部署路径)", 32}, {"Master专属排除文件", 26}, {"备注", 50},
}

var hostColumns = []struct {
	title string
	width float64
}{
	{"应用名称", 20}, {"群组", 9}, {"主机IP", 14}, {"SSH端口", 9}, {"SSH用户", 10},
	{"部署路径(绝对)", 34}, {"服务端口", 10}, {"健康检查URI", 24},
	{"启动命令", 28}, {"停止命令", 28}, {"文件属主用户", 14}, {"文件属主组", 14}, {"备注", 24},
}

// globalRows 全局设置的键值行。
var globalRows = []struct{ key, value, desc string }{
	{"ansible_user", "root", "SSH 登录用户名（主机清单里可按主机覆盖）"},
	{"ansible_ssh_port", "22", "默认 SSH 端口（主机清单里可按主机覆盖）"},
	{"ansible_ssh_pass", "", "SSH 密码。强烈建议留空走免密；工具可帮你推送公钥"},
	{"global_exclude_logs", "*.log,logs/", "全局排除的日志模式，备份/更新时跳过，逗号分隔"},
	{"tomcat_check_minutes", "20", "tomcat 应用健康检查预算（分钟）；大站 WAR 启动慢可调大，0=默认20"},
	{"jar_check_minutes", "5", "jar 应用健康检查预算（分钟）；大 jar 启动慢可调大，0=默认5"},
}

// BuildTemplate 在空白工作簿上写出带示例行的模板。
func BuildTemplate(f *excelize.File) error {
	if err := writeLayout(f); err != nil {
		return err
	}
	if err := writeExampleRows(f); err != nil {
		return err
	}
	if err := writeNotes(f); err != nil {
		return err
	}
	return writeValidations(f)
}

func writeLayout(f *excelize.File) error {
	// 把默认 Sheet1 改名为全局设置，再建其余三张。
	if err := f.SetSheetName("Sheet1", SheetGlobal); err != nil {
		return err
	}
	for _, s := range []string{SheetApps, SheetHosts, SheetNotes} {
		if _, err := f.NewSheet(s); err != nil {
			return err
		}
	}

	// ---- 全局设置 ----
	if err := f.MergeCell(SheetGlobal, "A1", "C1"); err != nil {
		return err
	}
	f.SetCellValue(SheetGlobal, "A1", "全局设置（所有应用共用；值列修改后保存，导入工具时生效）")
	setTitleStyle(f, SheetGlobal, 3)
	for i, h := range []string{"配置项", "值", "说明"} {
		cell, _ := excelize.CoordinatesToCellName(i+1, 2)
		f.SetCellValue(SheetGlobal, cell, h)
	}
	setHeaderStyle(f, SheetGlobal, 3, 2)
	for r, row := range globalRows {
		rn := r + 3
		f.SetCellValue(SheetGlobal, cellName(1, rn), row.key)
		f.SetCellValue(SheetGlobal, cellName(2, rn), row.value)
		f.SetCellValue(SheetGlobal, cellName(3, rn), row.desc)
		id, _ := f.NewStyle(&excelize.Style{
			Alignment: wrapTop, Border: border,
			Fill: keyFill, Font: &excelize.Font{Bold: true},
		})
		f.SetCellStyle(SheetGlobal, cellName(1, rn), cellName(1, rn), id)
		id2, _ := f.NewStyle(&excelize.Style{Alignment: wrapTop, Border: border})
		f.SetCellStyle(SheetGlobal, cellName(2, rn), cellName(3, rn), id2)
	}
	freeze(f, SheetGlobal, "A3")
	for i, w := range []float64{22, 24, 66} {
		col, _ := excelize.ColumnNumberToName(i + 1)
		f.SetColWidth(SheetGlobal, col, col, w)
	}

	// ---- 应用清单 ----
	if err := f.MergeCell(SheetApps, "A1", cellName(len(appColumns), 1)); err != nil {
		return err
	}
	f.SetCellValue(SheetApps, "A1", "应用清单（一个应用一行；带「示例」字样的行导入时会被忽略，参照格式填写）")
	setTitleStyle(f, SheetApps, len(appColumns))
	for i, c := range appColumns {
		f.SetCellValue(SheetApps, cellName(i+1, 2), c.title)
	}
	setHeaderStyle(f, SheetApps, len(appColumns), 2)
	for i, c := range appColumns {
		col, _ := excelize.ColumnNumberToName(i + 1)
		f.SetColWidth(SheetApps, col, col, c.width)
	}
	freeze(f, SheetApps, "A3")

	// ---- 主机清单 ----
	if err := f.MergeCell(SheetHosts, "A1", cellName(len(hostColumns), 1)); err != nil {
		return err
	}
	f.SetCellValue(SheetHosts, "A1", "主机清单（一个 应用×群组×主机 一行；static 群组=静态页面/nginx 服务器，服务端口和启停命令可留空）")
	setTitleStyle(f, SheetHosts, len(hostColumns))
	for i, c := range hostColumns {
		f.SetCellValue(SheetHosts, cellName(i+1, 2), c.title)
	}
	setHeaderStyle(f, SheetHosts, len(hostColumns), 2)
	for i, c := range hostColumns {
		col, _ := excelize.ColumnNumberToName(i + 1)
		f.SetColWidth(SheetHosts, col, col, c.width)
	}
	freeze(f, SheetHosts, "C3")
	return nil
}

func writeExampleRows(f *excelize.File) error {
	apps := [][]interface{}{
		{ExamplePrefix + "eUrbanMIS", "tomcat", "WEB-INF/log",
			"WEB-INF/classes/jdbc.properties,WEB-INF/classes/redis.properties",
			"egova-liquibase-[0-9]*.jar,egova-jobmanager-[0-9]*.jar", "WAR 包应用；排除文件仅 tomcat 生效"},
		{ExamplePrefix + "gisserver", "jar", "logs/", "gisserver.env,jvm/", "", "JAR 应用；保留配置是启动关键"},
	}
	for r, vals := range apps {
		for c, v := range vals {
			f.SetCellValue(SheetApps, cellName(c+1, r+3), v)
		}
		setExampleStyle(f, SheetApps, len(appColumns), r+3)
	}

	hosts := [][]interface{}{
		{ExamplePrefix + "eUrbanMIS", "master", "10.2.0.172", 22, "root", "/egova/web/eUrbanMIS",
			8081, "/eUrbanMIS/main.htm", "systemctl start tomcat-MIS", "systemctl stop tomcat-MIS", "egova", "egova", "tomcat 主节点"},
		{ExamplePrefix + "eUrbanMIS", "update", "10.2.0.173", 22, "root", "/egova/web/eUrbanMIS",
			8081, "/eUrbanMIS/main.htm", "systemctl start tomcat-MIS", "systemctl stop tomcat-MIS", "egova", "egova", ""},
		{ExamplePrefix + "eUrbanMIS", "static", "10.2.0.172", 22, "root", "/egova/web/nginx_deploy/eUrbanMIS",
			"", "", "", "", "nginx", "nginx", "静态页面服务器"},
		{ExamplePrefix + "gisserver", "master", "10.2.0.180", 22, "root", "/egova/web/egovagisserver/gisserver",
			8090, "/gisserver/health", "systemctl start gisserver", "systemctl stop gisserver", "egova", "egova", "JAR 应用"},
	}
	for r, vals := range hosts {
		for c, v := range vals {
			f.SetCellValue(SheetHosts, cellName(c+1, r+3), v)
		}
		setExampleStyle(f, SheetHosts, len(hostColumns), r+3)
	}
	return nil
}

func writeNotes(f *excelize.File) error {
	notes := []string{
		"【整体规则】",
		"1. 「示例-」开头的行仅作参考，导入时自动忽略；正式数据不要以「示例-」开头。",
		"2. 应用清单里的应用名称 = 主机清单里的应用名称（严格一致），主机清单按应用名称关联。",
		"3. 每个应用在主机清单中至少要有一行 master 群组主机；update/static 群组可选。",
		"4. 逗号分隔的多值（排除/保留规则）内不要有空格，如：gisserver.env,jvm/",
		"",
		"【各列说明】",
		"· 中间件类型：tomcat（WAR 包）/ jar（直接运行）。",
		"· 应用日志目录：相对部署路径，如 logs/，备份与更新时排除，不会被删。",
		"· 保留配置文件：相对部署路径，多个用逗号分隔，如 gisserver.env,jvm/ —— JAR 应用更新保命项。",
		"· Master专属排除文件：仅 tomcat 生效；不该随 WAR 更新的 jar（数据库驱动等），相对部署路径。",
		"· 群组：master（主节点）/ update（更新节点）/ static（静态页面 nginx 服务器）。",
		"· SSH端口/SSH用户：留空则使用全局设置，可按主机覆盖。",
		"· 部署路径：服务器上的绝对路径，tomcat 一般为 .../webapps/应用名，jar 为 jar 所在目录。",
		"· 健康检查URI：只填相对路径（如 /eUrbanUMA/main.htm）。填写=启动后轮询 HTTP 200 验证；",
		"  留空=默认按服务端口做 TCP 端口探测（一键部署标准做法，端口通即视为启动完成）。",
		"· 健康检查执行位置（health_mode，YAML 字段）：留空/local=工具所在机发起；",
		"  remote=经 SSH 在目标机本地探测（服务器间端口不通时的推荐做法）；none=显式跳过检查。",
		"· 文件属主用户/组：更新后执行 chown -R user:group 部署路径。",
		"",
		"【工作流】",
		"1. 填完三个 sheet 后执行：app-updater import -f 本文件.xlsx",
		"2. 工具校验（必填/IP格式/应用关联/群组完整性），有问题会逐行列出。",
		"3. 校验通过生成 config.yaml，后续更新/回滚流程与旧版一致（模拟→确认→执行）。",
		"4. 也可以 app-updater export 把现有 config.yaml 反向导出成 Excel，人工核对后再改。",
	}
	for r, line := range notes {
		cell := cellName(1, r+1)
		f.SetCellValue(SheetNotes, cell, line)
		if strings.HasPrefix(line, "【") {
			id, _ := f.NewStyle(&excelize.Style{Font: &excelize.Font{Bold: true, Size: 12, Color: "1F4E79"}})
			f.SetCellStyle(SheetNotes, cell, cell, id)
		}
	}
	f.SetColWidth(SheetNotes, "A", "A", 110)
	return nil
}

func writeValidations(f *excelize.File) error {
	dvType := excelize.NewDataValidation(true)
	dvType.SetDropList([]string{"tomcat", "jar"})
	dvType.Sqref = "B3:B200"
	dvType.SetError(excelize.DataValidationErrorStyleStop, "取值非法", "只能是 tomcat 或 jar")
	f.AddDataValidation(SheetApps, dvType)

	dvGroup := excelize.NewDataValidation(true)
	dvGroup.SetDropList([]string{"master", "update", "static"})
	dvGroup.Sqref = "B3:B500"
	dvGroup.SetError(excelize.DataValidationErrorStyleStop, "取值非法", "只能是 master / update / static")
	f.AddDataValidation(SheetHosts, dvGroup)
	return nil
}

// ---- 小工具 ----

func cellName(col, row int) string {
	name, _ := excelize.CoordinatesToCellName(col, row)
	return name
}

func setTitleStyle(f *excelize.File, sheet string, ncol int) {
	id, _ := f.NewStyle(&excelize.Style{Font: &excelize.Font{Bold: true, Size: 13}})
	f.SetCellStyle(sheet, "A1", cellName(ncol, 1), id)
}

func setHeaderStyle(f *excelize.File, sheet string, ncol, row int) {
	id, _ := f.NewStyle(&excelize.Style{
		Font: hdrFont, Fill: hdrFill, Alignment: center, Border: border,
	})
	f.SetCellStyle(sheet, cellName(1, row), cellName(ncol, row), id)
}

func setExampleStyle(f *excelize.File, sheet string, ncol, row int) {
	id, _ := f.NewStyle(&excelize.Style{Fill: exFill, Alignment: wrapTop, Border: border})
	f.SetCellStyle(sheet, cellName(1, row), cellName(ncol, row), id)
}

func freeze(f *excelize.File, sheet, topLeft string) {
	f.SetPanes(sheet, &excelize.Panes{
		Freeze: true, XSplit: 0, YSplit: 2,
		TopLeftCell: topLeft, ActivePane: "bottomLeft",
		Selection: []excelize.Selection{{SQRef: topLeft}},
	})
}
