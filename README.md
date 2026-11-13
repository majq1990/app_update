# eops

统一运维工具（原名 app-updater，Go 版）——通过 SSH 自动化 Java 应用（Tomcat WAR / 独立 JAR）的**更新与回滚**，并提供日志、备份、巡检、监控、加固等日常运维能力，替代早期 Python+Bash+Docker 实现。

> **改名说明**：本工具自本轮起更名为 **eops**。旧名 `app-updater` 的二进制仍可用（同一程序，行为一致），老脚本无需修改；go module 路径与 `cmd/app-updater` 目录名保持不变。

> 旧版 Python 实现完整保留在 [`legacy-python-archive`](https://github.com/majq1990/app_update/tree/legacy-python-archive) 分支（含全部历史提交），该分支已废弃不再维护，仅作对照。

## 特性

- **单文件免安装**：跨平台静态二进制（Linux x86_64/ARM64、Windows x64/ARM64、macOS ARM64），不依赖 Python、rsync、sshpass、Docker
- **交互菜单 + 命令行双模式**：不带参数进菜单（选应用→选群组→模拟→确认执行）；带子命令供脚本调用
- **自研同步引擎**：文件级 mtime+size 增量、`--delete` 语义、rsync 风格排除模式、保留配置保护、dry-run 预览
- **健康检查**：默认在目标机本地探测（不受工具机到应用端口网络限制）；有 URI 走 HTTP 200，无 URI 按端口 TCP 探测；预算可配
- **一键部署识别**：从 oneinstall v1/v2 部署清单自动生成配置（systemd 单元名、标准健康检查地址、liquibase 排除规则自动填充）
- **Excel 配置**：模板生成 / 导入校验 / 反向导出，适合现场人工填写与核对
- **运维扩展**：日志运维（汇聚/清理/切割体检与下发）、备份运维（现场留包/完整性校验/保留期清理/台账导出）、
  项目巡检（32 项：20 项自研 + 12 项 auto-check 资产——安全 6 + OS 1 + 中间件 5）、监控诊断（agent/proxy/PSK/备份目录/云连通性）、
  安全加固清单（只读建议，不改网络与内核）
- **安全**：所有改服务器的操作先 dry-run，需 `--yes` 才执行；回滚保护运行期日志

## 快速开始

```bash
# 1. 下载对应平台产物（或自行构建：./build.sh v1.0.0）
chmod +x eops-linux-amd64
mv eops-linux-amd64 eops

# 2. 查看版本
./eops version

# 3. 进入交互菜单（推荐）
./eops

# 或使用子命令
./eops gen-from-oneinstall -o 初稿.xlsx --yaml config.yaml   # 识别一键部署清单
./eops setup-ssh -c config.yaml                              # 免密初始化
./eops update -c config.yaml --app usercenter                # dry-run
./eops update -c config.yaml --app usercenter --yes          # 正式执行
./eops rollback -c config.yaml --app usercenter --list       # 可回滚版本
./eops logs clean -c config.yaml                             # 日志清理（dry-run）
./eops backup run -c config.yaml                             # 备份计划（dry-run）
./eops backup run -c config.yaml --yes                       # 现场备份（产物留现场）
./eops backup verify -c config.yaml                          # 完整性校验
./eops backup report -c config.yaml --out 台账.json --verify  # 台账导出
./eops backup restore -c config.yaml --app usercenter \
    --file /egova/backup/20261107/eops-usercenter-172.21.133.222-103000.tar.gz   # 恢复计划（dry-run）
./eops backup restore -c config.yaml --app usercenter --file <同上> --yes        # 正式恢复
./eops backup push -c config.yaml --out payload.json         # 生成 ztoa 备份中间表 payload（不联网）
./eops inspect run -c config.yaml --json 巡检.json            # 巡检（只读）
./eops inspect security -c config.yaml                        # 只看安全
./eops monitor doctor -c config.yaml                          # 监控诊断
./eops harden check -c config.yaml                            # 加固清单（只读）
```

### 安全加固 sec 系列（对齐 oneinstall_v2 安全工具箱）

```bash
# 只读体检：暴露面/未授权 + nginx + tomcat
./eops harden sec check -c config.yaml --host all

# 写修复（默认 dry-run；--yes 落盘，改前逐文件备份，nginx -t 失败自动还原）
./eops harden sec fix -c config.yaml --host 10.0.0.11 --manifest-out sec-manifest.json
./eops harden sec rollback -c config.yaml --manifest sec-manifest.json --yes

# 应用配置体检 / 仅写 8 个白名单键（Swagger/Actuator/错误页）
./eops harden sec appconfig check -c config.yaml
./eops harden sec appconfig fix   -c config.yaml --yes

# 数据库只读体检（凭据只走环境变量，不进命令行/不落盘）
export EOPS_DB_PASSWORD='<口令>'
./eops harden sec db -c config.yaml --type mysql --db-host 127.0.0.1 \
    --db-user root --sql-out remediation.sql

# 系统基线 / 网络拦截
./eops harden sec os check|fix -c config.yaml
./eops harden sec network status|docker|guard|ban|unban|install-cron -c config.yaml

# 能力对照表
./eops harden sec gap
```

境外 IP 默认拉黑（内置 8786 条中国网段，挂 INPUT/DOCKER-USER）：

```bash
./eops harden sec cn status -c config.yaml
./eops harden sec cn enable -c config.yaml --allow 203.0.113.10/32,172.21.133.0/24 --yes
./eops harden sec cn disable -c config.yaml --yes
```

> SSH 认证默认用 `~/.ssh/id_rsa`；密钥不是默认名时加 `--key <私钥路径>`，
> 口令登录用 `--pass` 或环境变量 `APP_UPDATER_SSH_PASS`。
> `os/network` 的写操作同样默认 dry-run，`--yes` 才落盘；`network guard/docker`
> 在 `egova-vpc-nets` 为空时会拒绝执行（防全站不可达）。

## 交互菜单

不带参数运行 `./eops` 进入交互模式，主菜单按能力域分三组（分组标题仅用于展示，编号即输入选择）：

```
============================================
  eops 统一运维工具 · 交互模式
  <版本行>
  当前配置: config.yaml
============================================
—— 项目交付 ——
1. 应用更新
2. 应用回滚
3. 备份运维（执行 / 清单 / 校验 / 清理 / 台账）
—— 日常运维 ——
4. 日志运维（汇聚 / 清理 / 切割）
5. 项目巡检（OS / 安全 / 中间件）
6. 监控运维（诊断 / 白名单修复 / 部署清单）
7. 安全加固（只读清单 / 建议片段 / 台账）
—— 配置与接入 ——
8. 配置管理（识别一键 / 表格导入 / 导出）
9. 免密初始化
0. 退出
```

`3 备份运维` 子菜单：执行备份 / 清单 / 校验 / 清理 / 台账 / **从备份恢复应用** / **生成 ztoa 备份中间表 payload**。

## 备份恢复与台账推送

### backup restore（从现场备份包恢复应用）

```bash
./eops backup restore -c config.yaml --app usercenter \
    --file /egova/backup/20261107/eops-usercenter-172.21.133.222-103000.tar.gz          # dry-run，打印完整计划
./eops backup restore -c config.yaml --app usercenter --file <同上> --yes             # 正式执行
```

- 备份包必须位于 `backup.root` 下、且为本工具产物 `eops-*.tar.gz`（前缀 + 路径白名单双重校验）；
- 包名中的「应用-主机」必须与 `webs` 中的目标主机匹配，避免错配恢复；
- 执行序列：停应用 → **变更前自动备份** 当前 `web_path` 到 `<root>/pre-restore-<ts>.tar.gz` → `tar -xzf` 覆盖解压 →
  `chown -R user:group` → 启应用 → 健康检查（有 `check_uri` 走 curl，否则远端 `/dev/tcp` 探端口；
  jar/tomcat 分别按 `jar_check_minutes` / `tomcat_check_minutes` 预算）；
- 覆盖式恢复，**不删除运行期新增文件**（日志天然保留）；任一步骤失败即停，并列出已执行步骤。

### backup push（生成 ztoa 项目备份中间表 payload）

```bash
./eops backup push -c config.yaml                          # 输出 payload JSON 到 stdout
./eops backup push -c config.yaml --out payload.json       # 落盘
./eops backup push -c config.yaml --verify --out payload.json          # 同时校验每份备份
./eops backup push -c config.yaml --project 某项目 --region 某大区 ...  # 附带台账外的项目元数据
```

- 读现场台账，按 `kind=app` / `kind=mysql` 分别取最新备份时间，算出「最新上传日期（YYYY-MM-DD）」与「上传间隔（天）」；
- 输出为明道云写行格式 `{"controls":[{"controlId":"...","value":"..."}]}`，控件 id 对应 worksheet 项目备份中间表；
  项目经理 / 省份工程总 / 大区工程总 / 交付项目等成员与关联字段默认留空，由人工或上层补齐；
- **工具不联网**：只产出 JSON，真实写表由上层用 ztoa MCP 执行。

## 配置

配置文件 `config.yaml`（兼容旧版 Python 工具格式）：

```yaml
ansible_user: root
ansible_ssh_port: 22
tomcat_check_minutes: 20      # tomcat 健康检查预算（默认 20）
jar_check_minutes: 5          # jar 健康检查预算（默认 5）
global_exclude_logs: ['*.log', 'logs/']

webs:
  - web: usercenter
    middle_type: jar
    log_dir: logs/
    retained_config_file: [usercenter.env, application.properties]
    master:
      - host: 172.21.133.222
        service_port: 10050
        check_uri: /usercenter-api/free/application/check
        web_path: /egova/apps/basic/usercenter
        start_cmd: systemctl start usercenter
        stop_cmd: systemctl stop usercenter
        user: egova
        group: egova
        health_mode: remote       # 留空=remote（默认）/ local / none

# 支持软件（日志 + 备份目标；mysql 另支持 mysqldump）
supports:
  - kind: mysql
    name: 业务库
    hosts:
      - host: 172.21.133.230
  - kind: redis
    name: 缓存
    backup_paths: [/egova/apps/redis/data/dump.rdb]
    hosts:
      - host: 172.21.133.230

# 备份运维（backup 子命令）
backup:
  root: /egova/backup          # 备份根目录（默认）
  keep_days: 14                # 保留天数
  databases: [eurbanpro]       # 需要 mysqldump 的库（空=不备份数据库）
  dump_defaults_file: /root/.my.cnf   # 凭据文件；工具不保存数据库口令
  exclude: [tmp/, '*.pid']     # 打包排除（相对应用根）
```

备份产物命名固定 `eops-<目标>-<主机>-<时分秒>.tar.gz|.sql.gz`，放在 `backup.root/<日期>/`；
`prune` 只处理该前缀产物，绝不误删现场其他文件。台账 JSON 供项目管理表推送，工具本身不联网。

```yaml
# 监控运维（monitor doctor/fix/plan）
monitor:
  server: zabbix.egova.com.cn
  server_port: 7001
  agent_port: 9000          # wiki 约定的受控机 agent 端口
  proxy_port: 9001
  yum_port: 8080
  proxy_hosts:              # 主控机（proxy）
    - host: 172.21.133.10
  agent_hosts: []           # 受控机；留空=用 webs + supports 的主机
  # agent_conf / proxy_conf / plugin_dir / script_dir / psk_file 均有默认值，按现场覆盖
```

## 检查资产同步（auto-check GitLab）

巡检的安全资产一部分来自内网 auto-check（gitlab.egova.com.cn:devops/auto-check），同步机制：

```bash
bash tools/sync-autocheck-assets.sh   # fetch → 按 origin/master 提取 → LF 规范化 → 写 assets/ + manifest.json
go test -count=1 ./internal/inspect   # 回归
```

- 资产脚本经 **stdin 下发执行**（`bash -s <file>` / `python3 -s <file>`），零目标机依赖、不进 shell 解释；
- 旧版 key-DSL 结果（`{"basic","topics"}`）由移植自上游 `internal/result/normalize.go` 的解析器处理（`internal/inspect/legacy.go`）；
- **每轮更新约定**：`sync → 对比上游 normalize.go 语义 diff → 合并 legacy.go → 全测 → 提交 assets+代码（manifest 记录上游 commit）`；
- 已迁入 12 项：安全 6（security-port/login/agent、interface-interception、kernel-cve、vulnerable-jar）
  + OS 1（os-check 综合体检）+ 中间件 5（middleware JVM/线程、jvm-spy 就位、threadpool-leak、gis、geoserver）；
- 暂缓：security-admin-check / version-check / video-url-check（需数据库凭据，待凭据方案落地后迁）。

## 项目结构

```
cmd/app-updater/       CLI 入口（交互模式 + 子命令）
internal/config/       配置模型、校验、YAML 读写、标准健康检查地址表
internal/oneinstall/   oneinstall v1/v2 部署清单识别与转换
internal/xlsx/         Excel 模板/导入/导出
internal/syncx/        同步引擎（增量、排除、保留、清理、dry-run）
internal/sshx/         SSH 层（连接、密钥对、免密推送、SFTP 适配器）
internal/appflow/      执行流程（update / rollback / 静态页面 / 健康检查）
internal/logs/         日志运维（clean / gather / rotate）
internal/backup/       备份运维（tar / mysqldump / 校验 / 保留期 / 台账）
internal/inspect/      项目巡检（20 项只读检查：OS / 安全 / 中间件）
internal/monitor/      监控诊断（agent / proxy / PSK / 备份目录 / 云连通性）
internal/harden/       安全加固清单（巡检发现 → 建议片段 / 台账，首期不改配置）
testdata/oneinstall/   真实部署清单快照（测试夹具）
dist/                  发布包（二进制由 .gitignore 排除，仅保留清单）
```

## 构建

```bash
./build.sh v1.0.0     # 交叉编译全部平台到 dist/
go test ./...         # 全量测试
```

## 文档

完整使用说明（含操作记录、更新记录、健康检查标准地址表）见发布包内 `app-updater操作手册.md`（内容已按 eops 更新；旧文件名保留）。

## 平台验证状态

| 平台 | 状态 |
|---|---|
| Linux x86_64 | ✅ 已在麒麟 V10 一键部署控制节点实弹验证（update/rollback/健康检查/liquibase 清理） |
| Windows x86_64 | ✅ 本机验证（CLI/交互/配置链路） |
| Linux ARM64 / Windows ARM64 / macOS ARM64 | ⚠️ 交叉编译验证，未在对应硬件实跑 |

## License

内部工具，majq1990。
