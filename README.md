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
  项目巡检（OS/安全/中间件 20 项只读检查）、监控诊断（agent/proxy/PSK/备份目录/云连通性）、
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
./eops inspect run -c config.yaml --json 巡检.json            # 巡检（只读）
./eops inspect security -c config.yaml                        # 只看安全
./eops monitor doctor -c config.yaml                          # 监控诊断
./eops harden check -c config.yaml                            # 加固清单（只读）
```

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
