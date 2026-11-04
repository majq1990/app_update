# app-updater

Java 应用更新工具（Go 版）——通过 SSH 自动化 Java 应用（Tomcat WAR / 独立 JAR）的**更新与回滚**，替代早期 Python+Bash+Docker 实现。

> 旧版 Python 实现完整保留在 [`legacy-python-archive`](https://github.com/majq1990/app_update/tree/legacy-python-archive) 分支（含全部历史提交），该分支已废弃不再维护，仅作对照。

## 特性

- **单文件免安装**：跨平台静态二进制（Linux x86_64/ARM64、Windows x64/ARM64、macOS ARM64），不依赖 Python、rsync、sshpass、Docker
- **交互菜单 + 命令行双模式**：不带参数进菜单（选应用→选群组→模拟→确认执行）；带子命令供脚本调用
- **自研同步引擎**：文件级 mtime+size 增量、`--delete` 语义、rsync 风格排除模式、保留配置保护、dry-run 预览
- **健康检查**：默认在目标机本地探测（不受工具机到应用端口网络限制）；有 URI 走 HTTP 200，无 URI 按端口 TCP 探测；预算可配
- **一键部署识别**：从 oneinstall v1/v2 部署清单自动生成配置（systemd 单元名、标准健康检查地址、liquibase 排除规则自动填充）
- **Excel 配置**：模板生成 / 导入校验 / 反向导出，适合现场人工填写与核对
- **安全**：所有改服务器的操作先 dry-run，需 `--yes` 才执行；回滚保护运行期日志

## 快速开始

```bash
# 1. 下载对应平台产物（或自行构建：./build.sh v1.0.0）
chmod +x app-updater-linux-amd64
mv app-updater-linux-amd64 app-updater

# 2. 查看版本
./app-updater version

# 3. 进入交互菜单（推荐）
./app-updater

# 或使用子命令
./app-updater gen-from-oneinstall -o 初稿.xlsx --yaml config.yaml   # 识别一键部署清单
./app-updater setup-ssh -c config.yaml                              # 免密初始化
./app-updater update -c config.yaml --app usercenter                # dry-run
./app-updater update -c config.yaml --app usercenter --yes          # 正式执行
./app-updater rollback -c config.yaml --app usercenter --list       # 可回滚版本
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
testdata/oneinstall/   真实部署清单快照（测试夹具）
dist/                  发布包（二进制由 .gitignore 排除，仅保留清单）
```

## 构建

```bash
./build.sh v1.0.0     # 交叉编译全部平台到 dist/
go test ./...         # 全量测试
```

## 文档

完整使用说明（含操作记录、更新记录、健康检查标准地址表）见发布包内 `app-updater使用说明.md`。

## 平台验证状态

| 平台 | 状态 |
|---|---|
| Linux x86_64 | ✅ 已在麒麟 V10 一键部署控制节点实弹验证（update/rollback/健康检查/liquibase 清理） |
| Windows x86_64 | ✅ 本机验证（CLI/交互/配置链路） |
| Linux ARM64 / Windows ARM64 / macOS ARM64 | ⚠️ 交叉编译验证，未在对应硬件实跑 |

## License

内部工具，majq1990。
