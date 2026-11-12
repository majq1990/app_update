#!/usr/bin/env bash
# sync-autocheck-assets.sh —— 从 auto-check GitLab 拉取最新安全检查资产并合并进 eops
#
# 用法（每轮更新入口）：
#   bash tools/sync-autocheck-assets.sh
#   # 可选：AC_DIR=/path/to/auto-check 覆盖本地仓库位置
#
# 行为：
#   1. 在本地 auto-check 仓库 git fetch origin（GitLab，SSH 222）；
#   2. 以 origin/master 为准，用 git show 提取下表检查脚本（不受本地脏工作区影响）；
#   3. 统一转 LF（上游 tasks 有 sed CRLF 的约定）；
#   4. 写 internal/inspect/assets/autocheck/ 与 manifest.json（含 commit + 每文件 sha256）；
#   5. 提示后续动作：gofmt / go test / 与上游 normalize.go diff。
#
# 语义同步（解析器）：assets 之外还需对比
#   git -C "$AC_DIR" diff <上次commit> origin/master -- internal/result/normalize.go
# 上游有变化时人工合并到 internal/inspect/legacy.go（函数名一一对应）。

set -euo pipefail

AC_DIR="${AC_DIR:-/d/git/auto-check}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ASSET_DIR="$ROOT/internal/inspect/assets/autocheck"
MANIFEST="$ASSET_DIR/manifest.json"

mkdir -p "$ASSET_DIR"
cd "$AC_DIR"

echo "[1/4] git fetch origin ..."
git fetch origin

REV="$(git rev-parse origin/master)"
SYNC_AT="$(date '+%Y-%m-%d %H:%M:%S')"
echo "    origin/master = $REV"

echo "[2/4] 提取检查脚本（origin/master）..."
# name → 上游路径（每轮新增资产在此追加）
MAP_NAME=(security-port security-login security-agent interface-interception kernel-cve vulnerable-jar \
  os-check middleware check-script-jvm check-threadpool-leak check-gis check-geoserver)
MAP_SRC=(
  "ansible/roles/security-port/files/check_port_security.sh"
  "ansible/roles/check_security_login/files/check_security_login.sh"
  "ansible/roles/check_security_agent/files/check_security_agent.sh"
  "ansible/roles/check-interface_interception/files/check-interface_interception.sh"
  "ansible/roles/check-kernel-cve/files/check-kernel-cve.sh"
  "ansible/roles/security-vulnerable-jar/files/check_vulnerable_jar.py"
  "ansible/roles/os-check/files/check_linux.sh"
  "ansible/roles/middleware/files/check_middleware.sh"
  "ansible/roles/check-script-jvm/files/check-script-jvm.sh"
  "ansible/roles/check-threadpool-leak/files/check-threadpool-leak.sh"
  "ansible/roles/check-gis/files/check-gis.sh"
  "ansible/roles/check-geoserver/files/check-geoserver.sh"
)

declare -A SHA
for i in "${!MAP_NAME[@]}"; do
  name="${MAP_NAME[$i]}"; src="${MAP_SRC[$i]}"
  out="$ASSET_DIR/$name"
  case "$name" in
    vulnerable-jar) out="$out.py" ;;
    *)              out="$out.sh" ;;
  esac
  git show "origin/master:$src" | tr -d '\r' > "$out"
  SHA[$name]="$(sha256sum "$out" | cut -d' ' -f1)"
  echo "    $name  <-  $src  ($(wc -c < "$out") bytes)"
done

echo "[3/4] 写 manifest.json ..."
{
  printf '{\n'
  printf '  "source": "gitlab.egova.com.cn:devops/auto-check",\n'
  printf '  "commit": "%s",\n' "$REV"
  printf '  "synced_at": "%s",\n' "$SYNC_AT"
  printf '  "files": {\n'
  for i in "${!MAP_NAME[@]}"; do
    name="${MAP_NAME[$i]}"
    comma=","
    [ $((i+1)) -eq ${#MAP_NAME[@]} ] && comma=""
    printf '    "%s": {"sha256": "%s"}%s\n' "$name" "${SHA[$name]}" "$comma"
  done
  printf '  }\n}\n'
} > "$MANIFEST"

echo "[4/4] 完成。后续动作："
echo "  - 解析语义对比：git -C $AC_DIR diff <上次commit> $REV -- internal/result/normalize.go"
echo "  - 回归：cd $ROOT && go test -count=1 ./internal/inspect"
echo "  - 提交：git add internal/inspect/assets && git commit"
