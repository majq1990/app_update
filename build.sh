#!/bin/bash
# 全平台带版本号构建脚本
# 用法: ./build.sh v1.0.0
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "用法: $0 <版本号，如 v1.0.0>"
  exit 1
fi

BUILD_TIME="$(date '+%Y-%m-%d %H:%M')"
LDFLAGS="-s -w -X main.version=${VERSION} -X 'main.buildTime=${BUILD_TIME}'"

# 只清理构建产物，保留 dist/*.md（操作手册）
mkdir -p dist
find dist -maxdepth 1 -type f ! -name '*.md' -delete 2>/dev/null || true

build() {
  local goos="$1" goarch="$2" out="$3"
  echo "构建 $out ..."
  GOOS="$goos" GOARCH="$goarch" go build -ldflags "$LDFLAGS" -o "dist/$out" ./cmd/app-updater
}

build linux   amd64 "eops-linux-amd64"
build linux   arm64 "eops-linux-arm64"
build windows amd64 "eops-windows-amd64.exe"
build windows arm64 "eops-windows-arm64.exe"
build darwin  arm64 "eops-darwin-arm64"

echo
echo "=== 产物 ==="
ls -la dist/
echo
echo "=== SHA256 ==="
cd dist && sha256sum * 2>/dev/null | grep -v README
