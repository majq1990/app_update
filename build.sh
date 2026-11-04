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

rm -rf dist
mkdir -p dist

build() {
  local goos="$1" goarch="$2" out="$3"
  echo "构建 $out ..."
  GOOS="$goos" GOARCH="$goarch" go build -ldflags "$LDFLAGS" -o "dist/$out" ./cmd/app-updater
}

build linux   amd64 "app-updater-linux-amd64"
build linux   arm64 "app-updater-linux-arm64"
build windows amd64 "app-updater-windows-amd64.exe"
build windows arm64 "app-updater-windows-arm64.exe"
build darwin  arm64 "app-updater-darwin-arm64"

echo
echo "=== 产物 ==="
ls -la dist/
echo
echo "=== SHA256 ==="
cd dist && sha256sum * 2>/dev/null | grep -v README
