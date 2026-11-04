package main

import (
	"fmt"
	"runtime"
)

// version 版本号：构建时通过 -ldflags "-X main.version=v1.0.0" 注入。
// 未注入时为 dev（本地 go run/go build 直出）。
var version = "dev"

// buildTime 构建时间，同样由 -ldflags 注入。
var buildTime = ""

// versionString 完整版本描述（含平台信息，便于现场排查）。
func versionString() string {
	s := version
	if buildTime != "" {
		s += " (" + buildTime + ")"
	}
	return fmt.Sprintf("app-updater %s  %s/%s  %s",
		s, runtime.GOOS, runtime.GOARCH, runtime.Version())
}
