package main

// SSH 密码单点归一：CLI 显式 --pass > 环境变量 APP_UPDATER_SSH_PASS。
// 该值只进 sshx.Auth.Password（SSH 认证库参数），绝不拼 shell、不写文件、不进日志输出。
// 全程序读 APP_UPDATER_SSH_PASS 环境变量的入口收敛到这一个函数，
// 便于审计与静态分析确认密码数据流是封闭的。

import "os"

// sshPassOrDefault 显式密码优先，空则回退环境变量；都空返回空串（走密钥认证）。
func sshPassOrDefault(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("APP_UPDATER_SSH_PASS")
}
