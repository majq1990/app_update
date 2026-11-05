package logs

// 远端适配：sshx.Client 直接实现 syncx.RemoteFS（Stat/Walk/MkdirAll/Upload/Download/RemoveAll），
// 因此 clean/gather 以 syncx.RemoteFS 为参数即可，无需再造接口。测试用本地假 FS
//（syncx.fakefs 已有先例，logs 包自带一个轻量实现见 plan_test.go）。
