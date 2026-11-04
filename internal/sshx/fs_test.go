package sshx

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/majq1990/app-updater-go/internal/syncx"
)

// newSFTPPair 在进程内起 sftp server（直接服务本地文件系统），
// 通过 net.Pipe 连接真实 SFTP 客户端 —— 覆盖 SFTPFS 的线上协议路径。
func newSFTPPair(t *testing.T) (*SFTPFS, func()) {
	t.Helper()
	c1, c2 := net.Pipe()
	srv, err := sftp.NewServer(c1)
	if err != nil {
		t.Fatalf("启动 SFTP server: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_ = srv.Serve()
		close(done)
	}()
	cli, err := sftp.NewClientPipe(c2, c2)
	if err != nil {
		_ = c2.Close()
		_ = srv.Close()
		t.Fatalf("建立 SFTP client: %v", err)
	}
	cleanup := func() {
		_ = cli.Close()
		_ = c2.Close()
		_ = srv.Close()
		<-done
	}
	return &SFTPFS{cli: cli}, cleanup
}

func TestSFTPFSRoundTrip(t *testing.T) {
	root := t.TempDir() // server 直接服务本地文件系统，abs 即本机路径
	s, cleanup := newSFTPPair(t)
	defer cleanup()

	// 1. 不存在的路径 → ErrNotExist
	if _, err := s.Stat(filepath.Join(root, "nope")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("缺失路径应返回 ErrNotExist: %v", err)
	}

	// 2. Upload（含深层父目录自动创建 + mtime 保留）
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(src, "app.jar")
	if err := os.WriteFile(local, []byte("jar-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2026, 11, 2, 12, 0, 0, 0, time.Local)
	if err := os.Chtimes(local, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	dst := filepath.ToSlash(filepath.Join(root, "webapps", "mis", "deep", "app.jar"))
	if err := s.MkdirAll(filepath.ToSlash(filepath.Join(root, "webapps", "mis", "deep"))); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := s.Upload(local, dst, mtime); err != nil {
		t.Fatalf("upload: %v", err)
	}

	// 3. Stat：大小/mtime 一致
	e, err := s.Stat(dst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if e.IsDir || e.Size != int64(len("jar-content")) || e.Mtime.Unix() != mtime.Unix() {
		t.Fatalf("stat 不符: %+v", e)
	}

	// 4. Walk：相对路径规范 + 目录先序
	sub := filepath.ToSlash(filepath.Join(root, "webapps", "mis", "logs"))
	if err := s.MkdirAll(sub); err != nil {
		t.Fatal(err)
	}
	logF, err := s.cli.Create(filepath.Join(sub, "a.log"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := logF.Write([]byte("log")); err != nil {
		t.Fatal(err)
	}
	_ = logF.Close()
	var seen []string
	err = s.Walk(filepath.ToSlash(filepath.Join(root, "webapps")), func(e2 syncx.Entry) error {
		seen = append(seen, e2.Rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	want := []string{"mis", "mis/deep", "mis/deep/app.jar", "mis/logs", "mis/logs/a.log"}
	if len(seen) != len(want) {
		t.Fatalf("walk 顺序/数量不符: %v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("walk[%d]=%s want %s", i, seen[i], want[i])
		}
	}

	// 5. Download 回本机并保 mtime（真实调用链中 syncx.downloadFile 会先建本地父目录）
	local2 := filepath.Join(root, "back", "app.jar")
	if err := os.MkdirAll(filepath.Dir(local2), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Download(dst, local2); err != nil {
		t.Fatalf("download: %v", err)
	}
	data, err := os.ReadFile(local2)
	if err != nil || string(data) != "jar-content" {
		t.Fatalf("download 内容错误: %s %v", data, err)
	}
	if fi, err := os.Stat(local2); err != nil || fi.ModTime().Unix() != mtime.Unix() {
		t.Fatalf("download mtime 未保留: %v %v", fi, err)
	}

	// 6. RemoveAll 递归
	if err := s.RemoveAll(filepath.ToSlash(filepath.Join(root, "webapps", "mis"))); err != nil {
		t.Fatalf("removeall: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "webapps", "mis")); !os.IsNotExist(err) {
		t.Fatalf("RemoveAll 后目录应消失: %v", err)
	}
	// 幂等
	if err := s.RemoveAll(filepath.ToSlash(filepath.Join(root, "webapps", "mis"))); err != nil {
		t.Fatalf("RemoveAll 幂等性: %v", err)
	}
}

// 密钥对生成：与 ssh.ParsePrivateKey 兼容（PKCS8），公钥行格式正确，二次调用幂等。
func TestEnsureKeyPairIn(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, err := EnsureKeyPairIn(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	privData, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(privData)
	if err != nil {
		t.Fatalf("生成的私钥无法被 ssh.ParsePrivateKey 解析: %v", err)
	}

	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = pubData
	line, err := PublicKeyLine(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if !containsField(line, signer.PublicKey().Type()) {
		t.Fatalf("公钥行类型不符: %s", line)
	}

	// 幂等：再调一次不重建
	p2, _, err := EnsureKeyPairIn(dir)
	if err != nil || p2 != privPath {
		t.Fatalf("幂等失败: %s %v", p2, err)
	}
}

func containsField(s, sub string) bool {
	return len(s) > len(sub) && (s[:len(sub)] == sub || indexOf(s, sub) > 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
