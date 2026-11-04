// Package sshx 是 app-updater 的 SSH 层：连接（密码/私钥）、远程命令执行、SFTP 文件拉取。
// 也是后续更新/回滚执行链路的底层。
package sshx

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/majq1990/app-updater-go/internal/syncx"
)

// Auth SSH 连接参数。
type Auth struct {
	Host     string
	Port     int    // 0 → 22
	User     string // "" → root
	Password string // 优先用密钥，密码作回退；两者都为空报错
	KeyPath  string // "" → ~/.ssh/id_rsa
}

// Client SSH 客户端。
type Client struct {
	cli     *ssh.Client
	fsCache *SFTPFS
}

// Connect 建立连接。密钥优先、密码回退；主机指纹采用 accept-new 策略（首次接受并打印）。
func Connect(a Auth) (*Client, error) {
	var methods []ssh.AuthMethod
	methods = append(methods, keyOnlyMethods(a)...)
	if a.Password != "" {
		methods = append(methods, ssh.Password(a.Password))
	}
	if len(methods) == 0 {
		home, _ := os.UserHomeDir()
		return nil, fmt.Errorf("无可用的认证方式：请提供 --pass 或默认私钥 %s",
			filepath.Join(home, ".ssh", "id_rsa"))
	}
	cli, err := dial(a, methods)
	if err != nil {
		port := a.Port
		if port == 0 {
			port = 22
		}
		return nil, fmt.Errorf("SSH 连接 %s@%s:%d 失败: %w", a.User, a.Host, port, err)
	}
	return &Client{cli: cli}, nil
}

func loadPrivateKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if ok := asPassphraseMissing(err, &missing); ok {
			return nil, fmt.Errorf("私钥 %s 有密码保护，暂不支持交互输入，请改用 --pass", path)
		}
		return nil, err
	}
	return signer, nil
}

func asPassphraseMissing(err error, target **ssh.PassphraseMissingError) bool {
	if e, ok := err.(*ssh.PassphraseMissingError); ok {
		*target = e
		return true
	}
	return false
}

// Close 断开连接（含 SFTP 通道）。
func (c *Client) Close() error {
	if c.fsCache != nil {
		_ = c.fsCache.cli.Close()
	}
	return c.cli.Close()
}

// ---- syncx.RemoteFS 委托（Client 直接满足接口，执行链路免二次断言） ----

func (c *Client) Stat(abs string) (syncx.Entry, error) {
	fs, err := c.FS()
	if err != nil {
		return syncx.Entry{}, err
	}
	return fs.Stat(abs)
}

func (c *Client) Walk(abs string, fn func(syncx.Entry) error) error {
	fs, err := c.FS()
	if err != nil {
		return err
	}
	return fs.Walk(abs, fn)
}

func (c *Client) MkdirAll(abs string) error {
	fs, err := c.FS()
	if err != nil {
		return err
	}
	return fs.MkdirAll(abs)
}

func (c *Client) Upload(localPath, abs string, mtime time.Time) error {
	fs, err := c.FS()
	if err != nil {
		return err
	}
	return fs.Upload(localPath, abs, mtime)
}

func (c *Client) Download(abs, localPath string) (int64, error) {
	fs, err := c.FS()
	if err != nil {
		return 0, err
	}
	return fs.Download(abs, localPath)
}

func (c *Client) RemoveAll(abs string) error {
	fs, err := c.FS()
	if err != nil {
		return err
	}
	return fs.RemoveAll(abs)
}

// Run 执行远程命令并返回合并输出（stdout+stderr）。非零退出码返回 error，但输出仍可用。
func (c *Client) Run(cmd string) (string, error) {
	sess, err := c.cli.NewSession()
	if err != nil {
		return "", fmt.Errorf("创建会话失败: %w", err)
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	return string(out), err
}

// TestPath 判断远端路径是否存在。
func (c *Client) TestPath(path string) bool {
	out, _ := c.Run(fmt.Sprintf("test -e %s && echo __Y__ || echo __N__", shellQuote(path)))
	return strings.Contains(out, "__Y__")
}

// ReadFile 通过 SFTP 读取远端文件内容。
func (c *Client) ReadFile(remotePath string) ([]byte, error) {
	sftpCli, err := sftp.NewClient(c.cli)
	if err != nil {
		return nil, fmt.Errorf("建立 SFTP: %w", err)
	}
	defer sftpCli.Close()
	f, err := sftpCli.Open(remotePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
