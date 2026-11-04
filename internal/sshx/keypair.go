package sshx

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// EnsureKeyPair 确保本机 ~/.ssh 下存在 SSH 密钥对。
func EnsureKeyPair() (string, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	return EnsureKeyPairIn(filepath.Join(home, ".ssh"))
}

// EnsureKeyPairIn 确保指定目录存在 SSH 密钥对（RSA 4096，无口令，对齐旧版
// ssh-keygen -t rsa -b 4096）。已存在则直接返回；缺公钥时从私钥恢复。
func EnsureKeyPairIn(sshDir string) (string, string, error) {
	privPath := filepath.Join(sshDir, "id_rsa")
	pubPath := privPath + ".pub"

	if _, err := os.Stat(privPath); err == nil {
		if _, err := os.Stat(pubPath); err == nil {
			return privPath, pubPath, nil
		}
		// 私钥在、公钥丢：从私钥恢复公钥
		signer, err := loadPrivateKey(privPath)
		if err != nil {
			return "", "", fmt.Errorf("读取已有私钥 %s: %w", privPath, err)
		}
		pub := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
		if err := os.WriteFile(pubPath, []byte(pub), 0o644); err != nil {
			return "", "", err
		}
		return privPath, pubPath, nil
	}

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return "", "", err
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		return "", "", err
	}

	pubKey, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubLine := string(ssh.MarshalAuthorizedKey(pubKey))
	host, _ := os.Hostname()
	pubLine = strings.TrimRight(pubLine, "\n") + " " + host + "\n"
	if err := os.WriteFile(pubPath, []byte(pubLine), 0o644); err != nil {
		return "", "", err
	}
	return privPath, pubPath, nil
}

// PublicKeyLine 读取公钥文件的单行内容（去掉注释外多余空白）。
func PublicKeyLine(pubPath string) (string, error) {
	data, err := os.ReadFile(pubPath)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(data))
	if line == "" {
		return "", fmt.Errorf("公钥文件为空: %s", pubPath)
	}
	return line, nil
}

// PushPubKey 用密码认证一次性把公钥写入远端 authorized_keys（替代 sshpass+ssh-copy-id，
// 解决 Windows 下无 sshpass 的问题）。已存在（整行精确匹配）则跳过。
func PushPubKey(a Auth, pubKeyLine string) error {
	if a.Password == "" {
		return fmt.Errorf("免密推送需要密码认证（--pass 或配置 ansible_ssh_pass）")
	}
	cli, err := dial(a, []ssh.AuthMethod{ssh.Password(a.Password)})
	if err != nil {
		return err
	}
	defer cli.Close()

	// 整行精确匹配去重；authorized_keys 权限收紧到 600
	script := fmt.Sprintf(`mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && grep -qxF '%s' ~/.ssh/authorized_keys || echo '%s' >> ~/.ssh/authorized_keys`,
		pubKeyLine, pubKeyLine)
	sess, err := cli.NewSession()
	if err != nil {
		return fmt.Errorf("创建会话失败: %w", err)
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(script)
	if err != nil {
		return fmt.Errorf("写入 authorized_keys 失败: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// VerifyKeyAuth 验证当前默认私钥能否免密登录（返回 error 即未通）。
func VerifyKeyAuth(a Auth) error {
	cli, err := dial(a, keyOnlyMethods(a))
	if err != nil {
		return err
	}
	return cli.Close()
}

// dial 独立拨号（供免密推送用固定认证方式，不走 Connect 的密钥+密码混合策略）。
func dial(a Auth, methods []ssh.AuthMethod) (*ssh.Client, error) {
	port := a.Port
	if port == 0 {
		port = 22
	}
	user := a.User
	if user == "" {
		user = "root"
	}
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: methods,
		HostKeyCallback: func(hostname string, _ net.Addr, key ssh.PublicKey) error {
			fmt.Fprintf(os.Stderr, "[ssh] %s 主机指纹 %s %s（accept-new，已接受）\n",
				hostname, key.Type(), ssh.FingerprintSHA256(key))
			return nil
		},
		Timeout: 15 * time.Second,
	}
	return ssh.Dial("tcp", net.JoinHostPort(a.Host, fmt.Sprint(port)), cfg)
}

func keyOnlyMethods(a Auth) []ssh.AuthMethod {
	keyPath := a.KeyPath
	if keyPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			keyPath = filepath.Join(home, ".ssh", "id_rsa")
		}
	}
	if signer, err := loadPrivateKey(keyPath); err == nil {
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}
	}
	return nil
}
