package oneinstall

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/majq1990/app-updater-go/internal/sshx"
)

// Detected 自动识别结果。
type Detected struct {
	Mode   string    // "v2"（oneinstall_v2 inventory）| "v1"（install-multi.conf）
	Source string    // 配置来源描述（远端路径）
	Inv    Inventory // v2 模式下的三份文件内容
	V1Conf []byte    // v1 模式下 install-multi.conf 内容
}

// 规范路径候选（现场约定）。
const (
	v2CanonicalDir  = "/egova/onekey_install/oneinstall_v2/ansible/inventory"
	v1CanonicalConf = "/egova/conf/install-multi.conf"
)

// DetectRemote 在远端服务器上自动识别一键部署类型并拉取配置：
//  1. v2 规范路径 /egova/onekey_install/oneinstall_v2/ansible/inventory（三件套齐全）
//  2. find 兜底搜索 /egova 下的 metadata.yml（应对非规范安装目录）
//  3. v1 现场约定 /egova/conf/install-multi.conf（对齐 oneops init_hosts_from_oneinstall.sh）
func DetectRemote(c *sshx.Client) (*Detected, error) {
	// ---- 1. v2 规范路径 ----
	if d, ok := tryV2Dir(c, v2CanonicalDir); ok {
		return d, nil
	}

	// ---- 2. find 兜底 ----
	out, _ := c.Run("find /egova -maxdepth 6 -type f -name metadata.yml 2>/dev/null | head -5")
	for _, line := range strings.Split(out, "\n") {
		f := strings.TrimSpace(line)
		if f == "" {
			continue
		}
		dir := f[:strings.LastIndex(f, "/")]
		if d, ok := tryV2Dir(c, dir); ok {
			return d, nil
		}
	}

	// ---- 3. v1 现场约定 ----
	if c.TestPath(v1CanonicalConf) {
		data, err := c.ReadFile(v1CanonicalConf)
		if err != nil {
			return nil, fmt.Errorf("读取 %s: %w", v1CanonicalConf, err)
		}
		return &Detected{Mode: "v1", Source: v1CanonicalConf, V1Conf: data}, nil
	}

	return nil, fmt.Errorf("未识别到一键部署信息：已尝试 v2 规范路径/find 搜索(/egova 下 metadata.yml)/v1 约定路径 %s", v1CanonicalConf)
}

// DetectLocal 在本机自动识别一键部署信息（工具装在控制节点时零参数使用）。
// 顺序与 DetectRemote 一致：v2 规范路径 → find 兜底 → v1 约定路径。
func DetectLocal() (*Detected, bool) {
	if d, ok := tryV2DirLocal(v2CanonicalDir); ok {
		return d, true
	}

	// find 兜底（仅 Unix；Windows 本机无 /egova，静默跳过）
	if out, err := exec.Command("find", "/egova", "-maxdepth", "6", "-type", "f", "-name", "metadata.yml").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.TrimSpace(line)
			if f == "" {
				continue
			}
			dir := f[:strings.LastIndex(f, "/")]
			if d, ok := tryV2DirLocal(dir); ok {
				return d, true
			}
		}
	}

	if data, err := os.ReadFile(v1CanonicalConf); err == nil {
		return &Detected{Mode: "v1", Source: v1CanonicalConf, V1Conf: data}, true
	}
	return nil, false
}

func tryV2DirLocal(dir string) (*Detected, bool) {
	for _, n := range []string{"hosts.yml", "metadata.yml"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			return nil, false
		}
	}
	inv := Inventory{}
	haveGroup := false
	for _, gf := range []struct {
		name string
		dst  *[]byte
	}{
		{"eurbanpro_multi_server.yml", &inv.MultiServer},
		{"multi_server.yml", &inv.MultiServerBase},
		{"mjing_multi_server.yml", &inv.MultiServerMjing},
	} {
		data, err := os.ReadFile(filepath.Join(dir, gf.name))
		if err != nil {
			continue
		}
		haveGroup = true
		*gf.dst = data
	}
	if !haveGroup {
		return nil, false
	}
	inv.Hosts, _ = os.ReadFile(filepath.Join(dir, "hosts.yml"))
	inv.Metadata, _ = os.ReadFile(filepath.Join(dir, "metadata.yml"))
	return &Detected{Mode: "v2", Source: dir, Inv: inv}, true
}

func tryV2Dir(c *sshx.Client, dir string) (*Detected, bool) {
	// hosts.yml / metadata.yml 必备；服务组文件三条产品线任一即可
	for _, n := range []string{"hosts.yml", "metadata.yml"} {
		if !c.TestPath(dir + "/" + n) {
			return nil, false
		}
	}
	inv := Inventory{}
	haveGroup := false
	for _, gf := range []struct {
		name string
		dst  *[]byte
	}{
		{"eurbanpro_multi_server.yml", &inv.MultiServer},
		{"multi_server.yml", &inv.MultiServerBase},
		{"mjing_multi_server.yml", &inv.MultiServerMjing},
	} {
		data, err := c.ReadFile(dir + "/" + gf.name)
		if err != nil {
			continue
		}
		haveGroup = true
		*gf.dst = data
	}
	if !haveGroup {
		return nil, false
	}
	for _, n := range []string{"hosts.yml", "metadata.yml"} {
		data, err := c.ReadFile(dir + "/" + n)
		if err != nil {
			return nil, false
		}
		switch n {
		case "hosts.yml":
			inv.Hosts = data
		case "metadata.yml":
			inv.Metadata = data
		}
	}
	return &Detected{Mode: "v2", Source: dir, Inv: inv}, true
}
