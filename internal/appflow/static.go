package appflow

// 静态页面更新（语义对齐旧版 run_update.py 的静态流程）：
//   - StaticFullTomcat：本地从 update/<app>/WEB-INF/lib/egova-*.jar 解包 META-INF/resources，
//     合并 library/other/style/view/productionLibrary（GIS 为 data/data3d/resourceCenter），
//     删除 *.xml/*.jsp，生成 update/<app>/nginx_deploy/<app>，推送到 static 群组（--delete）。
//   - StaticPartial：把 update/<app>/<rel> 推到各群组同相对路径（--delete）。
//   - StaticJar：把本地指定目录推到 JAR 应用各群组的静态根（--delete）。

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/majq1990/app-updater-go/internal/config"
	"github.com/majq1990/app-updater-go/internal/syncx"
)

// staticDirsFor 应用对应的静态目录清单（对齐旧版 pack 脚本）。
func staticDirsFor(appName string) []string {
	if appName == "eUrbanGIS" {
		return []string{"data", "data3d", "resourceCenter"}
	}
	return []string{"library", "other", "style", "view", "productionLibrary"}
}

// extractStaticTomcat 本地提取静态文件，返回 nginx_deploy/<app> 目录。
func (r *Runner) extractStaticTomcat(app *config.App) (string, error) {
	localAppDir := path.Join(r.updateDir(), app.Web)
	outBase := path.Join(localAppDir, "nginx_deploy")
	outDir := path.Join(outBase, app.Web)

	if !dirExists(localAppDir) {
		return "", fmt.Errorf("本地更新源目录不存在: %s", localAppDir)
	}
	r.logf("    - 提取静态文件 → %s", outDir)
	if r.DryRun {
		// 模拟模式也要求目录存在，便于核对
		if !dirExists(outDir) {
			_ = os.MkdirAll(outDir, 0o755)
		}
		return outDir, nil
	}
	if err := os.RemoveAll(outBase); err != nil {
		return "", err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}

	// 1. 解包 egova-*.jar 内的 META-INF/resources
	jars, _ := filepath.Glob(filepath.Join(localAppDir, "WEB-INF", "lib", "egova-*.jar"))
	for _, jar := range jars {
		r.logf("      解包 %s", filepath.Base(jar))
		if err := unzipResources(jar, "META-INF/resources/", outDir); err != nil {
			return "", fmt.Errorf("解包 %s: %w", jar, err)
		}
	}

	// 2. 合并静态目录
	for _, d := range staticDirsFor(app.Web) {
		src := filepath.Join(localAppDir, d)
		if !dirExists(src) {
			continue
		}
		if err := copyTree(src, filepath.Join(outDir, d)); err != nil {
			return "", fmt.Errorf("复制 %s: %w", d, err)
		}
	}

	// 3. 清理 .xml / .jsp
	if err := stripExtensions(outDir, ".xml", ".jsp"); err != nil {
		return "", err
	}
	return outDir, nil
}

// StaticFullTomcat Tomcat 应用静态页面全量更新（前置：master/update 已更新）。
func (r *Runner) StaticFullTomcat(appName string) (*Summary, error) {
	app := r.Cfg.AppByName(appName)
	if app == nil {
		return nil, fmt.Errorf("配置中不存在应用 %q", appName)
	}
	if app.MiddleType != "tomcat" {
		return nil, fmt.Errorf("全量静态更新仅支持 tomcat 应用（%s 为 %s）", appName, app.MiddleType)
	}
	if len(app.StaticPageGroup) == 0 {
		return nil, fmt.Errorf("应用 %s 未配置 static_page_group", appName)
	}

	ts := r.now().Format("2006010215")
	sum := &Summary{App: appName, Version: ts}
	outDir, err := r.extractStaticTomcat(app)
	if err != nil {
		return sum, err
	}

	cache := r.dialer()
	defer cache.close()
	for _, h := range app.StaticPageGroup {
		r.logf("  ▶ %s (%s)", h.Host, h.WebPath)
		conn, err := cache.get(h)
		if err != nil {
			sum.Results = append(sum.Results, HostStatus{App: appName, Group: GroupStatic, Host: h.Host, Detail: "连接失败: " + err.Error()})
			continue
		}
		backupPath := path.Join(r.backupDir(), appName, ts, h.Host, "nginx_deploy", "static_full_backup")
		if res, err := syncx.Pull(conn, h.WebPath, backupPath, syncx.Options{DryRun: r.DryRun, Logf: r.detailFor(app, true)}); err != nil {
			r.logf("      ❌ 备份失败: %v", err)
			sum.Results = append(sum.Results, HostStatus{App: appName, Group: GroupStatic, Host: h.Host, Detail: "备份失败"})
			continue
		} else {
			r.logf("      备份→ %s（%s）", backupPath, res)
		}
		if res, err := syncx.Push(conn, outDir, h.WebPath, syncx.Options{Delete: true, DryRun: r.DryRun, Logf: r.detailFor(app, true)}); err != nil {
			r.logf("      ❌ 推送失败: %v", err)
			sum.Results = append(sum.Results, HostStatus{App: appName, Group: GroupStatic, Host: h.Host, Detail: "推送失败"})
			continue
		} else {
			r.logf("      推送完成（%s）", res)
		}
		r.runCmd(conn, fmt.Sprintf("chown -R %s:%s %s", h.User, h.Group, strings.TrimRight(h.WebPath, "/")), "更新属主")
		sum.Results = append(sum.Results, HostStatus{App: appName, Group: GroupStatic, Host: h.Host, OK: true})
	}
	return sum, nil
}

// StaticPartial 静态页面部分更新：update/<app>/<rel> → 各群组同相对路径。
func (r *Runner) StaticPartial(appName, rel string) (*Summary, error) {
	app := r.Cfg.AppByName(appName)
	if app == nil {
		return nil, fmt.Errorf("配置中不存在应用 %q", appName)
	}
	if strings.TrimSpace(rel) == "" {
		return nil, fmt.Errorf("静态更新路径不能为空（应用内相对路径，如 view/css）")
	}
	srcDir := path.Join(r.updateDir(), appName, rel)
	if !dirExists(srcDir) {
		return nil, fmt.Errorf("本地静态源不存在: %s", srcDir)
	}
	return r.pushStatic(app, srcDir, rel, "partial")
}

// StaticJar JAR 应用静态更新：指定本地目录 → 各群组静态根。
func (r *Runner) StaticJar(appName, localSrc string) (*Summary, error) {
	app := r.Cfg.AppByName(appName)
	if app == nil {
		return nil, fmt.Errorf("配置中不存在应用 %q", appName)
	}
	if !dirExists(localSrc) {
		return nil, fmt.Errorf("本地静态源不存在: %s", localSrc)
	}
	return r.pushStatic(app, localSrc, "", "jar")
}

// pushStatic 静态内容推送核心（partial/jar 共用）：
//   - partial：目标 = 群组根路径 + rel（三种群组都拼 rel，对齐旧版）；
//   - jar：目标 = 群组根路径（内容整体覆盖）。
//   - 群组根路径：static 群组 = web_path；jar 的 master/update = web_path+static_page_path；
//     tomcat 的 master/update = web_path。
func (r *Runner) pushStatic(app *config.App, srcDir, rel, mode string) (*Summary, error) {
	groups := []string{GroupMaster, GroupUpdate, GroupStatic}
	ts := r.now().Format("2006010215")
	sum := &Summary{App: app.Web, Version: ts}
	cache := r.dialer()
	defer cache.close()

	for _, g := range groups {
		for _, h := range app.GroupHosts(g) {
			var target, backupRel string
			switch {
			case g == GroupStatic:
				target = strings.TrimRight(h.WebPath, "/")
				backupRel = "nginx_deploy/static_jar_backup"
			case app.MiddleType == "jar":
				if strings.TrimSpace(h.StaticPagePath) == "" {
					r.logf("  ▶ %s (%s) 无 static_page_path，跳过", h.Host, g)
					continue
				}
				target = strings.TrimRight(h.WebPath, "/") + "/" + strings.Trim(h.StaticPagePath, "/")
				backupRel = "nginx_deploy/static_jar_backup"
			default: // tomcat master/update
				target = strings.TrimRight(h.WebPath, "/")
				backupRel = path.Join(app.Web, strings.Trim(rel, "/"))
			}
			destPath := target
			if mode == "partial" {
				destPath = target + "/" + strings.Trim(rel, "/")
			}

			r.logf("  ▶ %s [%s] → %s", h.Host, g, destPath)
			conn, err := cache.get(h)
			if err != nil {
				sum.Results = append(sum.Results, HostStatus{App: app.Web, Group: g, Host: h.Host, Detail: "连接失败"})
				continue
			}
			backupPath := path.Join(r.backupDir(), app.Web, ts, h.Host, backupRel)
			if res, err := syncx.Pull(conn, destPath, backupPath, syncx.Options{DryRun: r.DryRun, Logf: r.detailFor(app, true)}); err != nil {
				r.logf("      ❌ 备份失败: %v", err)
				sum.Results = append(sum.Results, HostStatus{App: app.Web, Group: g, Host: h.Host, Detail: "备份失败"})
				continue
			} else {
				r.logf("      备份→ %s（%s）", backupPath, res)
			}
			if res, err := syncx.Push(conn, srcDir, destPath, syncx.Options{Delete: true, DryRun: r.DryRun, Logf: r.detailFor(app, true)}); err != nil {
				r.logf("      ❌ 推送失败: %v", err)
				sum.Results = append(sum.Results, HostStatus{App: app.Web, Group: g, Host: h.Host, Detail: "推送失败"})
				continue
			} else {
				r.logf("      推送完成（%s）", res)
			}
			r.runCmd(conn, fmt.Sprintf("chown -R %s:%s %s", h.User, h.Group, target), "更新属主")
			sum.Results = append(sum.Results, HostStatus{App: app.Web, Group: g, Host: h.Host, OK: true})
		}
	}
	return sum, nil
}

// ---- 本地文件工具 ----

// unzipResources 把 zip 内 prefix 前缀下的所有条目解到 outDir（前缀被剥掉）。
func unzipResources(jarPath, prefix, outDir string) error {
	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, prefix) || f.Name == prefix {
			continue
		}
		rel := strings.TrimPrefix(f.Name, prefix)
		target := filepath.Join(outDir, filepath.FromSlash(rel))
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := extractZipFile(f, target); err != nil {
			return err
		}
	}
	return nil
}

func extractZipFile(f *zip.File, target string) error {
	src, err := f.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, src)
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	return err
}

// copyTree 递归复制目录（合并语义，dirs_exist_ok）。
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(p, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// stripExtensions 递归删除指定扩展名文件。
func stripExtensions(root string, exts ...string) error {
	var doomed []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		for _, ext := range exts {
			if strings.HasSuffix(d.Name(), ext) {
				doomed = append(doomed, p)
				break
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// 长路径先删无所谓，都是文件
	sort.Strings(doomed)
	for _, p := range doomed {
		if err := os.Remove(p); err != nil {
			return err
		}
	}
	return nil
}
