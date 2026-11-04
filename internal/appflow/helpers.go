package appflow

import (
	"os"
	"sort"
)

// dirExists 本地目录是否存在。
func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// osReadDir 目录列表（错误透传）。
func osReadDir(p string) ([]os.DirEntry, error) {
	return os.ReadDir(p)
}

// latestVersion 最新的备份版本目录名。
func latestVersion(root string) (string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	var vs []string
	for _, e := range entries {
		if e.IsDir() {
			vs = append(vs, e.Name())
		}
	}
	if len(vs) == 0 {
		return "", errNoBackup{root: root}
	}
	sortReverse(vs)
	return vs[0], nil
}

type errNoBackup struct{ root string }

func (e errNoBackup) Error() string { return "没有可用的备份版本: " + e.root }

func sortReverse(vs []string) {
	sort.Slice(vs, func(i, j int) bool { return vs[i] > vs[j] })
}
