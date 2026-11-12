package inspect

// legacy.go —— auto-check 旧版 key-DSL 结果解析器。
//
// 移植来源：auto-check（gitlab.egova.com.cn:devops/auto-check）
//   internal/result/normalize.go @ origin/master 29ddae4（2026-11-11 同步）
// 同步约定：每轮 `bash tools/sync-autocheck-assets.sh` 拉取最新资产后，
// 用 `git diff 29ddae4 origin/master -- internal/result/normalize.go`
// 对比上游解析语义变化，人工合并到本文件（函数名保持一一对应便于 diff）。
//
// 语义：检查脚本 stdout 为 {"basic":{...},"topics":{"NN:指标::表达式:#ID":值|[{...}]}}，
// key 第 3 段编码比较表达式（如 DATA_gt_60、WRAPDATA_eq__quot_NO_quot_），
// 触发阈值即产生一条 finding，未触发不产出（与 auto-check 行为一致）。

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// exprReplacer 把旧版 key 中编码的预警表达式还原为可读比较式。
// 该编码源自 ansible/filter_plugins/filters.py 的 get_comp_expr。
var exprReplacer = strings.NewReplacer(
	"_lbc_", "(",
	"_rbc_", ")",
	"_lbk_", "[",
	"_rbk_", "]",
	"_quot_", `"`,
	"_and_", " and ",
	"_or_", " or ",
	"mul_", "*",
	"dot_", ".",
	"gt_", ">",
	"ge_", ">=",
	"lt_", "<",
	"le_", "<=",
	"eq_", "==",
	"ne_", "!=",
)

// legacyFinding 是移植期间的中间结构（对应 auto-check result.Finding）。
type legacyFinding struct {
	Metric    string
	Unit      string
	Value     any
	Op        string
	Threshold any
	Severity  string
	Message   string
	Ref       string
	RawKey    string
}

// parseLegacyTopics 解析 legacy topics JSON（容忍 SSH banner 等前缀噪声）。
// 返回指标汇总与异常项。
func parseLegacyTopics(host, typ string, dim Dimension, data []byte) ([]Metric, []Finding, error) {
	payload := extractJSON(data)
	if payload == nil {
		return nil, nil, fmt.Errorf("未找到 JSON 结果（可能输出被截断）")
	}
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, nil, fmt.Errorf("结果 JSON 解析失败: %v", err)
	}

	var legacy []legacyFinding
	collect := func(k string, v any) {
		if f, abnormal := legacyAnalyze(k, v); abnormal {
			legacy = append(legacy, f)
		}
	}
	forEachKV(doc["basic"], collect)
	if topics, ok := doc["topics"].(map[string]any); ok {
		for _, arr := range topics {
			if items, ok := arr.([]any); ok {
				for _, it := range items {
					forEachKV(it, collect)
				}
			}
		}
	}

	var findings []Finding
	for _, f := range legacy {
		sev := SevWarn
		switch f.Severity {
		case "error":
			sev = SevError
		case "info":
			sev = SevInfo
		}
		findings = append(findings, Finding{
			Host:      host,
			Target:    host,
			Check:     typ,
			Dimension: string(dim),
			Severity:  sev,
			Metric:    f.Metric,
			Value:     fmt.Sprintf("%v", f.Value),
			Threshold: fmt.Sprintf("%v", f.Threshold),
			Message:   f.Message,
			Ref:       f.RawKey,
		})
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if rank(findings[i].Severity) != rank(findings[j].Severity) {
			return rank(findings[i].Severity) > rank(findings[j].Severity)
		}
		return findings[i].Metric < findings[j].Metric
	})
	metrics := []Metric{{Name: "legacy_abnormal_count", Value: strconv.Itoa(len(findings))}}
	return metrics, findings, nil
}

// extractJSON 从混杂输出（SSH banner、进度行）中截取最后一个完整 JSON 对象。
func extractJSON(data []byte) []byte {
	s := string(data)
	last := strings.LastIndexByte(s, '{')
	for last >= 0 {
		cand := s[last:]
		if json.Valid([]byte(cand)) {
			return []byte(cand)
		}
		// 尝试逐层截断到配对的 '}'（JSON 在尾部时通常一次即中）
		if end := strings.LastIndexByte(cand, '}'); end >= 0 {
			cand = cand[:end+1]
			if json.Valid([]byte(cand)) {
				return []byte(cand)
			}
		}
		last = strings.LastIndexByte(s[:last], '{')
	}
	return nil
}

func forEachKV(v any, fn func(k string, v any)) {
	switch m := v.(type) {
	case map[string]any:
		for k, val := range m {
			fn(k, val)
		}
	case []any:
		for _, it := range m {
			if mm, ok := it.(map[string]any); ok {
				for k, val := range mm {
					fn(k, val)
				}
			}
		}
	}
}

// legacyAnalyze 解码单个指标 key，并在触发阈值时返回异常项。
// 第二个返回值为 true 表示该指标需要关注（异常或无法判定）。
// key 形如 "01:cpu_used%:%:DATA_gt_60:#4864"，第 5 段允许放完整链接（含冒号），
// 因此按前 4 段切分（SplitN=5）。
func legacyAnalyze(key string, value any) (legacyFinding, bool) {
	f := legacyFinding{RawKey: key, Value: value}

	parts := strings.SplitN(key, ":", 5)
	if len(parts) >= 2 {
		f.Metric = strings.TrimSpace(parts[1])
	}
	if len(parts) >= 3 {
		f.Unit = parts[2]
	}
	expr := ""
	if len(parts) >= 4 {
		expr = parts[3]
	}
	if len(parts) >= 5 && strings.HasPrefix(parts[4], "#") {
		f.Ref = strings.TrimPrefix(parts[4], "#")
	}

	if expr == "" {
		f.Severity = "info"
		return f, false
	}

	decoded := decodeExpr(expr)
	f.Op, f.Threshold = legacyThresholdOf(decoded)
	f.Severity = "warning"

	matched, known := legacyEvalExpr(decoded, value)
	if !known {
		f.Severity = "unknown"
		f.Message = fmt.Sprintf("%s=%v，无法自动判定阈值表达式 [%s]", f.Metric, value, decoded)
		return f, true
	}
	if !matched {
		return f, false
	}
	f.Message = fmt.Sprintf("%s=%v 触发阈值 [%s]", f.Metric, value, decoded)
	return f, true
}

func decodeExpr(expr string) string {
	// 先还原运算符/括号/引号（与 filters.py 的 comp_dict 顺序一致），
	// 再消费变量前缀 DATA_ / WRAPDATA_ 末尾的下划线，避免留下孤立下划线。
	s := exprReplacer.Replace(expr)
	s = strings.ReplaceAll(s, "WRAPDATA_", "WRAPDATA ")
	s = strings.ReplaceAll(s, "DATA_", "DATA ")
	return strings.TrimSpace(s)
}

func legacyThresholdOf(decoded string) (string, any) {
	op, _, rhs, ok := splitComparison(decoded)
	if !ok {
		return "", nil
	}
	return op, strings.TrimSpace(rhs)
}

// legacyEvalExpr 安全地求值比较表达式（不执行任意代码），返回 (是否触发, 是否可判定)。
func legacyEvalExpr(expr string, value any) (matched bool, known bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false, false
	}

	if parts := splitTop(expr, " or "); len(parts) > 1 {
		knownAny := false
		for _, p := range parts {
			m, k := legacyEvalExpr(p, value)
			if k {
				knownAny = true
			}
			if k && m {
				return true, true
			}
		}
		return false, knownAny
	}
	if parts := splitTop(expr, " and "); len(parts) > 1 {
		for _, p := range parts {
			m, k := legacyEvalExpr(p, value)
			if !k {
				return false, false
			}
			if !m {
				return false, true
			}
		}
		return true, true
	}

	op, lhs, rhs, ok := splitComparison(expr)
	if !ok {
		return false, false
	}
	lv, lok := legacyOperand(lhs, value)
	rv, rok := legacyOperand(rhs, value)
	if !lok || !rok {
		return false, false
	}
	return legacyCompare(lv, rv, op)
}

// splitTop 在括号/引号之外按 sep 切分。
func splitTop(s, sep string) []string {
	var parts []string
	depth := 0
	inQuote := false
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
			i++
			continue
		}
		if inQuote {
			i++
			continue
		}
		switch c {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		}
		if depth == 0 && strings.HasPrefix(s[i:], sep) {
			parts = append(parts, s[start:i])
			i += len(sep)
			start = i
			continue
		}
		i++
	}
	parts = append(parts, s[start:])
	return parts
}

// splitComparison 在顶层找到第一个比较运算符。
func splitComparison(expr string) (op, lhs, rhs string, ok bool) {
	depth := 0
	inQuote := false
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		switch c {
		case '(', '[':
			depth++
			continue
		case ')', ']':
			depth--
			continue
		}
		if depth != 0 {
			continue
		}
		if i+1 < len(expr) {
			switch expr[i : i+2] {
			case ">=", "<=", "==", "!=":
				return expr[i : i+2], expr[:i], expr[i+2:], true
			}
		}
		switch c {
		case '>', '<':
			return string(c), expr[:i], expr[i+1:], true
		}
	}
	return "", "", "", false
}

// legacyOperand 求值操作数：字面量、DATA/WRAPDATA 或 abs(...)。
func legacyOperand(s string, value any) (any, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	if strings.HasPrefix(s, "abs(") && strings.HasSuffix(s, ")") {
		inner, ok := legacyOperand(s[4:len(s)-1], value)
		if !ok {
			return nil, false
		}
		f, ok := legacyToFloat(inner)
		if !ok {
			return nil, false
		}
		return math.Abs(f), true
	}
	switch s {
	case "DATA", "WRAPDATA":
		return value, true
	case "CURTIME30":
		return nil, false
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1], true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, true
	}
	return s, true
}

func legacyCompare(lv, rv any, op string) (bool, bool) {
	if lf, ok := legacyToFloat(lv); ok {
		if rf, ok := legacyToFloat(rv); ok {
			switch op {
			case ">":
				return lf > rf, true
			case ">=":
				return lf >= rf, true
			case "<":
				return lf < rf, true
			case "<=":
				return lf <= rf, true
			case "==":
				return lf == rf, true
			case "!=":
				return lf != rf, true
			}
		}
	}
	ls, rs := fmt.Sprint(lv), fmt.Sprint(rv)
	switch op {
	case "==":
		return ls == rs, true
	case "!=":
		return ls != rs, true
	case ">":
		return ls > rs, true
	case ">=":
		return ls >= rs, true
	case "<":
		return ls < rs, true
	case "<=":
		return ls <= rs, true
	}
	return false, false
}

func legacyToFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		s := strings.TrimSpace(strings.ReplaceAll(n, ",", ""))
		if s == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(s, 64)
		return f, err == nil
	}
	return 0, false
}
