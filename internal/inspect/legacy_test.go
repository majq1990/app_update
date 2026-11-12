package inspect

// legacy_test.go —— 移植自 auto-check internal/result/normalize_test.go 的语义锁定用例
// （DSL 解码/阈值判定/未知表达式），外加 banner 噪声容忍与主机归属测试。

import (
	"strings"
	"testing"
)

// 上游用例：07:fstab::WRAPDATA_eq__quot_ERROR_quot_ —— ERROR 触发，OK 不触发
func TestLegacyEqQuotedTrigger(t *testing.T) {
	key := "07:fstab::WRAPDATA_eq__quot_ERROR_quot_:#9776"
	if f, abnormal := legacyAnalyze(key, "ERROR"); !abnormal {
		t.Fatalf("ERROR 应触发: %+v", f)
	} else {
		if f.Severity != "warning" {
			t.Errorf("severity 应为 warning: %+v", f)
		}
		if f.Metric != "fstab" || f.Threshold != `"ERROR"` {
			t.Errorf("字段解析错误: %+v", f)
		}
	}
	if _, abnormal := legacyAnalyze(key, "OK"); abnormal {
		t.Error("OK 不应触发")
	}
}

// 上游典型：数值阈值 DATA_gt_60
func TestLegacyGtNumeric(t *testing.T) {
	key := "01:cpu_used%:%:DATA_gt_60:#4864"
	if _, abnormal := legacyAnalyze(key, 59); abnormal {
		t.Error("59 不应触发")
	}
	f, abnormal := legacyAnalyze(key, 61.5)
	if !abnormal {
		t.Fatal("61.5 应触发")
	}
	if f.Op != ">" || f.Threshold != "60" {
		t.Fatalf("阈值解析错误: %+v", f)
	}
}

// 未知表达式（CURTIME30 无本机语义）→ 不可判定也要上报
func TestLegacyUnknownExpr(t *testing.T) {
	key := "08:next_fire_time::WRAPDATA_lt_CURTIME30"
	f, abnormal := legacyAnalyze(key, "2026-11-12")
	if !abnormal || f.Severity != "unknown" {
		t.Fatalf("CURTIME30 应判 unknown 并上报: %+v", f)
	}
	if !strings.Contains(f.Message, "无法自动判定") {
		t.Fatalf("应含无法判定文案: %s", f.Message)
	}
}

// 与/或组合表达式
func TestLegacyAndOrExpr(t *testing.T) {
	key := "01:x::DATA_gt_90_and_DATA_lt_100"
	if _, abnormal := legacyAnalyze(key, 50); abnormal {
		t.Error("50 不应触发 and 组合")
	}
	if _, abnormal := legacyAnalyze(key, 95); !abnormal {
		t.Error("95 应触发 and 组合")
	}
}

// parseLegacyTopics：banner 噪声容忍 + 严重级别映射 + 主机归属
func TestParseLegacyTopicsEndToEnd(t *testing.T) {
	out := "Authorized users only.\n" + `{
	"basic": {"01:ok_item::DATA_eq_0:#1": 5},
	"topics": {
		"01:failed": [
			{"02:count::DATA_gt_0:#2": 3},
			{"03:ip::WRAPDATA_eq__quot_1.2.3.4_quot_:#3": "1.2.3.4"}
		]
	}
}` + "\n"
	ms, fs, err := parseLegacyTopics("10.0.0.9", "ac-x", DimSecurity, []byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Name != "legacy_abnormal_count" {
		t.Fatalf("指标汇总错误: %+v", ms)
	}
	if len(fs) != 2 {
		t.Fatalf("应 2 条异常（basic 正常项不报），实际 %d: %+v", len(fs), fs)
	}
	for _, f := range fs {
		if f.Host != "10.0.0.9" || f.Check != "ac-x" {
			t.Fatalf("归属错误: %+v", f)
		}
		if f.Severity != SevWarn {
			t.Fatalf("warning 应映射 SevWarn: %+v", f)
		}
	}
	if fs[0].Metric != "count" || fs[0].Value != "3" {
		t.Fatalf("排序/字段错误: %+v", fs[0])
	}
}

// JSON 损坏时报错而非 panic
func TestParseLegacyBrokenJSON(t *testing.T) {
	if _, _, err := parseLegacyTopics("h", "c", DimSecurity, []byte("not json at all")); err == nil {
		t.Fatal("坏 JSON 应返回错误")
	}
}
