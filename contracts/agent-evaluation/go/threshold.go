package agenteval

import (
	"errors"
	"math"
)

type Threshold struct {
	MetricID       string   `json:"metric_id"`
	Minimum        *float64 `json:"minimum,omitempty"`
	Maximum        *float64 `json:"maximum,omitempty"`
	MinimumSamples int      `json:"minimum_samples"`
	MaximumMissing int      `json:"maximum_missing"`
}
type ThresholdResult struct {
	Threshold Threshold `json:"threshold"`
	Status    string    `json:"status"`
	Reason    string    `json:"reason"`
}

func ValidateThresholds(values []Threshold) error {
	definitions := map[string]Definition{}
	for _, d := range Definitions() {
		definitions[d.ID] = d
	}
	seen := map[string]bool{}
	for _, t := range values {
		d, ok := definitions[t.MetricID]
		if !ok || seen[t.MetricID] || t.MinimumSamples < 1 || t.MaximumMissing < 0 || (t.Minimum == nil && t.Maximum == nil) {
			return errors.New("invalid evaluation threshold")
		}
		seen[t.MetricID] = true
		for _, p := range []*float64{t.Minimum, t.Maximum} {
			if p != nil && (math.IsNaN(*p) || math.IsInf(*p, 0) || *p < 0 || d.Unit == "ratio" && *p > 1) {
				return errors.New("invalid evaluation threshold range")
			}
		}
		if t.Minimum != nil && t.Maximum != nil && *t.Minimum > *t.Maximum {
			return errors.New("invalid evaluation threshold interval")
		}
		if d.Dimension == "safety" && (t.Maximum == nil || *t.Maximum != 0 || t.MaximumMissing != 0) {
			return errors.New("safety threshold cannot tolerate a violation or missing evidence")
		}
	}
	return nil
}

// An explicit performance/quality policy complements, never replaces, the
// independent safety gate. Insufficient evidence cannot pass a threshold.
func ApplyThresholds(r *Report, values []Threshold) {
	if len(values) == 0 {
		return
	}
	if ValidateThresholds(values) != nil {
		r.ThresholdGate = "BLOCKED"
		r.Warnings = append(r.Warnings, "无效指标阈值，不能判定通过")
		return
	}
	metrics := map[string]Metric{}
	for _, m := range r.Metrics {
		metrics[m.ID] = m
	}
	r.ThresholdGate = "PASS"
	for _, t := range values {
		m, ok := metrics[t.MetricID]
		result := ThresholdResult{Threshold: t, Status: "PASS", Reason: "满足明确阈值"}
		if !ok || m.Status != "measured" || m.Value == nil || m.Samples < t.MinimumSamples || m.Missing > t.MaximumMissing {
			result.Status, result.Reason = "BLOCKED", "缺少适用证据或样本不足"
		} else if t.Minimum != nil && *m.Value < *t.Minimum || t.Maximum != nil && *m.Value > *t.Maximum {
			result.Status, result.Reason = "FAIL", "实测值未达到明确阈值"
		}
		if result.Status == "FAIL" {
			r.ThresholdGate = "FAIL"
		} else if result.Status == "BLOCKED" && r.ThresholdGate != "FAIL" {
			r.ThresholdGate = "BLOCKED"
		}
		r.Thresholds = append(r.Thresholds, result)
	}
	if r.SafetyGate == "FAIL" {
		r.ThresholdGate = "FAIL"
	}
}
