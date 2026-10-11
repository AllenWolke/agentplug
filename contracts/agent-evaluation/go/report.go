package agenteval

import (
	"fmt"
	"strings"
)

// Markdown contains summaries and identifiers, never raw inputs or model outputs.
func Markdown(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Agent Evaluation报告\n\n版本：%s；样本：%d；来源：%s。\n\n安全门禁：**%s**；任务与安全门禁：**%s**。\n\n", r.Version, r.Trials, r.Source, r.SafetyGate, r.QualityGate)
	if len(r.Targets) > 0 {
		b.WriteString("| Agent | 发布版本 | 安装实例 |\n|---|---|---|\n")
		for _, a := range r.Targets {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", a.AgentID, a.VersionID, a.InstallationID)
		}
		b.WriteString("\n")
	}
	b.WriteString("| 维度 | 指标 | 状态 | 数值 | 样本 | 缺失 |\n|---|---|---|---:|---:|---:|\n")
	for _, m := range r.Metrics {
		value := "—"
		if m.Value != nil {
			value = fmt.Sprintf("%.4f %s", *m.Value, m.Unit)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %d |\n", m.Dimension, m.Name, m.Status, value, m.Samples, m.Missing)
	}
	b.WriteString("\n## 改进建议\n\n")
	if len(r.Thresholds) > 0 {
		fmt.Fprintf(&b, "明确阈值门禁：**%s**；该结论不替代安全门禁。\n\n", r.ThresholdGate)
		for _, t := range r.Thresholds {
			fmt.Fprintf(&b, "- %s：%s，%s。\n", t.Threshold.MetricID, t.Status, t.Reason)
		}
		b.WriteString("\n")
	}
	for _, s := range r.Recommendations {
		fmt.Fprintf(&b, "- **%s · %s**：%s。原因%s：%s。建议：%s。复验：%s。证据：%s。\n", s.Priority, s.MetricID, s.Problem, map[bool]string{true: "已确认", false: "待核查"}[s.CauseConfirmed], s.Cause, s.Change, s.Retest, strings.Join(s.Evidence, ", "))
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "\n注意：%s。\n", w)
	}
	if len(r.Reviews) > 0 {
		b.WriteString("\n## 评分与人工校准记录\n\n| 来源 | 原Run | Rubric | 评分Run或反馈ID | 评分模型 | 已确认评分费用 | 校准分歧 |\n|---|---|---|---|---|---|---|\n")
		for _, s := range r.Reviews {
			cost := "未知"
			if s.Measurements.CostMicros != nil {
				cost = fmt.Sprintf("%d micros %s", *s.Measurements.CostMicros, s.Measurements.Currency)
			}
			ref := s.JudgeRunID
			if s.Source == "human" {
				ref = s.ReviewEvidenceID
			}
			fmt.Fprintf(&b, "| %s | %s | %s @ %s | %s | %s @ %s | %s | %s |\n", s.Source, s.SourceRunID, s.RubricID, s.RubricHash, ref, s.ScoringModel, s.ScoringModelVersion, cost, strings.Join(s.Overrides, ","))
		}
	}
	return b.String()
}
