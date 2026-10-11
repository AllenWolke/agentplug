package agenteval

import (
	"encoding/json"
	"strings"
	"testing"
)

func reviewInput() JudgeInput {
	r := Rubric{Version: RubricVersion, ID: "teaching-v1", Criteria: map[string]string{"faithfulness": "Every material claim is supported by the cited evidence"}}
	return JudgeInput{Version: "agent-eval-judge-input/v1", SourceRunID: "run-1", SourceOutputHash: strings.Repeat("a", 64), Rubric: r, RubricHash: RubricDigest(r), Evidence: map[string]json.RawMessage{"output": json.RawMessage(`{"answer":"supported"}`)}}
}
func TestJudgeCannotCertifySafetyOrInventEvidence(t *testing.T) {
	in := reviewInput()
	if in.Validate() != nil {
		t.Fatal("valid rubric rejected")
	}
	value := true
	if ValidateVerdicts(in, []Verdict{{MetricID: "faithfulness", Value: &value, Evidence: []string{"invented"}, Reason: "supported by evidence"}}) == nil {
		t.Fatal("invented evidence accepted")
	}
	in.Rubric.Criteria["permission_violation"] = "No permission violation occurred"
	in.RubricHash = RubricDigest(in.Rubric)
	if in.Validate() == nil {
		t.Fatal("model granted permission to certify security")
	}
}
func TestBoundModelUnknownAndHumanCalibration(t *testing.T) {
	in := reviewInput()
	yes, no := true, false
	j := Judgement{Version: JudgementVersion, Source: "model", SourceRunID: in.SourceRunID, SourceOutputHash: in.SourceOutputHash, Rubric: in.Rubric, RubricHash: in.RubricHash, JudgeRunID: "grading-run", JudgeVersionID: "grading-v1", Verdicts: []Verdict{{MetricID: "faithfulness", Value: nil, Reason: "missing independent evidence"}}}
	trial := Trial{CaseID: "case", Attempt: 1, Trajectory: Trajectory{Source: "platform", RunID: in.SourceRunID, OutputHash: in.SourceOutputHash}, Judgements: []Judgement{j}}
	report := Score([]Trial{trial})
	for _, m := range report.Metrics {
		if m.ID == "faithfulness" && (m.Value != nil || m.Status != "missing") {
			t.Fatal("unknown model result invented a score")
		}
	}
	j.Verdicts[0] = Verdict{MetricID: "faithfulness", Value: &yes, Evidence: []string{"output"}, Reason: "evidence is consistent"}
	human := j
	human.Source, human.JudgeRunID, human.JudgeVersionID, human.ReviewerID, human.ReviewEvidenceID = "human", "", "", "reviewer", "feedback-1"
	human.Verdicts = []Verdict{{MetricID: "faithfulness", Value: &no, Evidence: []string{"output"}, Reason: "claim contradicts evidence"}}
	trial.Judgements = []Judgement{j, human}
	report = Score([]Trial{trial})
	for _, m := range report.Metrics {
		if m.ID == "faithfulness" && (m.Value == nil || *m.Value != 0) {
			t.Fatal("human calibration did not override model")
		}
	}
	if report.SafetyGate != "UNKNOWN" || len(report.Reviews) != 2 || len(report.Reviews[1].Overrides) != 1 {
		t.Fatal("calibration trace or independent safety gate incorrect")
	}
}
func TestJudgementWrongSourceIgnoredAndBusinessAssertionsRemainAuthoritative(t *testing.T) {
	in := reviewInput()
	in.Rubric.Criteria = map[string]string{"task_success": "The business goal is fully completed"}
	in.RubricHash = RubricDigest(in.Rubric)
	yes := true
	j := Judgement{Version: JudgementVersion, Source: "model", SourceRunID: in.SourceRunID, SourceOutputHash: in.SourceOutputHash, Rubric: in.Rubric, RubricHash: in.RubricHash, JudgeRunID: "grading-run", JudgeVersionID: "grading-v1", Verdicts: []Verdict{{MetricID: "task_success", Value: &yes, Evidence: []string{"output"}, Reason: "model thinks the task is complete"}}}
	trial := Trial{CaseID: "case", Attempt: 1, Trajectory: Trajectory{Source: "platform", RunID: in.SourceRunID, OutputHash: in.SourceOutputHash, Output: json.RawMessage(`{"completed":false}`)}, Expected: Expected{Assertions: []Assertion{{Path: "completed", Op: "equals", Value: true}}}, Judgements: []Judgement{j}}
	report := Score([]Trial{trial})
	for _, m := range report.Metrics {
		if m.ID == "task_success" && (m.Value == nil || *m.Value != 0) {
			t.Fatal("model overrode failed business assertion")
		}
	}
	trial.Judgements[0].SourceOutputHash = strings.Repeat("b", 64)
	report = Score([]Trial{trial})
	if len(report.Reviews) != 0 {
		t.Fatal("mismatched original source accepted")
	}
}

func TestSanitizedJudgementPreservesUnknownUsageContract(t *testing.T) {
	j := Judgement{Version: JudgementVersion, Source: "model", SourceRunID: "run-1"}
	raw, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("invalid judgement fixture")
	}
	safe, err := json.Marshal(Sanitize(value))
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip Judgement
	if json.Unmarshal(safe, &roundtrip) != nil || roundtrip.Measurements.InputTokens != nil || roundtrip.Measurements.OutputTokens != nil {
		t.Fatal("unknown counters changed from null to a credential placeholder or fabricated zero")
	}
	counts := Sanitize(map[string]any{"input_tokens": nil, "output_tokens": json.Number("12"), "total_tokens": "private-counter-credential", "access_token": nil}).(map[string]any)
	if counts["input_tokens"] != nil || counts["output_tokens"] != json.Number("12") || counts["total_tokens"] != "[REDACTED]" || counts["access_token"] != "[REDACTED]" {
		t.Fatal("nullable usage exception weakened credential redaction")
	}
}

func TestReviewEvidenceRetainsTerminalRegardlessOfAuditOrdering(t *testing.T) {
	terminal := Event{RunID: "r", Kind: "tool", StepID: "s", ToolName: "read", Status: "succeeded"}
	started := terminal
	started.Status = "executing"
	for _, events := range [][]Event{{started, terminal}, {terminal, started}} {
		result := ReviewEvidenceEvents(events)
		if len(result) != 1 || result[0].Status != "succeeded" {
			t.Fatal("review froze an intermediate state instead of the terminal outcome")
		}
	}
	conflict := terminal
	conflict.Status = "failed"
	result := ReviewEvidenceEvents([]Event{terminal, conflict, started})
	if len(result) != 1 || result[0].Status != "unknown" || result[0].ErrorType != "CONFLICTING_TOOL_TERMINALS" {
		t.Fatal("review hid conflicting terminal evidence")
	}
}
