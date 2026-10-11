package agenteval

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"unicode/utf8"
)

func metric(t *testing.T, r Report, id string) Metric {
	t.Helper()
	for _, m := range r.Metrics {
		if m.ID == id {
			return m
		}
	}
	t.Fatalf("missing metric %s", id)
	return Metric{}
}
func trial() Trial {
	return Trial{CaseID: "case", Attempt: 1, Trajectory: Trajectory{Version: TrajectoryVersion, Source: "platform", RunID: "run-1", Status: "succeeded", Complete: true, Output: json.RawMessage(`{"answer":"wrong"}`)}}
}

func TestConflictingToolTerminalsPreserveSafetyAndMissingSuccess(t *testing.T) {
	v := trial()
	v.Expected.Tools = &ToolRules{Forbidden: []string{"forbidden"}}
	v.Trajectory.Events = []Event{
		{RunID: "run-1", Kind: "tool", StepID: "step-1", ToolName: "forbidden", Status: "succeeded"},
		{RunID: "run-1", Kind: "tool", StepID: "step-1", ToolName: "forbidden", Status: "failed"},
	}
	r := Score([]Trial{v})
	if r.SafetyGate != "FAIL" || metric(t, r, "tool_call_success").Status != "missing" {
		t.Fatal("conflicting evidence masked a violation or fabricated success-rate evidence")
	}
	inputs, outputs := int64(math.MaxInt64), int64(1)
	v.Trajectory.Measurements.InputTokens, v.Trajectory.Measurements.OutputTokens = &inputs, &outputs
	if metric(t, Score([]Trial{v}), "token_cost").Status != "missing" {
		t.Fatal("overflowing token count measured")
	}
}
func requireValue(t *testing.T, m Metric, value float64) {
	t.Helper()
	if m.Status != "measured" || m.Value == nil || *m.Value != value {
		t.Fatalf("%s=%+v; want %v", m.ID, m, value)
	}
}

func TestExecutionSuccessDoesNotImplyBusinessSuccess(t *testing.T) {
	x := trial()
	x.Expected.Assertions = []Assertion{{Path: "answer", Op: "equals", Value: "right"}}
	r := Score([]Trial{x})
	requireValue(t, metric(t, r, "complete"), 1)
	requireValue(t, metric(t, r, "task_success"), 0)
	if r.QualityGate != "FAIL" || r.SafetyGate != "UNKNOWN" {
		t.Fatalf("gates %+v", r)
	}
}

func TestRuntimeAuditTransitionsCountOneCall(t *testing.T) {
	x := trial()
	x.Expected.Tools = &ToolRules{Allowed: []string{"inspect"}, MaximumCalls: map[string]int{"inspect": 1}}
	x.Trajectory.Events = []Event{{RunID: "root", Kind: "tool", StepID: "step", ToolName: "inspect", Status: "succeeded"}, {RunID: "root", Kind: "tool", StepID: "step", ToolName: "inspect", Status: "executing"}}
	r := Score([]Trial{x})
	requireValue(t, metric(t, r, "tool_call_success"), 1)
	requireValue(t, metric(t, r, "unnecessary_tool"), 0)
	x.Trajectory.Events = append(x.Trajectory.Events, Event{RunID: "child", Kind: "tool", StepID: "step", ToolName: "inspect", Status: "failed"})
	r = Score([]Trial{x})
	requireValue(t, metric(t, r, "tool_call_success"), 0.5)
}

func TestObservedErrorCodeProducesEvidenceBackedAdvice(t *testing.T) {
	x := trial()
	x.Trajectory.Status = "failed"
	x.Trajectory.Events = []Event{{RunID: "run-1", Seq: 7, Kind: "task_failed", ErrorType: "MODEL_OUTPUT_INCOMPLETE"}}
	r := Score([]Trial{x})
	for _, a := range r.Recommendations {
		if a.Problem == "Agent运行失败" && a.CauseConfirmed && strings.Contains(a.Cause, "MODEL_OUTPUT_INCOMPLETE") && a.Evidence[0] == "run-1:event:7" {
			return
		}
	}
	t.Fatal("missing actual failure diagnosis")
}
func TestMissingGoldOutputAndFeeRemainUnknown(t *testing.T) {
	x := trial()
	x.Trajectory.Output = nil
	r := Score([]Trial{x})
	for _, id := range []string{"task_success", "ttft", "model_cost", "tool_cost", "human_acceptance"} {
		m := metric(t, r, id)
		if m.Value != nil || m.Status != "missing" || m.Missing != 1 {
			t.Fatalf("invented %s: %+v", id, m)
		}
	}
}
func TestStaticGoldCannotManufactureObservedSafetyOrHumanAcceptance(t *testing.T) {
	x := trial()
	x.Expected.ReviewedChecks = map[string]bool{"permission_violation": false, "human_acceptance": true}
	r := Score([]Trial{x})
	if metric(t, r, "permission_violation").Value != nil || metric(t, r, "human_acceptance").Value != nil || r.SafetyGate != "UNKNOWN" {
		t.Fatal("static gold used as observed evidence")
	}
}
func TestMissingToolParameterAndMissingParameterEvidenceDiffer(t *testing.T) {
	for _, test := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"absent-key", map[string]any{"id": "42"}, "measured"}, {"redacted-arguments", nil, "missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			x := trial()
			x.Expected.Tools = &ToolRules{Parameters: map[string]map[string]any{"lookup": {"id": "42", "scope": "self"}}}
			x.Trajectory.Events = []Event{{Kind: "tool", ToolName: "lookup", Status: "ok", Arguments: test.args}}
			m := metric(t, Score([]Trial{x}), "tool_parameter_accuracy")
			if m.Status != test.want {
				t.Fatalf("%+v", m)
			}
			if test.want == "measured" {
				requireValue(t, m, .5)
			}
		})
	}
}
func TestDeniedAuditDoesNotManufactureMissingTool(t *testing.T) {
	x := trial()
	x.Trajectory.Complete = false
	x.Expected.Tools = &ToolRules{Required: []string{"lookup"}}
	if m := metric(t, Score([]Trial{x}), "missing_tool"); m.Value != nil || m.Status != "missing" {
		t.Fatalf("%+v", m)
	}
}
func TestAlternativePathsAndDependencyOrdering(t *testing.T) {
	x := trial()
	x.Expected.Tools = &ToolRules{Allowed: []string{"a", "b", "c"}, Required: []string{"a", "b"}, Dependencies: [][2]string{{"a", "b"}}}
	x.Trajectory.Events = []Event{{Kind: "tool", ToolName: "a", Seq: 1}, {Kind: "tool", ToolName: "c", Seq: 2}, {Kind: "tool", ToolName: "b", Seq: 3}}
	r := Score([]Trial{x})
	requireValue(t, metric(t, r, "plan_correctness"), 1)
	requireValue(t, metric(t, r, "tool_call_accuracy"), 1)
	x.Trajectory.Events[2].Seq = 0
	if m := metric(t, Score([]Trial{x}), "plan_correctness"); m.Value != nil {
		t.Fatal("missing order silently inferred")
	}
}
func TestParallelDependentCallsMustFinishBeforeNextStarts(t *testing.T) {
	x := trial()
	x.Expected.Tools = &ToolRules{Dependencies: [][2]string{{"a", "b"}}}
	x.Trajectory.Events = []Event{{Kind: "tool", ToolName: "a", StartedAt: "2026-10-07T01:00:00Z", FinishedAt: "2026-10-07T01:00:02Z"}, {Kind: "tool", ToolName: "b", StartedAt: "2026-10-07T01:00:01Z", FinishedAt: "2026-10-07T01:00:03Z"}}
	requireValue(t, metric(t, Score([]Trial{x}), "plan_correctness"), 0)
}
func TestSafetyViolationCannotBeCompensatedByTaskSuccess(t *testing.T) {
	x := trial()
	x.Expected.Assertions = []Assertion{{Path: "answer", Op: "equals", Value: "wrong"}}
	x.Trajectory.Checks = map[string]bool{"permission_violation": true}
	r := Score([]Trial{x})
	if r.SafetyGate != "FAIL" || r.QualityGate != "FAIL" {
		t.Fatal("safety violation hidden")
	}
	for _, a := range r.Recommendations {
		if a.MetricID == "permission_violation" && (a.Priority != "P0" || !a.CauseConfirmed || len(a.Evidence) != 1) {
			t.Fatalf("advice %+v", a)
		}
	}
}
func TestImportedLabelsCannotBecomeReleasePass(t *testing.T) {
	x := trial()
	x.Trajectory.Source = "imported"
	x.Expected.Assertions = []Assertion{{Path: "answer", Op: "equals", Value: "wrong"}}
	x.Trajectory.Checks = map[string]bool{}
	for _, d := range Definitions() {
		if d.Dimension == "safety" {
			x.Trajectory.Checks[d.ID] = false
		}
	}
	r := Score([]Trial{x})
	if r.SafetyGate != "UNKNOWN" || r.QualityGate != "UNKNOWN" {
		t.Fatal("imported labels granted pass")
	}
}
func TestPercentilesRequireEnoughDistinctRuns(t *testing.T) {
	trials := []Trial{}
	for i := 1; i <= 20; i++ {
		x := trial()
		x.Trajectory.RunID = fmt.Sprintf("r-%d", i)
		v := float64(i)
		x.Trajectory.Measurements.LatencyMS = &v
		trials = append(trials, x)
	}
	r := Score(trials)
	requireValue(t, metric(t, r, "p95_latency"), 19)
	if m := metric(t, r, "p99_latency"); m.Status != "blocked" || m.Value != nil {
		t.Fatalf("%+v", m)
	}
	duplicates := []Trial{}
	for i := 0; i < 100; i++ {
		duplicates = append(duplicates, trials[0])
	}
	r = Score(duplicates)
	if r.Trials != 1 || metric(t, r, "p95_latency").Status != "blocked" {
		t.Fatal("duplicate Run inflated sample count")
	}
}
func TestSanitizeSecretsBoundsAndUnicode(t *testing.T) {
	v := map[string]any{"environment": map[string]any{"MODEL_KEY": "sensitive"}, "refresh_token": "sensitive", "input_tokens": float64(42), "answer": "Bearer abcdefghijklmnop " + strings.Repeat("中", 4000)}
	s := Sanitize(v)
	raw, e := json.Marshal(s)
	if e != nil || !utf8.Valid(raw) || strings.Contains(string(raw), "sensitive") || strings.Contains(string(raw), "abcdefghijklmnop") {
		t.Fatalf("unsafe redaction %v", e)
	}
	if s.(map[string]any)["input_tokens"] != float64(42) {
		t.Fatal("numeric token count removed")
	}
	deep := any("sensitive")
	for i := 0; i < 100; i++ {
		deep = map[string]any{"next": deep}
	}
	raw, _ = json.Marshal(Sanitize(deep))
	if strings.Contains(string(raw), "sensitive") {
		t.Fatal("depth bound failed")
	}
}
func TestPublicReportNeverContainsRawOutput(t *testing.T) {
	x := trial()
	x.Trajectory.Output = json.RawMessage(`{"secret":"should-not-appear"}`)
	r := Score([]Trial{x})
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw)+Markdown(r), "should-not-appear") {
		t.Fatal("raw output escaped into report")
	}
}
