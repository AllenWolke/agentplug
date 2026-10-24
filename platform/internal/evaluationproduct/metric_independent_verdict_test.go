package evaluationproduct

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	agenteval "github.com/lexagent/agent-evaluation"
)

func independentVerdictFixture(t *testing.T, value *bool) (json.RawMessage, agenteval.Judgement) {
	t.Helper()
	expected := agenteval.Expected{DomainFacts: []string{"The frozen balance is 1200."}, GoldReferences: []agenteval.GoldReference{{ID: "doc-1", Revision: "v2", Source: "independent-simulation", Content: "The balance is 1200."}}}
	rubric := agenteval.Rubric{Version: agenteval.RubricVersion, ID: "quality-v1", Criteria: map[string]string{"domain_correctness": "Compare the output with the independent frozen balance."}}
	expectedJSON, _ := json.Marshal(expected)
	judge := agenteval.JudgeInput{Version: agenteval.JudgeInputV2, SourceRunID: "business-run-1", SourceOutputHash: strings.Repeat("a", 64), Rubric: rubric, RubricHash: agenteval.RubricDigest(rubric), Evidence: map[string]json.RawMessage{"output": json.RawMessage(`{"answer":"1200"}`), "expected": expectedJSON}}
	ref, err := judge.SourceReference()
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]any{"input": judge, "expected": map[string]string{"routing_complexity": "simple"}})
	verdict := agenteval.Verdict{MetricID: "domain_correctness", Value: value, Reason: "Compared with independent source."}
	if value != nil {
		verdict.Evidence = []string{"output", "expected"}
	}
	return input, agenteval.Judgement{Version: agenteval.JudgementVersion, Source: "model", JudgeRunID: "judge-run-1", JudgeVersionID: "judge-v2", SourceRunID: ref.RunID, SourceOutputHash: ref.OutputHash, SourceRedactedOutputHash: ref.RedactedOutputHash, Rubric: rubric, RubricHash: judge.RubricHash, ExpectedHash: agenteval.ExpectedDigest(expected), Verdicts: []agenteval.Verdict{verdict}}
}

func independentVerdictOutput(j agenteval.Judgement) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"schema": "schema://agent-eval-judge/output/v1", "judgement": j})
	return raw
}

func TestIndependentVerdictRetainsWrongAndUnknownSeparately(t *testing.T) {
	metric := MetricSnapshot{ID: "domain_correctness.1", Kind: "independent_verdict", Formula: json.RawMessage(`{"version":"independent-verdict/v1","metric_id":"domain_correctness"}`)}
	good, bad := true, false
	for _, item := range []struct {
		name    string
		verdict *bool
		score   *float64
	}{{"correct", &good, floatPointer(1)}, {"wrong", &bad, floatPointer(0)}, {"unknown", nil, nil}} {
		t.Run(item.name, func(t *testing.T) {
			input, j := independentVerdictFixture(t, item.verdict)
			for _, evaluator := range []MetricEvaluator{BuiltinMetricEvaluator{}, RemoteMetricEvaluator{}} {
				result, err := evaluator.EvaluateMetric(context.Background(), metric, input, independentVerdictOutput(j))
				if err != nil || result.MetricID != metric.ID {
					t.Fatalf("unexpected projection: %+v %v", result, err)
				}
				if item.score == nil {
					if result.Value != nil || result.Status != "unknown" {
						t.Fatal("unknown verdict was made measurable")
					}
				} else if result.Value == nil || *result.Value != *item.score || result.Status != "passed" {
					t.Fatal("measured false/true verdict was lost")
				}
			}
		})
	}
}

func TestIndependentVerdictRejectsReboundOrSelfDeclaredJudgement(t *testing.T) {
	metric := MetricSnapshot{ID: "domain_correctness.1", Formula: json.RawMessage(`{"version":"independent-verdict/v1","metric_id":"domain_correctness"}`)}
	good := true
	for name, change := range map[string]func(*agenteval.Judgement){
		"self assertion":        func(j *agenteval.Judgement) { j.Source = "agent" },
		"wrong source":          func(j *agenteval.Judgement) { j.SourceRunID = "another-run" },
		"wrong raw output":      func(j *agenteval.Judgement) { j.SourceOutputHash = strings.Repeat("b", 64) },
		"wrong redaction":       func(j *agenteval.Judgement) { j.SourceRedactedOutputHash = strings.Repeat("c", 64) },
		"changed gold":          func(j *agenteval.Judgement) { j.ExpectedHash = strings.Repeat("d", 64) },
		"changed rubric":        func(j *agenteval.Judgement) { j.RubricHash = strings.Repeat("e", 64) },
		"missing judge":         func(j *agenteval.Judgement) { j.JudgeRunID = "" },
		"missing judge version": func(j *agenteval.Judgement) { j.JudgeVersionID = "" },
		"invented evidence":     func(j *agenteval.Judgement) { j.Verdicts[0].Evidence = []string{"output", "invented"} },
		"duplicate verdict":     func(j *agenteval.Judgement) { j.Verdicts = append(j.Verdicts, j.Verdicts[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			input, j := independentVerdictFixture(t, &good)
			change(&j)
			result, err := EvaluateIndependentVerdict(metric, input, independentVerdictOutput(j))
			if err == nil || result.Status != "unknown" || result.Value != nil {
				t.Fatal("unbound judgement produced a quality measurement")
			}
		})
	}
	for _, formula := range []string{`{"version":"independent-verdict/v2","metric_id":"domain_correctness"}`, `{"version":"independent-verdict/v1","metric_id":"permission_violation"}`, `{"version":"independent-verdict/v1","metric_id":"domain_correctness","constant":1}`, `{"version":"independent-verdict/v1","metric_id":"task_success","metric_id":"domain_correctness"}`} {
		if _, err := parseIndependentVerdictFormula(json.RawMessage(formula)); err == nil {
			t.Fatal("unreviewable or unknown formula accepted")
		}
	}
}

func TestIndependentVerdictAverageDoesNotCountUnknownAsZero(t *testing.T) {
	metric := MetricSnapshot{ID: "domain_correctness.1"}
	measured := []CaseResultData{{Metrics: []MetricOutcome{{MetricID: metric.ID, Status: "passed", Value: floatPointer(1), Direction: "higher_is_better"}}}, {Metrics: []MetricOutcome{{MetricID: metric.ID, Status: "passed", Value: floatPointer(0), Direction: "higher_is_better"}}}}
	result := aggregateCaseMetrics([]MetricSnapshot{metric}, measured)[0]
	if result.Value == nil || *result.Value != .5 || result.Status != "passed" {
		t.Fatal("wrong verdict disappeared from the denominator")
	}
	measured[1].Metrics[0].Status, measured[1].Metrics[0].Value = "unknown", nil
	result = aggregateCaseMetrics([]MetricSnapshot{metric}, measured)[0]
	if result.Value != nil || result.Status != "unknown" {
		t.Fatal("missing judgement fabricated a complete average")
	}
}

func TestDerivedJudgeV2DatasetHonorsExistingEnvelopeLimit(t *testing.T) {
	good := true
	fixture, _ := independentVerdictFixture(t, &good)
	var wrapper struct {
		Input agenteval.JudgeInput `json:"input"`
	}
	if err := json.Unmarshal(fixture, &wrapper); err != nil {
		t.Fatal(err)
	}
	wrapper.Input.Evidence["output"] = json.RawMessage(`{"answer":"` + strings.Repeat("x", 70<<10) + `"}`)
	build := func(in agenteval.JudgeInput) DatasetData {
		raw, _ := json.Marshal(map[string]any{"case_id": "long-judge-v2", "input": in, "expected": map[string]string{"routing_complexity": "complex"}, "split": "frozen"})
		return DatasetData{Name: "source-bound long judge input", Version: "1", SourceType: "imported_redacted", Cases: []json.RawMessage{raw}}
	}
	if err := validateDataset(build(wrapper.Input)); err != nil {
		t.Fatal("valid 70 KiB judge-v2 output rejected", err)
	}
	wrapper.Input.Version = agenteval.JudgeInputV1
	if validateDataset(build(wrapper.Input)) == nil {
		t.Fatal("judge-v1 silently adopted the larger envelope")
	}
	wrapper.Input.Version = agenteval.JudgeInputV2
	dataset := build(wrapper.Input)
	dataset.SourceType = "manual_gold"
	if validateDataset(dataset) == nil {
		t.Fatal("large source-bound evidence accepted without derived-source protection")
	}
	wrapper.Input.Evidence["output"] = json.RawMessage(`{"answer":"` + strings.Repeat("x", 97<<10) + `"}`)
	if validateDataset(build(wrapper.Input)) == nil {
		t.Fatal("judge-v2 per-output bound exceeded")
	}
	wrapper.Input.Version = agenteval.JudgeInputV3
	wrapper.Input.Evidence["output"] = json.RawMessage(`{"answer":"` + strings.Repeat("x", 200<<10) + `"}`)
	if validateDataset(build(wrapper.Input)) != nil {
		t.Fatal("source-bound V3 capacity rejected")
	}
	large := build(wrapper.Input)
	large.SourceType = "manual_gold"
	if validateDataset(large) == nil {
		t.Fatal("V3 large case bypassed source protection")
	}
}

func TestIndependentReviewProtocolSeparatesVerifiedMeasurementFromQuality(t *testing.T) {
	bad := false
	input, judgement := independentVerdictFixture(t, &bad)
	metric := MetricSnapshot{ID: "domain_correctness.1", Kind: "independent_verdict", Formula: json.RawMessage(`{"version":"independent-verdict/v1","metric_id":"domain_correctness"}`)}
	invocation := InvocationResult{ExecutionRunID: judgement.JudgeRunID, Output: independentVerdictOutput(judgement), ProviderMode: "real"}
	if !independentReviewMeasured("agent-eval-judge", judgement.JudgeVersionID, invocation, []MetricSnapshot{metric}, input) {
		t.Fatal("valid false measurement lost its source protocol")
	}
	if independentReviewMeasured("business-agent", judgement.JudgeVersionID, invocation, []MetricSnapshot{metric}, input) {
		t.Fatal("business self-evaluation received independent protocol")
	}
	if independentReviewMeasured("agent-eval-judge", "another-version", invocation, []MetricSnapshot{metric}, input) {
		t.Fatal("native reviewer version was not bound")
	}
	invocation.ExecutionRunID = "another-native-run"
	if independentReviewMeasured("agent-eval-judge", judgement.JudgeVersionID, invocation, []MetricSnapshot{metric}, input) {
		t.Fatal("native reviewer identity was not bound")
	}
	now := time.Now().UTC()
	evidence := EvidenceData{MeasurementProtocol: IndependentVerdictProtocol, RunID: "evaluation-run", Status: "succeeded", SourceType: "imported_redacted", ProviderMode: "real", SampleCount: 1, CaseResultIDs: []string{"case-1"}, MetricsPresent: true, ArtifactsPresent: true, ReportHash: strings.Repeat("a", 64), SuiteSnapshotHash: strings.Repeat("b", 64), DatasetContentHash: strings.Repeat("c", 64), ProducedAt: now, CitationGrounding: "unknown", DomainGrounding: "unknown", Metrics: []MetricOutcome{{MetricID: metric.ID, Status: "passed", Value: floatPointer(0), Direction: "higher_is_better"}}}
	if evaluateEvidence(evidence, nil, now).State != GatePass {
		t.Fatal("valid measurement was confused with quality acceptance")
	}
	if evaluateEvidence(evidence, floatPointer(.90), now).State == GatePass {
		t.Fatal("wrong verdict passed the quality threshold")
	}
	evidence.MeasurementProtocol = ""
	if evaluateEvidence(evidence, nil, now).State == GatePass {
		t.Fatal("legacy grounding requirements were loosened")
	}
	evidence.MeasurementProtocol = IndependentVerdictProtocol
	evidence.Metrics[0].Status, evidence.Metrics[0].Value = "unknown", nil
	if evaluateEvidence(evidence, nil, now).State == GatePass {
		t.Fatal("missing independent measurement passed")
	}
}

func TestIndependentProtocolIsOmittedFromLegacyRecordsAndBoundToNewReports(t *testing.T) {
	legacyCase := CaseResultData{RunID: "legacy-run", Index: 0}
	legacyEvidence := EvidenceData{RunID: "legacy-run"}
	for _, value := range []any{legacyCase, legacyEvidence} {
		raw, _ := json.Marshal(value)
		if strings.Contains(string(raw), "measurement_protocol") || strings.Contains(string(raw), "execution_run_id") {
			t.Fatal("optional protocol changed legacy JSON")
		}
	}
	before, err := evaluationReportHash(legacyEvidence, []CaseResultData{legacyCase})
	if err != nil {
		t.Fatal(err)
	}
	legacyCase.MeasurementProtocol, legacyCase.ExecutionRunID = IndependentVerdictProtocol, "native-review-run"
	legacyEvidence.MeasurementProtocol = IndependentVerdictProtocol
	after, err := evaluationReportHash(legacyEvidence, []CaseResultData{legacyCase})
	if err != nil || after == before {
		t.Fatal("native independent execution metadata was not bound to the report")
	}
}
