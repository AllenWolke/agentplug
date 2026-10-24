package evaluationproduct

import (
	"bytes"
	"encoding/json"
	"io"

	agenteval "github.com/lexagent/agent-evaluation"
)

type independentVerdictFormula struct {
	Version  string `json:"version"`
	MetricID string `json:"metric_id"`
}

const IndependentVerdictProtocol = "independent-verdict/v1"

// Only an actual gateway execution of the independent reviewer may receive the
// protocol marker. Missing outcomes remain unknown in the normal aggregator.
func independentReviewMeasured(agentID, version string, invocation InvocationResult, metrics []MetricSnapshot, input json.RawMessage) bool {
	if agentID != "agent-eval-judge" || invocation.ProviderMode != "real" || !validID(invocation.ExecutionRunID) || len(metrics) == 0 {
		return false
	}
	for _, metric := range metrics {
		if metric.Kind != "independent_verdict" {
			return false
		}
	}
	var result struct {
		Judgement agenteval.Judgement `json:"judgement"`
	}
	if json.Unmarshal(invocation.Output, &result) != nil || result.Judgement.JudgeRunID != invocation.ExecutionRunID || result.Judgement.JudgeVersionID != version || result.Judgement.SourceRunID == invocation.ExecutionRunID {
		return false
	}
	_, err := EvaluateIndependentVerdict(metrics[0], input, invocation.Output)
	return err == nil
}

func parseIndependentVerdictFormula(raw json.RawMessage) (independentVerdictFormula, error) {
	var f independentVerdictFormula
	if rejectDuplicateJSONKeys(raw) != nil {
		return f, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || d.Decode(new(any)) != io.EOF || f.Version != "independent-verdict/v1" || !agenteval.ModelReviewable(f.MetricID) {
		return f, ErrInvalid
	}
	return f, nil
}

// EvaluateIndependentVerdict projects an existing independent model judgement.
// It performs no model call and adds no domain rubric. Publication/invocation
// protection still authorizes the original source, and routing qualification
// additionally verifies the native judge and business Run/model receipts.
func EvaluateIndependentVerdict(metric MetricSnapshot, input, output json.RawMessage) (MetricOutcome, error) {
	unknown := MetricOutcome{MetricID: metric.ID, Status: "unknown", Direction: "higher_is_better"}
	f, err := parseIndependentVerdictFormula(metric.Formula)
	if err != nil {
		return unknown, err
	}
	var sample struct {
		Input json.RawMessage `json:"input"`
	}
	var judge agenteval.JudgeInput
	if rejectDuplicateJSONKeys(input) != nil || json.Unmarshal(input, &sample) != nil {
		return unknown, ErrSnapshotInvalid
	}
	d := json.NewDecoder(bytes.NewReader(sample.Input))
	d.DisallowUnknownFields()
	if d.Decode(&judge) != nil || d.Decode(new(any)) != io.EOF {
		return unknown, ErrSnapshotInvalid
	}
	ref, err := judge.SourceReference()
	if err != nil {
		return unknown, ErrSnapshotInvalid
	}
	var result struct {
		Schema    string              `json:"schema"`
		Judgement agenteval.Judgement `json:"judgement"`
	}
	if len(output) > 1<<20 || rejectDuplicateJSONKeys(output) != nil || json.Unmarshal(output, &result) != nil {
		return unknown, ErrSnapshotInvalid
	}
	j := result.Judgement
	if result.Schema != "schema://agent-eval-judge/output/v1" || j.Version != agenteval.JudgementVersion || j.Source != "model" ||
		!validID(j.JudgeRunID) || !validID(j.JudgeVersionID) ||
		j.SourceRunID != ref.RunID || j.SourceOutputHash != ref.OutputHash || j.SourceRedactedOutputHash != ref.RedactedOutputHash ||
		j.RubricHash != judge.RubricHash || agenteval.RubricDigest(j.Rubric) != judge.RubricHash || agenteval.ValidateVerdicts(judge, j.Verdicts) != nil {
		return unknown, ErrSnapshotInvalid
	}
	if raw, exists := judge.Evidence["expected"]; exists {
		var expected agenteval.Expected
		if json.Unmarshal(raw, &expected) != nil || j.ExpectedHash != agenteval.ExpectedDigest(expected) {
			return unknown, ErrSnapshotInvalid
		}
	}
	for _, verdict := range j.Verdicts {
		if verdict.MetricID != f.MetricID {
			continue
		}
		if verdict.Value == nil {
			return unknown, nil
		}
		value := 0.0
		if *verdict.Value {
			value = 1
		}
		// "passed" denotes a verified measurement, not semantic success. A
		// verified false verdict is retained as zero; suite quality thresholds
		// and routing's required thresholds judge its aggregate quality.
		return MetricOutcome{MetricID: metric.ID, Status: "passed", Value: &value, Direction: "higher_is_better"}, nil
	}
	return unknown, nil
}
