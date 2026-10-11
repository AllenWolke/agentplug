package evaluationproduct

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	agenteval "github.com/lexagent/agent-evaluation"
)

func evaluationLimitsEqual(a, b *EvaluationLimits) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// EvaluateAgentAssertions scores evaluator-owned gold. Expected labels never
// reach the Agent-visible input. It cannot manufacture semantic grounding.
func EvaluateAgentAssertions(_ context.Context, metric MetricSnapshot, input, output json.RawMessage) (MetricOutcome, error) {
	sample, err := decodeEvaluationCase(input)
	if err != nil {
		return MetricOutcome{}, err
	}
	var expected agenteval.Expected
	var actual any
	gold := json.NewDecoder(bytes.NewReader(sample.Expected))
	gold.UseNumber()
	result := json.NewDecoder(bytes.NewReader(output))
	result.UseNumber()
	if gold.Decode(&expected) != nil || len(expected.Assertions) == 0 || result.Decode(&actual) != nil {
		return MetricOutcome{}, errors.New("agent assertions require reviewed gold and actual output")
	}
	passed := true
	for _, assertion := range expected.Assertions {
		if !agenteval.Assert(actual, assertion) {
			passed = false
		}
	}
	value := 0.
	status := "blocked"
	if passed {
		value, status = 1., "passed"
	}
	return MetricOutcome{MetricID: metric.ID, Status: status, Value: &value, Direction: "higher_is_better"}, nil
}
