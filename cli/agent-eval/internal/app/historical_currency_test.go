package app

import (
	agenteval "github.com/lexagent/agent-evaluation"
	"testing"
)

func TestHistoricalCohortPreservesOnlyProvenUniformCurrency(t *testing.T) {
	for _, tc := range []struct {
		name       string
		currencies []string
		expected   string
	}{
		{"USD", []string{"USD", "USD"}, "USD"},
		{"missing", []string{"USD", ""}, ""},
		{"mixed", []string{"USD", "CNY"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trials := []agenteval.Trial{}
			for i, currency := range tc.currencies {
				trials = append(trials, agenteval.Trial{Trajectory: agenteval.Trajectory{Source: "platform", RunID: []string{"run1", "run2"}[i], BusinessInputHash: "fixed-input", Agent: agenteval.Agent{AgentID: "qa"}, Measurements: agenteval.Measurements{Currency: currency}}})
			}
			result := historicalCohort(trials, agenteval.Expected{})
			if result == nil || result.Currency != tc.expected || result.Concurrency != 0 || result.LimitTokens != 0 || result.Mode != "online" {
				t.Fatalf("invented historical measurement: %+v", result)
			}
		})
	}
}
