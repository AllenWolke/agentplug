package app

import (
	agenteval "github.com/lexagent/agent-evaluation"
	"sort"
)

// Compare only matching workloads. Version and installation may change;
// unmeasured budgets, concurrency and timing are not filled with assumptions.
func historicalCohort(trials []agenteval.Trial, expected agenteval.Expected) *agenteval.Cohort {
	if len(trials) == 0 {
		return nil
	}
	inputs := []string{}
	agentID := trials[0].Trajectory.Agent.AgentID
	seen := map[string]bool{}
	for _, t := range trials {
		if t.Trajectory.Source != "platform" || t.Trajectory.Agent.AgentID != agentID || t.Trajectory.BusinessInputHash == "" {
			return nil
		}
		if seen[t.Trajectory.RunID] {
			continue
		}
		seen[t.Trajectory.RunID] = true
		inputs = append(inputs, t.Trajectory.BusinessInputHash)
	}
	sort.Strings(inputs)
	// 历史测量条件保持未知；币种仅来自平台已证明的实际轨迹。
	currency := trials[0].Trajectory.Measurements.Currency
	for _, t := range trials {
		if t.Trajectory.Measurements.Currency == "" || t.Trajectory.Measurements.Currency != currency {
			currency = ""
			break
		}
	}
	return &agenteval.Cohort{AgentID: agentID, DatasetHash: checksum([]any{inputs, expected}), Mode: "online", ScorerVersion: "agent-eval-rules/v1", MeasurementProtocol: "historical-read/v1", Currency: currency}
}

func reviewProtocolHash(r agenteval.Report) string {
	if len(r.Reviews) == 0 {
		return ""
	}
	protocols := map[string]bool{}
	for _, j := range r.Reviews {
		protocols[checksum([]string{j.Source, j.RubricHash, j.JudgeVersionID, j.ScoringModel, j.ScoringModelVersion, j.ReviewerID})] = true
	}
	keys := []string{}
	for k := range protocols {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return checksum(keys)
}
