package evaluationproduct

import "encoding/json"

// Grounding belongs to the frozen suite's independent evaluator. Agent output
// is merely evidence to score; its own claim of passing is never sufficient.
func applyMetricGrounding(result *CaseResultData, metrics []MetricSnapshot) {
	seen := map[string]bool{}
	for i, metric := range metrics {
		if metric.Kind != "grounding" || i >= len(result.Metrics) {
			continue
		}
		var formula remoteMetricFormula
		if json.Unmarshal(metric.Formula, &formula) != nil || !formula.validFor(metric.Kind) {
			result.CitationGrounding, result.DomainGrounding = "unknown", "unknown"
			return
		}
		target := formula.GroundingTarget
		if target == "" {
			target = "citation"
		}
		verdict := "unknown"
		outcome := result.Metrics[i]
		if outcome.MetricID == metric.ID {
			switch outcome.Status {
			case "passed":
				if outcome.Value != nil && *outcome.Value == 1 {
					verdict = "passed"
				} else if outcome.Value != nil {
					verdict = "failed"
				}
			case "blocked":
				verdict = "failed"
			}
		}
		field := &result.CitationGrounding
		if target == "domain" {
			field = &result.DomainGrounding
		}
		if seen[target] {
			verdict = mergeGrounding(*field, verdict)
		}
		*field, seen[target] = verdict, true
	}
}
