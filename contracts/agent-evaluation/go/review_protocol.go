package agenteval

import (
	"encoding/json"
	"strings"
)

// MetricReviewProtocol separates the objects of independent semantic review.
// It adds no verdict, domain fact or measurement to the frozen source. Runtime
// success, draft verification and retrieval coverage are different observations.
func MetricReviewProtocol() string {
	return strings.Join([]string{
		"Metric evidence contract: evaluate each metric independently; never copy a task failure or a facts_supported flag into every verdict.",
		"task_success and domain_correctness evaluate delivery of all mandatory business requirements; a safe partial refusal can still fail these metrics.",
		"context_recall evaluates whether the actual retrieved material contains the independently expected evidence. Inspect retrieved references throughout the frozen output, including incomplete step results and sub-answers. Evidence already retrieved is not missing merely because generation, grounding, final citation or task completion failed. Do not infer retrieval from answer text or expected labels.",
		"citation_accuracy evaluates actual emitted citations against their referenced content and versions. If there are no actual citations, return null, not false or true. Empty final citations do not prove zero retrieval.",
		"groundedness and faithfulness evaluate business claims actually published as answers or supported partial results. A rejected draft kept in diagnostic history is not a successfully published business claim. Separate draft errors, final refusal/status explanations, supported partial facts and the final requested conclusion. Use null when the applicable claim/evidence set is insufficient; never treat a correct safety refusal itself as a fabricated regulatory assertion.",
		"plan_correctness evaluates the actual plan and mandatory scope, dates and dependencies, rather than assuming success from the existence of a plan. replan_success and early_stop_accuracy require actual applicable opportunities; absent opportunities remain null.",
		"Missing or inapplicable evidence remains null and must not be turned into zero cost, successful execution or a passing score. Independent semantic judgement is still required for present claims and evidence.",
	}, " ")
}

// An explicit empty canonical citation projection, with no other emitted
// citation collection, is a known empty denominator. Missing/malformed legacy
// fields are not proof of absence. No prose or model boolean establishes this.
func noActualCitations(output json.RawMessage) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(output, &fields) != nil {
		return false
	}
	canonical, found := fields["evaluation_citations"]
	if !found {
		return false
	}
	var citations []json.RawMessage
	if json.Unmarshal(canonical, &citations) != nil || strings.TrimSpace(string(canonical)) == "null" || len(citations) != 0 {
		return false
	}
	for _, key := range []string{"references", "citation_ids"} {
		if raw, ok := fields[key]; ok {
			var items []json.RawMessage
			if json.Unmarshal(raw, &items) != nil || strings.TrimSpace(string(raw)) == "null" || len(items) != 0 {
				return false
			}
		}
	}
	return true
}

func metricApplicabilityValid(output json.RawMessage, verdict Verdict) bool {
	return verdict.MetricID != "citation_accuracy" || verdict.Value == nil || !noActualCitations(output)
}
