package agenteval

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEmptyCitationDenominatorCannotProduceMeasuredVerdict(t *testing.T) {
	for _, raw := range []string{
		`{"evaluation_citations":[],"references":[],"citation_ids":[]}`,
		`{"evaluation_citations":[]}`,
	} {
		in := reviewInput()
		in.Rubric.Criteria = map[string]string{"citation_accuracy": "Compare actual emitted citations; empty denominator remains unknown"}
		in.RubricHash = RubricDigest(in.Rubric)
		in.Evidence["output"] = json.RawMessage(raw)
		for _, value := range []bool{true, false} {
			if ValidateVerdicts(in, []Verdict{{MetricID: "citation_accuracy", Value: &value, Evidence: []string{"output"}, Reason: "No actual citations were emitted"}}) == nil {
				t.Fatal("empty citation denominator was measured", raw, value)
			}
		}
		if err := ValidateVerdicts(in, []Verdict{{MetricID: "citation_accuracy", Evidence: []string{"output"}, Reason: "No actual citations were emitted"}}); err != nil {
			t.Fatal("unknown citation verdict rejected", err)
		}
	}
}

func TestMissingMalformedOrConflictingCitationProjectionIsNotProofOfEmptyDenominator(t *testing.T) {
	for _, raw := range []string{
		`{"answer":"unsupported source"}`,
		`{"evaluation_citations":null}`,
		`{"evaluation_citations": null }`,
		`{"evaluation_citations":{}}`,
		`{"evaluation_citations":[],"references":[{"doc_id":"wrong"}]}`,
		`{"evaluation_citations":[{"id":"wrong"}]}`,
		`{"evaluation_citations":[],"citation_ids":["wrong"]}`,
	} {
		if noActualCitations(json.RawMessage(raw)) {
			t.Fatal("unknown or present citations fabricated an empty denominator", raw)
		}
	}
}

func TestMetricProtocolSeparatesRetrievalDraftsAndBusinessDelivery(t *testing.T) {
	text := MetricReviewProtocol()
	for _, rule := range []string{"context_recall", "incomplete step results", "not missing merely because generation", "citation_accuracy", "return null", "rejected draft", "task_success"} {
		if !strings.Contains(text, rule) {
			t.Fatal("missing independent metric evidence contract", rule)
		}
	}
}
