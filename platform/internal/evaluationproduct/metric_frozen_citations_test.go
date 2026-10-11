package evaluationproduct

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFrozenGroundingReferencesCannotBeReplacedByAgent(t *testing.T) {
	formula := json.RawMessage(`{"input_citations_field":"expected.citations","output_claims_field":"evaluation_claims","gate":{"min_entailment":1,"require_all_claims":true,"fail_on_unknown":true,"expected_revision":"v1"}}`)
	metric := MetricSnapshot{Kind: "grounding", Version: "1.0.0", FormulaHash: Checksum(formula), Formula: formula}
	input := json.RawMessage(`{"case_id":"known-1","input":{"question":"Who may use the knowledge source?"},"expected":{"citations":[{"id":"known-1","revision":"v1","source":"approved-snapshot","content":"Only authorized users may retrieve documents."}]}}`)
	output := json.RawMessage(`{"evaluation_citations":[{"id":"known-1","revision":"v1","content":"Everyone may retrieve all documents."}],"evaluation_claims":[{"id":"answer","text":"Everyone may retrieve all documents.","citation_ids":["known-1"]}]}`)
	request, err := buildMetricRunnerRequest(metric, input, output)
	if err != nil || len(request.Citations) != 1 || request.Citations[0].Content != "Only authorized users may retrieve documents." || len(request.Claims) != 1 || request.Claims[0].Text != "Everyone may retrieve all documents." {
		t.Fatal("Agent replaced frozen reference or claim", request, err)
	}
	projected, err := decodeEvaluationCase(input)
	if err != nil || strings.Contains(string(projected.Input), "authorized users") || strings.Contains(string(projected.Input), "expected") {
		t.Fatal("frozen reference leaked to Agent input", err)
	}
	if _, err := buildMetricRunnerRequest(metric, json.RawMessage(`{"input":{},"expected":{}}`), output); err == nil {
		t.Fatal("missing frozen references fell back to Agent text")
	}
}

func TestDocumentExampleMetricsUsePublicFrozenEvaluator(t *testing.T) {
	path := filepath.Join("..", "..", "..", "examples", "python-documents", "evaluation", "metrics.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var metrics []MetricData
	if json.Unmarshal(raw, &metrics) != nil || len(metrics) != 6 {
		t.Fatal("six public RAG metrics required")
	}
	for _, metric := range metrics {
		t.Run(metric.Kind, func(t *testing.T) {
			if err := validateMetric(metric); err != nil {
				t.Fatal("public metric API rejects example configuration", err)
			}
			var formula remoteMetricFormula
			if json.Unmarshal(metric.Formula, &formula) != nil || !formula.validFor(metric.Kind) {
				t.Fatal("example formula invalid")
			}
			if metric.Kind == "grounding" && (formula.InputCitationsField != "expected.citations" || formula.OutputCitationsField != "") {
				t.Fatal("example grounding trusts Agent reference text")
			}
		})
	}
}

func TestFrozenGroundingFormulaRequiresExclusiveGoldReferencePath(t *testing.T) {
	valid := remoteMetricFormula{InputCitationsField: "expected.citations", OutputClaimsField: "claims", Gate: &metricGateFormula{RequireAllClaims: true, FailOnUnknown: true, MinEntailment: 1}}
	if !valid.validFor("grounding") {
		t.Fatal("valid frozen reference formula rejected")
	}
	for _, path := range []string{"input.citations", "citations", "expected.", "expected.citations..text"} {
		invalid := valid
		invalid.InputCitationsField = path
		if invalid.validFor("grounding") {
			t.Fatal("untrusted or invalid reference path accepted", path)
		}
	}
	mixed := valid
	mixed.OutputCitationsField = "citations"
	if mixed.validFor("grounding") {
		t.Fatal("ambiguous Agent and gold citation sources accepted")
	}
	if valid.validFor("recall_at_k") || valid.validFor("citation_accuracy") || valid.validFor("custom_deterministic") {
		t.Fatal("grounding reference field accepted by another metric")
	}
}
