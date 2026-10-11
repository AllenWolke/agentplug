package engine

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lexagent/metric-runner/contracts"
	"github.com/lexagent/metric-runner/internal/sandbox"
)

func testAdmission() sandbox.Admission {
	return sandbox.Admission{
		SignatureVerified: true,
		Network:           "none",
		MaxOutputBytes:    4096,
		MaxSeconds:        10,
		MaxPIDs:           1,
	}
}

func handleTestRequest(t *testing.T, req request) map[string]any {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	response := Handle(context.Background(), raw)
	var result map[string]any
	if err := json.Unmarshal(response, &result); err != nil {
		t.Fatalf("Handle returned invalid JSON: %s: %v", response, err)
	}
	return result
}

func TestHandleCitationMetricIsVersionedAndZeroDenominatorIsUnknown(t *testing.T) {
	base := request{
		Metric:      "citation_precision",
		Version:     "1.2.0",
		FormulaHash: "sha256:test-formula",
		Admission:   testAdmission(),
		Total:       2,
		Correct:     2,
		MinSamples:  1,
	}
	passed := handleTestRequest(t, base)
	if passed["status"] != contracts.StatusOK || passed["metric_id"] != base.Metric || passed["version"] != base.Version {
		t.Fatalf("citation outcome lost its frozen metric identity or did not pass: %+v", passed)
	}
	value, ok := passed["value"].(float64)
	if !ok || value != 1 {
		t.Fatalf("citation precision = %v, want 1", passed["value"])
	}

	base.Total, base.Correct = 0, 0
	unknown := handleTestRequest(t, base)
	if unknown["status"] != contracts.StatusUnknown {
		t.Fatalf("zero citation denominator must be UNKNOWN, got %+v", unknown)
	}
	if _, exists := unknown["value"]; exists {
		t.Fatalf("UNKNOWN citation result must not carry a stale score: %+v", unknown)
	}
}

func TestHandleRetrievalPrecisionKeepsFrozenMetricIdentity(t *testing.T) {
	base := request{Metric: "precision", Version: "1.0.0", FormulaHash: "precision-fixture", Admission: testAdmission(), Relevant: []string{"a", "b"}, Ranked: []string{"x", "a"}, K: 2, MinSamples: 1}
	result := handleTestRequest(t, base)
	if result["status"] != contracts.StatusOK || result["value"] != .5 || result["metric_id"] != base.Metric || result["formula_hash"] != base.FormulaHash {
		t.Fatal(result)
	}
	base.Relevant = nil
	result = handleTestRequest(t, base)
	if result["status"] != contracts.StatusUnknown || result["value"] != nil {
		t.Fatal("unlabelled sample was scored", result)
	}
}

func TestHandleGroundingGateBlocksUnsupportedClaimsAndRevisionConflicts(t *testing.T) {
	base := request{
		Metric:      "grounding_gate",
		Version:     "1.0.0",
		FormulaHash: "sha256:grounding-formula",
		Admission:   testAdmission(),
		Citations: []contracts.Citation{{
			ID: "evidence-1", Revision: "index-v3", Content: "The credit limit is not greater than 5 units.",
		}},
		Claims: []contracts.Claim{{
			ID: "claim-1", Text: "The credit limit is greater than 5 units.", CitationIDs: []string{"evidence-1"},
		}},
		Gate: contracts.GateConfig{MinEntailment: 0.8, RequireAllClaims: true, ExpectedRevision: "index-v3", FailOnUnknown: true},
	}
	unsupported := handleTestRequest(t, base)
	if unsupported["status"] != contracts.StatusBlocked {
		t.Fatalf("a cited but polarity-reversed claim must be blocked, got %+v", unsupported)
	}
	unsupportedDetails, ok := unsupported["details"].(map[string]any)
	if !ok {
		t.Fatalf("grounding gate outcome is missing details: %+v", unsupported)
	}
	unsupportedIDs, ok := unsupportedDetails["unsupported"].([]any)
	if !ok || len(unsupportedIDs) != 1 || unsupportedIDs[0] != "claim-1" {
		t.Fatalf("grounding gate did not identify the unsupported claim: %+v", unsupported)
	}

	base.Claims[0].Text = "The credit limit is not greater than 5 units."
	base.Citations[0].Revision = "index-v2"
	conflict := handleTestRequest(t, base)
	if conflict["status"] != contracts.StatusBlocked {
		t.Fatalf("a citation from a conflicting index revision must be blocked, got %+v", conflict)
	}
	conflictDetails, ok := conflict["details"].(map[string]any)
	if !ok {
		t.Fatalf("grounding gate outcome is missing details: %+v", conflict)
	}
	conflictIDs, ok := conflictDetails["version_conflict"].([]any)
	if !ok || len(conflictIDs) != 1 || conflictIDs[0] != "claim-1" {
		t.Fatalf("grounding gate did not identify the revision-conflicting claim: %+v", conflict)
	}
}

func TestHandleGroundingGateBlocksMissingEvidenceAndUnknownMetric(t *testing.T) {
	missing := handleTestRequest(t, request{
		Metric:      "grounding_gate",
		Version:     "1.0.0",
		FormulaHash: "sha256:grounding-formula",
		Admission:   testAdmission(),
		Claims:      []contracts.Claim{{ID: "claim-missing", Text: "A conclusion", CitationIDs: []string{"not-retrieved"}}},
		Gate:        contracts.GateConfig{RequireAllClaims: true, FailOnUnknown: true},
	})
	if missing["status"] != contracts.StatusBlocked {
		t.Fatalf("claims referencing absent evidence must be blocked, got %+v", missing)
	}

	unknown := handleTestRequest(t, request{Metric: "not-registered", Admission: testAdmission()})
	if unknown["status"] != "ERROR" || unknown["code"] != "UNKNOWN_METRIC" {
		t.Fatalf("unknown metric must return a stable error, got %+v", unknown)
	}
}

func TestHandlePluginPathFailsClosedBeforePluginResolutionWithoutAdmission(t *testing.T) {
	req := request{
		Metric:      "custom_deterministic",
		Version:     "1.0.0",
		FormulaHash: "sha256:formula",
		Plugin:      "unregistered-plugin",
		Admission:   sandbox.Admission{},
	}
	result := handleTestRequest(t, req)
	if result["status"] != "BLOCKED" || result["code"] != "SANDBOX_ADMISSION_DENIED" {
		t.Fatalf("custom plugin execution must be refused before resolution without admission: %+v", result)
	}
	if result["metric_id"] != req.Metric || result["version"] != req.Version || result["formula_hash"] != req.FormulaHash {
		t.Fatalf("blocked response must bind its identity to the request: %+v", result)
	}
}
