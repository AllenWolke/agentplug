package evaluationproduct

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBuildMetricRunnerRequestUsesOnlyMappedFields(t *testing.T) {
	tests := []struct {
		name   string
		metric MetricSnapshot
		input  string
		output string
		check  func(*testing.T, metricRunnerRequest)
	}{
		{name: "retrieval", metric: MetricSnapshot{MetricID: "retrieval-recall", Version: "1", Kind: "recall_at_k", Formula: json.RawMessage(`{"input_relevant_field":"expected.relevant_ids","output_ranked_field":"retrieved_ids","k":3}`), FormulaHash: "f"}, input: `{"expected":{"relevant_ids":["a","b"]},"must_not_send":"sensitive"}`, output: `{"retrieved_ids":["x","b","a"],"free_text":"not forwarded"}`, check: func(t *testing.T, got metricRunnerRequest) {
			if got.Metric != "recall" || got.K != 3 || strings.Join(got.Relevant, ",") != "a,b" || strings.Join(got.Ranked, ",") != "x,b,a" {
				t.Fatalf("unexpected retrieval projection: %+v", got)
			}
		}},
		{name: "citation", metric: MetricSnapshot{MetricID: "citation-accuracy", Version: "1", Kind: "citation_accuracy", Formula: json.RawMessage(`{"input_expected_field":"expected.citation_ids","output_actual_field":"citations"}`), FormulaHash: "f"}, input: `{"expected":{"citation_ids":["doc-1","doc-2"]}}`, output: `{"citations":["doc-1","doc-3"]}`, check: func(t *testing.T, got metricRunnerRequest) {
			if got.Metric != "citation_precision" || got.Total != 2 || got.Correct != 1 {
				t.Fatalf("unexpected citation counts: %+v", got)
			}
		}},
		{name: "grounding", metric: MetricSnapshot{MetricID: "grounding", Version: "1", Kind: "grounding", Formula: json.RawMessage(`{"output_citations_field":"evaluation_citations","output_claims_field":"evaluation_claims","gate":{"min_entailment":1,"require_all_claims":true,"expected_revision":"kb-v4","fail_on_unknown":true}}`), FormulaHash: "f"}, input: `{}`, output: `{"evaluation_citations":[{"id":"doc-1#clause-2","revision":"kb-v4","source":"platform-knowledge","content":"A regulated claim."}],"evaluation_claims":[{"id":"claim-1","text":"A regulated claim.","citation_ids":["doc-1#clause-2"]}]}`, check: func(t *testing.T, got metricRunnerRequest) {
			if got.Metric != "grounding_gate" || len(got.Citations) != 1 || got.Citations[0].ID != "doc-1#clause-2" || got.Citations[0].Revision != "kb-v4" || len(got.Claims) != 1 || got.Claims[0].ID != "claim-1" || got.Gate.ExpectedRevision != "kb-v4" || !got.Gate.RequireAllClaims || !got.Gate.FailOnUnknown {
				t.Fatalf("unexpected grounding projection: %+v", got)
			}
		}},
		{name: "plugin", metric: MetricSnapshot{MetricID: "domain-quality", Version: "2", Kind: "custom_deterministic", PluginID: "example_metric", PluginVersion: "1.0.0", PluginDigest: strings.Repeat("a", 64), Formula: json.RawMessage(`{"input_total_field":"expected.total","output_correct_field":"score.correct"}`), FormulaHash: "f"}, input: `{"expected":{"total":5},"private":"not forwarded"}`, output: `{"score":{"correct":4},"answer":"not forwarded"}`, check: func(t *testing.T, got metricRunnerRequest) {
			raw, _ := json.Marshal(got)
			if got.Plugin != "example_metric" || got.PluginVersion != "1.0.0" || got.PluginDigest != strings.Repeat("a", 64) || got.Total != 5 || got.Correct != 4 || strings.Contains(string(raw), "private") || strings.Contains(string(raw), "not forwarded") {
				t.Fatalf("plugin request must pin identity and minimize data: %s", raw)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildMetricRunnerRequest(tc.metric, json.RawMessage(tc.input), json.RawMessage(tc.output))
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, got)
		})
	}
}

func TestRetrievalPrecisionUsesExistingMetricRegistryAndProjection(t *testing.T) {
	formula := json.RawMessage(`{"input_relevant_field":"expected.relevant_ids","output_ranked_field":"retrieved_ids","k":2}`)
	if err := validateMetric(MetricData{MetricID: "precision", Version: "1.0.0", Name: "Precision at K", Kind: "precision_at_k", Formula: formula}); err != nil {
		t.Fatal(err)
	}
	request, err := buildMetricRunnerRequest(MetricSnapshot{MetricID: "precision", Version: "1.0.0", Kind: "precision_at_k", Formula: formula, FormulaHash: "frozen-formula"}, json.RawMessage(`{"expected":{"relevant_ids":["a","b"]},"private_gold":"must not be sent"}`), json.RawMessage(`{"retrieved_ids":["x","a"],"private_answer":"must not be sent"}`))
	if err != nil || request.Metric != "precision" || request.K != 2 || len(request.Relevant) != 2 || len(request.Ranked) != 2 {
		t.Fatal(request, err)
	}
	encoded, _ := json.Marshal(request)
	if strings.Contains(string(encoded), "must not be sent") {
		t.Fatal("unmapped data reached metric runner")
	}
}

func TestValidateMetricRequiresPinnedSignedPluginBinding(t *testing.T) {
	base := MetricData{MetricID: "custom", Version: "1.0.0", Name: "custom", Kind: "custom_deterministic", Formula: json.RawMessage(`{"input_total_field":"expected.total","output_correct_field":"correct"}`)}
	if validateMetric(base) == nil {
		t.Fatal("custom metrics without an immutable signed plugin binding must be rejected")
	}
	base.PluginID, base.PluginVersion, base.PluginDigest = "example_metric", "1.0.0", strings.Repeat("b", 64)
	if err := validateMetric(base); err != nil {
		t.Fatalf("valid pinned plugin binding rejected: %v", err)
	}
	base.PluginDigest = "mutable"
	if validateMetric(base) == nil {
		t.Fatal("invalid plugin artifact digest must be rejected")
	}
}

func TestRemoteMetricEvaluatorValidatesIdentityAndFailsClosed(t *testing.T) {
	const token = "platform-runner-token-0123456789"
	metric := MetricSnapshot{MetricID: "retrieval", Version: "1.0.0", Kind: "recall_at_k", Formula: json.RawMessage(`{"input_relevant_field":"expected.relevant_ids","output_ranked_field":"retrieved_ids","k":2}`), FormulaHash: strings.Repeat("a", 64)}
	input, output := json.RawMessage(`{"expected":{"relevant_ids":["doc-1"]}}`), json.RawMessage(`{"retrieved_ids":["doc-1"]}`)
	t.Run("accepts matching runner outcome", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+token {
				t.Errorf("missing service identity header")
			}
			var request metricRunnerRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode request: %v", err)
			}
			if request.Metric != "recall" || request.Admission.Network != "none" || !request.Admission.SignatureVerified {
				t.Errorf("unsafe runner request: %+v", request)
			}
			_, _ = fmt.Fprintf(w, `{"metric_id":"%s","version":"%s","formula_hash":"%s","status":"OK","numerator":1,"denominator":1,"value":1}`, request.Metric, request.Version, request.FormulaHash)
		}))
		defer server.Close()
		got, err := (RemoteMetricEvaluator{URL: server.URL, Token: token, Timeout: time.Second}).EvaluateMetric(context.Background(), metric, input, output)
		if err != nil {
			t.Fatal(err)
		}
		if got.MetricID != metric.ID || got.Status != "passed" || got.Value == nil || *got.Value != 1 {
			t.Fatalf("unexpected product metric: %+v", got)
		}
	})
	t.Run("preserves identity-bound sandbox block", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request metricRunnerRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode request: %v", err)
			}
			_, _ = fmt.Fprintf(w, `{"metric_id":%q,"version":%q,"formula_hash":%q,"status":"BLOCKED","code":"SANDBOX_ADMISSION_DENIED","message":"network syscall denied"}`,
				request.Metric, request.Version, request.FormulaHash)
		}))
		defer server.Close()
		got, err := (RemoteMetricEvaluator{URL: server.URL, Token: token, Timeout: time.Second}).EvaluateMetric(context.Background(), metric, input, output)
		if err != nil {
			t.Fatal(err)
		}
		if got.MetricID != metric.ID || got.Status != "blocked" || got.Value != nil {
			t.Fatalf("identity-bound sandbox refusal must stay blocked, got %+v", got)
		}
	})
	for _, tc := range []struct{ name, response string }{
		{name: "identity mismatch", response: `{"metric_id":"other","version":"1.0.0","formula_hash":"` + strings.Repeat("a", 64) + `","status":"OK","numerator":1,"denominator":1,"value":1}`},
		{name: "unknown with value", response: `{"metric_id":"recall","version":"1.0.0","formula_hash":"` + strings.Repeat("a", 64) + `","status":"UNKNOWN","value":1}`},
		{name: "malformed", response: `{"status":"OK","value":"1"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(tc.response)) }))
			defer server.Close()
			got, err := (RemoteMetricEvaluator{URL: server.URL, Token: token, Timeout: time.Second}).EvaluateMetric(context.Background(), metric, input, output)
			if err == nil || got.Status == "passed" || got.Value != nil {
				t.Fatalf("invalid runner response must not pass: result=%+v err=%v", got, err)
			}
		})
	}
}

func TestRemoteMetricEvaluatorPreservesGroundingGateBlock(t *testing.T) {
	const token = "platform-runner-token-0123456789"
	metric := MetricSnapshot{
		MetricID:    "grounding",
		Version:     "1.0.0",
		Kind:        "grounding",
		Formula:     json.RawMessage(`{"output_citations_field":"evaluation_citations","output_claims_field":"evaluation_claims","gate":{"min_entailment":1,"require_all_claims":true,"expected_revision":"kb-v4","fail_on_unknown":true}}`),
		FormulaHash: strings.Repeat("b", 64),
	}
	input := json.RawMessage(`{}`)
	output := json.RawMessage(`{"evaluation_citations":[],"evaluation_claims":[{"id":"claim-1","text":"Unsupported claim","citation_ids":[]}]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("missing service identity header")
		}
		_, _ = fmt.Fprintf(w, `{"metric_id":"grounding_gate","version":"1.0.0","formula_hash":%q,"kind":"grounding_gate","status":"BLOCKED","reason":"claims reference missing or unknown evidence","details":{"missing_citation":["claim-1"]}}`, metric.FormulaHash)
	}))
	defer server.Close()

	got, err := (RemoteMetricEvaluator{URL: server.URL, Token: token, Timeout: time.Second}).EvaluateMetric(context.Background(), metric, input, output)
	if err != nil {
		t.Fatal(err)
	}
	if got.MetricID != metric.ID || got.Status != "blocked" || got.Value != nil {
		t.Fatalf("grounding refusal must remain a blocked, non-numeric result, got %+v", got)
	}
}

func TestRemoteMetricEvaluatorRejectsUnrecognizedGroundingBlock(t *testing.T) {
	const token = "platform-runner-token-0123456789"
	metric := MetricSnapshot{
		MetricID:    "grounding",
		Version:     "1.0.0",
		Kind:        "grounding",
		Formula:     json.RawMessage(`{"output_citations_field":"evaluation_citations","output_claims_field":"evaluation_claims","gate":{"min_entailment":1,"require_all_claims":true,"fail_on_unknown":true}}`),
		FormulaHash: strings.Repeat("c", 64),
	}
	input := json.RawMessage(`{}`)
	output := json.RawMessage(`{"evaluation_citations":[],"evaluation_claims":[{"id":"claim-1","text":"Unsupported claim","citation_ids":[]}]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"metric_id":"grounding_gate","version":"1.0.0","formula_hash":%q,"status":"BLOCKED","reason":"arbitrary failure"}`, metric.FormulaHash)
	}))
	defer server.Close()
	if _, err := (RemoteMetricEvaluator{URL: server.URL, Token: token, Timeout: time.Second}).EvaluateMetric(context.Background(), metric, input, output); err == nil {
		t.Fatal("unknown grounding block reason must not be accepted")
	}
}
