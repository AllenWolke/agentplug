package evaluationproduct

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunnerGroundingEvidenceFollowsIndependentMetricNotAgentAssertion(t *testing.T) {
	exerciseIndependentGroundingRunner(t, func() ExecutionStore { return newMemoryStore() })
}

func exerciseIndependentGroundingRunner(t *testing.T, factory func() ExecutionStore) {
	for _, tc := range []struct{ status, citation string }{{"BLOCKED", "failed"}, {"UNKNOWN", "unknown"}, {"OK", "passed"}} {
		t.Run(tc.status, func(t *testing.T) {
			store := factory()
			scope := Scope{TenantID: "rag-tenant", DepartmentID: "rag-department", ApplicationID: "rag-app-" + tc.status}
			run := seedProductRun(t, store, scope, "rag-grounding-"+tc.status, "manual_gold", "grounding", []json.RawMessage{json.RawMessage(`{"case_id":"case-1","input":{"question":"teaching query"},"expected":{"answer":"gold never sent"}}`)})
			service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request metricRunnerRequest
				if json.NewDecoder(r.Body).Decode(&request) != nil || request.Metric != "grounding_gate" {
					t.Error("frozen grounding metric did not reach independent service")
				}
				base := fmt.Sprintf(`{"metric_id":%q,"version":%q,"formula_hash":%q,"status":%q`, request.Metric, request.Version, request.FormulaHash, tc.status)
				switch tc.status {
				case "OK":
					base += `,"numerator":1,"denominator":1,"value":1}`
				case "BLOCKED":
					base += `,"numerator":0,"denominator":0,"reason":"entailment verdict is unknown"}`
				default:
					base += `}`
				}
				_, _ = w.Write([]byte(base))
			}))
			defer service.Close()
			invoker := &testAgentInvoker{fn: func(_ context.Context, request InvocationRequest) (InvocationResult, error) {
				var input map[string]any
				_ = json.Unmarshal(request.Input, &input)
				if input["expected"] != nil {
					t.Error("gold leaked to Agent")
				}
				return InvocationResult{Output: json.RawMessage(`{"grounding":{"supported":true},"evaluation_citations":[],"evaluation_claims":[]}`), ProviderMode: "real", CitationGrounding: "passed", DomainGrounding: "unknown"}, nil
			}}
			var artifacts ArtifactWriter = &testArtifactWriter{}
			if writer, ok := store.(ArtifactWriter); ok {
				artifacts = writer
			}
			runner, err := NewRunner(store, invoker, RemoteMetricEvaluator{URL: service.URL, Token: "metric-service-test-token", Timeout: time.Second}, artifacts, RunnerOptions{Workers: 1, PollInterval: 10 * time.Millisecond, LeaseDuration: 10 * time.Second, CaseTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if runner.Start(ctx) != nil || runner.Enqueue(ctx, scope, run) != nil {
				t.Fatal("runner startup failed")
			}
			defer func() { _ = runner.Close(context.Background()) }()
			waitForRun(t, store, scope, run.ID, "succeeded")
			row, err := store.Get(ctx, scope, KindEvidence, evidenceResourceID(run.ID))
			if err != nil {
				t.Fatal(err)
			}
			var evidence EvidenceData
			if json.Unmarshal(row.Data, &evidence) != nil || evidence.CitationGrounding != tc.citation || evidence.DomainGrounding != "unknown" || evidence.Gate.State == GatePass {
				t.Fatalf("independent verdict or missing domain boundary ignored: %+v", evidence)
			}
		})
	}
}

func TestGroundingTargetsCannotMasqueradeAsRetrievalMetrics(t *testing.T) {
	formula := remoteMetricFormula{GroundingTarget: "domain", InputRelevantField: "expected.ids", OutputRankedField: "ids", K: 3}
	if formula.validFor("recall_at_k") {
		t.Fatal("retrieval score became domain grounding")
	}
	formula = remoteMetricFormula{GroundingTarget: "unknown", OutputCitationsField: "citations", OutputClaimsField: "claims", Gate: &metricGateFormula{RequireAllClaims: true, FailOnUnknown: true, MinEntailment: 1}}
	if formula.validFor("grounding") {
		t.Fatal("unreviewable grounding target accepted")
	}
}
