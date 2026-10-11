package evaluationproduct

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type testAgentInvoker struct {
	calls atomic.Int32
	fn    func(context.Context, InvocationRequest) (InvocationResult, error)
}

func (i *testAgentInvoker) InvokeEvaluationCase(ctx context.Context, request InvocationRequest) (InvocationResult, error) {
	i.calls.Add(1)
	if i.fn != nil {
		return i.fn(ctx, request)
	}
	return InvocationResult{Output: json.RawMessage(`{"answer":"approved"}`), ProviderMode: "real", CitationGrounding: "passed", DomainGrounding: "passed"}, nil
}

type testArtifactWriter struct{ calls atomic.Int32 }

func TestRunnerEnqueueAfterRecoveryCompletedIsIdempotent(t *testing.T) {
	for _, status := range []string{"succeeded", "failed", "cancelled"} {
		t.Run(status, func(t *testing.T) {
			store := newMemoryStore()
			scope := Scope{TenantID: "enqueue-tenant", DepartmentID: "enqueue-department", ApplicationID: "enqueue-application"}
			original := seedProductRun(t, store, scope, "enqueue-completed-"+status, "manual_gold", "exact_match", []json.RawMessage{json.RawMessage(`{"input":{"question":"q"},"expected":{"answer":"approved"}}`)})
			finished := original
			finished.Revision++
			finished.Status = status
			if err := store.UpdateCAS(context.Background(), scope, KindRun, original.ID, original.Revision, finished); err != nil {
				t.Fatal(err)
			}
			invoker := &testAgentInvoker{}
			runner, err := NewRunner(store, invoker, nil, &testArtifactWriter{}, RunnerOptions{Workers: 1})
			if err != nil {
				t.Fatal(err)
			}
			if err := runner.Enqueue(context.Background(), scope, original); err != nil {
				t.Fatal("already finished enqueue reported failure", err)
			}
			if invoker.calls.Load() != 0 || len(runner.wake) != 0 {
				t.Fatal("terminal enqueue dispatched again")
			}
		})
	}
}

func (w *testArtifactWriter) PutEvaluationOutput(_ context.Context, scope Scope, runID string, index int, key string, output []byte) (ArtifactReference, error) {
	w.calls.Add(1)
	if !scope.valid() || !validID(runID) || index < 0 || key != caseResultID(runID, index) {
		return ArtifactReference{}, errors.New("invalid artifact scope or idempotency key")
	}
	return ArtifactReference{ID: fmt.Sprintf("artifact.%s.%d", runID, index), SHA256: Checksum(output), Size: int64(len(output))}, nil
}

func seedProductRun(t *testing.T, store Store, scope Scope, runID, sourceType, metricKind string, cases []json.RawMessage) Resource {
	return seedProductRunWithFormula(t, store, scope, runID, sourceType, metricKind, cases, nil)
}

func seedProductRunWithFormula(t *testing.T, store Store, scope Scope, runID, sourceType, metricKind string, cases []json.RawMessage, frozenFormula json.RawMessage) Resource {
	t.Helper()
	now := time.Now().UTC()
	datasetData := DatasetData{Name: "approved dataset", Version: "1", SourceType: sourceType, ReviewStatus: "approved", ReviewerID: "reviewer", SampleCount: len(cases), Cases: cases, ReviewedAt: &now}
	datasetData.ContentHash, _ = contentHash(cases)
	datasetBytes, _ := json.Marshal(datasetData)
	dataset := Resource{ID: "dataset." + runID, Kind: KindDataset, Scope: scope, Status: "published", Revision: 1, CreatedBy: "owner", CreatedAt: now, UpdatedAt: now, Data: datasetBytes}
	if err := store.Create(context.Background(), dataset); err != nil {
		t.Fatal(err)
	}
	formula := json.RawMessage(`{"field":"expected.answer","output_field":"answer"}`)
	if metricKind == "mrr" || metricKind == "recall_at_k" || metricKind == "ndcg" {
		formula = json.RawMessage(`{"input_relevant_field":"expected.relevant_ids","output_ranked_field":"retrieved_ids","k":5}`)
	}
	if metricKind == "grounding" {
		formula = json.RawMessage(`{"output_citations_field":"evaluation_citations","output_claims_field":"evaluation_claims","gate":{"min_entailment":1,"require_all_claims":true,"fail_on_unknown":true}}`)
	}
	if frozenFormula != nil {
		formula = append(json.RawMessage(nil), frozenFormula...)
	}
	metricData := MetricData{MetricID: "quality", Version: "1.0.0", Name: "Quality", Kind: metricKind, Formula: formula, Status: "published"}
	metricData.FormulaHash, _ = contentHash(formula)
	metricBytes, _ := json.Marshal(metricData)
	metric := Resource{ID: metricData.MetricID + "." + metricData.Version, Kind: KindMetric, Scope: scope, Status: "published", Revision: 1, CreatedBy: "owner", CreatedAt: now, UpdatedAt: now, Data: metricBytes}
	if err := store.Create(context.Background(), metric); err != nil {
		t.Fatal(err)
	}
	metricRefs := []map[string]any{{"id": metric.ID, "revision": metric.Revision, "formula_hash": metricData.FormulaHash}}
	snapshot := map[string]any{"dataset_id": dataset.ID, "dataset_revision": dataset.Revision, "dataset_hash": datasetData.ContentHash, "agent_id": "agent.product", "agent_version_id": "agent-v1", "metrics": metricRefs}
	snapshotBytes, _ := json.Marshal(snapshot)
	suiteData := SuiteData{Name: "product suite", Version: "1", DatasetID: dataset.ID, AgentID: "agent.product", AgentVersionID: "agent-v1", MetricIDs: []string{metric.ID}, Snapshot: snapshotBytes}
	suiteData.SnapshotHash, _ = contentHash(snapshot)
	suiteBytes, _ := json.Marshal(suiteData)
	suite := Resource{ID: "suite." + runID, Kind: KindSuite, Scope: scope, Status: "published", Revision: 1, CreatedBy: "owner", CreatedAt: now, UpdatedAt: now, Data: suiteBytes}
	if err := store.Create(context.Background(), suite); err != nil {
		t.Fatal(err)
	}
	runData := RunData{SuiteID: suite.ID, AgentID: suiteData.AgentID, AgentVersionID: suiteData.AgentVersionID, IdempotencyKey: "idem." + runID, ExecutionState: "dispatch_pending"}
	runBytes, _ := json.Marshal(runData)
	run := Resource{ID: runID, Kind: KindRun, Scope: scope, Status: "queued", Revision: 1, CreatedBy: "alice", CreatedAt: now, UpdatedAt: now, Data: runBytes}
	if err := store.Create(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	return run
}

func TestRunnerExecutesFrozenCasesAndPublishesVerifiedMetricEvidence(t *testing.T) {
	store := newMemoryStore()
	scope := Scope{TenantID: "tenant-run", DepartmentID: "department-run", ApplicationID: "app-run"}
	cases := []json.RawMessage{json.RawMessage(`{"case_id":"case-1","input":{"question":"q1"},"expected":{"answer":"approved"}}`), json.RawMessage(`{"case_id":"case-2","input":{"question":"q2"},"expected":{"answer":"approved"}}`)}
	run := seedProductRun(t, store, scope, "run-product-1", "manual_gold", "exact_match", cases)
	invoker := &testAgentInvoker{fn: func(_ context.Context, request InvocationRequest) (InvocationResult, error) {
		var input map[string]any
		if err := json.Unmarshal(request.Input, &input); err != nil || input["expected"] != nil || input["case_id"] != nil || input["question"] == nil {
			t.Errorf("Agent received the gold label or an invalid input projection: %s", request.Input)
		}
		return InvocationResult{Output: json.RawMessage(`{"answer":"approved"}`), ProviderMode: "real", CitationGrounding: "passed", DomainGrounding: "passed"}, nil
	}}
	artifacts := &testArtifactWriter{}
	runner, err := NewRunner(store, invoker, nil, artifacts, RunnerOptions{Workers: 2, PollInterval: 10 * time.Millisecond, LeaseDuration: 10 * time.Second, CaseTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runner.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runner.Close(context.Background()) }()
	if err := runner.Enqueue(ctx, scope, run); err != nil {
		t.Fatal(err)
	}
	completed := waitForRun(t, store, scope, run.ID, "succeeded")
	var runData RunData
	if json.Unmarshal(completed.Data, &runData) != nil || runData.Completed != 2 || runData.Total != 2 || runData.LeaseToken != "" {
		t.Fatalf("terminal run progress or lease is invalid: %+v", runData)
	}
	if invoker.calls.Load() != 2 || artifacts.calls.Load() != 2 {
		t.Fatalf("expected one Gateway and Artifact call per case: invoke=%d artifact=%d", invoker.calls.Load(), artifacts.calls.Load())
	}
	evidenceRow, err := store.Get(ctx, scope, KindEvidence, evidenceResourceID(run.ID))
	if err != nil {
		t.Fatal(err)
	}
	var evidence EvidenceData
	if json.Unmarshal(evidenceRow.Data, &evidence) != nil || evidence.SampleCount != 2 || evidence.Status != "succeeded" || evidence.Gate.State != GatePass || !validSHA256(evidence.ReportHash) {
		t.Fatalf("runner did not produce complete passing evidence: %+v", evidence)
	}
	snapshot, err := verifyEvidenceSnapshot(ctx, store, scope, completed, evidence)
	if err != nil {
		t.Fatalf("snapshot verification failed: %v", err)
	}
	if err := verifyEvidenceCases(ctx, store, scope, evidence, snapshot.Cases); err != nil {
		t.Fatalf("case evidence verification failed: %v", err)
	}
	rows, total, err := store.ListRunCases(ctx, scope, run.ID, 1, 1)
	if err != nil || total != 2 || len(rows) != 1 {
		t.Fatalf("case evidence page failed: total=%d items=%d err=%v", total, len(rows), err)
	}
	var caseEvidence CaseResultData
	if json.Unmarshal(rows[0].Data, &caseEvidence) != nil || caseEvidence.OutputArtifactID == "" || len(caseEvidence.Metrics) != 1 || caseEvidence.Metrics[0].Status != "passed" {
		t.Fatalf("case result is missing per-metric/artifact evidence: %+v", caseEvidence)
	}
	if string(rows[0].Data) == string(cases[0]) {
		t.Fatal("case result unexpectedly stores the raw input")
	}
}

func TestRunnerRoutesPublishedRetrievalMetricThroughMetricRunner(t *testing.T) {
	store := newMemoryStore()
	scope := Scope{TenantID: "tenant-metric", DepartmentID: "department-metric", ApplicationID: "app-metric"}
	cases := []json.RawMessage{json.RawMessage(`{"case_id":"retrieval-1","input":{"question":"q"},"expected":{"relevant_ids":["doc-1"]}}`)}
	run := seedProductRun(t, store, scope, "run-metric-runner", "manual_gold", "recall_at_k", cases)
	const token = "metric-runner-service-token-012345"
	var dispatched atomic.Int32
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("metric runner request omitted service identity")
		}
		var request metricRunnerRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode metric runner request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if request.Metric != "recall" || request.K != 5 || len(request.Relevant) != 1 || request.Relevant[0] != "doc-1" || len(request.Ranked) != 1 || request.Ranked[0] != "doc-1" || request.Admission.Network != "none" || !request.Admission.SignatureVerified || request.Admission.SecretAccess {
			t.Errorf("product did not send a minimized, admitted retrieval request: %+v", request)
		}
		dispatched.Add(1)
		_ = json.NewEncoder(w).Encode(metricRunnerResponse{MetricID: request.Metric, Version: request.Version, Kind: "ratio", FormulaHash: request.FormulaHash, Status: "OK", Numerator: 1, Denominator: 1, Value: floatPointer(1)})
	}))
	defer service.Close()

	invoker := &testAgentInvoker{fn: func(_ context.Context, request InvocationRequest) (InvocationResult, error) {
		if string(request.Input) != `{"question":"q"}` {
			t.Errorf("agent input projection changed unexpectedly: %s", request.Input)
		}
		return InvocationResult{Output: json.RawMessage(`{"retrieved_ids":["doc-1"]}`), ProviderMode: "real", CitationGrounding: "passed", DomainGrounding: "passed"}, nil
	}}
	evaluator := RemoteMetricEvaluator{URL: service.URL, Token: token, Timeout: time.Second}
	runner, err := NewRunner(store, invoker, evaluator, &testArtifactWriter{}, RunnerOptions{PollInterval: 10 * time.Millisecond, LeaseDuration: 10 * time.Second, CaseTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runner.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runner.Close(context.Background()) }()
	if err := runner.Enqueue(ctx, scope, run); err != nil {
		t.Fatal(err)
	}
	completed := waitForRun(t, store, scope, run.ID, "succeeded")
	if dispatched.Load() != 1 {
		t.Fatalf("expected one call to the isolated Metric Runner, got %d", dispatched.Load())
	}
	rows, total, err := store.ListRunCases(ctx, scope, run.ID, 1, 10)
	if err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("case result was not persisted: total=%d items=%d err=%v", total, len(rows), err)
	}
	var result CaseResultData
	if err := json.Unmarshal(rows[0].Data, &result); err != nil || len(result.Metrics) != 1 || result.Metrics[0].MetricID != "quality.1.0.0" || result.Metrics[0].Status != "passed" || result.Metrics[0].Value == nil || *result.Metrics[0].Value != 1 {
		t.Fatalf("isolated Metric Runner result was not attached to the persisted case evidence: run=%+v result=%+v err=%v", completed, result, err)
	}
}

func floatPointer(value float64) *float64 { return &value }

func TestRunnerUnknownMetricAndSyntheticSourceFailClosed(t *testing.T) {
	for _, test := range []struct {
		name       string
		sourceType string
		metricKind string
	}{
		{name: "unsupported metric", sourceType: "manual_gold", metricKind: "mrr"},
		{name: "synthetic dataset", sourceType: "synthetic_generated", metricKind: "exact_match"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newMemoryStore()
			scope := Scope{TenantID: "tenant-run", DepartmentID: "department-run", ApplicationID: "app-run"}
			run := seedProductRun(t, store, scope, "run-product-2", test.sourceType, test.metricKind, []json.RawMessage{json.RawMessage(`{"case_id":"case-1","input":{"question":"q"},"expected":{"answer":"approved"}}`)})
			runner, err := NewRunner(store, &testAgentInvoker{}, nil, &testArtifactWriter{}, RunnerOptions{PollInterval: 10 * time.Millisecond, LeaseDuration: 10 * time.Second, CaseTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := runner.Start(ctx); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = runner.Close(context.Background()) }()
			if err := runner.Enqueue(ctx, scope, run); err != nil {
				t.Fatal(err)
			}
			waitForRun(t, store, scope, run.ID, "succeeded")
			evidenceRow, err := store.Get(ctx, scope, KindEvidence, evidenceResourceID(run.ID))
			if err != nil {
				t.Fatal(err)
			}
			var evidence EvidenceData
			_ = json.Unmarshal(evidenceRow.Data, &evidence)
			if evidence.Gate.State != GateBlocked {
				t.Fatalf("unknown metric/provenance must block evidence, got %+v", evidence.Gate)
			}
			if test.metricKind == "mrr" && evidence.Metrics[0].Status != "unknown" {
				t.Fatalf("unsupported metric should be explicit UNKNOWN: %+v", evidence.Metrics[0])
			}
		})
	}
}

func TestRunnerRecoversExpiredLeaseAndReusesPersistedCaseResult(t *testing.T) {
	store := newMemoryStore()
	scope := Scope{TenantID: "tenant-run", DepartmentID: "department-run", ApplicationID: "app-run"}
	run := seedProductRun(t, store, scope, "run-product-3", "manual_gold", "exact_match", []json.RawMessage{json.RawMessage(`{"case_id":"case-1","input":{"question":"q"},"expected":{"answer":"approved"}}`)})
	oldClaim, claimed, err := store.ClaimNextRun(context.Background(), "old-worker", "old-token", time.Now().Add(-2*time.Minute), time.Second)
	if err != nil || !claimed {
		t.Fatalf("initial lease claim failed: claimed=%v err=%v", claimed, err)
	}
	value := 1.0
	caseData := CaseResultData{RunID: run.ID, Index: 0, InputHash: Checksum([]byte(`{"case_id":"case-1","input":{"question":"q"},"expected":{"answer":"approved"}}`)), OutputHash: Checksum([]byte(`{"answer":"approved"}`)), OutputArtifactID: "artifact.recovered", ProviderMode: "real", CitationGrounding: "passed", DomainGrounding: "passed", Metrics: []MetricOutcome{{MetricID: "quality.1.0.0", Status: "passed", Value: &value, Direction: "higher_is_better"}}, ProducedAt: time.Now().UTC()}
	caseBytes, _ := json.Marshal(caseData)
	if err := store.Create(context.Background(), Resource{ID: caseResultID(run.ID, 0), Kind: KindCaseResult, Scope: scope, Status: "completed", Revision: 1, CreatedBy: "old-worker", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Data: caseBytes}); err != nil {
		t.Fatal(err)
	}
	invoker := &testAgentInvoker{}
	runner, err := NewRunner(store, invoker, nil, &testArtifactWriter{}, RunnerOptions{PollInterval: 10 * time.Millisecond, LeaseDuration: 10 * time.Second, CaseTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runner.Close(context.Background()) }()
	waitForRun(t, store, scope, run.ID, "succeeded")
	if invoker.calls.Load() != 0 {
		t.Fatalf("recovery reinvoked an already committed case %d times", invoker.calls.Load())
	}
	if _, err := store.RenewRunLease(context.Background(), scope, oldClaim.ID, oldClaim.Revision, "old-token", time.Now().Add(time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale worker token should be fenced, got %v", err)
	}
}

func TestModuleCancellationFencesLateEvaluationResults(t *testing.T) {
	store := newMemoryStore()
	scope := Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}
	run := seedProductRun(t, store, scope, "run-product-cancel", "manual_gold", "exact_match", []json.RawMessage{
		json.RawMessage(`{"case_id":"case-1","input":{"question":"q"},"expected":{"answer":"approved"}}`),
	})
	started := make(chan struct{})
	invoker := &testAgentInvoker{fn: func(ctx context.Context, _ InvocationRequest) (InvocationResult, error) {
		close(started)
		<-ctx.Done()
		return InvocationResult{}, ctx.Err()
	}}
	runner, err := NewRunner(store, invoker, nil, &testArtifactWriter{}, RunnerOptions{
		PollInterval: 10 * time.Millisecond, LeaseDuration: 10 * time.Second, CaseTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	if err := runner.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runner.Close(context.Background()) }()
	if err := runner.Enqueue(ctx, scope, run); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("evaluation case did not start")
	}
	running := waitForRun(t, store, scope, run.ID, "running")
	module := NewModule(store, "module-secret", allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return nil }), runner)
	response := request(module, http.MethodPost, "/runs/"+run.ID+"/cancel", fmt.Sprintf(`{"expected_revision":%d}`, running.Revision), "alice", true)
	if response.Code != http.StatusAccepted {
		t.Fatalf("cancel request status=%d body=%s", response.Code, response.Body.String())
	}
	cancelled := waitForRun(t, store, scope, run.ID, "cancelling")
	var cancelledData RunData
	if err := json.Unmarshal(cancelled.Data, &cancelledData); err != nil || cancelledData.ExecutionState != "cancelling" {
		t.Fatalf("cancelled run state was not persisted: data=%s err=%v", cancelled.Data, err)
	}
	// Give the cancelled worker a chance to unwind. It must not append late
	// case/evidence rows after the HTTP transition has fenced the Run.
	time.Sleep(50 * time.Millisecond)
	if _, err := store.Get(ctx, scope, KindCaseResult, caseResultID(run.ID, 0)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancelled invocation persisted a late Case result: %v", err)
	}
	if _, err := store.Get(ctx, scope, KindEvidence, evidenceResourceID(run.ID)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancelled invocation persisted release Evidence: %v", err)
	}
	if cancelled.Revision <= running.Revision {
		t.Fatalf("cancel must advance the durable revision: before=%d after=%d", running.Revision, cancelled.Revision)
	}
}

func waitForRun(t *testing.T, store Store, scope Scope, runID, status string) Resource {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		row, err := store.Get(context.Background(), scope, KindRun, runID)
		if err == nil && row.Status == status {
			return row
		}
		time.Sleep(10 * time.Millisecond)
	}
	row, _ := store.Get(context.Background(), scope, KindRun, runID)
	t.Fatalf("run did not reach %s: status=%s data=%s", status, row.Status, row.Data)
	return Resource{}
}
