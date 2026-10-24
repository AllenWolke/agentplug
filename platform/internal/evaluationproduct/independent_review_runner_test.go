package evaluationproduct

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	agenteval "github.com/lexagent/agent-evaluation"
)

func TestRunnerPersistsIndependentReviewAndKeepsQualityThresholdSeparate(t *testing.T) {
	store := newMemoryStore()
	scope := Scope{TenantID: "review-tenant", DepartmentID: "review-department", ApplicationID: "review-application"}
	good := true
	wrapped, fixture := independentVerdictFixture(t, &good)
	var sample struct {
		Input json.RawMessage `json:"input"`
	}
	if json.Unmarshal(wrapped, &sample) != nil {
		t.Fatal("invalid review fixture")
	}
	cases := []json.RawMessage{}
	for _, id := range []string{"correct-review", "wrong-review"} {
		raw, _ := json.Marshal(map[string]any{"case_id": id, "input": json.RawMessage(sample.Input), "expected": map[string]string{"routing_complexity": "simple"}, "split": "frozen"})
		cases = append(cases, raw)
	}
	run := seedProductRunWithFormula(t, store, scope, "independent-review-run", "imported_redacted", "independent_verdict", cases, json.RawMessage(`{"version":"independent-verdict/v1","metric_id":"domain_correctness"}`))
	var runData RunData
	if err := json.Unmarshal(run.Data, &runData); err != nil {
		t.Fatal(err)
	}
	suite, err := store.Get(context.Background(), scope, KindSuite, runData.SuiteID)
	if err != nil {
		t.Fatal(err)
	}
	var suiteData SuiteData
	var snapshot map[string]any
	if json.Unmarshal(suite.Data, &suiteData) != nil || json.Unmarshal(suiteData.Snapshot, &snapshot) != nil {
		t.Fatal("invalid suite fixture")
	}
	snapshot["agent_id"], suiteData.AgentID, runData.AgentID = "agent-eval-judge", "agent-eval-judge", "agent-eval-judge"
	suiteData.Snapshot, _ = json.Marshal(snapshot)
	suiteData.SnapshotHash, _ = contentHash(snapshot)
	suite.Data, _ = json.Marshal(suiteData)
	suite.Revision++
	if err := store.UpdateCAS(context.Background(), scope, KindSuite, suite.ID, suite.Revision-1, suite); err != nil {
		t.Fatal(err)
	}
	run.Data, _ = json.Marshal(runData)
	run.Revision++
	if err := store.UpdateCAS(context.Background(), scope, KindRun, run.ID, run.Revision-1, run); err != nil {
		t.Fatal(err)
	}
	invoker := &testAgentInvoker{fn: func(_ context.Context, req InvocationRequest) (InvocationResult, error) {
		if strings.Contains(string(req.Input), "routing_complexity") || req.AgentID != "agent-eval-judge" {
			t.Error("review-only case labels reached the Agent")
			return InvocationResult{}, ErrSnapshotInvalid
		}
		j := fixture
		j.JudgeVersionID = req.AgentVersionID
		if req.CaseIndex == 0 {
			j.JudgeRunID = "native-correct-review"
		} else {
			j.JudgeRunID = "native-wrong-review"
		}
		value := req.CaseIndex == 0
		j.Verdicts = []agenteval.Verdict{{MetricID: "domain_correctness", Value: &value, Evidence: []string{"output", "expected"}, Reason: "Actual output compared with independent frozen source."}}
		return InvocationResult{ExecutionRunID: j.JudgeRunID, Output: independentVerdictOutput(j), ProviderMode: "real", CitationGrounding: "unknown", DomainGrounding: "unknown"}, nil
	}}
	runner, err := NewRunner(store, invoker, nil, &testArtifactWriter{}, RunnerOptions{Workers: 1, PollInterval: 10 * time.Millisecond, LeaseDuration: 10 * time.Second, CaseTimeout: time.Second})
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
	finished := waitForRun(t, store, scope, run.ID, "succeeded")
	row, err := store.Get(ctx, scope, KindEvidence, evidenceResourceID(run.ID))
	if err != nil {
		t.Fatal(err)
	}
	var evidence EvidenceData
	if json.Unmarshal(row.Data, &evidence) != nil || evidence.MeasurementProtocol != IndependentVerdictProtocol || evidence.Gate.State != GatePass || evidence.Metrics[0].Value == nil || *evidence.Metrics[0].Value != .5 {
		t.Fatal("source-bound wrong review was lost or raw judge output required business grounding")
	}
	if evidence.CitationGrounding != "unknown" || evidence.DomainGrounding != "unknown" {
		t.Fatal("judge provenance fabricated business grounding")
	}
	if evaluateEvidence(evidence, floatPointer(.9), time.Now().UTC()).State == GatePass {
		t.Fatal("50% domain correctness passed a 90% quality gate")
	}
	dataset, err := verifyEvidenceSnapshot(ctx, store, scope, finished, evidence)
	if err != nil {
		t.Fatal("new review protocol did not bind to the frozen suite", err)
	}
	if err := verifyEvidenceCases(ctx, store, scope, evidence, dataset.Cases); err != nil {
		t.Fatal("new review protocol did not bind to persisted cases", err)
	}
	if invoker.calls.Load() != 2 {
		t.Fatal("unexpected duplicate judge invocations")
	}
}
