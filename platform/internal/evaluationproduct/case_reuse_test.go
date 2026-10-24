package evaluationproduct

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The unit-only authorizer is explicit; production uses the same live checks
// as a real invocation, stopping before signing/dispatch.
type reuseTestInvoker struct {
	*testAgentInvoker
	authorizations atomic.Int32
	authorize      func(context.Context, InvocationRequest) error
}

func (i *reuseTestInvoker) AuthorizeEvaluationCaseReuse(ctx context.Context, request InvocationRequest) error {
	i.authorizations.Add(1)
	if i.authorize != nil {
		return i.authorize(ctx, request)
	}
	return nil
}

func runReuseFixture(t *testing.T, store ExecutionStore, row Resource, invoker AgentInvoker, artifacts ArtifactWriter, want string) Resource {
	t.Helper()
	runner, err := NewRunner(store, invoker, nil, artifacts, RunnerOptions{LeaseDuration: 10 * time.Second, CaseTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := store.ClaimNextRun(context.Background(), runner.owner, "lease-"+row.ID, time.Now().UTC(), 10*time.Second)
	if err != nil || !ok || claimed.ID != row.ID {
		t.Fatalf("claim exact fixture: %v %v %s", err, ok, claimed.ID)
	}
	runner.process(context.Background(), claimed)
	result, err := store.Get(context.Background(), row.Scope, KindRun, row.ID)
	if err != nil || result.Status != want {
		t.Fatalf("fixture status: %v %s want %s", err, result.Status, want)
	}
	return result
}

func seedReuseDestination(t *testing.T, store Store, source Resource, id string, cases []json.RawMessage) Resource {
	t.Helper()
	ctx, now := context.Background(), time.Now().UTC()
	request, err := ResolveHistoricalExecutionSnapshot(ctx, store, source.Scope, source)
	if err != nil {
		t.Fatal(err)
	}
	dataset := DatasetData{Name: "same-condition incremental evaluation", Version: "1", SourceType: request.dataset.SourceType,
		ReviewStatus: "approved", ReviewerID: "independent-reviewer", ReviewedAt: &now, SampleCount: len(cases), Cases: cases}
	dataset.ContentHash, _ = contentHash(cases)
	raw, _ := json.Marshal(dataset)
	d := Resource{ID: "dataset." + id, Kind: KindDataset, Scope: source.Scope, Status: "published", Revision: 1,
		CreatedBy: "owner", CreatedAt: now, UpdatedAt: now, Data: raw}
	if err := store.Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	oldSuite, err := store.Get(ctx, source.Scope, KindSuite, request.suite.ID)
	if err != nil {
		t.Fatal(err)
	}
	var suite SuiteData
	var snapshot map[string]any
	if json.Unmarshal(oldSuite.Data, &suite) != nil || json.Unmarshal(suite.Snapshot, &snapshot) != nil {
		t.Fatal("source suite")
	}
	suite.DatasetID = d.ID
	snapshot["dataset_id"], snapshot["dataset_revision"], snapshot["dataset_hash"] = d.ID, d.Revision, dataset.ContentHash
	suite.Snapshot, _ = json.Marshal(snapshot)
	suite.SnapshotHash, _ = contentHash(snapshot)
	raw, _ = json.Marshal(suite)
	s := Resource{ID: "suite." + id, Kind: KindSuite, Scope: source.Scope, Status: "published", Revision: 1,
		CreatedBy: "owner", CreatedAt: now, UpdatedAt: now, Data: raw}
	if err := store.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	data := RunData{SuiteID: s.ID, AgentID: request.AgentID(), AgentVersionID: request.AgentVersionID(),
		InstallationID: request.InstallationID(), InstallationRevision: request.InstallationRevision(),
		IdempotencyKey: "idem." + id, ExecutionState: "dispatch_pending"}
	raw, _ = json.Marshal(data)
	run := Resource{ID: id, Kind: KindRun, Scope: source.Scope, Status: "queued", Revision: 1, CreatedBy: source.CreatedBy, CreatedAt: now, UpdatedAt: now, Data: raw}
	if err := store.Create(ctx, run); err != nil {
		t.Fatal(err)
	}
	return run
}

func reuseOriginalFixture(t *testing.T, store ExecutionStore, scope Scope, id string) (Resource, []json.RawMessage, CaseReuseReference) {
	t.Helper()
	cases := []json.RawMessage{}
	for i := 0; i < 3; i++ {
		cases = append(cases, json.RawMessage(fmt.Sprintf(`{"case_id":"case-%d","input":{"question":"q%d"},"expected":{"answer":"approved"},"split":"frozen"}`, i, i)))
	}
	original := seedProductRun(t, store, scope, id, "manual_gold", "exact_match", cases)
	invoker := &testAgentInvoker{fn: func(_ context.Context, r InvocationRequest) (InvocationResult, error) {
		if r.CaseIndex == 1 {
			return InvocationResult{}, errors.New("provider model failed; no new output")
		}
		return InvocationResult{Output: json.RawMessage(`{"answer":"wrong"}`), ProviderMode: "real", CitationGrounding: "passed", DomainGrounding: "passed"}, nil
	}}
	var writer ArtifactWriter = &testArtifactWriter{}
	if native, ok := store.(ArtifactWriter); ok {
		writer = native
	}
	original = runReuseFixture(t, store, original, invoker, writer, "failed")
	if invoker.calls.Load() != 2 {
		t.Fatal("original case execution count")
	}
	row, err := store.Get(context.Background(), scope, KindCaseResult, caseResultID(original.ID, 0))
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := contentHash(json.RawMessage(row.Data))
	return original, cases, CaseReuseReference{Version: "evaluation-case-reuse/v1", RunID: original.ID, Index: 0, ResultHash: hash}
}

func reusedInput(t *testing.T, raw json.RawMessage, ref CaseReuseReference) json.RawMessage {
	t.Helper()
	c, err := decodeEvaluationCase(raw)
	if err != nil {
		t.Fatal(err)
	}
	c.Reuse = &ref
	out, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCaseReusePreservesOriginalWrongMeasurementAndCallsOnlyMissingCases(t *testing.T) {
	verifyCaseReuseMissingOnly(t, newMemoryStore(), Scope{TenantID: "reuse-tenant", DepartmentID: "dept", ApplicationID: "app"})
}

func verifyCaseReuseMissingOnly(t *testing.T, store ExecutionStore, scope Scope) {
	t.Helper()
	ctx := context.Background()
	source, cases, ref := reuseOriginalFixture(t, store, scope, "reuse-original")
	old, _ := store.Get(ctx, scope, KindCaseResult, caseResultID(source.ID, 0))
	cases[0] = reusedInput(t, cases[0], ref)
	target := seedReuseDestination(t, store, source, "reuse-missing-only", cases)
	invoker := &reuseTestInvoker{testAgentInvoker: &testAgentInvoker{}}
	writer := &testArtifactWriter{}
	var artifacts ArtifactWriter = writer
	if native, ok := store.(ArtifactWriter); ok {
		artifacts = native
	}
	finished := runReuseFixture(t, store, target, invoker, artifacts, "succeeded")
	if invoker.calls.Load() != 2 || invoker.authorizations.Load() != 2 {
		t.Fatal("reuse invoked model or skipped live checks")
	}
	if artifacts == writer && writer.calls.Load() != 2 {
		t.Fatal("reuse wrote a fresh model artifact")
	}
	after, _ := store.Get(ctx, scope, KindCaseResult, caseResultID(source.ID, 0))
	if string(old.Data) != string(after.Data) || old.Revision != after.Revision {
		t.Fatal("original result changed")
	}
	reused, _ := store.Get(ctx, scope, KindCaseResult, caseResultID(target.ID, 0))
	value, err := decodeCaseResult(reused)
	if err != nil || value.ReusedFrom == nil || *value.ReusedFrom != ref || len(value.Metrics) != 1 || value.Metrics[0].Value == nil || *value.Metrics[0].Value != 0 {
		t.Fatalf("wrong original measurement was not preserved: %+v %v", value, err)
	}
	var oldValue CaseResultData
	_ = json.Unmarshal(old.Data, &oldValue)
	if value.OutputArtifactID != oldValue.OutputArtifactID || value.OutputHash != oldValue.OutputHash || value.ExecutionRunID != oldValue.ExecutionRunID {
		t.Fatal("source artifact or real execution identity replaced")
	}
	rows, _, err := store.List(ctx, scope, KindEvidence, 1, 100)
	if err != nil || len(rows) != 1 {
		t.Fatalf("expected complete native evidence: %v %d", err, len(rows))
	}
	var evidence EvidenceData
	_ = json.Unmarshal(rows[0].Data, &evidence)
	dataset, err := verifyEvidenceSnapshot(ctx, store, scope, finished, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyEvidenceCases(ctx, store, scope, evidence, dataset.Cases); err != nil {
		t.Fatal("reused report did not verify", err)
	}
	// Corrupting an original after publication invalidates the derived evidence.
	var corrupted CaseResultData
	_ = json.Unmarshal(old.Data, &corrupted)
	corrupted.Metrics[0].Value = floatPointer(1)
	changed := old
	changed.Revision++
	changed.Data, _ = json.Marshal(corrupted)
	if err = store.UpdateCAS(ctx, scope, KindCaseResult, old.ID, old.Revision, changed); err != nil {
		t.Fatal(err)
	}
	if err = verifyEvidenceCases(ctx, store, scope, evidence, dataset.Cases); err == nil {
		t.Fatal("mutated source still qualified")
	}
}

func TestCaseReuseRejectsInvalidTailBeforeAnyFreshInvocation(t *testing.T) {
	for _, mode := range []string{"input", "gold", "case_id", "split", "weight", "hash", "index", "scope", "active_source", "forged_creator", "missing_authority", "revoked_authority"} {
		t.Run(mode, func(t *testing.T) {
			store := newMemoryStore()
			scope := Scope{TenantID: "reuse-negative", DepartmentID: "dept", ApplicationID: "app"}
			source, cases, ref := reuseOriginalFixture(t, store, scope, "reuse-source-"+mode)
			raw := reusedInput(t, cases[0], ref)
			sample, _ := decodeEvaluationCase(raw)
			switch mode {
			case "input":
				sample.Input = json.RawMessage(`{"question":"different"}`)
			case "gold":
				sample.Expected = json.RawMessage(`{"answer":"different"}`)
			case "case_id":
				sample.CaseID = "different-case"
			case "split":
				sample.Split = "dev"
			case "weight":
				v := 2.0
				sample.Weight = &v
			case "hash":
				sample.Reuse.ResultHash = strings.Repeat("0", 64)
			case "index":
				sample.Reuse.Index = 2
			case "scope":
				sample.Reuse.RunID = "unreadable-other-application"
			case "active_source":
				changed := source
				changed.Revision++
				changed.Status = "running"
				if err := store.UpdateCAS(context.Background(), scope, KindRun, source.ID, source.Revision, changed); err != nil {
					t.Fatal(err)
				}
			case "forged_creator":
				row, _ := store.Get(context.Background(), scope, KindCaseResult, caseResultID(source.ID, 0))
				changed := row
				changed.Revision++
				changed.CreatedBy = "client"
				if err := store.UpdateCAS(context.Background(), scope, KindCaseResult, row.ID, row.Revision, changed); err != nil {
					t.Fatal(err)
				}
			}
			raw, _ = json.Marshal(sample)
			// Restore a terminal source only for target fixture snapshot loading;
			// the resolver must observe the later active status.
			fixtureSource := source
			if mode == "active_source" {
				current, _ := store.Get(context.Background(), scope, KindRun, source.ID)
				current.Status = "failed"
				current.Revision++
				if err := store.UpdateCAS(context.Background(), scope, KindRun, source.ID, current.Revision-1, current); err != nil {
					t.Fatal(err)
				}
				fixtureSource = current
			}
			target := seedReuseDestination(t, store, fixtureSource, "reuse-tail-"+mode, []json.RawMessage{cases[2], raw})
			if mode == "active_source" {
				current, _ := store.Get(context.Background(), scope, KindRun, source.ID)
				changed := current
				changed.Status = "running"
				changed.Revision++
				var data RunData
				_ = json.Unmarshal(changed.Data, &data)
				data.ExecutionState = "running"
				data.LeaseOwner = "other-owner"
				data.LeaseToken = "other-token"
				data.LeaseUntil = time.Now().Add(time.Hour)
				changed.Data, _ = json.Marshal(data)
				if err := store.UpdateCAS(context.Background(), scope, KindRun, current.ID, current.Revision, changed); err != nil {
					t.Fatal(err)
				}
			}
			invoker := &reuseTestInvoker{testAgentInvoker: &testAgentInvoker{}}
			var caller AgentInvoker = invoker
			if mode == "missing_authority" {
				caller = invoker.testAgentInvoker
			}
			if mode == "revoked_authority" {
				invoker.authorize = func(context.Context, InvocationRequest) error { return ErrForbidden }
			}
			artifacts := &testArtifactWriter{}
			runReuseFixture(t, store, target, caller, artifacts, "failed")
			if invoker.calls.Load() != 0 || artifacts.calls.Load() != 0 {
				t.Fatal("invalid reuse tail spent on prefix")
			}
		})
	}
}

func TestCaseReuseRechecksAuthorityAfterPreflightAndBeforeCommit(t *testing.T) {
	store := newMemoryStore()
	scope := Scope{TenantID: "reuse-revocation", DepartmentID: "dept", ApplicationID: "app"}
	source, cases, ref := reuseOriginalFixture(t, store, scope, "reuse-revocation-source")
	target := seedReuseDestination(t, store, source, "reuse-revoked-before-commit", []json.RawMessage{reusedInput(t, cases[0], ref)})
	checks := 0
	invoker := &reuseTestInvoker{testAgentInvoker: &testAgentInvoker{}, authorize: func(_ context.Context, r InvocationRequest) error {
		checks++
		var input map[string]any
		_ = json.Unmarshal(r.Input, &input)
		if input["expected"] != nil || input["reuse"] != nil || r.RunID != target.ID || r.Scope != scope {
			t.Error("authorization received gold or wrong scope")
		}
		if checks > 1 {
			return ErrForbidden
		}
		return nil
	}}
	artifacts := &testArtifactWriter{}
	runReuseFixture(t, store, target, invoker, artifacts, "failed")
	if checks != 2 || invoker.calls.Load() != 0 || artifacts.calls.Load() != 0 {
		t.Fatal("revocation bypassed")
	}
	if _, err := store.Get(context.Background(), scope, KindCaseResult, caseResultID(target.ID, 0)); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked reuse persisted a result")
	}
}

type cancelReuseCommitStore struct{ ExecutionStore }

func (s cancelReuseCommitStore) CommitRunCase(ctx context.Context, scope Scope, id string, expected uint64, token string, row Resource) error {
	parent, err := s.ExecutionStore.Get(ctx, scope, KindRun, id)
	if err != nil {
		return err
	}
	var data RunData
	_ = json.Unmarshal(parent.Data, &data)
	data.ExecutionState = "cancelled"
	data.LeaseOwner = ""
	data.LeaseToken = ""
	data.LeaseUntil = time.Time{}
	parent.Status = "cancelled"
	parent.Revision++
	parent.Data, _ = json.Marshal(data)
	if err = s.ExecutionStore.FinalizeRun(ctx, scope, expected, token, parent, nil); err != nil {
		return err
	}
	return s.ExecutionStore.CommitRunCase(ctx, scope, id, expected, token, row)
}

func TestCaseReuseUsesTheSameCancellationFenceAsFreshResults(t *testing.T) {
	base := newMemoryStore()
	scope := Scope{TenantID: "reuse-cancel", DepartmentID: "dept", ApplicationID: "app"}
	source, cases, ref := reuseOriginalFixture(t, base, scope, "reuse-cancel-source")
	target := seedReuseDestination(t, base, source, "reuse-cancel-target", []json.RawMessage{reusedInput(t, cases[0], ref)})
	invoker := &reuseTestInvoker{testAgentInvoker: &testAgentInvoker{}}
	runReuseFixture(t, cancelReuseCommitStore{base}, target, invoker, &testArtifactWriter{}, "cancelled")
	if invoker.calls.Load() != 0 {
		t.Fatal("cancellation caused a fresh invocation")
	}
	if _, err := base.Get(context.Background(), scope, KindCaseResult, caseResultID(target.ID, 0)); !errors.Is(err, ErrNotFound) {
		t.Fatal("late reused result committed")
	}
}

func TestCaseReuseReferenceRequiresIndexAndRejectsUnknownFields(t *testing.T) {
	for _, value := range []string{
		`{"version":"evaluation-case-reuse/v1","run_id":"old","result_hash":"` + strings.Repeat("a", 64) + `"}`,
		`{"version":"evaluation-case-reuse/v1","run_id":"old","index":0,"result_hash":"` + strings.Repeat("a", 64) + `","force":true}`,
		`{"version":"evaluation-case-reuse/v1","run_id":"old","index":-1,"result_hash":"` + strings.Repeat("a", 64) + `"}`,
	} {
		var ref CaseReuseReference
		if json.Unmarshal([]byte(value), &ref) == nil {
			t.Fatal("invalid reference accepted")
		}
	}
}

func TestCaseReuseRejectsEvaluatorAndMetricBindingChanges(t *testing.T) {
	for _, mode := range []string{"agent", "version", "installation", "installation_revision", "metric_revision", "formula", "plugin"} {
		t.Run(mode, func(t *testing.T) {
			store := newMemoryStore()
			scope := Scope{TenantID: "reuse-bindings", DepartmentID: "dept", ApplicationID: "app"}
			source, cases, ref := reuseOriginalFixture(t, store, scope, "reuse-binding-source")
			target := seedReuseDestination(t, store, source, "reuse-binding-target", []json.RawMessage{reusedInput(t, cases[0], ref)})
			request, err := ResolveExecutionSnapshot(context.Background(), store, scope, target)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "agent":
				request.agentID = "another-evaluator"
			case "version":
				request.agentVersionID = "another-version"
			case "installation":
				request.installationID = "another-installation"
			case "installation_revision":
				request.installationRevision++
			case "metric_revision":
				request.metrics[0].Revision++
			case "formula":
				request.metrics[0].FormulaHash = strings.Repeat("a", 64)
			case "plugin":
				request.metrics[0].PluginDigest = strings.Repeat("b", 64)
			}
			if _, err := newCaseReuseResolver(store, request).prepare(context.Background(), request.dataset.Cases[0], 0); err == nil {
				t.Fatal("different evaluator or metric accepted")
			}
		})
	}
}

func TestCaseReusePreservesUnknownAndRejectsTransitiveResults(t *testing.T) {
	store := newMemoryStore()
	scope := Scope{TenantID: "reuse-unknown", DepartmentID: "dept", ApplicationID: "app"}
	source, cases, ref := reuseOriginalFixture(t, store, scope, "reuse-unknown-source")
	row, _ := store.Get(context.Background(), scope, KindCaseResult, caseResultID(source.ID, 0))
	var value CaseResultData
	_ = json.Unmarshal(row.Data, &value)
	// A deliberately seeded unknown measurement is never converted to success.
	value.Metrics[0].Status, value.Metrics[0].Value = "unknown", nil
	changed := row
	changed.Revision++
	changed.Data, _ = json.Marshal(value)
	if err := store.UpdateCAS(context.Background(), scope, KindCaseResult, row.ID, row.Revision, changed); err != nil {
		t.Fatal(err)
	}
	ref.ResultHash, _ = contentHash(json.RawMessage(changed.Data))
	target := seedReuseDestination(t, store, source, "reuse-unknown-target", []json.RawMessage{reusedInput(t, cases[0], ref)})
	invoker := &reuseTestInvoker{testAgentInvoker: &testAgentInvoker{}}
	finished := runReuseFixture(t, store, target, invoker, &testArtifactWriter{}, "succeeded")
	stored, _ := store.Get(context.Background(), scope, KindCaseResult, caseResultID(finished.ID, 0))
	actual, err := decodeCaseResult(stored)
	if err != nil || actual.Metrics[0].Value != nil || actual.Metrics[0].Status != "unknown" || invoker.calls.Load() != 0 {
		t.Fatal("unknown became a fresh passing measurement", err)
	}
	transitiveHash, _ := contentHash(json.RawMessage(stored.Data))
	transitive := CaseReuseReference{Version: ref.Version, RunID: finished.ID, Index: 0, ResultHash: transitiveHash}
	nested := seedReuseDestination(t, store, finished, "reuse-nested-target", []json.RawMessage{reusedInput(t, cases[0], transitive)})
	runReuseFixture(t, store, nested, invoker, &testArtifactWriter{}, "failed")
	if invoker.calls.Load() != 0 {
		t.Fatal("transitive reference invoked model")
	}
}
