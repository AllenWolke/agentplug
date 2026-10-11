package evaluationproduct

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryStore struct {
	mu   sync.Mutex
	rows map[string]Resource
}

func newMemoryStore() *memoryStore { return &memoryStore{rows: map[string]Resource{}} }

// CommitRunCase mirrors the database ownership boundary under one lock.
// 单锁模拟生产数据库的租约与写入原子边界。
func (s *memoryStore) CommitRunCase(_ context.Context, scope Scope, runID string, expected uint64, token string, row Resource) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	parent := s.rows[resourceKey(scope, KindRun, runID)]
	var data RunData
	if json.Unmarshal(parent.Data, &data) != nil || parent.Status != "running" || parent.Revision != expected || data.LeaseToken != token || !data.LeaseUntil.After(time.Now()) {
		return ErrConflict
	}
	key := resourceKey(scope, KindCaseResult, row.ID)
	if _, exists := s.rows[key]; exists {
		return ErrConflict
	}
	s.rows[key] = row
	return nil
}
func resourceKey(scope Scope, kind Kind, id string) string {
	return strings.Join([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, string(kind), id}, "|")
}
func (s *memoryStore) EnsureSchema(context.Context) error { return nil }
func (s *memoryStore) Create(_ context.Context, row Resource) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := resourceKey(row.Scope, row.Kind, row.ID)
	if _, ok := s.rows[key]; ok {
		return ErrConflict
	}
	if row.Kind == KindRun {
		var data RunData
		_ = json.Unmarshal(row.Data, &data)
		for _, existing := range s.rows {
			if existing.Scope == row.Scope && existing.Kind == KindRun {
				var other RunData
				_ = json.Unmarshal(existing.Data, &other)
				if data.IdempotencyKey != "" && other.IdempotencyKey == data.IdempotencyKey {
					return ErrConflict
				}
			}
		}
	}
	s.rows[key] = row
	return nil
}
func (s *memoryStore) Get(_ context.Context, scope Scope, kind Kind, id string) (Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.rows[resourceKey(scope, kind, id)]
	if !ok {
		return Resource{}, ErrNotFound
	}
	return row, nil
}
func (s *memoryStore) List(_ context.Context, scope Scope, kind Kind, page, size int) ([]Resource, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := []Resource{}
	for _, row := range s.rows {
		if row.Scope == scope && row.Kind == kind {
			all = append(all, row)
		}
	}
	total := int64(len(all))
	start := (page - 1) * size
	if start >= len(all) {
		return []Resource{}, total, nil
	}
	end := start + size
	if end > len(all) {
		end = len(all)
	}
	return append([]Resource(nil), all[start:end]...), total, nil
}
func (s *memoryStore) UpdateCAS(_ context.Context, scope Scope, kind Kind, id string, expected uint64, row Resource) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := resourceKey(scope, kind, id)
	current, ok := s.rows[key]
	if !ok {
		return ErrNotFound
	}
	if current.Revision != expected || row.Revision != expected+1 {
		return ErrConflict
	}
	s.rows[key] = row
	return nil
}
func (s *memoryStore) FindByIdempotency(_ context.Context, scope Scope, kind Kind, key string) (Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, row := range s.rows {
		if row.Scope == scope && row.Kind == kind {
			var data RunData
			_ = json.Unmarshal(row.Data, &data)
			if data.IdempotencyKey == key {
				return row, nil
			}
		}
	}
	return Resource{}, ErrNotFound
}

func (s *memoryStore) ClaimNextRun(_ context.Context, owner, token string, now time.Time, lease time.Duration) (Resource, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var selected Resource
	found := false
	for _, row := range s.rows {
		if row.Kind != KindRun || (row.Status != "queued" && row.Status != "running") {
			continue
		}
		var data RunData
		if json.Unmarshal(row.Data, &data) != nil {
			continue
		}
		if row.Status == "running" && data.LeaseUntil.After(now) {
			continue
		}
		if !found || row.CreatedAt.Before(selected.CreatedAt) || row.CreatedAt.Equal(selected.CreatedAt) && row.ID < selected.ID {
			selected, found = row, true
		}
	}
	if !found {
		return Resource{}, false, nil
	}
	var data RunData
	if json.Unmarshal(selected.Data, &data) != nil {
		return Resource{}, false, ErrSnapshotInvalid
	}
	data.ExecutionState, data.LeaseOwner, data.LeaseToken = "running", owner, token
	data.LeaseUntil, data.Attempt = now.Add(lease), data.Attempt+1
	selected.Status, selected.Revision, selected.UpdatedAt = "running", selected.Revision+1, now
	selected.Data, _ = json.Marshal(data)
	s.rows[resourceKey(selected.Scope, selected.Kind, selected.ID)] = selected
	return selected, true, nil
}

func (s *memoryStore) RenewRunLease(_ context.Context, scope Scope, runID string, expected uint64, token string, until time.Time) (Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := resourceKey(scope, KindRun, runID)
	row, ok := s.rows[key]
	if !ok {
		return Resource{}, ErrNotFound
	}
	var data RunData
	if json.Unmarshal(row.Data, &data) != nil || row.Revision != expected || row.Status != "running" || data.LeaseToken != token || !data.LeaseUntil.After(time.Now()) {
		return Resource{}, ErrConflict
	}
	data.LeaseUntil = until
	row.Revision++
	row.UpdatedAt = time.Now().UTC()
	row.Data, _ = json.Marshal(data)
	s.rows[key] = row
	return row, nil
}

func (s *memoryStore) FinalizeRun(_ context.Context, scope Scope, expected uint64, token string, row Resource, evidence *Resource) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := resourceKey(scope, KindRun, row.ID)
	current, ok := s.rows[key]
	if !ok {
		return ErrNotFound
	}
	var currentData, finalData RunData
	if json.Unmarshal(current.Data, &currentData) != nil || json.Unmarshal(row.Data, &finalData) != nil || current.Revision != expected || current.Status != "running" || currentData.LeaseToken != token || !currentData.LeaseUntil.After(time.Now()) {
		return ErrConflict
	}
	if row.Revision != expected+1 || row.Scope != scope || row.Kind != KindRun || finalData.LeaseToken != "" || finalData.ExecutionState != row.Status {
		return ErrInvalid
	}
	if evidence != nil {
		evidenceKey := resourceKey(scope, KindEvidence, evidence.ID)
		if evidence.Scope != scope || evidence.Kind != KindEvidence || evidence.Revision != 1 || evidence.Status != "completed" {
			return ErrInvalid
		}
		if _, exists := s.rows[evidenceKey]; exists {
			return ErrConflict
		}
		s.rows[evidenceKey] = *evidence
	}
	s.rows[key] = row
	return nil
}

func (s *memoryStore) ListRunCases(_ context.Context, scope Scope, runID string, page, size int) ([]Resource, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := make([]Resource, 0)
	for _, row := range s.rows {
		if row.Scope != scope || row.Kind != KindCaseResult {
			continue
		}
		var data CaseResultData
		if json.Unmarshal(row.Data, &data) == nil && data.RunID == runID {
			all = append(all, row)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		var left, right CaseResultData
		_ = json.Unmarshal(all[i].Data, &left)
		_ = json.Unmarshal(all[j].Data, &right)
		return left.Index < right.Index
	})
	total := int64(len(all))
	start := (page - 1) * size
	if start >= len(all) {
		return []Resource{}, total, nil
	}
	end := start + size
	if end > len(all) {
		end = len(all)
	}
	return append([]Resource(nil), all[start:end]...), total, nil
}

type allowAuthorizer func(context.Context, Actor, Action, Scope) error

func TestEvaluationAvailabilityRequiresCurrentActionAuthority(t *testing.T) {
	for _, failure := range []error{ErrForbidden, errors.New("identity unavailable")} {
		calls := 0
		module := NewModule(newMemoryStore(), "module-secret", allowAuthorizer(func(_ context.Context, _ Actor, action Action, _ Scope) error {
			calls++
			if action != ActionRead {
				t.Fatal("availability used wrong action", action)
			}
			return failure
		}), nil)
		w := request(module, http.MethodGet, "/availability", "", "alice", true)
		want := http.StatusServiceUnavailable
		if errors.Is(failure, ErrForbidden) {
			want = http.StatusForbidden
		}
		if w.Code != want || calls != 1 || strings.Contains(w.Body.String(), `"configured"`) {
			t.Fatal("availability bypassed authorization", w.Code, calls)
		}
	}
	module := NewModule(newMemoryStore(), "module-secret", nil, nil)
	if w := request(module, http.MethodGet, "/availability", "", "alice", true); w.Code != http.StatusServiceUnavailable {
		t.Fatal("availability allowed without authorizer", w.Code)
	}
}

func (f allowAuthorizer) AuthorizeEvaluation(ctx context.Context, a Actor, action Action, scope Scope) error {
	return f(ctx, a, action, scope)
}

type fakeDispatcher struct {
	mu        sync.Mutex
	enqueued  []Resource
	cancelled int
	err       error
	onEnqueue func(Resource) error
}

func (d *fakeDispatcher) Enqueue(_ context.Context, _ Scope, row Resource) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.enqueued = append(d.enqueued, row)
	if d.onEnqueue != nil {
		return d.onEnqueue(row)
	}
	return d.err
}
func (d *fakeDispatcher) Cancel(context.Context, Scope, string, uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cancelled++
	return nil
}

func TestDispatchAcknowledgesConcurrentWorkerTransition(t *testing.T) {
	for _, retryPending := range []bool{false, true} {
		t.Run(fmt.Sprint(retryPending), func(t *testing.T) {
			store := newMemoryStore()
			scope := Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}
			dataset, _ := json.Marshal(DatasetData{Name: "dataset", Version: "1", SourceType: "manual_gold", Cases: []json.RawMessage{json.RawMessage(`{"case_id":"case-1","input":{"task":"query"}}`)}})
			suite, _ := json.Marshal(SuiteData{Name: "suite", Version: "1", DatasetID: "ds", AgentID: "agent", AgentVersionID: "v1", MetricIDs: []string{"m"}})
			for _, row := range []Resource{{ID: "ds", Kind: KindDataset, Scope: scope, Status: "published", Revision: 1, Data: dataset}, {ID: "s1", Kind: KindSuite, Scope: scope, Status: "published", Revision: 1, Data: suite}} {
				if err := store.Create(context.Background(), row); err != nil {
					t.Fatal(err)
				}
			}
			dispatcher := &fakeDispatcher{err: errors.New("queue unavailable")}
			module := NewModule(store, "module-secret", allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return nil }), dispatcher)
			var firstID string
			if retryPending {
				firstID = decodeResource(t, request(module, http.MethodPost, "/runs", `{"suite_id":"s1","idempotency_key":"race-1"}`, "alice", true)).ID
			}
			dispatcher.onEnqueue = func(row Resource) error {
				var data RunData
				if err := json.Unmarshal(row.Data, &data); err != nil {
					return err
				}
				data.ExecutionState = "running"
				row.Data, _ = json.Marshal(data)
				row.Status, row.Revision = "running", row.Revision+1
				return store.UpdateCAS(context.Background(), scope, KindRun, row.ID, row.Revision-1, row)
			}
			w := request(module, http.MethodPost, "/runs", `{"suite_id":"s1","idempotency_key":"race-1"}`, "alice", true)
			row := decodeResource(t, w)
			if w.Code != http.StatusAccepted || row.ID == "" || row.Status != "running" || row.Revision != 2 || (firstID != "" && row.ID != firstID) {
				t.Fatalf("lost accepted identity after worker transition: %d %s", w.Code, w.Body.String())
			}
			calls := len(dispatcher.enqueued)
			repeated := decodeResource(t, request(module, http.MethodPost, "/runs", `{"suite_id":"s1","idempotency_key":"race-1"}`, "alice", true))
			if repeated.ID != row.ID || len(dispatcher.enqueued) != calls {
				t.Fatal("duplicate execution after reconciliation")
			}
		})
	}
}

func request(module *Module, method, path, body, principal string, browser bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer module-secret")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	req.Header.Set("X-Department-ID", "dept-a")
	req.Header.Set("X-Application-ID", "app-a")
	req.Header.Set("X-Principal-Type", "user")
	req.Header.Set("X-Principal-ID", principal)
	if browser {
		req.Header.Set("X-Browser-Module", "1")
	} else {
		req.Header.Set("X-Principal-Type", "service")
	}
	w := httptest.NewRecorder()
	module.Handler().ServeHTTP(w, req)
	return w
}
func decodeResource(t *testing.T, w *httptest.ResponseRecorder) Resource {
	t.Helper()
	var row Resource
	if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil {
		t.Fatalf("decode resource: %v; body=%s", err, w.Body.String())
	}
	return row
}

func TestBrowserScopeAuthorizationAndBodyCannotSetScope(t *testing.T) {
	store := newMemoryStore()
	module := NewModule(store, "module-secret", allowAuthorizer(func(_ context.Context, actor Actor, action Action, scope Scope) error {
		if !actor.Browser || actor.PrincipalID != "reviewer" || action != ActionCreate || scope != actor.Scope {
			return ErrForbidden
		}
		return nil
	}), &fakeDispatcher{})
	body := `{"name":"safe","version":"1","source_type":"manual_gold","cases":[{"case_id":"case-1","input":{"question":"q"},"expected":{"answer":"a"}}],"tenant_id":"tenant-b"}`
	w := request(module, http.MethodPost, "/datasets", body, "reviewer", true)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("body scope should be rejected: status=%d body=%s", w.Code, w.Body.String())
	}
	denied := NewModule(store, "module-secret", allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return ErrForbidden }), &fakeDispatcher{})
	w = request(denied, http.MethodGet, "/datasets", "", "reviewer", true)
	if w.Code != http.StatusForbidden {
		t.Fatalf("identity denial status=%d body=%s", w.Code, w.Body.String())
	}
	bad := httptest.NewRequest(http.MethodGet, "/datasets", nil)
	bad.Header.Set("Authorization", "Bearer wrong")
	out := httptest.NewRecorder()
	module.Handler().ServeHTTP(out, bad)
	if out.Code != http.StatusUnauthorized {
		t.Fatalf("bad token status=%d", out.Code)
	}
}

func TestAvailabilityReportsInjectedDispatcherAndRunsFailClosed(t *testing.T) {
	auth := allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return nil })
	withoutDispatcher := NewModule(newMemoryStore(), "module-secret", auth, nil)
	w := request(withoutDispatcher, http.MethodGet, "/availability", "", "alice", true)
	if w.Code != http.StatusOK {
		t.Fatalf("availability status=%d body=%s", w.Code, w.Body.String())
	}
	var unavailable struct {
		Configured bool   `json:"configured"`
		State      string `json:"state"`
		ReasonCode string `json:"reason_code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &unavailable); err != nil {
		t.Fatalf("decode availability: %v", err)
	}
	if unavailable.Configured || unavailable.State != "unavailable" || unavailable.ReasonCode != "EVALUATOR_UNAVAILABLE" {
		t.Fatalf("unexpected fail-closed availability: %+v", unavailable)
	}

	// The absence of a Dispatcher is visible to clients and cannot be bypassed
	// by directly submitting a Run.
	w = request(withoutDispatcher, http.MethodPost, "/runs", `{}`, "alice", true)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "EVALUATOR_UNAVAILABLE") {
		t.Fatalf("unconfigured run must fail closed: status=%d body=%s", w.Code, w.Body.String())
	}

	withDispatcher := NewModule(newMemoryStore(), "module-secret", auth, &fakeDispatcher{})
	w = request(withDispatcher, http.MethodGet, "/availability", "", "alice", true)
	if w.Code != http.StatusOK {
		t.Fatalf("configured availability status=%d body=%s", w.Code, w.Body.String())
	}
	var configured struct {
		Configured bool   `json:"configured"`
		State      string `json:"state"`
		ReasonCode string `json:"reason_code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &configured); err != nil {
		t.Fatalf("decode configured availability: %v", err)
	}
	if !configured.Configured || configured.State != "configured" || configured.ReasonCode != "" {
		t.Fatalf("unexpected configured availability: %+v", configured)
	}
}

func TestAvailabilityRequiresGatewayAuthenticationAndGet(t *testing.T) {
	module := NewModule(newMemoryStore(), "module-secret", nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/availability", nil)
	w := httptest.NewRecorder()
	module.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated availability status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(module, http.MethodPost, "/availability", `{}`, "alice", true)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("availability POST status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestAvailabilityExposesOnlySafeWorkerFailureCounters(t *testing.T) {
	store := newMemoryStore()
	runner, err := NewRunner(store, &testAgentInvoker{}, nil, &testArtifactWriter{}, RunnerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	runner.claimFailures.Store(4)
	runner.finalizeFailures.Store(2)
	module := NewModule(store, "module-secret", allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return nil }), runner)
	w := request(module, http.MethodGet, "/availability", "", "alice", true)
	if w.Code != http.StatusOK {
		t.Fatalf("availability status=%d", w.Code)
	}
	var response struct {
		Worker WorkerStats `json:"worker"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Worker.ClaimFailures != 4 || response.Worker.FinalizeFailures != 2 {
		t.Fatalf("wrong safe counters: %+v", response.Worker)
	}
	if strings.Contains(w.Body.String(), "module-secret") || strings.Contains(w.Body.String(), "alice") {
		t.Fatal("availability leaked authentication or actor information")
	}
}

func TestDatasetReviewPublishMetricSuiteAndRunWorkflow(t *testing.T) {
	store := newMemoryStore()
	dispatcher := &fakeDispatcher{}
	auth := allowAuthorizer(func(ctx context.Context, actor Actor, action Action, scope Scope) error {
		if actor.PrincipalID == "" || scope != actor.Scope {
			return ErrForbidden
		}
		return nil
	})
	module := NewModule(store, "module-secret", auth, dispatcher)
	datasetBody := `{"name":"document-assistant","version":"1.0.0","source_type":"manual_gold","cases":[{"case_id":"case-1","input":{"question":"term?"},"expected":{"answer":"definition"}}]}`
	w := request(module, http.MethodPost, "/datasets", datasetBody, "alice", true)
	if w.Code != http.StatusCreated {
		t.Fatalf("dataset create: %d %s", w.Code, w.Body.String())
	}
	dataset := decodeResource(t, w)
	if dataset.Scope.TenantID != "tenant-a" || dataset.CreatedBy != "alice" || dataset.Status != "draft" {
		t.Fatalf("dataset scope/status not server-owned: %+v", dataset)
	}
	w = request(module, http.MethodPost, "/datasets/"+dataset.ID+"/publish", `{"expected_revision":1}`, "bob", true)
	if w.Code != http.StatusConflict {
		t.Fatalf("unreviewed publish status=%d", w.Code)
	}
	w = request(module, http.MethodPost, "/datasets/"+dataset.ID+"/review", `{"expected_revision":1,"decision":"approved","reason":"checked gold cases"}`, "alice", true)
	if w.Code != http.StatusConflict {
		t.Fatalf("self-review status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(module, http.MethodPost, "/datasets/"+dataset.ID+"/review", `{"expected_revision":1,"decision":"approved","reason":"checked gold cases"}`, "bob", true)
	if w.Code != http.StatusOK {
		t.Fatalf("dataset review status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(module, http.MethodPost, "/datasets/"+dataset.ID+"/publish", `{"expected_revision":2}`, "bob", true)
	if w.Code != http.StatusOK {
		t.Fatalf("dataset publish status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(module, http.MethodPost, "/metrics", `{"metric_id":"exact","version":"1.0.0","name":"Exact match","kind":"exact_match","formula":{"field":"expected.answer","output_field":"answer"}}`, "alice", true)
	if w.Code != http.StatusCreated {
		t.Fatalf("metric create %d %s", w.Code, w.Body.String())
	}
	metric := decodeResource(t, w)
	w = request(module, http.MethodPost, "/metrics/"+metric.ID+"/publish", `{"expected_revision":1}`, "bob", true)
	if w.Code != http.StatusOK {
		t.Fatalf("metric publish %d %s", w.Code, w.Body.String())
	}
	suiteBody := fmt.Sprintf(`{"name":"QA smoke","version":"1.0.0","dataset_id":%q,"agent_id":"document-assistant","agent_version_id":"qa-v1","metric_ids":[%q]}`, dataset.ID, metric.ID)
	w = request(module, http.MethodPost, "/suites", suiteBody, "alice", true)
	if w.Code != http.StatusCreated {
		t.Fatalf("suite create %d %s", w.Code, w.Body.String())
	}
	suite := decodeResource(t, w)
	var suiteData SuiteData
	if json.Unmarshal(suite.Data, &suiteData) != nil || suiteData.SnapshotHash == "" {
		t.Fatalf("suite snapshot missing: %s", suite.Data)
	}
	runBody := fmt.Sprintf(`{"suite_id":%q,"idempotency_key":"qa-run-001"}`, suite.ID)
	w = request(module, http.MethodPost, "/runs", runBody, "alice", true)
	if w.Code != http.StatusAccepted {
		t.Fatalf("run enqueue %d %s", w.Code, w.Body.String())
	}
	run := decodeResource(t, w)
	if run.Status != "queued" || len(dispatcher.enqueued) != 1 {
		t.Fatalf("run not enqueued: run=%+v enqueued=%d", run, len(dispatcher.enqueued))
	}
	w = request(module, http.MethodPost, "/runs", runBody, "alice", true)
	if w.Code != http.StatusOK || len(dispatcher.enqueued) != 1 {
		t.Fatalf("run retry should replay existing resource: status=%d enqueue_count=%d", w.Code, len(dispatcher.enqueued))
	}
	w = request(module, http.MethodPost, "/runs/"+run.ID+"/status", `{"expected_revision":2,"status":"running","total":1}`, "worker", false)
	if w.Code != http.StatusOK {
		t.Fatalf("run running transition %d %s", w.Code, w.Body.String())
	}
	run = decodeResource(t, w)
	w = request(module, http.MethodPost, "/runs/"+run.ID+"/status", `{"expected_revision":3,"status":"succeeded","total":1,"completed":1}`, "worker", false)
	if w.Code != http.StatusOK {
		t.Fatalf("run success transition %d %s", w.Code, w.Body.String())
	}
}

func TestEvidenceReviewBaselineAndGateFailClosed(t *testing.T) {
	store := newMemoryStore()
	dispatcher := &fakeDispatcher{}
	module := NewModule(store, "module-secret", allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return nil }), dispatcher)
	// Seed a real frozen suite and per-case evidence so the gate validates its
	// complete provenance chain before evaluating baseline/review policy.
	scope := Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}
	run := seedProductRun(t, store, scope, "run-1", "manual_gold", "exact_match", []json.RawMessage{json.RawMessage(`{"case_id":"case-1","input":{"question":"q"},"expected":{"answer":"approved"}}`)})
	var runData RunData
	_ = json.Unmarshal(run.Data, &runData)
	runData.ExecutionState, runData.Total, runData.Completed = "succeeded", 1, 1
	run.Status, run.Revision, run.UpdatedAt = "succeeded", 2, time.Now().UTC()
	run.Data, _ = json.Marshal(runData)
	if err := store.UpdateCAS(context.Background(), scope, KindRun, run.ID, 1, run); err != nil {
		t.Fatal(err)
	}
	suite, err := store.Get(context.Background(), scope, KindSuite, runData.SuiteID)
	if err != nil {
		t.Fatal(err)
	}
	var suiteData SuiteData
	_ = json.Unmarshal(suite.Data, &suiteData)
	snapshot, err := decodeSuiteSnapshot(suiteData.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	score := 0.95
	caseID := caseResultID(run.ID, 0)
	caseEvidence := CaseResultData{RunID: run.ID, Index: 0, InputHash: Checksum([]byte(`{"case_id":"case-1","input":{"question":"q"},"expected":{"answer":"approved"}}`)), OutputHash: strings.Repeat("c", 64), OutputArtifactID: "artifact.run-1", ProviderMode: "real", CitationGrounding: "passed", DomainGrounding: "passed", Metrics: []MetricOutcome{{MetricID: suiteData.MetricIDs[0], Status: "passed", Value: &score, Direction: "higher_is_better"}}, ProducedAt: time.Now().UTC()}
	caseBytes, _ := json.Marshal(caseEvidence)
	if err := store.Create(context.Background(), Resource{ID: caseID, Kind: KindCaseResult, Scope: scope, Status: "completed", Revision: 1, CreatedBy: "worker", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Data: caseBytes}); err != nil {
		t.Fatal(err)
	}
	evidenceData := EvidenceData{RunID: run.ID, SuiteID: suite.ID, SuiteSnapshotHash: suiteData.SnapshotHash, DatasetContentHash: snapshot.DatasetHash, AgentVersionID: suiteData.AgentVersionID, Status: "succeeded", ProviderMode: "real", SourceType: "manual_gold", SampleCount: 1, Metrics: []MetricOutcome{{MetricID: suiteData.MetricIDs[0], Status: "passed", Value: &score, Direction: "higher_is_better"}}, MetricsPresent: true, ArtifactsPresent: true, CitationGrounding: "passed", DomainGrounding: "passed", ProducedAt: time.Now().UTC(), CaseResultIDs: []string{caseID}}
	evidenceData.ReportHash, _ = evaluationReportHash(evidenceData, []CaseResultData{caseEvidence})
	evidenceData.Gate = evaluateEvidence(evidenceData, nil, time.Now().UTC())
	eBytes, _ := json.Marshal(evidenceData)
	evidence := Resource{ID: "evidence-1", Kind: KindEvidence, Scope: scope, Status: "completed", Revision: 1, CreatedBy: "worker", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Data: eBytes}
	if err := store.Create(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	// A candidate without a baseline or human reviewer is never passed.
	w := request(module, http.MethodPost, "/gates/evaluate", `{"evidence_id":"evidence-1","minimum_score":0.8}`, "bob", true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), GateUnknown) {
		t.Fatalf("missing baseline must be UNKNOWN: %d %s", w.Code, w.Body.String())
	}
	w = request(module, http.MethodPost, "/reviews", `{"evidence_id":"evidence-1","decision":"approved","reason":"reviewed claims"}`, "alice", true)
	if w.Code != http.StatusForbidden {
		t.Fatalf("creator self-review must be denied: %d %s", w.Code, w.Body.String())
	}
	w = request(module, http.MethodPost, "/reviews", `{"evidence_id":"evidence-1","decision":"approved","reason":"reviewed claims"}`, "bob", true)
	if w.Code != http.StatusCreated {
		t.Fatalf("review create: %d %s", w.Code, w.Body.String())
	}
	w = request(module, http.MethodPost, "/baselines", fmt.Sprintf(`{"suite_id":%q,"evidence_id":"evidence-1","expected_revision":0}`, suite.ID), "bob", true)
	if w.Code != http.StatusCreated {
		t.Fatalf("baseline create: %d %s", w.Code, w.Body.String())
	}
	// A later candidate must be compared with the frozen metric values; a lower
	// higher-is-better score blocks even if it clears the absolute threshold.
	run2Data, _ := json.Marshal(RunData{SuiteID: suite.ID, AgentID: suiteData.AgentID, AgentVersionID: suiteData.AgentVersionID, IdempotencyKey: "run-2", ExecutionState: "succeeded", Total: 1, Completed: 1})
	run2 := Resource{ID: "run-2", Kind: KindRun, Scope: scope, Status: "succeeded", Revision: 1, CreatedBy: "alice", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Data: run2Data}
	if err := store.Create(context.Background(), run2); err != nil {
		t.Fatal(err)
	}
	caseID2 := caseResultID(run2.ID, 0)
	caseEvidence2 := caseEvidence
	caseEvidence2.RunID, caseEvidence2.Index = run2.ID, 0
	caseEvidence2.OutputArtifactID = "artifact.run-2"
	lowerScore := 0.70
	caseEvidence2.Metrics = []MetricOutcome{{MetricID: suiteData.MetricIDs[0], Status: "passed", Value: &lowerScore, Direction: "higher_is_better"}}
	caseBytes2, _ := json.Marshal(caseEvidence2)
	if err := store.Create(context.Background(), Resource{ID: caseID2, Kind: KindCaseResult, Scope: scope, Status: "completed", Revision: 1, CreatedBy: "worker", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Data: caseBytes2}); err != nil {
		t.Fatal(err)
	}
	candidate := evidenceData
	candidate.RunID, candidate.ProducedAt, candidate.CaseResultIDs = run2.ID, time.Now().UTC(), []string{caseID2}
	candidate.Metrics = []MetricOutcome{{MetricID: suiteData.MetricIDs[0], Status: "passed", Value: &lowerScore, Direction: "higher_is_better"}}
	candidate.ReportHash, _ = evaluationReportHash(candidate, []CaseResultData{caseEvidence2})
	candidate.Gate = evaluateEvidence(candidate, nil, time.Now().UTC())
	candidateBytes, _ := json.Marshal(candidate)
	if err := store.Create(context.Background(), Resource{ID: "evidence-2", Kind: KindEvidence, Scope: scope, Status: "completed", Revision: 1, CreatedBy: "worker", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Data: candidateBytes}); err != nil {
		t.Fatal(err)
	}
	w = request(module, http.MethodPost, "/gates/evaluate", `{"evidence_id":"evidence-2","minimum_score":0.6}`, "bob", true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "baseline_regression") {
		t.Fatalf("baseline regression should block: %d %s", w.Code, w.Body.String())
	}
	// A later, independently reviewed candidate at or above the frozen
	// baseline must be able to pass the complete release gate.
	run3Data, _ := json.Marshal(RunData{SuiteID: suite.ID, AgentID: suiteData.AgentID, AgentVersionID: suiteData.AgentVersionID, IdempotencyKey: "run-3", ExecutionState: "succeeded", Total: 1, Completed: 1})
	run3 := Resource{ID: "run-3", Kind: KindRun, Scope: scope, Status: "succeeded", Revision: 1, CreatedBy: "alice", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Data: run3Data}
	if err := store.Create(context.Background(), run3); err != nil {
		t.Fatal(err)
	}
	caseID3 := caseResultID(run3.ID, 0)
	caseEvidence3 := caseEvidence
	caseEvidence3.RunID, caseEvidence3.Index, caseEvidence3.OutputArtifactID = run3.ID, 0, "artifact.run-3"
	higherScore := 0.96
	caseEvidence3.Metrics = []MetricOutcome{{MetricID: suiteData.MetricIDs[0], Status: "passed", Value: &higherScore, Direction: "higher_is_better"}}
	caseBytes3, _ := json.Marshal(caseEvidence3)
	if err := store.Create(context.Background(), Resource{ID: caseID3, Kind: KindCaseResult, Scope: scope, Status: "completed", Revision: 1, CreatedBy: "worker", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Data: caseBytes3}); err != nil {
		t.Fatal(err)
	}
	candidate3 := evidenceData
	candidate3.RunID, candidate3.ProducedAt, candidate3.CaseResultIDs = run3.ID, time.Now().UTC(), []string{caseID3}
	candidate3.Metrics = []MetricOutcome{{MetricID: suiteData.MetricIDs[0], Status: "passed", Value: &higherScore, Direction: "higher_is_better"}}
	candidate3.ReportHash, _ = evaluationReportHash(candidate3, []CaseResultData{caseEvidence3})
	candidateBytes3, _ := json.Marshal(candidate3)
	evidenceID3 := evidenceResourceID(run3.ID)
	if err := store.Create(context.Background(), Resource{ID: evidenceID3, Kind: KindEvidence, Scope: scope, Status: "completed", Revision: 1, CreatedBy: "worker", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Data: candidateBytes3}); err != nil {
		t.Fatal(err)
	}
	review3 := request(module, http.MethodPost, "/reviews", fmt.Sprintf(`{"evidence_id":%q,"decision":"approved","reason":"independent fixture review"}`, evidenceID3), "charlie", true)
	if review3.Code != http.StatusCreated {
		t.Fatalf("independent candidate review: %d %s", review3.Code, review3.Body.String())
	}
	passed := request(module, http.MethodPost, "/gates/evaluate", fmt.Sprintf(`{"evidence_id":%q,"minimum_score":0.8}`, evidenceID3), "bob", true)
	if passed.Code != http.StatusOK || !strings.Contains(passed.Body.String(), `"state":"PASS"`) {
		t.Fatalf("reviewed, non-regressing evidence should pass the release gate: %d %s", passed.Code, passed.Body.String())
	}
	// The baseline report itself cannot be re-used as a fresh release candidate.
	w = request(module, http.MethodPost, "/gates/evaluate", `{"evidence_id":"evidence-1","minimum_score":0.8}`, "bob", true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), GateBlocked) {
		t.Fatalf("baseline evidence replay must block: %d %s", w.Code, w.Body.String())
	}
	// Malformed and synthetic evidence are deterministically blocked.
	bad := evidenceData
	bad.SourceType = "synthetic_only"
	got := evaluateEvidence(bad, nil, time.Now().UTC())
	if got.State != GateBlocked {
		t.Fatalf("synthetic evidence gate=%+v", got)
	}
	missing := request(module, http.MethodPost, "/gates/evaluate", `{"evidence_id":"does-not-exist","minimum_score":0.8}`, "bob", true)
	if missing.Code != http.StatusOK || !strings.Contains(missing.Body.String(), GateUnknown) {
		t.Fatalf("missing evidence should be UNKNOWN: %d %s", missing.Code, missing.Body.String())
	}
}

func TestBodyLimitAndStrictJSON(t *testing.T) {
	store := newMemoryStore()
	module := NewModule(store, "module-secret", allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return nil }), &fakeDispatcher{})
	oversized := `{"name":"` + strings.Repeat("x", MaxBodySize) + `"}`
	w := request(module, http.MethodPost, "/datasets", oversized, "alice", true)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized body status=%d", w.Code)
	}
	w = request(module, http.MethodPost, "/datasets", `{"name":"ok","version":"1","source_type":"manual_gold","cases":[{}]} {}`, "alice", true)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON accepted: %d", w.Code)
	}
}

func TestRunStatusOnlyServiceAndRevisionCAS(t *testing.T) {
	store := newMemoryStore()
	module := NewModule(store, "module-secret", allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return nil }), &fakeDispatcher{})
	scope := Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}
	data, _ := json.Marshal(RunData{SuiteID: "suite", IdempotencyKey: "run", ExecutionState: "queued"})
	row := Resource{ID: "run-1", Kind: KindRun, Scope: scope, Status: "queued", Revision: 1, CreatedBy: "alice", CreatedAt: time.Now(), UpdatedAt: time.Now(), Data: data}
	if err := store.Create(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	w := request(module, http.MethodPost, "/runs/run-1/status", `{"expected_revision":1,"status":"running","total":1}`, "alice", true)
	if w.Code != http.StatusForbidden {
		t.Fatalf("browser status write should be denied: %d", w.Code)
	}
	w = request(module, http.MethodPost, "/runs/run-1/status", `{"expected_revision":2,"status":"running","total":1}`, "worker", false)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale status revision should conflict: %d %s", w.Code, w.Body.String())
	}
}

func TestDispatchFailureIsVisibleAndRetryable(t *testing.T) {
	store := newMemoryStore()
	dispatcher := &fakeDispatcher{err: errors.New("temporary queue outage")}
	module := NewModule(store, "module-secret", allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return nil }), dispatcher)
	scope := Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}
	datasetData, _ := json.Marshal(DatasetData{Name: "dataset", Version: "1", SourceType: "manual_gold", Cases: []json.RawMessage{json.RawMessage(`{"case_id":"case-1","input":{"task":"query"}}`)}})
	if err := store.Create(context.Background(), Resource{ID: "ds", Kind: KindDataset, Scope: scope, Status: "published", Revision: 1, Data: datasetData}); err != nil {
		t.Fatal(err)
	}
	suiteData, _ := json.Marshal(SuiteData{Name: "suite", Version: "1", DatasetID: "ds", AgentID: "agent", AgentVersionID: "v1", MetricIDs: []string{"m"}})
	if err := store.Create(context.Background(), Resource{ID: "s1", Kind: KindSuite, Scope: scope, Status: "published", Revision: 1, Data: suiteData}); err != nil {
		t.Fatal(err)
	}
	w := request(module, http.MethodPost, "/runs", `{"suite_id":"s1","idempotency_key":"retry-1"}`, "alice", true)
	if w.Code != http.StatusAccepted {
		t.Fatalf("failed enqueue should remain accepted/pending: %d %s", w.Code, w.Body.String())
	}
	row := decodeResource(t, w)
	var runData RunData
	_ = json.Unmarshal(row.Data, &runData)
	if runData.ExecutionState != "dispatch_pending" {
		t.Fatalf("failed enqueue hidden from caller: %+v", runData)
	}
	dispatcher.err = nil
	w = request(module, http.MethodPost, "/runs", `{"suite_id":"s1","idempotency_key":"retry-1"}`, "alice", true)
	if w.Code != http.StatusAccepted {
		t.Fatalf("retry dispatch status=%d body=%s", w.Code, w.Body.String())
	}
	row = decodeResource(t, w)
	_ = json.Unmarshal(row.Data, &runData)
	if runData.ExecutionState != "queued" || row.Revision != 2 || len(dispatcher.enqueued) != 2 {
		t.Fatalf("retry did not enqueue existing Run exactly once: run=%+v calls=%d", row, len(dispatcher.enqueued))
	}
}
