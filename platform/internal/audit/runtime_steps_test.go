package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestRuntimeAuditProjectionIsStrictAndRedacted(t *testing.T) {
	event := runtimeAuditFixtureEvent()
	projection, err := decodeRuntimeAuditRecord(event, "run-1")
	if err != nil || projection.Version != runtimeAuditVersion || projection.ToolName != "db.read" || projection.PermissionScope == nil {
		t.Fatalf("projection=%+v err=%v", projection, err)
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"summary", "fingerprint", "lease_fence", "approval_digest", "payload"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("private field %q leaked in %s", forbidden, encoded)
		}
	}
	var content map[string]json.RawMessage
	if json.Unmarshal(encoded, &content) != nil || len(content) != 18 {
		t.Fatalf("unexpected projection shape %s", encoded)
	}
	var permission map[string]json.RawMessage
	if json.Unmarshal(content["permission_scope"], &permission) != nil || len(permission) != 3 {
		t.Fatalf("permission scope is not the closed three-field object: %s", content["permission_scope"])
	}
}

func TestRuntimeAuditProjectionPreservesTimeoutObservationStatus(t *testing.T) {
	for _, status := range []string{"timeout", "timed_out"} {
		event := runtimeAuditFixtureEvent()
		var summary map[string]any
		if err := json.Unmarshal([]byte(event.Summary), &summary); err != nil {
			t.Fatal(err)
		}
		summary["observation_status"] = status
		raw, err := json.Marshal(summary)
		if err != nil {
			t.Fatal(err)
		}
		event.Summary = string(raw)
		projection, err := decodeRuntimeAuditRecord(event, "run-1")
		if err != nil || projection.ObservationStatus == nil || *projection.ObservationStatus != status {
			t.Fatalf("status=%q projection=%+v err=%v", status, projection, err)
		}
	}
}

func TestRuntimeAuditProjectionFailsClosedOnBindingOrUnknownFields(t *testing.T) {
	event := runtimeAuditFixtureEvent()
	var summary map[string]any
	if err := json.Unmarshal([]byte(event.Summary), &summary); err != nil {
		t.Fatal(err)
	}
	summary["permission_scope"] = map[string]any{"action": "tool.invoke", "resource_type": "tool", "resource_id": "different.tool"}
	raw, _ := json.Marshal(summary)
	event.Summary = string(raw)
	if _, err := decodeRuntimeAuditRecord(event, "run-1"); !errors.Is(err, ErrRuntimeStepCorrupt) {
		t.Fatalf("mismatched permission resource accepted: %v", err)
	}
	event = runtimeAuditFixtureEvent()
	if err := json.Unmarshal([]byte(event.Summary), &summary); err != nil {
		t.Fatal(err)
	}
	summary["unreviewed_private_field"] = "must not be disclosed"
	raw, _ = json.Marshal(summary)
	event.Summary = string(raw)
	if _, err := decodeRuntimeAuditRecord(event, "run-1"); !errors.Is(err, ErrRuntimeStepCorrupt) {
		t.Fatalf("unknown audit field accepted: %v", err)
	}
}

func TestRuntimeAuditAcceptsTheProducerOutputBoundWithoutDisclosingData(t *testing.T) {
	for _, size := range []int{65537, 162405, sharedkernel.MaxToolObservationOutputBytes, -1, sharedkernel.MaxToolObservationOutputBytes + 1} {
		event := runtimeAuditFixtureEvent()
		var summary map[string]any
		if err := json.Unmarshal([]byte(event.Summary), &summary); err != nil {
			t.Fatal(err)
		}
		summary["output_size_bytes"] = size
		raw, _ := json.Marshal(summary)
		event.Summary = string(raw)
		projection, err := decodeRuntimeAuditRecord(event, "run-1")
		if size < 0 || size > sharedkernel.MaxToolObservationOutputBytes {
			if !errors.Is(err, ErrRuntimeStepCorrupt) {
				t.Fatalf("invalid output size accepted: %d", size)
			}
			continue
		}
		if err != nil || projection.OutputSizeBytes == nil || *projection.OutputSizeBytes != int64(size) {
			t.Fatalf("legal producer metadata rejected: size=%d err=%v", size, err)
		}
		encoded, _ := json.Marshal(projection)
		if strings.Contains(string(encoded), "payload") || strings.Contains(string(encoded), "fingerprint") {
			t.Fatal("larger byte-count metadata disclosed private fields")
		}
	}
}

func TestRuntimeStepsCursorBindsScopeRunAndStep(t *testing.T) {
	query := RuntimeStepsQuery{Scope: MetadataScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}, RunID: "run-1", StepID: runtimeAuditFixtureStepID(), PageSize: 20}
	event := runtimeAuditFixtureEvent()
	cursor, err := encodeRuntimeStepsCursor(query, event)
	if err != nil {
		t.Fatal(err)
	}
	if _, id, err := decodeRuntimeStepsCursor(cursor, query); err != nil || id != event.ID {
		t.Fatalf("cursor decode id=%q err=%v", id, err)
	}
	for _, change := range []func(*RuntimeStepsQuery){
		func(q *RuntimeStepsQuery) { q.Scope.ApplicationID = "other" },
		func(q *RuntimeStepsQuery) { q.RunID = "run-2" },
		func(q *RuntimeStepsQuery) { q.StepID = "runtime-" + strings.Repeat("0", 64) },
	} {
		altered := query
		altered.Cursor = cursor
		change(&altered)
		if _, _, err := decodeRuntimeStepsCursor(altered.Cursor, altered); !errors.Is(err, ErrInvalidRuntimeSteps) {
			t.Fatalf("cursor reused outside its scope/query: %v", err)
		}
	}
}

func TestRuntimeStepsHTTPRechecksMetadataPermissionBeforeDisclosure(t *testing.T) {
	store := &runtimeStepsTestStore{page: RuntimeStepsPage{Items: []RuntimeExecutionAudit{runtimeAuditFixtureProjection()}}}
	module := NewModule(store, "runtime-step-test-token")
	checks := 0
	module.SetMetadataAuthorizer(func(_ context.Context, actorScope sharedkernel.Scope, target MetadataScope) error {
		checks++
		if actorScope.PrincipalID != "auditor" || target.TenantID != "t" || target.DepartmentID != "d" || target.ApplicationID != "a" {
			t.Fatalf("unexpected authority scope: actor=%+v target=%+v", actorScope, target)
		}
		return nil
	})
	request := runtimeStepsHTTPGet(t, "/runtime-steps?run_id=run-1")
	recorder := httptest.NewRecorder()
	module.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || checks != 2 || store.calls != 1 {
		t.Fatalf("status=%d checks=%d store calls=%d body=%s", recorder.Code, checks, store.calls, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "sensitive_summary") || !strings.Contains(recorder.Body.String(), "runtime-execution-audit/v1") {
		t.Fatalf("unexpected typed response: %s", recorder.Body.String())
	}

	checks = 0
	store.calls = 0
	module.SetMetadataAuthorizer(func(context.Context, sharedkernel.Scope, MetadataScope) error {
		checks++
		if checks == 2 {
			return ErrMetadataForbidden
		}
		return nil
	})
	recorder = httptest.NewRecorder()
	module.Handler().ServeHTTP(recorder, runtimeStepsHTTPGet(t, "/runtime-steps?run_id=run-1"))
	if recorder.Code != http.StatusForbidden || checks != 2 || store.calls != 1 || strings.Contains(recorder.Body.String(), "runtime-execution-audit/v1") {
		t.Fatalf("permission revocation disclosed rows: status=%d checks=%d body=%s", recorder.Code, checks, recorder.Body.String())
	}
}

func TestRuntimeStepsHTTPRejectsMalformedQueries(t *testing.T) {
	store := &runtimeStepsTestStore{}
	module := NewModule(store, "runtime-step-test-token")
	module.SetMetadataAuthorizer(func(context.Context, sharedkernel.Scope, MetadataScope) error { return nil })
	for _, target := range []string{`/runtime-steps`, `/runtime-steps?run_id=run-1&run_id=run-2`, `/runtime-steps?run_id=run-1&unexpected=x`, `/runtime-steps?run_id=run-1&page_size=101`} {
		recorder := httptest.NewRecorder()
		module.Handler().ServeHTTP(recorder, runtimeStepsHTTPGet(t, target))
		if recorder.Code != http.StatusBadRequest || store.calls != 0 {
			t.Fatalf("query %q status=%d store calls=%d", target, recorder.Code, store.calls)
		}
	}
}

type runtimeStepsTestStore struct {
	page  RuntimeStepsPage
	err   error
	calls int
}

func (s *runtimeStepsTestStore) EnsureSchema(context.Context) error  { return nil }
func (s *runtimeStepsTestStore) Record(context.Context, Event) error { return nil }
func (s *runtimeStepsTestStore) List(context.Context, string, string, string, int, int) (Page, error) {
	return Page{}, nil
}
func (s *runtimeStepsTestStore) ListRuntimeSteps(_ context.Context, query RuntimeStepsQuery) (RuntimeStepsPage, error) {
	s.calls++
	if err := validateRuntimeStepsQuery(query); err != nil {
		return RuntimeStepsPage{}, err
	}
	return s.page, s.err
}

func runtimeStepsHTTPGet(t *testing.T, target string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	for key, value := range map[string]string{
		"X-Internal-Token": "runtime-step-test-token", "X-Browser-Module": "1",
		"X-Principal-Type": "user", "X-Principal-ID": "auditor",
		"X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a", "X-Trace-ID": "trace",
	} {
		request.Header.Set(key, value)
	}
	return request
}

func runtimeAuditFixtureStepID() string {
	digest := sha256.Sum256([]byte(strings.Repeat("a", 64) + "\x00call-1"))
	return "runtime-" + hex.EncodeToString(digest[:])
}

func runtimeAuditFixtureEvent() Event {
	permissionHash := strings.Repeat("a", 64)
	fingerprint := strings.Repeat("b", 64)
	policyHash := strings.Repeat("c", 64)
	started := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	finished := started.Add(25 * time.Millisecond)
	stepID := runtimeAuditFixtureStepID()
	summary := map[string]any{
		"version": runtimeAuditVersion, "run_id": "run-1", "step_id": stepID, "call_id": "call-1",
		"tool_name": "db.read", "permission_scope_hash": permissionHash,
		"permission_scope":    map[string]any{"action": "tool.invoke", "resource_type": "tool", "resource_id": "db.read"},
		"authorization_epoch": 1, "fingerprint": fingerprint, "lease_fence": 1,
		"status": "completed", "execution_type": "tool", "risk": "read_only",
		"policy_snapshot_hash": policyHash, "approval_digest": nil, "started_at": started,
		"finished_at": finished, "duration_ms": int64(25), "error_type": nil,
		"output_size_bytes": int64(5), "observation_status": "succeeded",
		"resource_usage": map[string]any{"cpu_time_ms": nil, "peak_memory_bytes": nil, "disk_bytes": nil,
			"sampled_peak_memory_bytes": int64(1024), "sample_count": int64(2), "disk_sample_count": int64(1),
			"measurement_complete": true, "measurement_source": "docker_engine_sampled/v1", "disk_measurement_source": "docker_exec_tmpfs_stat/v1"},
	}
	body, _ := json.Marshal(summary)
	return Event{ID: "runtime-event-1", TenantID: "t", DepartmentID: "d", ApplicationID: "a", ActorType: "user", ActorID: "caller", TraceID: "trace", AggregateType: "run", AggregateID: "run-1", Action: "runtime.tool.completed", Outcome: "completed", Summary: string(body), CreatedAt: finished}
}

func runtimeAuditFixtureProjection() RuntimeExecutionAudit {
	event := runtimeAuditFixtureEvent()
	projection, err := decodeRuntimeAuditRecord(event, "run-1")
	if err != nil {
		panic(err)
	}
	return projection
}

var _ RuntimeStepsReader = (*runtimeStepsTestStore)(nil)
