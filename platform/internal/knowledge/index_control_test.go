package knowledge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type indexControlFixture struct {
	calls   int
	failure error
}

func (*indexControlFixture) Ready(context.Context) error { return nil }
func (*indexControlFixture) Change(context.Context, sharedkernel.Scope, ProjectionScope, SourceChange) (SourceReceipt, error) {
	return SourceReceipt{}, nil
}
func (*indexControlFixture) Snapshot(context.Context, sharedkernel.Scope, ProjectionScope, int) (SourceSnapshot, error) {
	return SourceSnapshot{}, nil
}
func (f *indexControlFixture) SubmitIndex(_ context.Context, actor sharedkernel.Scope, scope ProjectionScope, r IndexTaskRequest) (IndexTaskReceipt, error) {
	f.calls++
	if actor.PrincipalID != "manager" || scope.KnowledgeID != "docs" {
		panic("untrusted actor or knowledge scope")
	}
	return IndexTaskReceipt{SchemaVersion: "knowledge-index-task/v1", RunID: "index-run", Status: "accepted"}, f.failure
}

func (f *indexControlFixture) QueryIndex(_ context.Context, actor sharedkernel.Scope, scope ProjectionScope, id string) (IndexTaskDetail, error) {
	f.calls++
	if actor.PrincipalID != "manager" || scope.KnowledgeID != "docs" || id != "index-run" {
		panic("untrusted query")
	}
	return IndexTaskDetail{SchemaVersion: "knowledge-index-task-detail/v1", RunID: id, KnowledgeID: scope.KnowledgeID, Mode: "full", Status: "accepted", Revision: 1}, f.failure
}

func (f *indexControlFixture) CancelIndex(ctx context.Context, actor sharedkernel.Scope, scope ProjectionScope, id string, request IndexCancelRequest) (IndexTaskDetail, error) {
	if request.ExpectedRevision != 2 {
		panic("untrusted revision")
	}
	detail, err := f.QueryIndex(ctx, actor, scope, id)
	detail.Status, detail.Revision = "cancelling", 3
	return detail, err
}

func TestIndexCancelRejectsForgedAuthorityAndInvalidCAS(t *testing.T) {
	for _, mode := range []string{"allowed", "untrusted", "denied", "not-found", "conflict", "unavailable", "missing-revision", "authority-override", "trailing-json", "negative-revision"} {
		t.Run(mode, func(t *testing.T) {
			service := &indexControlFixture{}
			module := NewControlModule("internal", service)
			module.SetIndexService(service)
			expected, body := 202, `{"expected_revision":2}`
			switch mode {
			case "untrusted":
				expected = 401
			case "denied":
				service.failure, expected = ErrManagementDenied, 403
			case "not-found":
				service.failure, expected = ErrIndexTaskNotFound, 404
			case "conflict":
				service.failure, expected = ErrIndexTaskConflict, 409
			case "unavailable":
				module.SetIndexService(nil)
				expected = 503
			case "missing-revision":
				body, expected = `{}`, 400
			case "authority-override":
				body, expected = `{"expected_revision":2,"lease_token":"forged"}`, 400
			case "trailing-json":
				body, expected = body+`{}`, 400
			case "negative-revision":
				body, expected = `{"expected_revision":-1}`, 400
			}
			r := httptest.NewRequest("POST", "/indexes/docs/tasks/index-run/cancel", strings.NewReader(body))
			for key, value := range map[string]string{"X-Internal-Token": "internal", "X-Browser-Module": "1", "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a", "X-Principal-Type": "user", "X-Principal-ID": "manager", "X-Trace-ID": "trace"} {
				r.Header.Set(key, value)
			}
			if mode == "untrusted" {
				r.Header.Del("X-Internal-Token")
			}
			w := httptest.NewRecorder()
			module.Handler().ServeHTTP(w, r)
			if w.Code != expected {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if (expected == 400 || expected == 401 || expected == 503) && service.calls != 0 {
				t.Fatal("rejected cancel reached service")
			}
		})
	}
}

func TestIndexQueryRequiresTrustedManagerContext(t *testing.T) {
	for _, mode := range []string{"allowed", "untrusted", "denied", "not-found", "unavailable", "invalid-id"} {
		t.Run(mode, func(t *testing.T) {
			service := &indexControlFixture{}
			module := NewControlModule("internal", service)
			module.SetIndexService(service)
			expected, id := 200, "index-run"
			switch mode {
			case "denied":
				service.failure, expected = ErrManagementDenied, 403
			case "not-found":
				service.failure, expected = ErrIndexTaskNotFound, 404
			case "unavailable":
				module.SetIndexService(nil)
				expected = 503
			case "untrusted":
				expected = 401
			case "invalid-id":
				id, expected = strings.Repeat("x", 129), 400
			}
			r := httptest.NewRequest("GET", "/indexes/docs/tasks/"+id, nil)
			for key, value := range map[string]string{"X-Internal-Token": "internal", "X-Browser-Module": "1", "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a", "X-Principal-Type": "user", "X-Principal-ID": "manager", "X-Trace-ID": "trace"} {
				r.Header.Set(key, value)
			}
			if mode == "untrusted" {
				r.Header.Del("X-Browser-Module")
			}
			w := httptest.NewRecorder()
			module.Handler().ServeHTTP(w, r)
			if w.Code != expected || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if (mode == "untrusted" || mode == "unavailable" || mode == "invalid-id") && service.calls != 0 {
				t.Fatal("rejected request reached service")
			}
		})
	}
}

func TestIndexControlAuthenticatesAndRejectsAuthorityOverrides(t *testing.T) {
	for _, mode := range []string{"full", "incremental", "unknown-field", "invalid-mode", "invalid-bounds", "trailing-body", "untrusted", "missing-service", "denied", "conflict"} {
		t.Run(mode, func(t *testing.T) {
			service := &indexControlFixture{}
			module := NewControlModule("internal", service)
			module.SetIndexService(service)
			request := IndexTaskRequest{InstallationID: "installation", IdempotencyKey: "index-request", Mode: "full", Config: IndexSettings{Dimensions: 1024, WindowRunes: 512, OverlapRunes: 64, MaximumDocuments: 100, MaximumChunks: 1000}}
			expected := http.StatusAccepted
			switch mode {
			case "incremental":
				request.Mode = "incremental"
			case "invalid-mode":
				request.Mode = "other"
				expected = 400
			case "invalid-bounds":
				request.Config.OverlapRunes = 512
				expected = 400
			case "unknown-field", "trailing-body":
				expected = 400
			case "untrusted":
				expected = 401
			case "missing-service":
				module.SetIndexService(nil)
				expected = 503
			case "denied":
				service.failure = ErrManagementDenied
				expected = 403
			case "conflict":
				service.failure = ErrIndexTaskConflict
				expected = 409
			}
			raw, _ := json.Marshal(request)
			body := string(raw)
			if mode == "unknown-field" {
				body = strings.TrimSuffix(body, "}") + `,"policy_snapshot":{"model":"unapproved"}}`
			}
			if mode == "trailing-body" {
				body += "{}"
			}
			r := httptest.NewRequest(http.MethodPost, "/indexes/docs/tasks", strings.NewReader(body))
			for k, v := range map[string]string{"X-Internal-Token": "internal", "X-Browser-Module": "1", "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a", "X-Principal-Type": "user", "X-Principal-ID": "manager", "X-Trace-ID": "trace"} {
				r.Header.Set(k, v)
			}
			if mode == "untrusted" {
				r.Header.Del("X-Browser-Module")
			}
			w := httptest.NewRecorder()
			module.Handler().ServeHTTP(w, r)
			if w.Code != expected {
				t.Fatal(mode, w.Code, w.Body.String())
			}
			shouldCall := expected == 202 || expected == 403 || expected == 409
			if (service.calls == 1) != shouldCall {
				t.Fatal("invalid request reached service", service.calls)
			}
		})
	}
}
