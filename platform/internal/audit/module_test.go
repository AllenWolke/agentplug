package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type memoryAuditStore struct{ events []Event }

func (s *memoryAuditStore) EnsureSchema(context.Context) error { return nil }
func (s *memoryAuditStore) Record(_ context.Context, event Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	for _, prior := range s.events {
		if prior.ID == event.ID {
			one, _ := prior.Digest()
			two, _ := event.Digest()
			if one != two {
				return ErrConflict
			}
			return nil
		}
	}
	s.events = append(s.events, event)
	return nil
}
func (s *memoryAuditStore) List(_ context.Context, tenant, department, application string, page, size int) (Page, error) {
	if tenant == "" || department == "" || application == "" {
		return Page{}, ErrInvalidEvent
	}
	return Page{Items: s.events, Total: int64(len(s.events)), Page: page, PageSize: size}, nil
}

func (s *memoryAuditStore) ListFiltered(_ context.Context, tenant, department, application, taskID, traceID string, page, size int) (Page, error) {
	if tenant == "" || department == "" || application == "" || (taskID == "" && traceID == "") {
		return Page{}, ErrInvalidEvent
	}
	items := make([]Event, 0)
	for _, event := range s.events {
		if event.TenantID != tenant || event.DepartmentID != department || event.ApplicationID != application {
			continue
		}
		if (taskID != "" && event.AggregateID == taskID) || (traceID != "" && event.TraceID == traceID) {
			items = append(items, event)
		}
	}
	return Page{Items: items, Total: int64(len(items)), Page: page, PageSize: size}, nil
}

func TestAuditModuleRequiresInternalAuthAndRejectsConflictingReplay(t *testing.T) {
	store := &memoryAuditStore{}
	handler := NewModule(store, "token").Handler()
	body := `{"id":"audit-1","tenant_id":"tenant","department_id":"department","application_id":"application","actor_type":"user","actor_id":"actor","aggregate_type":"run","aggregate_id":"run-1","action":"completed","outcome":"accepted","summary":"redacted","created_at":"2026-01-01T00:00:00Z"}`
	call := func(payload string, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(payload))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if out := call(body, ""); out.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth status=%d", out.Code)
	}
	if out := call(body, "token"); out.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", out.Code, out.Body.String())
	}
	conflict := strings.Replace(body, `"summary":"redacted"`, `"summary":"different"`, 1)
	if out := call(conflict, "token"); out.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d body=%s", out.Code, out.Body.String())
	}
}

func TestBrowserAuditSearchRequiresTrustedAuditorAndUsesScopedFilters(t *testing.T) {
	store := &memoryAuditStore{events: []Event{{ID: "event-1", TenantID: "tenant-1", DepartmentID: "dept-1", ApplicationID: "app-1", TraceID: "trace-1", AggregateType: "run", AggregateID: "task-1", Action: "run.completed"}}}
	module := NewModule(store, "internal")
	var resolvedPrincipal string
	module.SetBrowserReader(func(_ context.Context, tenant, department, application, principal string) (bool, error) {
		resolvedPrincipal = principal
		return tenant == "tenant-1" && department == "dept-1" && application == "app-1" && principal == "auditor-1", nil
	})
	handler := module.Handler()
	call := func(principal string, method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer internal")
		req.Header.Set("X-Browser-Module", "1")
		req.Header.Set("X-Principal-Type", "user")
		req.Header.Set("X-Principal-ID", principal)
		req.Header.Set("X-Tenant-ID", "tenant-1")
		req.Header.Set("X-Department-ID", "dept-1")
		req.Header.Set("X-Application-ID", "app-1")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if denied := call("operator-1", http.MethodGet, "/events?task_id=task-1&page=1&page_size=20"); denied.Code != http.StatusForbidden {
		t.Fatalf("non-auditor status=%d body=%s", denied.Code, denied.Body.String())
	}
	if allowed := call("auditor-1", http.MethodGet, "/events?task_id=task-1&trace_id=trace-1&page=1&page_size=20"); allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), "event-1") {
		t.Fatalf("auditor query status=%d body=%s", allowed.Code, allowed.Body.String())
	}
	if resolvedPrincipal != "auditor-1" {
		t.Fatalf("identity resolver principal=%q", resolvedPrincipal)
	}
	if forbiddenWrite := call("auditor-1", http.MethodPost, "/events"); forbiddenWrite.Code != http.StatusForbidden {
		t.Fatalf("browser audit write status=%d body=%s", forbiddenWrite.Code, forbiddenWrite.Body.String())
	}
}
