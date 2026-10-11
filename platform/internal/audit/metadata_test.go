package audit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type metadataStoreStub struct {
	memoryAuditStore
	calls int
	query MetadataQuery
}

func (s *metadataStoreStub) ListMetadata(_ context.Context, query MetadataQuery) (Page, error) {
	s.calls++
	s.query = query
	return Page{Items: s.events, Total: int64(len(s.events)), Page: 1, PageSize: 20}, nil
}

func TestBrowserAuditMetadataScopesAndSensitiveSummaryBoundary(t *testing.T) {
	store := &metadataStoreStub{memoryAuditStore: memoryAuditStore{events: []Event{{ID: "event", TenantID: "t", DepartmentID: "d", ApplicationID: "a", Summary: "private fixture content"}}}}
	m := NewModule(store, "token")
	denial := error(nil)
	m.SetMetadataAuthorizer(func(_ context.Context, actor sharedkernel.Scope, target MetadataScope) error {
		if actor.PrincipalID != "auditor" {
			return ErrMetadataForbidden
		}
		return denial
	})
	invoke := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		for key, value := range map[string]string{"X-Internal-Token": "token", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": "auditor", "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a"} {
			r.Header.Set(key, value)
		}
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		return w
	}
	for _, scope := range []string{"scope_type=global", "scope_type=tenant&tenant_id=t", "scope_type=department&tenant_id=t&department_id=d", "scope_type=application&tenant_id=t&department_id=d&application_id=a"} {
		w := invoke("/events?" + scope + "&task_id=task&trace_id=trace&include_summary=true")
		var page Page
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || !page.MetadataOnly || page.Items[0].Summary != "" || strings.Contains(w.Body.String(), "private fixture content") || store.events[0].Summary != "private fixture content" {
			t.Fatal("metadata exposed or overwrote sensitive evidence", w.Code, w.Body.String())
		}
		if store.query.TaskID != "task" || store.query.TraceID != "trace" {
			t.Fatal("filters not passed to indexed store")
		}
	}
	before := store.calls
	for _, path := range []string{"/events?scope_type=global&tenant_id=t", "/events?scope_type=unknown", "/events?tenant_id=foreign", "/events?scope_type=application&tenant_id=*&department_id=d&application_id=a", "/events?page=999999999999999999999999999"} {
		if w := invoke(path); w.Code != 400 {
			t.Fatal("invalid scope or pagination reached reader", w.Code)
		}
	}
	if store.calls != before {
		t.Fatal("invalid query reached store")
	}
	denial = ErrMetadataForbidden
	if w := invoke("/events"); w.Code != 403 || store.calls != before {
		t.Fatal("denial reached audit store")
	}
	denial = errors.New("policy unavailable")
	if w := invoke("/events"); w.Code != 503 || store.calls != before {
		t.Fatal("policy outage fell through")
	}
	denial = nil
	store.events[0].TenantID = "foreign"
	if w := invoke("/events"); w.Code != 500 || strings.Contains(w.Body.String(), "foreign") {
		t.Fatal("store scope mismatch leaked out-of-scope event")
	}
}
