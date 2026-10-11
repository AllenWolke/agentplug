package audit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type contentStoreFixture struct {
	memoryAuditStore
	rows        map[string]Event
	reads       int
	afterRead   func()
	afterRecord func()
	recordError error
}

func (s *contentStoreFixture) GetEventMetadata(_ context.Context, scope MetadataScope, id string) (Event, error) {
	e, ok := s.rows[id]
	if !ok || !scope.contains(e) {
		return Event{}, ErrNotFound
	}
	e.Summary = ""
	return e, nil
}
func (s *contentStoreFixture) GetEventContent(_ context.Context, header Event) (Event, error) {
	s.reads++
	if s.afterRead != nil {
		s.afterRead()
	}
	return s.rows[header.ID], nil
}
func (s *contentStoreFixture) Record(ctx context.Context, e Event) error {
	if s.recordError != nil {
		return s.recordError
	}
	if s.afterRecord != nil {
		s.afterRecord()
	}
	return s.memoryAuditStore.Record(ctx, e)
}
func contentFixtureRequest(m *Module, method, path, body string, browser bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range map[string]string{"X-Internal-Token": "token", "X-Principal-Type": "user", "X-Principal-ID": "auditor", "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a"} {
		r.Header.Set(k, v)
	}
	if browser {
		r.Header.Set("X-Browser-Module", "1")
	}
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, r)
	return w
}
func TestAuditContentAndExportRequireIndependentCurrentAuthority(t *testing.T) {
	for _, scenario := range []string{"allowed-content", "allowed-export", "metadata-only", "export-denied", "partial-export", "revoked-during-read", "revoked-during-record", "record-failure", "internal-token", "duplicate", "foreign-row"} {
		t.Run(scenario, func(t *testing.T) {
			e := Event{ID: "e1", TenantID: "t", DepartmentID: "d", ApplicationID: "a", ActorID: "owner", AggregateType: "agent_run", AggregateID: "run", Action: "run.complete", Outcome: "success", Summary: "private-audit-body", CreatedAt: time.Now().UTC()}
			s := &contentStoreFixture{rows: map[string]Event{"e1": e, "e2": e}}
			second := e
			second.ID = "e2"
			s.rows["e2"] = second
			m := NewModule(s, "token")
			denied := false
			m.SetContentAuthorizer(func(_ context.Context, actor sharedkernel.Scope, event Event, action string) error {
				if event.Summary != "" || actor.PrincipalID != "auditor" {
					t.Fatal("untrusted content supplied to authorizer")
				}
				if denied || scenario == "metadata-only" || scenario == "export-denied" && action == "audit.export" || scenario == "partial-export" && event.ID == "e2" {
					return ErrContentForbidden
				}
				return nil
			})
			method, path, body := http.MethodGet, "/events/e1/content", ""
			if strings.Contains(scenario, "export") || scenario == "duplicate" {
				method, path, body = http.MethodPost, "/exports", `{"event_ids":["e1","e2"]}`
			}
			if scenario == "duplicate" {
				body = `{"event_ids":["e1","e1"]}`
			}
			if scenario == "foreign-row" {
				e.TenantID = "foreign"
				s.rows["e1"] = e
			}
			if scenario == "revoked-during-read" {
				s.afterRead = func() { denied = true }
			}
			if scenario == "revoked-during-record" {
				s.afterRecord = func() { denied = true }
			}
			if scenario == "record-failure" {
				s.recordError = errors.New("outbox unavailable")
			}
			w := contentFixtureRequest(m, method, path, body, scenario != "internal-token")
			allowed := scenario == "allowed-content" || scenario == "allowed-export"
			if (w.Code == 200) != allowed || strings.Contains(w.Body.String(), "private-audit-body") != allowed {
				t.Fatal(scenario, w.Code, w.Body.String())
			}
			if scenario == "metadata-only" || scenario == "export-denied" || scenario == "partial-export" || scenario == "internal-token" || scenario == "duplicate" || scenario == "foreign-row" {
				if s.reads != 0 {
					t.Fatal("sensitive column read before all rows authorized")
				}
			}
			if allowed && (len(s.events) != 1 || strings.Contains(s.events[0].Summary, "private-audit-body") || w.Header().Get("Cache-Control") != "no-store") {
				t.Fatal("access audit or response cache boundary missing")
			}
			if scenario == "allowed-export" && w.Header().Get("Content-Disposition") == "" {
				t.Fatal("export attachment missing")
			}
		})
	}
}

func TestAuditContentPermissionsDoNotReadSensitiveColumns(t *testing.T) {
	s := &contentStoreFixture{rows: map[string]Event{"e": {ID: "e", TenantID: "t", DepartmentID: "d", ApplicationID: "a", Summary: "private-audit-body"}}}
	m := NewModule(s, "token")
	m.SetMetadataAuthorizer(func(context.Context, sharedkernel.Scope, MetadataScope) error { return nil })
	m.SetContentAuthorizer(func(_ context.Context, _ sharedkernel.Scope, _ Event, action string) error {
		if action == "audit.export" {
			return ErrContentForbidden
		}
		return nil
	})
	w := contentFixtureRequest(m, http.MethodGet, "/events/e/permissions", "", true)
	if w.Code != 200 || s.reads != 0 || strings.Contains(w.Body.String(), "private-audit-body") || !strings.Contains(w.Body.String(), `"audit.content.read":true`) || !strings.Contains(w.Body.String(), `"audit.export":false`) {
		t.Fatal(w.Code, w.Body.String(), s.reads)
	}
}
