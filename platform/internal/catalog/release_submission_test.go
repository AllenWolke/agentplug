package catalog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/bootstrap"
)

// This adapter only verifies HTTP dispatch. Transaction guarantees are tested with SQL.
type submittedMemoryStore struct{ *memoryStore }

func (m submittedMemoryStore) CreateSubmittedDefinition(ctx context.Context, d Definition, actor ControlActor) error {
	d.SubmittedBy = actor.PrincipalID
	return m.CreateDefinition(ctx, d)
}
func (m submittedMemoryStore) CreateSubmittedVersion(ctx context.Context, v Version, actor ControlActor) error {
	v.SubmittedBy = actor.PrincipalID
	return m.CreateVersion(ctx, v)
}
func (m submittedMemoryStore) PublishSubmittedObject(ctx context.Context, kind, id string, expected uint64, actor ControlActor) error {
	creator := m.definition.SubmittedBy
	if kind == "version" {
		creator = m.version.SubmittedBy
	}
	if creator == "" {
		return ErrReleaseSubmissionMissing
	}
	if creator == actor.PrincipalID {
		return ErrCatalogForbidden
	}
	if kind == "definition" {
		if err := m.TransitionDefinition(ctx, id, DefinitionEvaluated, DefinitionPublished, expected); err != nil {
			return err
		}
		m.definition.ApprovedBy = actor.PrincipalID
	} else {
		if err := m.TransitionVersion(ctx, id, DefinitionEvaluated, DefinitionPublished, expected); err != nil {
			return err
		}
		m.version.ApprovedBy = actor.PrincipalID
	}
	return nil
}

func TestBrowserReleaseUsesTrustedSubmitterAndIndependentApproval(t *testing.T) {
	for _, kind := range []string{"definition", "version"} {
		t.Run(kind, func(t *testing.T) {
			memory := &memoryStore{}
			module := NewModule(submittedMemoryStore{memory}, "runtime")
			module.SetControlAuthorizer(controlAuthorizerFunc(func(_ context.Context, a ControlActor, action ControlAction, _ ControlScope) error {
				if a.PrincipalID == "manager" || (action != ControlSubmit && action != ControlApprove) {
					return ErrCatalogForbidden
				}
				return nil
			}))
			gateway := strings.Repeat("g", 40)
			handler := bootstrap.BrowserBoundary(http.StripPrefix("/modules/catalog", module.Handler()), gateway, "runtime")
			call := func(actor, path, body string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, "/modules/catalog"+path, strings.NewReader(body))
				for k, v := range map[string]string{"X-Internal-Token": gateway, "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": actor, "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a"} {
					r.Header.Set(k, v)
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			createPath, publishPath, body := "/definitions", "/definitions/def/publish", definitionRequestJSON("def", "agent", "Agent")
			if kind == "version" {
				createPath, publishPath, body = "/definitions/def/versions", "/versions/ver/publish", versionRequestJSON("ver", "def", "agent", "1.0.0")
			}
			if w := call("manager", createPath, body); w.Code != 403 {
				t.Fatal("catalog management conferred submission", w.Code, w.Body.String())
			}
			forged := strings.TrimSuffix(body, "}") + `,"submitted_by":"bob"}`
			if w := call("alice", createPath, forged); w.Code != 400 {
				t.Fatal("forged submitter accepted", w.Code, w.Body.String())
			}
			if w := call("alice", createPath, body); w.Code != 201 {
				t.Fatal("submission failed", w.Code, w.Body.String())
			}
			if kind == "definition" {
				memory.definition.Status = DefinitionEvaluated
				memory.definition.Revision = 2
			} else {
				memory.version.Status = DefinitionEvaluated
				memory.version.Revision = 2
			}
			for _, actor := range []string{"alice", "manager"} {
				if w := call(actor, publishPath, `{"expected_revision":2}`); w.Code != 403 {
					t.Fatal("self/unauthorized approval accepted", actor, w.Code, w.Body.String())
				}
			}
			if w := call("bob", publishPath, `{"expected_revision":2}`); w.Code != 200 {
				t.Fatal("independent approval failed", w.Code, w.Body.String())
			}
			if kind == "definition" && (memory.definition.SubmittedBy != "alice" || memory.definition.ApprovedBy != "bob") {
				t.Fatal("definition lost provenance")
			}
			if kind == "version" && (memory.version.SubmittedBy != "alice" || memory.version.ApprovedBy != "bob") {
				t.Fatal("version lost provenance")
			}
		})
	}
}
