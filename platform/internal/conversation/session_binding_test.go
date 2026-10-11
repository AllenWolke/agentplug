package conversation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type changingSessionBinding struct {
	binding RuntimeBinding
	err     error
	actor   Scope
}

func (b *changingSessionBinding) Resolve(_ context.Context, scope Scope, _, version string) (RuntimeBinding, error) {
	b.actor = scope
	if b.err != nil {
		return RuntimeBinding{}, b.err
	}
	if b.binding.AgentVersionID != version {
		return RuntimeBinding{}, ErrRuntimeBinding
	}
	return b.binding, nil
}

func TestBrowserSessionCreationAndRunPreserveTrustedInstallation(t *testing.T) {
	store := newModuleStore()
	starter := &stubRunStarter{}
	module := NewModule(store, "module-token", false)
	module.SetRunStarter(starter)
	resolver := &changingSessionBinding{binding: RuntimeBinding{AgentEndpoint: "http://agent:8080", AgentInstanceID: "installed-a", InstallationID: "installed-a", AgentVersionID: "v1", AuthorizationEpoch: 1}}
	module.SetRuntimeBindingResolver(resolver)
	call := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		requestHeaders(r, "alice")
		r.Header.Set("X-Browser-Module", "1")
		w := httptest.NewRecorder()
		module.Handler().ServeHTTP(w, r)
		return w
	}
	create := `{"id":"session","kind":"qa","agent_id":"qa","agent_version_id":"v1","status":"active","can_continue":true,"owner_id":"forged-owner","tenant_id":"forged-tenant"}`
	response := call("/sessions", create)
	var session Session
	if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &session) != nil || session.InstallationID != "installed-a" || session.OwnerID != "alice" || session.TenantID != resolver.actor.TenantID || resolver.actor.PrincipalID != "alice" {
		t.Fatalf("create lost trusted scope/binding: %d %s", response.Code, response.Body)
	}
	resolver.binding.InstallationID, resolver.binding.AgentInstanceID = "installed-b", "installed-b"
	response = call("/sessions/session/runs", `{"run_id":"run","idempotency_key":"idem","request":{}}`)
	if response.Code != 409 || !strings.Contains(response.Body.String(), "SESSION_INSTALLATION_CHANGED") || starter.called {
		t.Fatalf("deployment replacement changed old session: %d %s", response.Code, response.Body)
	}
	old := store.sessions["session"]
	old.InstallationID = ""
	store.sessions["session"] = old
	response = call("/sessions/session/runs", `{"run_id":"run","idempotency_key":"idem","request":{}}`)
	if response.Code != 409 || !strings.Contains(response.Body.String(), "SESSION_INSTALLATION_UNVERIFIED") || starter.called {
		t.Fatalf("unverified history re-bound to current installation: %d %s", response.Code, response.Body)
	}
}

func TestBrowserSessionCreationRejectsUntrustedAndUnavailableBinding(t *testing.T) {
	for _, tc := range []struct {
		name, installation string
		resolver           *changingSessionBinding
		status             int
	}{
		{"missing resolver", "", nil, 503},
		{"caller provenance without resolver", "forged", nil, 503},
		{"catalog failure", "", &changingSessionBinding{err: errors.New("unavailable")}, 409},
		{"permission denied", "", &changingSessionBinding{err: ErrForbidden}, 403},
		{"version mismatch", "", &changingSessionBinding{binding: RuntimeBinding{InstallationID: "real", AgentVersionID: "v2"}}, 409},
		{"installation mismatch", "forged", &changingSessionBinding{binding: RuntimeBinding{InstallationID: "real", AgentVersionID: "v1"}}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newModuleStore()
			module := NewModule(store, "module-token", false)
			if tc.resolver != nil {
				module.SetRuntimeBindingResolver(tc.resolver)
			}
			body, _ := json.Marshal(Session{Summary: Summary{ID: "session", Kind: "qa", AgentID: "qa", AgentVersionID: "v1", InstallationID: tc.installation}})
			r := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(string(body)))
			requestHeaders(r, "alice")
			r.Header.Set("X-Browser-Module", "1")
			w := httptest.NewRecorder()
			module.Handler().ServeHTTP(w, r)
			if w.Code != tc.status || len(store.sessions) != 0 {
				t.Fatalf("invalid create persisted: status=%d body=%s sessions=%v", w.Code, w.Body, store.sessions)
			}
		})
	}
}
