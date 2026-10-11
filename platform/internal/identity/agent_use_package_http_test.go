package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type agentUsePackageHTTPStore struct {
	*permissionHTTPStore
	reads int
	actor sharedkernel.Scope
	scope ManagementScope
}

func (s *agentUsePackageHTTPStore) AgentUsePackage(_ context.Context, actor sharedkernel.Scope, scope ManagementScope) (AgentUsePackage, error) {
	s.reads++
	s.actor, s.scope = actor, scope
	return AgentUsePackage{}, nil
}

func TestAgentUsePackageHTTPTrustedHumanAndStrictReadScope(t *testing.T) {
	snapshot, _ := permissionFixture()
	s := &agentUsePackageHTTPStore{permissionHTTPStore: &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal}, snapshot: snapshot}}
	handler := NewModule(s, "fixture-internal-token").Handler()
	call := func(method, path string, authenticated, browser bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(""))
		if browser {
			setBrowserIdentityHeaders(r, s.principal, "d", "a")
		}
		r.Header.Del("Authorization")
		r.Header.Del("X-Internal-Token")
		if authenticated {
			r.Header.Set("X-Internal-Token", "fixture-internal-token")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	path := "/agent-use-package?department_id=d&application_id=a&installation_id=i"
	if w := call("POST", path, true, true); w.Code != http.StatusMethodNotAllowed {
		t.Fatal("package read permitted a mutating verb", w.Code)
	}
	if w := call("GET", path, false, true); w.Code != http.StatusUnauthorized {
		t.Fatal("untrusted caller reached package read", w.Code)
	}
	if w := call("GET", path, true, false); w.Code != http.StatusForbidden {
		t.Fatal("internal service implied human administration", w.Code)
	}
	for _, bad := range []string{path + "&tenant_id=other", path + "&actor_id=other", path + "&installation_id=other", "/agent-use-package?department_id=d&application_id=a", "/agent-use-package?department_id=d&application_id=a&installation_id="} {
		if w := call("GET", bad, true, true); w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
			t.Fatal("package read accepted extra, duplicate or incomplete scope", bad, w.Code)
		}
	}
	if s.reads != 0 {
		t.Fatal("invalid request reached package repository")
	}
	if w := call("GET", path, true, true); w.Code != http.StatusOK || s.reads != 1 || s.actor.PrincipalID != snapshot.Principal.ID || s.scope.TenantID != snapshot.Principal.TenantID || s.scope.ResourceID != "i" {
		t.Fatal("package repository did not receive trusted company and explicit Agent scope", w.Code)
	}
}
