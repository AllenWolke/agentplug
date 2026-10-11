package identity

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

type permissionHTTPStore struct {
	*memoryStore
	snapshot PermissionSnapshot
	failure  error
	previews int
}

func (s *permissionHTTPStore) PermissionSnapshot(_ context.Context, _ PrincipalType, id string) (PermissionSnapshot, error) {
	if s.failure != nil {
		return PermissionSnapshot{}, s.failure
	}
	if id != s.snapshot.Principal.ID {
		return PermissionSnapshot{}, ErrPrincipalNotFound
	}
	return s.snapshot, nil
}
func (s *permissionHTTPStore) ResolvePermission(ctx context.Context, kind PrincipalType, id string, q PermissionQuery) (PermissionDecision, error) {
	p, err := s.PermissionSnapshot(ctx, kind, id)
	if err != nil {
		return PermissionDecision{}, err
	}
	q.Now = time.Now().UTC()
	return EvaluatePermission(p, q)
}
func (s *permissionHTTPStore) PreviewAuthorizationChange(_ context.Context, _ sharedkernel.Scope, _ AuthorizationChangeCommand) (AuthorizationChangePlan, error) {
	s.previews++
	return AuthorizationChangePlan{}, ErrPermissionDenied
}
func (s *permissionHTTPStore) CommitAuthorizationChange(_ context.Context, _ sharedkernel.Scope, _ AuthorizationChangeCommand) (AuthorizationChangeReceipt, error) {
	return AuthorizationChangeReceipt{}, ErrPermissionDenied
}

func TestPermissionHTTPRequiresTrustedActorAndRejectsObjectClaims(t *testing.T) {
	snapshot, _ := permissionFixture()
	store := &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal}, snapshot: snapshot}
	handler := NewModule(store, "private-token").Handler()
	call := func(path, body string, authenticated, browser bool) *httptest.ResponseRecorder {
		method := http.MethodGet
		if body != "" {
			method = http.MethodPost
		}
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if browser {
			setBrowserIdentityHeaders(r, store.principal, "d", "a")
		}
		r.Header.Del("Authorization")
		r.Header.Del("X-Internal-Token")
		if authenticated {
			r.Header.Set("X-Internal-Token", "private-token")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := call("/me/permissions", "", false, true); w.Code != http.StatusUnauthorized {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("/me/permissions", "", true, false); w.Code != http.StatusForbidden {
		t.Fatal("service token implied human permissions", w.Code, w.Body.String())
	}
	if w := call("/me/workspaces", "", true, true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"application_id":"a"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("/permissions:explain", `{"action":"run","scope":{"scope_type":"application","tenant_id":"t","department_id":"d","application_id":"a"},"resource_type":"agent_installation","resource_id":"i","object":{"owner_id":"u"}}`, true, true); w.Code != http.StatusBadRequest {
		t.Fatal("client supplied ownership accepted", w.Code, w.Body.String())
	}
	if w := call("/principals/other/access-profile", "", true, true); w.Code != http.StatusForbidden {
		t.Fatal("operator queried another account", w.Code, w.Body.String())
	}
	if w := call("/authorization-changes:preview", `{"subject_id":"u","unexpected":true}`, true, true); w.Code != http.StatusBadRequest || store.previews != 0 {
		t.Fatal("unknown command reached planner", w.Code, store.previews)
	}
	store.failure = errors.New("database unavailable")
	if w := call("/me/permissions", "", true, true); w.Code < 500 {
		t.Fatal("storage failure did not fail closed", w.Code, w.Body.String())
	}
}

func TestV2AccessDoesNotFallbackToLegacyAllow(t *testing.T) {
	snapshot, q := permissionFixture()
	snapshot.Bindings = nil
	legacy := snapshot.Grants[0]
	legacy.ResourceType = ""
	legacy.ResourceID = ""
	store := &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal, grants: []Grant{legacy}}, snapshot: snapshot}
	scope := sharedkernel.Scope{TenantID: q.Scope.TenantID, DepartmentID: q.Scope.DepartmentID, ApplicationID: q.Scope.ApplicationID, AgentInstanceID: q.ResourceID}
	decision, err := CheckPrincipalAccess(context.Background(), store, scope, PrincipalUser, "u", "run")
	if err != nil || decision.Allowed || decision.Reason != "ROLE_REQUIRED" {
		t.Fatal("legacy allow bypassed v2", decision, err)
	}
	store.failure = errors.New("database unavailable")
	if decision, err := CheckPrincipalAccess(context.Background(), store, scope, PrincipalUser, "u", "run"); err == nil || decision.Allowed {
		t.Fatal("failure fell back to legacy", decision, err)
	}
}

func TestUnknownPolicyModeCannotFallbackToLegacyAllow(t *testing.T) {
	snapshot, q := permissionFixture()
	legacy := snapshot.Grants[0]
	legacy.ResourceType, legacy.ResourceID = "", ""
	store := &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal, grants: []Grant{legacy}}, snapshot: snapshot}
	scope := sharedkernel.Scope{TenantID: q.Scope.TenantID, DepartmentID: q.Scope.DepartmentID, ApplicationID: q.Scope.ApplicationID, AgentInstanceID: q.ResourceID}
	for _, mode := range []string{"", "V2", "invalid"} {
		store.snapshot.Mode = mode
		decision, err := CheckPrincipalAccess(context.Background(), store, scope, PrincipalUser, "u", "run")
		if !errors.Is(err, ErrInvalidResource) || decision.Allowed {
			t.Fatalf("unknown mode %q used old permission: decision=%+v error=%v", mode, decision, err)
		}
	}
	for _, mode := range []string{"legacy", "shadow"} {
		store.snapshot.Mode = mode
		decision, err := CheckPrincipalAccess(context.Background(), store, scope, PrincipalUser, "u", "run")
		if err != nil || !decision.Allowed {
			t.Fatalf("explicit compatibility mode %q rejected: decision=%+v error=%v", mode, decision, err)
		}
	}
}

func TestV2OldAccessRequestEndpointCannotCreateOrListOrphans(t *testing.T) {
	snapshot, _ := permissionFixture()
	store := &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal}, snapshot: snapshot}
	handler := NewModule(store, "private-token").Handler()
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		r := httptest.NewRequest(method, "/access-requests", strings.NewReader(`{"agent_instance_id":"i","actions":["run"],"reason":"request operation access"}`))
		setBrowserIdentityHeaders(r, snapshot.Principal, "d", "a")
		r.Header.Set("Authorization", "Bearer private-token")
		r.Header.Set("X-Internal-Token", "private-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "USE_VERSIONED_PERMISSION_REQUESTS") || len(store.agentAccessRequests) != 0 {
			t.Fatal("old request endpoint accepted v2 caller", method, w.Code, w.Body.String())
		}
	}
}
