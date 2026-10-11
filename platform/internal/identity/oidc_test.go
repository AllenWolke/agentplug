package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type oidcTestStore struct {
	Store
	active bool
}

func (s oidcTestStore) ResolveOIDC(_ context.Context, issuer, subject string) (OIDCIdentity, error) {
	if !s.active || issuer != "https://idp.example.com/realm" || subject != "subject" {
		return OIDCIdentity{}, ErrOIDCBindingNotFound
	}
	return OIDCIdentity{Username: "user", TenantID: "tenant", DepartmentID: "department", ApplicationID: "app", Roles: []string{"operator"}}, nil
}

func TestResolveOIDCRequiresInternalTokenAndActiveBinding(t *testing.T) {
	store := &oidcTestStore{active: true}
	module := NewModule(store, "server-owned-token")
	check := func(token, body string) int {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/internal/oidc/resolve", strings.NewReader(body))
		r.Header.Set("X-Internal-Token", token)
		w := httptest.NewRecorder()
		module.Handler().ServeHTTP(w, r)
		return w.Code
	}
	body := `{"issuer":"https://idp.example.com/realm","subject":"subject"}`
	if got := check("", body); got != http.StatusUnauthorized {
		t.Fatalf("missing internal token: %d", got)
	}
	if got := check("server-owned-token", body); got != http.StatusOK {
		t.Fatalf("active binding: %d", got)
	}
	store.active = false
	if got := check("server-owned-token", body); got != http.StatusUnauthorized {
		t.Fatalf("revoked binding: %d", got)
	}
	if got := check("server-owned-token", `{"issuer":"http://idp.example.com","subject":"subject"}`); got != http.StatusBadRequest {
		t.Fatalf("insecure issuer: %d", got)
	}
}

type oidcManagerTestStore struct {
	*memoryStore
	binding  OIDCBinding
	disabled bool
}

func (s *oidcManagerTestStore) CreateOIDCBinding(_ context.Context, _ sharedkernel.Scope, binding OIDCBinding) error {
	s.binding = binding
	return nil
}

func (s *oidcManagerTestStore) DisableOIDCBinding(_ context.Context, _ sharedkernel.Scope, binding OIDCBinding, revision uint64) error {
	if binding.TenantID != s.binding.TenantID || revision != 1 {
		return ErrIdentityConflict
	}
	s.disabled = true
	return nil
}

func TestOIDCBindingManagementHonorsBrowserRoleAndTenant(t *testing.T) {
	admin := Principal{Type: PrincipalUser, ID: "tenant-admin", TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true}
	store := &oidcManagerTestStore{memoryStore: &memoryStore{
		principal: admin,
		principals: []Principal{
			{Type: PrincipalUser, ID: "employee", TenantID: "tenant-a", Roles: []string{"operator"}, IsActive: true},
			{Type: PrincipalUser, ID: "global-admin", TenantID: "tenant-a", Roles: []string{"admin"}, IsActive: true},
		},
	}}
	handler := NewModule(store, "identity-token").Handler()
	call := func(path, body string, actor Principal) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		setBrowserIdentityHeaders(req, actor, "dept-a", "app-a")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out.Code
	}
	create := `{"issuer":"https://idp.example.com/realm","subject":"subject","principal_id":"employee","tenant_id":"tenant-a","department_id":"dept-a","application_id":"app-a"}`
	if got := call("/oidc-bindings", create, Principal{Type: PrincipalUser, ID: "employee", TenantID: "tenant-a"}); got != http.StatusForbidden {
		t.Fatalf("non-admin created binding: %d", got)
	}
	if got := call("/oidc-bindings", strings.Replace(create, `"tenant-a"`, `"tenant-b"`, 1), admin); got != http.StatusForbidden {
		t.Fatalf("cross-tenant binding: %d", got)
	}
	if got := call("/oidc-bindings", strings.Replace(create, `"employee"`, `"global-admin"`, 1), admin); got != http.StatusForbidden {
		t.Fatalf("tenant admin bound global admin: %d", got)
	}
	if got := call("/oidc-bindings", create, admin); got != http.StatusCreated {
		t.Fatalf("tenant admin binding: %d", got)
	}
	if store.binding.PrincipalID != "employee" || store.binding.TenantID != "tenant-a" {
		t.Fatalf("binding changed: %+v", store.binding)
	}
	disable := `{"issuer":"https://idp.example.com/realm","subject":"subject","tenant_id":"tenant-a","expected_revision":1}`
	if got := call("/oidc-bindings:disable", strings.Replace(disable, `"tenant-a"`, `"tenant-b"`, 1), admin); got != http.StatusForbidden {
		t.Fatalf("cross-tenant revoke: %d", got)
	}
	if got := call("/oidc-bindings:disable", disable, admin); got != http.StatusOK || !store.disabled {
		t.Fatalf("binding revoke: status=%d disabled=%v", got, store.disabled)
	}
}

func TestOIDCBindingWritesFailClosedWithoutAuditRecorder(t *testing.T) {
	s := &SQLStore{}
	actor := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "dept", ApplicationID: "app", PrincipalType: "user", PrincipalID: "admin"}
	binding := OIDCBinding{Issuer: "https://idp.example.com/realm", Subject: "subject", PrincipalID: "employee", TenantID: "tenant", DepartmentID: "dept", ApplicationID: "app"}
	if err := s.CreateOIDCBinding(context.Background(), actor, binding); !errors.Is(err, ErrOIDCBindingRecorderUnavailable) {
		t.Fatalf("creation without audit recorder: %v", err)
	}
	if err := s.DisableOIDCBinding(context.Background(), actor, binding, 1); !errors.Is(err, ErrOIDCBindingRecorderUnavailable) {
		t.Fatalf("revocation without audit recorder: %v", err)
	}
}
