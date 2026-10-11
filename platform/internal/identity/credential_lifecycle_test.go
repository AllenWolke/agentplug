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

type credentialChangeStore struct {
	Store
	currentPassword string
	revision        uint64
	changed         int
}

func (s *credentialChangeStore) ChangeOwnPassword(_ context.Context, scope sharedkernel.Scope, currentPassword, newPasswordHash string) (uint64, error) {
	if scope.PrincipalID == "" || scope.PrincipalType != string(PrincipalUser) || currentPassword != s.currentPassword {
		return 0, ErrCurrentPasswordInvalid
	}
	s.currentPassword = newPasswordHash
	s.revision++
	s.changed++
	return s.revision, nil
}

func TestBrowserCanChangeOnlyItsOwnLocalPassword(t *testing.T) {
	principal := Principal{Type: PrincipalUser, ID: "alice", TenantID: "tenant-a", Roles: []string{"operator"}, IsActive: true, Revision: 1}
	base := &memoryStore{principal: principal}
	store := &credentialChangeStore{Store: base, currentPassword: "current-password", revision: 4}
	handler := NewModule(store, "identity-token").Handler()
	call := func(browser bool, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/credentials:change-password", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if browser {
			setBrowserIdentityHeaders(req, principal, "department-a", "application-a")
		} else {
			req.Header.Set("X-Internal-Token", "identity-token")
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder
	}

	if got := call(false, `{"current_password":"current-password","new_password":"next-password-123"}`); got.Code != http.StatusForbidden {
		t.Fatalf("service identity must not use self-service password endpoint: status=%d body=%s", got.Code, got.Body.String())
	}
	if got := call(true, `{"current_password":"wrong-password","new_password":"next-password-123"}`); got.Code != http.StatusUnauthorized || store.changed != 0 {
		t.Fatalf("wrong current password must be rejected without mutation: status=%d changed=%d body=%s", got.Code, store.changed, got.Body.String())
	}
	if got := call(true, `{"current_password":"current-password","new_password":"short"}`); got.Code != http.StatusBadRequest || store.changed != 0 {
		t.Fatalf("weak password must be rejected before storage: status=%d changed=%d body=%s", got.Code, store.changed, got.Body.String())
	}
	updated := call(true, `{"current_password":"current-password","new_password":"next-password-123"}`)
	if updated.Code != http.StatusOK || store.changed != 1 || !strings.Contains(updated.Body.String(), `"auth_revision":5`) || !strings.Contains(updated.Body.String(), `"reauthentication_required":true`) {
		t.Fatalf("valid own-password change did not require fresh authentication: status=%d changed=%d body=%s", updated.Code, store.changed, updated.Body.String())
	}
	if strings.Contains(updated.Body.String(), "next-password-123") || strings.Contains(updated.Body.String(), "current-password") {
		t.Fatal("password change response leaked a password")
	}
}

func TestSQLStorePasswordChangeFailsClosedWithoutAtomicRecorder(t *testing.T) {
	var store *SQLStore
	_, err := store.ChangeOwnPassword(context.Background(), sharedkernel.Scope{}, "old", "new-hash")
	if !errors.Is(err, ErrInvalidPrincipal) {
		t.Fatalf("invalid scope/store should fail before persistence, got %v", err)
	}
}
