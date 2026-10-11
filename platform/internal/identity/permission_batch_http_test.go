package identity

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type permissionBatchHTTPStore struct {
	*permissionHTTPStore
	reads, writes int
	actor         sharedkernel.Scope
}

func (s *permissionBatchHTTPStore) PreviewPermissionBatch(_ context.Context, actor sharedkernel.Scope, _ PermissionBatchCommand) (PermissionBatchPlan, error) {
	s.reads++
	s.actor = actor
	return PermissionBatchPlan{}, nil
}
func (s *permissionBatchHTTPStore) CreatePermissionBatch(_ context.Context, actor sharedkernel.Scope, _ PermissionBatchCommand) (PermissionBatch, error) {
	s.writes++
	s.actor = actor
	return PermissionBatch{}, nil
}
func (s *permissionBatchHTTPStore) GetPermissionBatch(_ context.Context, actor sharedkernel.Scope, _ string) (PermissionBatch, error) {
	s.reads++
	s.actor = actor
	return PermissionBatch{}, sql.ErrNoRows
}
func (s *permissionBatchHTTPStore) ContinuePermissionBatch(_ context.Context, actor sharedkernel.Scope, _ string) (PermissionBatch, error) {
	s.writes++
	s.actor = actor
	return PermissionBatch{}, nil
}
func (s *permissionBatchHTTPStore) CancelPermissionBatch(_ context.Context, actor sharedkernel.Scope, _ string) (PermissionBatch, error) {
	s.writes++
	s.actor = actor
	return PermissionBatch{}, nil
}

func TestPermissionBatchHTTPTrustedActorStrictCommandsAndReadOnlyRecovery(t *testing.T) {
	snapshot, _ := permissionFixture()
	s := &permissionBatchHTTPStore{permissionHTTPStore: &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal}, snapshot: snapshot}}
	handler := NewModule(s, "fixture-internal-token").Handler()
	call := func(method, path, body string, authenticated, browser bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
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
	for _, path := range []string{"/permission-batches:preview", "/permission-batches", "/permission-batches/original-key:continue", "/permission-batches/original-key:cancel"} {
		if w := call("POST", path, `{}`, false, true); w.Code != http.StatusUnauthorized {
			t.Fatal("unauthenticated batch operation", path, w.Code)
		}
		if w := call("POST", path, `{}`, true, false); w.Code != http.StatusForbidden {
			t.Fatal("internal service authentication implied a human administrator", path, w.Code)
		}
		if w := call("POST", path, `{"actor_id":"untrusted"}`, true, true); w.Code != http.StatusBadRequest {
			t.Fatal("client could replace batch actor", path, w.Code)
		}
	}
	if w := call("POST", "/permission-batches", `{"items":[{"authorization":{"step_up_token":"must-not-be-stored"}}]}`, true, true); w.Code != http.StatusBadRequest {
		t.Fatal("secret could be persisted in a batch command", w.Code)
	}
	if s.reads != 0 || s.writes != 0 {
		t.Fatal("invalid or untrusted commands reached the batch service")
	}
	if w := call("GET", "/permission-batches/original-key", "", true, true); w.Code != http.StatusNotFound || s.reads != 1 || s.writes != 0 {
		t.Fatal("unknown result lookup mutated or disguised missing batch", w.Code)
	}
	if s.actor.PrincipalID != snapshot.Principal.ID || s.actor.TenantID != snapshot.Principal.TenantID {
		t.Fatal("batch service did not receive trusted caller scope")
	}
	for _, path := range []string{"/permission-batches/original-key:continue", "/permission-batches/original-key:cancel"} {
		if w := call("GET", path, "", true, true); w.Code != http.StatusMethodNotAllowed {
			t.Fatal("read verb could execute batch mutation", path, w.Code)
		}
	}
	if w := call("POST", "/permission-batches/original-key:continue", `{}`, true, true); w.Code != http.StatusOK || s.writes != 1 {
		t.Fatal("explicit original-key continuation unavailable", w.Code)
	}
}
