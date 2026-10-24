package execution

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type browserCancelConflictStore struct {
	*platformruntime.Store
	conflicts, calls int
	onConflict       func()
	failure          error
}

func (s *browserCancelConflictStore) BeginCancellation(id string, revision uint64) (platformruntime.Run, error) {
	s.calls++
	if s.failure != nil {
		return platformruntime.Run{}, s.failure
	}
	if s.conflicts > 0 {
		s.conflicts--
		if s.onConflict != nil {
			s.onConflict()
		}
		return platformruntime.Run{}, platformruntime.ErrRevisionConflict
	}
	return s.Store.BeginCancellation(id, revision)
}

func TestBrowserCancellationRevisionRaceIsBoundedAndRechecksAuthority(t *testing.T) {
	for _, tc := range []struct {
		name          string
		conflicts     int
		revoke        bool
		failure       error
		status, calls int
	}{
		{name: "claim race", conflicts: 1, status: http.StatusAccepted, calls: 2},
		{name: "revoked between reads", conflicts: 1, revoke: true, status: http.StatusForbidden, calls: 1},
		{name: "bounded conflict", conflicts: 10, status: http.StatusConflict, calls: 3},
		{name: "storage failure is not retried", failure: errors.New("injected storage error"), status: http.StatusInternalServerError, calls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, scope := newWaitingQARun(t)
			store := &browserCancelConflictStore{Store: m.store.(*platformruntime.Store), conflicts: tc.conflicts, failure: tc.failure}
			m.store = store
			revoked := false
			store.onConflict = func() { revoked = tc.revoke }
			m.SetBrowserRunAuthorizer(func(_ context.Context, owner sharedkernel.Scope, actor BrowserRunActor, action string) error {
				if revoked || owner.PrincipalID != scope.PrincipalID || actor.Scope.PrincipalID != scope.PrincipalID || action != "cancel" {
					return ErrRunPermissionDenied
				}
				return nil
			})
			r := httptest.NewRequest(http.MethodPost, "/platform/runs/"+scope.RunID+"/cancel", nil)
			for key, value := range map[string]string{"X-Internal-Token": "secret", "X-Browser-Module": "1", "X-Tenant-ID": scope.TenantID, "X-Department-ID": scope.DepartmentID, "X-Application-ID": scope.ApplicationID, "X-Principal-Type": "user", "X-Principal-ID": scope.PrincipalID, "X-Authentication-Session": "fixture-signed-session", "X-Authentication-Revision": "7"} {
				r.Header.Set(key, value)
			}
			w := httptest.NewRecorder()
			m.Handler().ServeHTTP(w, r)
			if w.Code != tc.status || store.calls != tc.calls {
				t.Fatalf("status=%d calls=%d want=%d/%d body=%s", w.Code, store.calls, tc.status, tc.calls, w.Body.String())
			}
			run, err := store.Get(scope.RunID)
			if err != nil {
				t.Fatal(err)
			}
			if tc.status == http.StatusAccepted {
				if run.Status != platformruntime.StatusCancelling {
					t.Fatal("cancel intent not persisted", run.Status)
				}
			} else if run.Status != platformruntime.StatusWaiting {
				t.Fatal("failed/revoked cancellation changed run", run.Status)
			}
		})
	}
}
