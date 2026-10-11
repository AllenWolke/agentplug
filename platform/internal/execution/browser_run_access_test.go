package execution

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// Existing streaming fixtures explicitly authorize their owner; IAM itself is
// covered by composition and real SQL tests, not inferred from these fixtures.
func allowFixtureOwnedRunAccess(m *Module) {
	m.SetBrowserRunAuthorizer(func(_ context.Context, owner sharedkernel.Scope, actor BrowserRunActor, action string) error {
		if owner.PrincipalID != actor.Scope.PrincipalID || owner.PrincipalType != actor.Scope.PrincipalType || action != "history.read" && action != "cancel" {
			return ErrRunPermissionDenied
		}
		return nil
	})
}

func TestBrowserRunHistoryAndCancelHaveIndependentPermissions(t *testing.T) {
	m, scope := newWaitingQARun(t)
	read, cancelAllowed := true, false
	m.SetBrowserRunAuthorizer(func(_ context.Context, owner sharedkernel.Scope, actor BrowserRunActor, action string) error {
		if owner != scope || actor.Scope.PrincipalID != scope.PrincipalID || actor.AuthenticationSession != "fixture-signed-session" || actor.AuthenticationRevision != 7 {
			return ErrRunPermissionDenied
		}
		if action == "history.read" && read || action == "cancel" && cancelAllowed {
			return nil
		}
		return ErrRunPermissionDenied
	})
	call := func(method, suffix string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/platform/runs/"+scope.RunID+suffix, nil)
		for key, value := range map[string]string{"X-Internal-Token": "secret", "X-Browser-Module": "1", "X-Tenant-ID": scope.TenantID, "X-Department-ID": scope.DepartmentID, "X-Application-ID": scope.ApplicationID, "X-Principal-Type": "user", "X-Principal-ID": scope.PrincipalID, "X-Authentication-Session": "fixture-signed-session", "X-Authentication-Revision": "7"} {
			r.Header.Set(key, value)
		}
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		return w
	}
	if w := call(http.MethodGet, ""); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call(http.MethodGet, "/events"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "event: waiting") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call(http.MethodPost, "/cancel"); w.Code != http.StatusForbidden {
		t.Fatal("read implied cancel", w.Code, w.Body.String())
	}
	if run, err := m.store.Get(scope.RunID); err != nil || run.Status != platformruntime.StatusWaiting {
		t.Fatal("denied cancellation changed Run", run, err)
	}
	read, cancelAllowed = false, true
	if w := call(http.MethodGet, ""); w.Code != http.StatusForbidden {
		t.Fatal("cancel implied history read", w.Code, w.Body.String())
	}
	if w := call(http.MethodPost, "/cancel"); w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"status":"cancelling"`) {
		t.Fatal("explicit cancellation failed", w.Code, w.Body.String())
	}
	cancelAllowed = false
	if w := call(http.MethodPost, "/cancel"); w.Code != http.StatusForbidden {
		t.Fatal("revoked cancel replay accepted", w.Code, w.Body.String())
	}
	m.SetBrowserRunAuthorizer(func(context.Context, sharedkernel.Scope, BrowserRunActor, string) error {
		return ErrBrowserSessionInvalid
	})
	if w := call(http.MethodGet, ""); w.Code != http.StatusUnauthorized || w.Header().Get("X-Authentication-Error") != "access_token_invalid" {
		t.Fatal("invalid session misclassified", w.Code, w.Body.String())
	}
	m.SetBrowserRunAuthorizer(func(context.Context, sharedkernel.Scope, BrowserRunActor, string) error {
		return errors.New("private SQL failure")
	})
	if w := call(http.MethodGet, ""); w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "private SQL") {
		t.Fatal("authority failure leaked or allowed", w.Code, w.Body.String())
	}
}

func TestBrowserCannotUseRuntimeMutationCommands(t *testing.T) {
	m := NewModule("secret")
	for _, path := range []string{"/platform/runs", "/platform/runs/known/transition", "/platform/runs/known/lease", "/platform/runs/known/events"} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		r.Header.Set("X-Internal-Token", "secret")
		r.Header.Set("X-Browser-Module", "1")
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatal("browser used internal runtime write", path, w.Code, w.Body.String())
		}
	}
}

func TestBrowserSSERechecksBeforeEveryEvent(t *testing.T) {
	m, scope := newWaitingQARun(t)
	checks := 0
	m.SetBrowserRunAuthorizer(func(context.Context, sharedkernel.Scope, BrowserRunActor, string) error {
		checks++
		if checks >= 4 {
			return ErrRunPermissionDenied
		}
		return nil
	})
	r := httptest.NewRequest(http.MethodGet, "/platform/runs/"+scope.RunID+"/events", nil)
	for key, value := range map[string]string{"X-Internal-Token": "secret", "X-Browser-Module": "1", "X-Tenant-ID": scope.TenantID, "X-Department-ID": scope.DepartmentID, "X-Application-ID": scope.ApplicationID, "X-Principal-Type": "user", "X-Principal-ID": scope.PrincipalID} {
		r.Header.Set(key, value)
	}
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "event: accepted") || strings.Contains(w.Body.String(), "event: task_started") || !strings.Contains(w.Body.String(), `"code":"PERMISSION_DENIED"`) {
		t.Fatal("revocation did not fence event batch", checks, w.Body.String())
	}
}
