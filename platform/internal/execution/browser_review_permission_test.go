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

func TestBrowserReviewSeparatesContentAndDecisionAndRechecksReplay(t *testing.T) {
	m, scope := newWaitingQARun(t)
	allowContent, allowDecision := true, false
	m.SetReviewPermissionAuthorizer(func(_ context.Context, got sharedkernel.Scope, reviewer, action string) error {
		if got != scope || reviewer != "reviewer" {
			return ErrReviewPermissionDenied
		}
		if action == "business.content.read" && allowContent || action == "business.review" && allowDecision {
			return nil
		}
		return ErrReviewPermissionDenied
	})
	read := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/platform/runs/"+scope.RunID+"/review", nil)
		for key, value := range map[string]string{"X-Internal-Token": "secret", "X-Browser-Module": "1", "X-Tenant-ID": scope.TenantID, "X-Department-ID": scope.DepartmentID, "X-Application-ID": scope.ApplicationID, "X-Principal-Type": "user", "X-Principal-ID": "reviewer"} {
			r.Header.Set(key, value)
		}
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		return w
	}
	if w := read(); w.Code != http.StatusOK {
		t.Fatal("content permission denied", w.Code, w.Body.String())
	}
	decision := `{"decision":"approve"}`
	if w := browserReview(t, m, scope, "reviewer", decision, nil); w.Code != http.StatusForbidden {
		t.Fatal("content read implied approval", w.Code, w.Body.String())
	}
	run, err := m.store.Get(scope.RunID)
	if err != nil || run.Status != platformruntime.StatusWaiting || len(run.ResumeInputJSON) != 0 {
		t.Fatal("denied decision changed Run", run, err)
	}
	allowContent, allowDecision = false, true
	if w := read(); w.Code != http.StatusForbidden {
		t.Fatal("review grant implied draft read", w.Code, w.Body.String())
	}
	if w := browserReview(t, m, scope, "reviewer", decision, nil); w.Code != http.StatusOK {
		t.Fatal("explicit review permission denied", w.Code, w.Body.String())
	}
	allowDecision = false
	if w := browserReview(t, m, scope, "reviewer", decision, nil); w.Code != http.StatusForbidden {
		t.Fatal("revoked permission replayed a committed decision", w.Code, w.Body.String())
	}
	if w := read(); w.Code != http.StatusForbidden {
		t.Fatal("revoked content permission disclosed Run state", w.Code, w.Body.String())
	}
	m.SetReviewPermissionAuthorizer(func(context.Context, sharedkernel.Scope, string, string) error {
		return errors.New("private database outage")
	})
	if w := read(); w.Code != http.StatusServiceUnavailable {
		t.Fatal("IAM failure treated as a role denial", w.Code, w.Body.String())
	}
	if w := browserReview(t, m, scope, "reviewer", decision, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatal("IAM failure allowed decision replay", w.Code, w.Body.String())
	}
}
