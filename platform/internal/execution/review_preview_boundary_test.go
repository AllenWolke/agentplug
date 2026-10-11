package execution

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestReviewPreviewRejectsUndeclaredOrUnboundedContent(t *testing.T) {
	for _, preview := range []map[string]any{
		nil,
		{"schema_version": "agent-review/v0", "title": "draft", "summary": "private draft"},
		{"schema_version": "agent-review/v1", "title": "draft", "summary": strings.Repeat("x", 10001)},
		{"schema_version": "agent-review/v1", "title": "draft", "summary": "private draft", "references": []map[string]string{{"doc_id": strings.Repeat("x", 257)}}},
	} {
		m, scope := newWaitingReviewRun(t, "independent-business-agent")
		m.SetReviewAuthorizer(func(context.Context, sharedkernel.Scope, string) error { return nil })
		if _, err := m.store.PrepareResume(scope.RunID, []byte(`{"decision":"request_changes"}`)); err != nil {
			t.Fatal(err)
		}
		lease, err := m.store.AcquireLease(scope.RunID, "preview-boundary-lease", time.Now().UTC(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		output := map[string]any{"stage": "waiting_review", "answer": "private draft", "private_token": "must-never-leak"}
		if preview != nil {
			output["review"] = preview
		}
		if _, err := m.store.FinalizeLeased(scope.RunID, platformruntime.StatusWaiting, lease.Revision, lease.LeaseToken, output, nil); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "/platform/runs/"+scope.RunID+"/review", nil)
		for k, v := range map[string]string{"X-Internal-Token": "secret", "X-Browser-Module": "1", "X-Tenant-ID": scope.TenantID,
			"X-Department-ID": scope.DepartmentID, "X-Application-ID": scope.ApplicationID, "X-Principal-Type": "user", "X-Principal-ID": "reviewer"} {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "private draft") || strings.Contains(w.Body.String(), "must-never-leak") {
			t.Fatalf("invalid review preview crossed boundary: %d %s", w.Code, w.Body.String())
		}
	}
}
