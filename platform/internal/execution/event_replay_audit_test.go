package execution

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

type brokenStreamWriter struct {
	header http.Header
	writes int
}

func (w *brokenStreamWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *brokenStreamWriter) WriteHeader(int) {}
func (w *brokenStreamWriter) Write([]byte) (int, error) {
	w.writes++
	return 0, errors.New("client disconnected")
}
func (w *brokenStreamWriter) Flush() {}

func TestAuditSSEStopsOnCancelledClientAndWriteFailure(t *testing.T) {
	store := platformruntime.NewStore()
	scope := testScope("stream-disconnect")
	if _, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "stream-disconnect-idem", Fingerprint: "fp"}); err != nil {
		t.Fatal(err)
	}
	request := func() *http.Request {
		r := httptest.NewRequest("GET", "/events?after_seq=0", nil)
		r.Header.Set("X-Browser-Module", "1")
		for key, value := range map[string]string{"X-Tenant-ID": scope.TenantID, "X-Department-ID": scope.DepartmentID, "X-Application-ID": scope.ApplicationID, "X-Principal-ID": scope.PrincipalID, "X-Principal-Type": scope.PrincipalType} {
			r.Header.Set(key, value)
		}
		return r
	}
	module := &Module{store: store}
	allowFixtureOwnedRunAccess(module)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	module.eventsSSE(httptest.NewRecorder(), request().WithContext(ctx), scope.RunID)
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("cancelled client kept polling")
	}
	writer := &brokenStreamWriter{}
	start = time.Now()
	module.eventsSSE(writer, request(), scope.RunID)
	if writer.writes != 1 || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("failed stream write was retried or blocked: writes=%d", writer.writes)
	}
}

type failedEventRepository struct{ *platformruntime.Store }

func (s failedEventRepository) Events(string, uint64) ([]platformruntime.Event, error) {
	return nil, errors.New("database unavailable")
}

func TestAuditSSETerminalCursorAndExplicitStoreFailure(t *testing.T) {
	for _, failure := range []bool{false, true} {
		store := platformruntime.NewStore()
		scope := testScope("stream-audit")
		created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "stream-audit-idem", Fingerprint: "fp"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.Cancel(created.Run.ID, created.Run.Revision); err != nil {
			t.Fatal(err)
		}
		var repository Repository = store
		if failure {
			repository = failedEventRepository{store}
		}
		module := &Module{store: repository}
		allowFixtureOwnedRunAccess(module)
		r := httptest.NewRequest("GET", "/events?after_seq=999999", nil)
		r.Header.Set("X-Browser-Module", "1")
		for key, value := range map[string]string{"X-Tenant-ID": scope.TenantID, "X-Department-ID": scope.DepartmentID, "X-Application-ID": scope.ApplicationID, "X-Principal-ID": scope.PrincipalID, "X-Principal-Type": scope.PrincipalType} {
			r.Header.Set(key, value)
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		r = r.WithContext(ctx)
		w := httptest.NewRecorder()
		start := time.Now()
		module.eventsSSE(w, r, scope.RunID)
		cancel()
		if time.Since(start) > 500*time.Millisecond {
			t.Fatal("terminal cursor waited for another event")
		}
		if failure && !strings.Contains(w.Body.String(), `"code":"EVENT_STORE_UNAVAILABLE"`) {
			t.Fatalf("silent stream failure: %s", w.Body.String())
		}
	}
}

func TestAuditEventReplayIsPagedWithoutLosingEvents(t *testing.T) {
	store := platformruntime.NewStore()
	scope := testScope("page-audit")
	_, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "page-audit-idem", Fingerprint: "fp"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 600; i++ {
		if _, err := store.AppendEvent(scope.RunID, "progress", map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	var cursor uint64
	total := 0
	for {
		page, err := store.Events(scope.RunID, cursor)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) > 256 {
			t.Fatal("unbounded replay")
		}
		if len(page) == 0 {
			break
		}
		total += len(page)
		cursor = page[len(page)-1].Seq
	}
	if total != 601 {
		t.Fatalf("events lost: %d", total)
	}
}
