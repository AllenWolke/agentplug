package execution

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLCancellationScanRotatesPastBlockedRunsPostgres(t *testing.T) {
	f := newCancellationFixture(t)
	const blocked = 33
	freshID := f.id + "-scan-zz"
	f.runs.SetTerminalOutcomeFence(func(_ context.Context, _ *sql.Tx, scope sharedkernel.Scope) error {
		if scope.RunID != freshID {
			return ErrExecutionOutcomeUnconfirmed
		}
		return nil
	})
	for n := 0; n <= blocked; n++ {
		id := fmt.Sprintf("%s-scan-%02d", f.id, n)
		if n == blocked {
			id = freshID
		}
		scope := testScope(id).domain()
		scope.SessionID = id
		created, err := f.runs.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: id})
		if err != nil {
			t.Fatal(err)
		}
		revision := created.Run.Revision
		if n < blocked {
			claimed, err := f.runs.AcquireLease(id, "blocked-generation", time.Now(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			running, err := f.runs.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
			if err != nil {
				t.Fatal(err)
			}
			revision = running.Revision
		}
		if _, err := f.runs.BeginCancellation(id, revision); err != nil {
			t.Fatal(err)
		}
	}
	d := NewDispatcher(f.runs, "owned", 1)
	// The fixture database may contain other projects' retained unresolved
	// cases. Traverse the real queue, including those rows, without assuming
	// this test owns every pending cancellation in the database.
	for n := 0; n < 32; n++ {
		d.reconcileCancellations(f.ctx)
		fresh, err := f.runs.Get(freshID)
		if err == nil && fresh.Status == platformruntime.StatusCancelled && d.cancellationCursor == "" {
			break
		}
	}
	fresh, err := f.runs.Get(freshID)
	if err != nil || fresh.Status != platformruntime.StatusCancelled {
		t.Fatal("new cancellation starved behind unresolved history", err)
	}
	for n := 0; n < blocked; n++ {
		id := fmt.Sprintf("%s-scan-%02d", f.id, n)
		run, err := f.runs.Get(id)
		if err != nil || run.Status != platformruntime.StatusCancelling || run.LeaseToken == "" {
			t.Fatal("fair scanning altered unconfirmed history", err)
		}
	}
	if d.cancellationCursor != "" {
		t.Fatal("cursor did not wrap after the exhausted final page")
	}
}
