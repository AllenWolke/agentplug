package execution

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// The terminal fence must share the transaction that commits the terminal
// state, so a denied settlement cannot publish an outcome or release FIFO.
// PostgreSQL is explicitly configured through an isolated test DSN.
func TestSQLTerminalOutcomeFenceIsAtomicAndRunLocked(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store, err := openMigratedSQLFixture(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal("open isolated SQL fixture:", err)
	}
	defer store.Close()
	probeDB, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("open isolated lock probe:", err)
	}
	defer probeDB.Close()

	cleanupRun := func(testingT *testing.T, runID string, scope sharedkernel.Scope) {
		testingT.Helper()
		tx, err := store.db.BeginTx(context.Background(), nil)
		if err != nil {
			testingT.Errorf("begin fixture cleanup for %s: %v", runID, err)
			return
		}
		for _, statement := range []string{
			`DELETE FROM platform_execution_session_lease WHERE session_key=? AND run_id=?`,
			`DELETE FROM platform_execution_event WHERE run_id=?`,
			`DELETE FROM platform_execution_outcome WHERE run_id=?`,
			`DELETE FROM platform_execution_creation_projection WHERE run_id=?`,
			`DELETE FROM platform_execution_dispatch_command WHERE run_id=?`,
			`DELETE FROM platform_execution_run WHERE run_id=?`,
		} {
			args := []any{runID}
			if statement == `DELETE FROM platform_execution_session_lease WHERE session_key=? AND run_id=?` {
				args = []any{platformruntime.SessionExecutionKey(scope), runID}
			}
			if _, err := tx.ExecContext(context.Background(), sqlutil.Bind(statement), args...); err != nil {
				_ = tx.Rollback()
				testingT.Errorf("clean fixture run %s: %v", runID, err)
				return
			}
		}
		if err := tx.Commit(); err != nil {
			testingT.Errorf("commit fixture cleanup for %s: %v", runID, err)
		}
	}

	newRunningRun := func(testingT *testing.T, id string) platformruntime.Run {
		testingT.Helper()
		scope := testScope(id).domain()
		scope.SessionID = id
		created, err := store.Create(platformruntime.CreateRequest{
			ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID,
			IdempotencyKey: id, Fingerprint: "terminal-outcome-fence", MessageID: "message-" + id,
		})
		if err != nil {
			testingT.Fatal("create fixture run:", err)
		}
		testingT.Cleanup(func() { cleanupRun(testingT, id, scope) })
		claimed, err := store.AcquireLease(id, "terminal-fence-owner", time.Now().UTC(), time.Minute)
		if err != nil {
			testingT.Fatal("claim fixture run:", err)
		}
		running, err := store.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
		if err != nil {
			testingT.Fatal("start fixture run:", err)
		}
		if created.Run.ID != running.ID {
			testingT.Fatal("fixture run identity changed")
		}
		return running
	}

	assertFenceScopeAndLock := func(want sharedkernel.Scope, wantRevision uint64) func(context.Context, *sql.Tx, sharedkernel.Scope) error {
		return func(callbackCtx context.Context, tx *sql.Tx, got sharedkernel.Scope) error {
			if got != want {
				return fmt.Errorf("fence scope mismatch: got run %q, want %q", got.RunID, want.RunID)
			}
			var status string
			var revision uint64
			if err := tx.QueryRowContext(callbackCtx, sqlutil.Bind(`SELECT status,revision FROM platform_execution_run WHERE run_id=?`), want.RunID).Scan(&status, &revision); err != nil {
				return fmt.Errorf("read run through fence transaction: %w", err)
			}
			if status != string(platformruntime.StatusRunning) || revision != wantRevision {
				return fmt.Errorf("fence did not observe current running row: status=%q revision=%d", status, revision)
			}

			// A second pool must fail immediately while the callback's transaction
			// holds the execution-row lock. This proves the callback is inside the
			// terminal transaction rather than running as a racy pre-check.
			var lockedID string
			err := probeDB.QueryRowContext(callbackCtx, sqlutil.Bind(`SELECT run_id FROM platform_execution_run WHERE run_id=? FOR UPDATE NOWAIT`), want.RunID).Scan(&lockedID)
			var state interface{ SQLState() string }
			if !errors.As(err, &state) || state.SQLState() != "55P03" {
				return fmt.Errorf("terminal callback did not hold the run row lock (NOWAIT result %v)", err)
			}
			return nil
		}
	}

	assertDeniedRollback := func(run platformruntime.Run) {
		t.Helper()
		stored, err := store.Get(run.ID)
		if err != nil || stored.Status != platformruntime.StatusRunning || stored.Revision != run.Revision || stored.LeaseToken != run.LeaseToken {
			t.Fatalf("denied terminal result changed run: got=%+v err=%v want running revision %d", stored, err, run.Revision)
		}
		if _, err := store.GetOutcome(run.ID); !errors.Is(err, platformruntime.ErrRunNotFound) {
			t.Fatalf("denied terminal result left an outcome: %v", err)
		}
		events, err := store.Events(run.ID, 0)
		if err != nil || len(events) != 2 || events[0].Type != "accepted" || events[1].Type != "status" {
			t.Fatalf("denied terminal result appended events: %+v err=%v", events, err)
		}
		var sessionRun, sessionToken string
		var sessionUntil sql.NullTime
		if err := store.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id,lease_token,lease_until FROM platform_execution_session_lease WHERE session_key=?`), platformruntime.SessionExecutionKey(run.Scope)).Scan(&sessionRun, &sessionToken, &sessionUntil); err != nil {
			t.Fatalf("denied terminal result released the session: %v", err)
		}
		if sessionRun != run.ID || sessionToken != run.LeaseToken || !sessionUntil.Valid || !sessionUntil.Time.After(time.Now().UTC()) {
			t.Fatalf("denied terminal result changed session lease: run=%q token-match=%v until=%v", sessionRun, sessionToken == run.LeaseToken, sessionUntil)
		}
	}

	for _, target := range []platformruntime.Status{platformruntime.StatusSucceeded, platformruntime.StatusFailed} {
		t.Run(string(target), func(t *testing.T) {
			id := fmt.Sprintf("sql-terminal-fence-%s-%d", target, time.Now().UnixNano())
			running := newRunningRun(t, id)
			denied := errors.New("injected unsettled side effect")
			store.SetTerminalOutcomeFence(func(callbackCtx context.Context, tx *sql.Tx, got sharedkernel.Scope) error {
				if err := assertFenceScopeAndLock(running.Scope, running.Revision)(callbackCtx, tx, got); err != nil {
					return err
				}
				return denied
			})
			if _, err := store.FinalizeLeased(running.ID, target, running.Revision, running.LeaseToken, map[string]any{"result": "terminal"}, nil); !errors.Is(err, ErrExecutionOutcomeUnconfirmed) || !errors.Is(err, denied) {
				t.Fatalf("unsettled %s was not fenced: %v", target, err)
			}
			assertDeniedRollback(running)

			store.SetTerminalOutcomeFence(assertFenceScopeAndLock(running.Scope, running.Revision))
			final, err := store.FinalizeLeased(running.ID, target, running.Revision, running.LeaseToken, map[string]any{"result": "terminal"}, map[string]any{"fixture": true})
			if err != nil {
				t.Fatalf("settled %s did not finalize: %v", target, err)
			}
			if final.Status != target || final.Revision != running.Revision+1 {
				t.Fatalf("unexpected terminal run: %+v", final)
			}
			if final.LeaseToken != "" || !final.LeaseUntil.IsZero() {
				t.Fatalf("settled %s retained its returned execution lease", target)
			}
			var leasePresent bool
			var leaseUntil sql.NullTime
			if err := store.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT lease_token<>'',lease_until FROM platform_execution_run WHERE run_id=?`), running.ID).Scan(&leasePresent, &leaseUntil); err != nil || leasePresent || leaseUntil.Valid {
				t.Fatalf("settled %s retained its durable execution lease: token-present=%t until-present=%t err=%v", target, leasePresent, leaseUntil.Valid, err)
			}
			if _, err := store.GetOutcome(running.ID); err != nil {
				t.Fatalf("settled %s did not persist outcome: %v", target, err)
			}
			finalEvents, err := store.Events(running.ID, 0)
			if err != nil || len(finalEvents) != 4 {
				t.Fatalf("settled %s did not atomically persist terminal events: count=%d err=%v", target, len(finalEvents), err)
			}
			var sessionCount int
			if err := store.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_execution_session_lease WHERE session_key=? AND run_id=?`), platformruntime.SessionExecutionKey(running.Scope), running.ID).Scan(&sessionCount); err != nil || sessionCount != 0 {
				t.Fatalf("settled %s did not release FIFO session: count=%d err=%v", target, sessionCount, err)
			}
		})
	}
}
