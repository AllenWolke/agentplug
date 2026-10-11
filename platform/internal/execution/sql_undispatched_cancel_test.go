package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func undispatchedSQLFixture(t *testing.T) *SQLStore {
	t.Helper()
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL migration fixture required")
	}
	store, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.SetTerminalOutcomeFence(func(context.Context, *sql.Tx, sharedkernel.Scope) error { return nil })
	return store
}

func recordUndispatchedFixtureCommand(t *testing.T, store *SQLStore, run platformruntime.Run) platformruntime.DispatchCommand {
	t.Helper()
	var request contract.ExecuteRequest
	if err := json.Unmarshal(run.RequestJSON, &request); err != nil {
		t.Fatal(err)
	}
	if len(run.ResumeInputJSON) != 0 {
		request.Operation = "resume"
		if err := json.Unmarshal(run.ResumeInputJSON, &request.ResumeInput); err != nil {
			t.Fatal(err)
		}
	}
	hash, err := contract.CanonicalExecuteBodyHash(request)
	if err != nil {
		t.Fatal(err)
	}
	command := platformruntime.DispatchCommand{RunID: run.ID, Revision: run.Revision, Operation: request.Operation, BodyHash: hash, PolicyHash: request.Input["policy_snapshot"].(map[string]any)["content_hash"].(string)}
	return command
}

func newUndispatchedRun(t *testing.T, store *SQLStore, resumed, beforeTransition, sent bool) (platformruntime.Run, platformruntime.DispatchCommand) {
	t.Helper()
	id := fmt.Sprintf("undispatched-%d", time.Now().UnixNano())
	scope := testScope(id)
	scope.SessionID = id
	var request contract.ExecuteRequest
	if err := json.Unmarshal(gatewayRequest(t, scope, "invoke"), &request); err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = id
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(platformruntime.CreateRequest{ID: id, Scope: scope.domain(), AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: id, RequestJSON: raw, AgentEndpoint: "http://agent.example"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := store.AcquireLease(id, "owned-fixture", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !beforeTransition {
		run, err = store.TransitionLeased(id, created.Run.Status, platformruntime.StatusRunning, run.Revision, run.LeaseToken)
		if err != nil {
			t.Fatal(err)
		}
	}
	if resumed {
		command := recordUndispatchedFixtureCommand(t, store, run)
		if err := store.RecordDispatchCommand(command, run.LeaseToken); err != nil {
			t.Fatal(err)
		}
		paused, err := store.FinalizeLeased(id, platformruntime.StatusWaiting, run.Revision, run.LeaseToken, map[string]any{"stage": "review"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PrepareResume(id, []byte(`{"decision":"reject","reviewer_id":"reviewer"}`)); err != nil {
			t.Fatal(err)
		}
		if paused.Revision != 4 {
			t.Fatal("unexpected waiting fixture")
		}
		run, err = store.AcquireLease(id, "owned-resume", time.Now().UTC(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
	}
	command := recordUndispatchedFixtureCommand(t, store, run)
	if sent {
		if err := store.RecordDispatchCommand(command, run.LeaseToken); err != nil {
			t.Fatal(err)
		}
	}
	return run, command
}

func TestSQLUndispatchedCancelClaimAndAtomicOutcome(t *testing.T) {
	store := undispatchedSQLFixture(t)
	for _, mode := range []string{"claimed_accepted", "initial_running", "paused_resume"} {
		t.Run(mode, func(t *testing.T) {
			run, command := newUndispatchedRun(t, store, mode == "paused_resume", mode == "claimed_accepted", false)
			pending, err := store.BeginCancellation(run.ID, run.Revision)
			if err != nil {
				t.Fatal(err)
			}
			for _, changed := range []string{"scope", "lease", "request", "resume", "endpoint", "head"} {
				foreign := pending
				switch changed {
				case "scope":
					foreign.Scope.TenantID = "foreign"
				case "lease":
					foreign.LeaseToken = "wrong"
				case "request":
					foreign.RequestJSON = []byte(`{}`)
				case "resume":
					foreign.ResumeInputJSON = []byte(`{}`)
				case "endpoint":
					foreign.AgentEndpoint = "http://foreign.example"
				case "head":
					foreign.Revision++
				}
				if ok, err := store.TryCancelUndispatched(context.Background(), foreign); ok || !errors.Is(err, platformruntime.ErrRevisionConflict) {
					t.Fatal("foreign snapshot accepted", changed, ok, err)
				}
			}
			if ok, err := store.TryCancelUndispatched(context.Background(), pending); !ok || err != nil {
				t.Fatal("positive claim was not cancelled", ok, err)
			}
			actual, err := store.Get(run.ID)
			if err != nil || actual.Status != platformruntime.StatusCancelled || actual.LeaseToken != "" || actual.Revision != pending.Revision+1 {
				t.Fatal("terminal CAS incomplete", err)
			}
			var outcomes, proofs, events int
			if err := store.db.QueryRow(`SELECT (SELECT count(*) FROM platform_execution_outcome WHERE run_id=$1 AND event_type='task_cancelled'),(SELECT count(*) FROM platform_execution_event WHERE run_id=$1 AND event_type='undispatched_cancel_confirmed'),(SELECT count(*) FROM platform_execution_event WHERE run_id=$1 AND event_type='task_cancelled')`, run.ID).Scan(&outcomes, &proofs, &events); err != nil || outcomes != 1 || proofs != 1 || events != 1 {
				t.Fatal("outcome and proof are not atomic", outcomes, proofs, events, err)
			}
			if err := store.RecordDispatchCommand(command, run.LeaseToken); err == nil {
				t.Fatal("delayed dispatch escaped cancellation fence")
			}
		})
	}
}

func TestSQLUndispatchedCancelRejectsSentOrUnjournalledProjection(t *testing.T) {
	store := undispatchedSQLFixture(t)
	for _, mode := range []string{"sent_initial", "sent_resume", "forged_projection", "legacy_claim", "unknown_settlement"} {
		t.Run(mode, func(t *testing.T) {
			run, command := newUndispatchedRun(t, store, mode == "sent_resume", false, strings.HasPrefix(mode, "sent_"))
			if mode == "forged_projection" {
				if _, err := store.db.Exec(`INSERT INTO platform_execution_dispatch_command(run_id,revision,operation,body_hash,policy_hash) VALUES($1,$2,$3,$4,$5)`, run.ID, command.Revision, command.Operation, command.BodyHash, command.PolicyHash); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "legacy_claim" {
				// A new lease with no positive protocol journal cannot be backfilled.
				if _, err := store.db.Exec(`UPDATE platform_execution_run SET lease_token='legacy-unrecorded' WHERE run_id=$1`, run.ID); err != nil {
					t.Fatal(err)
				}
			}
			pending, err := store.BeginCancellation(run.ID, run.Revision)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unknown_settlement" {
				store.SetTerminalOutcomeFence(func(context.Context, *sql.Tx, sharedkernel.Scope) error { return errors.New("unknown model charge") })
				defer store.SetTerminalOutcomeFence(func(context.Context, *sql.Tx, sharedkernel.Scope) error { return nil })
			}
			ok, err := store.TryCancelUndispatched(context.Background(), pending)
			if ok || (mode != "unknown_settlement" && err != nil) || (mode == "unknown_settlement" && err == nil) {
				t.Fatal("unsafe terminal permission", ok, err)
			}
			actual, _ := store.Get(run.ID)
			if actual.Status != platformruntime.StatusCancelling || actual.Revision != pending.Revision || actual.LeaseToken != pending.LeaseToken {
				t.Fatal("failed proof released live fence")
			}
			var proof int
			if err := store.db.QueryRow(`SELECT count(*) FROM platform_execution_event WHERE run_id=$1 AND event_type='undispatched_cancel_confirmed'`, run.ID).Scan(&proof); err != nil || proof != 0 {
				t.Fatal("failed proof committed audit", proof, err)
			}
		})
	}
}

func TestSQLUndispatchedCancelRacesActualDispatchCommit(t *testing.T) {
	store := undispatchedSQLFixture(t)
	for round := 0; round < 12; round++ {
		run, command := newUndispatchedRun(t, store, true, false, false)
		start := make(chan struct{})
		done := make(chan error, 1)
		go func() { <-start; done <- store.RecordDispatchCommand(command, run.LeaseToken) }()
		close(start)
		pending, err := store.BeginCancellation(run.ID, run.Revision)
		if err != nil {
			t.Fatal(err)
		}
		sendErr := <-done
		ok, err := store.TryCancelUndispatched(context.Background(), pending)
		if err != nil {
			t.Fatal(err)
		}
		if (sendErr == nil) == ok {
			t.Fatal("dispatch and undispatched stop both committed or both unconfirmed", round, sendErr, ok)
		}
		actual, _ := store.Get(run.ID)
		if ok && actual.Status != platformruntime.StatusCancelled {
			t.Fatal("won cancel missing outcome")
		}
		if !ok && actual.Status != platformruntime.StatusCancelling {
			t.Fatal("sent generation stopped without SDK proof")
		}
	}
}
