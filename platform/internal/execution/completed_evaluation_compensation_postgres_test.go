package execution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Real PostgreSQL transactions and inverse receipts, with an explicitly
// fixture-owned product parent. This does not replace actual deployed IAM,
// immutable suite/case and Run-tree provenance verification.
func completedEvaluationFixture(t *testing.T, status platformruntime.Status, withOutcome bool) (*cancellationFixture, platformruntime.Run, compensation.Step) {
	t.Helper()
	f := newCancellationFixture(t)
	if _, err := f.runs.db.ExecContext(f.ctx, `CREATE TABLE IF NOT EXISTS compensation_evaluation_parent_fixture(id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,status TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	scope := testScope(f.id + "-completed-case").domain()
	scope.ParentRunID = f.id + "-product"
	scope.SessionID = f.id + "-session"
	if _, err := f.runs.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO compensation_evaluation_parent_fixture VALUES(?,?,'cancelling')`), scope.ParentRunID, scope.PrincipalID); err != nil {
		t.Fatal(err)
	}
	f.runs.completedEvaluationControl = func(ctx context.Context, tx *sql.Tx, run platformruntime.Run) error {
		var owner, parentStatus string
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT owner_id,status FROM compensation_evaluation_parent_fixture WHERE id=? FOR UPDATE`), run.Scope.ParentRunID).Scan(&owner, &parentStatus); err != nil {
			return err
		}
		if owner != run.Scope.PrincipalID || parentStatus != "cancelling" {
			return compensation.ErrConflict
		}
		return nil
	}
	// The repository restores immutable parent lineage from the persisted
	// request. This fixture owns only control transactions, not v2 admission.
	request, _ := json.Marshal(map[string]any{"scope": map[string]any{"parent_run_id": scope.ParentRunID}})
	created, err := f.runs.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: scope.RunID, Fingerprint: scope.RunID, RequestJSON: request})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := f.runs.AcquireLease(created.Run.ID, "fixture-case", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := f.runs.TransitionLeased(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	step := f.register(t, running)
	var terminal platformruntime.Run
	if withOutcome {
		terminal, err = f.runs.FinalizeLeased(running.ID, status, running.Revision, running.LeaseToken, map[string]any{"historical_result": "retain"}, map[string]any{"code": "FIXTURE_RESULT"})
	} else {
		terminal, err = f.runs.TransitionLeased(running.ID, platformruntime.StatusRunning, status, running.Revision, running.LeaseToken)
	}
	if err != nil {
		t.Fatal(err)
	}
	return f, terminal, step
}

func TestCompletedEvaluationCompensationRetainsOutcomeAndUndoesWritesPostgres(t *testing.T) {
	for _, status := range []platformruntime.Status{platformruntime.StatusSucceeded, platformruntime.StatusFailed} {
		t.Run(string(status), func(t *testing.T) {
			f, run, step := completedEvaluationFixture(t, status, true)
			before, err := f.runs.GetOutcome(run.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.runs.RequestCompletedEvaluationCompensation(f.ctx, run.Scope); err != nil {
				t.Fatal(err)
			}
			if complete, err := f.runs.CompletedEvaluationCompensationComplete(f.ctx, run.Scope); err != nil || complete {
				t.Fatal("inverse not yet confirmed", err)
			}
			engine, err := compensation.NewEngine(f.coordinator, "completed-case-worker", compensation.Registration{Provider: step.Provider, Version: step.ProviderVersion, Timeout: time.Second, Port: executionFixtureCompensator{f}})
			if err != nil {
				t.Fatal(err)
			}
			if handled, err := engine.Tick(f.ctx, run.Scope); err != nil || !handled {
				t.Fatal("inverse failed", err)
			}
			if err = f.coordinator.TryFinalize(f.ctx, run.Scope); err != nil {
				t.Fatal(err)
			}
			if complete, err := f.runs.CompletedEvaluationCompensationComplete(f.ctx, run.Scope); err != nil || !complete {
				t.Fatal("receipt not complete", err)
			}
			after, err := f.runs.GetOutcome(run.ID)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := f.runs.Get(run.ID)
			if err != nil {
				t.Fatal(err)
			}
			if actual.Status != status || actual.Revision != run.Revision || after.Revision != before.Revision || after.EventType != before.EventType || !bytes.Equal(after.OutputJSON, before.OutputJSON) {
				t.Fatal("inverse rewrote historical execution")
			}
			var value int
			if err = f.runs.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT value FROM compensation_execution_fixture_effect WHERE step_id=?`), step.ID).Scan(&value); err != nil || value != 0 {
				t.Fatal("effect not undone", err)
			}
			if err = f.runs.RequestCompletedEvaluationCompensation(f.ctx, run.Scope); err != nil {
				t.Fatal(err)
			}
			var events int
			if err = f.runs.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_execution_event WHERE run_id=? AND event_type='completed_effects_compensated'`), run.ID).Scan(&events); err != nil || events != 1 {
				t.Fatal("repeat control changed history", err)
			}
		})
	}
}

func TestCompletedEvaluationCompensationRequiresRecordedParentAndOutcomePostgres(t *testing.T) {
	f, run, _ := completedEvaluationFixture(t, platformruntime.StatusSucceeded, true)
	if _, err := f.runs.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE compensation_evaluation_parent_fixture SET status='running' WHERE id=?`), run.Scope.ParentRunID); err != nil {
		t.Fatal(err)
	}
	if err := f.runs.RequestCompletedEvaluationCompensation(f.ctx, run.Scope); !errors.Is(err, compensation.ErrConflict) {
		t.Fatal("active parent granted inverse authority", err)
	}
	foreign := run.Scope
	foreign.PrincipalID = "other-user"
	if err := f.runs.RequestCompletedEvaluationCompensation(f.ctx, foreign); !errors.Is(err, compensation.ErrConflict) {
		t.Fatal("foreign scope granted control", err)
	}
	var jobs int
	if err := f.runs.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_cancellation_operation WHERE root_run_id=?`), run.ID).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatal("denied control wrote intent", err)
	}
	missing, terminal, _ := completedEvaluationFixture(t, platformruntime.StatusSucceeded, false)
	if err := missing.runs.RequestCompletedEvaluationCompensation(missing.ctx, terminal.Scope); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("missing outcome invented a stop proof", err)
	}
}

func TestCompletedEvaluationCompensationPreservesUnsettledEvidencePostgres(t *testing.T) {
	f, run, _ := completedEvaluationFixture(t, platformruntime.StatusSucceeded, true)
	f.settled = false
	if err := f.runs.RequestCompletedEvaluationCompensation(f.ctx, run.Scope); !errors.Is(err, ErrExecutionOutcomeUnconfirmed) {
		t.Fatal("unsettled model/tool evidence bypassed", err)
	}
	var jobs int
	if err := f.runs.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_cancellation_operation WHERE root_run_id=?`), run.ID).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatal("unsettled control committed a proof", err)
	}
	actual, _ := f.runs.Get(run.ID)
	if actual.Status != run.Status || actual.Revision != run.Revision {
		t.Fatal("unsettled control altered original run")
	}
}
