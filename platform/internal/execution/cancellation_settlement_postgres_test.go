package execution

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestCancellationCompensationFenceKeepsSuccessAndRecoveryStrictPostgres(t *testing.T) {
	chargesSettled := false
	f := newCancellationFixture(t, func(context.Context, *sql.Tx, sharedkernel.Scope) error {
		if !chargesSettled {
			return ErrExecutionOutcomeUnconfirmed
		}
		return nil
	})
	run := f.create(t, "owned-response-lost", true)
	step := f.register(t, run)
	f.settled = false // Ordinary forward ledger settlement is still unresolved.
	if _, err := f.runs.TransitionLeased(run.ID, platformruntime.StatusRunning, platformruntime.StatusSucceeded, run.Revision, run.LeaseToken); !errors.Is(err, ErrExecutionOutcomeUnconfirmed) {
		t.Fatal("cancellation fence weakened successful completion", err)
	}
	if err := f.runs.SetCancellationOutcomeFence(func(context.Context, *sql.Tx, sharedkernel.Scope) error { return nil }); !errors.Is(err, compensation.ErrInvalid) {
		t.Fatal("live cancellation authority replaced", err)
	}
	pending, err := f.runs.BeginCancellation(run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.runs.CancelWithStopEvidence(run.ID, pending.Revision, fixtureControllerStop); !errors.Is(err, ErrExecutionOutcomeUnconfirmed) {
		t.Fatal("unsettled charges bypassed cancellation", err)
	}
	if progress, found, err := f.coordinator.Progress(f.ctx, run.Scope); err != nil || !found || progress.StopConfirmed || progress.Phase != "stopping" {
		t.Fatal("failed stop fence committed stop proof", err)
	}
	chargesSettled = true
	stopped, err := f.runs.CancelWithStopEvidence(run.ID, pending.Revision, fixtureControllerStop)
	if err != nil || stopped.Status != platformruntime.StatusCancelling {
		t.Fatal("owned effect could not enter compensation", err)
	}
	if _, err := f.runs.GetOutcome(run.ID); !errors.Is(err, platformruntime.ErrRunNotFound) {
		t.Fatal("stop alone produced cancelled outcome", err)
	}
	engine, err := compensation.NewEngine(f.coordinator, "owned-effect-worker", compensation.Registration{Provider: step.Provider, Version: step.ProviderVersion, Timeout: time.Second, Port: executionFixtureCompensator{f}})
	if err != nil {
		t.Fatal(err)
	}
	if handled, err := engine.Tick(f.ctx, run.Scope); err != nil || !handled {
		t.Fatal("inverse did not execute", err)
	}
	if err := f.coordinator.TryFinalize(f.ctx, run.Scope); err != nil {
		t.Fatal(err)
	}
	done, view, err := f.runs.ReadCancellationProjection(f.ctx, run.Scope)
	if err != nil || done.Status != platformruntime.StatusCancelled || view == nil || view.Disposition != "verified" || f.settled {
		t.Fatal("business inverse did not finalize independently of forward response", err)
	}
	// The unresolved forward result flag remains untouched. Recovery's fence is
	// the ordinary terminalOutcomeFence, never this cancellation control port.
	tx, err := f.runs.DB().BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := f.runs.terminalOutcomeFence(f.ctx, tx, run.Scope); !errors.Is(err, ErrExecutionOutcomeUnconfirmed) {
		t.Fatal("ordinary fence was altered", err)
	}
}
