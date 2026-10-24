package execution

import (
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestCancellationCompensationProgressUsesFrozenCoverageButLiveFencesPostgres(t *testing.T) {
	f := newCancellationFixture(t)
	f.progressEnabled = true
	run := f.create(t, "progress-guard", true)
	step := f.register(t, run)
	pending, err := f.runs.BeginCancellation(run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.runs.CancelWithStopEvidence(run.ID, pending.Revision, fixtureControllerStop); err != nil {
		t.Fatal(err)
	}
	before := f.coverageChecks.Load()
	progressBefore := f.progressChecks.Load()
	if before == 0 {
		t.Fatal("stop never checked full coverage")
	}
	a := cancellationAuthority{runs: f.runs, ports: f.runs.cancellationPorts}
	for i := 0; i < 1000; i++ {
		tx, err := f.runs.db.BeginTx(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = a.GuardCompensationTx(f.ctx, tx, run.Scope)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	if f.coverageChecks.Load() != before {
		t.Fatal("intermediate guards re-scanned frozen tree", before, f.coverageChecks.Load())
	}
	if f.progressChecks.Load()-progressBefore != 1000 {
		t.Fatal("intermediate guards did not execute every live progress fence", f.progressChecks.Load())
	}
	// Even after a stop proof exists, new unknown accounting must block an
	// inverse. Frozen coverage is not permission to skip live settlement.
	f.settled = false
	tx, err := f.runs.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = a.GuardCompensationTx(f.ctx, tx, run.Scope)
	tx.Rollback()
	if !errors.Is(err, ErrExecutionOutcomeUnconfirmed) {
		t.Fatal("live settlement fence bypassed", err)
	}
	f.settled = true
	engine, err := compensation.NewEngine(f.coordinator, "progress-fixture", compensation.Registration{Provider: step.Provider, Version: step.ProviderVersion, Timeout: time.Second, Port: executionFixtureCompensator{f}})
	if err != nil {
		t.Fatal(err)
	}
	if handled, err := engine.Tick(f.ctx, run.Scope); err != nil || !handled {
		t.Fatal(handled, err)
	}
	if f.coverageChecks.Load() != before {
		t.Fatal("single inverse re-scanned complete tree")
	}
	// All step receipts can be valid and final full-tree coverage still fail.
	f.coverage = false
	if err = f.coordinator.TryFinalize(f.ctx, run.Scope); !errors.Is(err, compensation.ErrPending) {
		t.Fatal("final coverage skipped", err)
	}
	current, err := f.runs.Get(run.ID)
	if err != nil || current.Status != platformruntime.StatusCancelling {
		t.Fatal("partial final state committed", current.Status, err)
	}
	if f.coverageChecks.Load() <= before {
		t.Fatal("final transaction did not recheck coverage")
	}
	f.coverage = true
	if err = f.coordinator.TryFinalize(f.ctx, run.Scope); err != nil {
		t.Fatal(err)
	}
	current, err = f.runs.Get(run.ID)
	if err != nil || current.Status != platformruntime.StatusCancelled {
		t.Fatal("verified root did not finalize", current.Status, err)
	}
	t.Logf("1000 intermediate guards, full coverage at stop and finalization only; live settlement and failed final rollback verified")
}
