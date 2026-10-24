package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/internal/compensation"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// These tests exercise real execution-owned transactions, locks, FIFO and
// outcomes. The controller stop/coverage callbacks are fixtures; a passing
// result must not be presented as actual deployed Agent/tree shutdown proof.
type cancellationFixture struct {
	ctx             context.Context
	runs            *SQLStore
	coordinator     compensation.Coordinator
	coverage        bool
	settled         bool
	coverageChecks  atomic.Int64
	progressEnabled bool
	progressChecks  atomic.Int64
	id              string
}

func newCancellationFixture(t *testing.T, cancellationFences ...func(context.Context, *sql.Tx, sharedkernel.Scope) error) *cancellationFixture {
	t.Helper()
	dsn := os.Getenv("COMPENSATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated owned PostgreSQL cancellation fixture required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(cfg.Database, "agentplug_compensation_test_") {
		t.Fatal("dedicated compensation database required; connection details suppressed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	runs, err := openMigratedSQLFixture(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runs.Close() })
	if err := compensation.Migrate(ctx, runs.DB()); err != nil {
		t.Fatal(err)
	}
	f := &cancellationFixture{ctx: ctx, runs: runs, coverage: true, settled: true, id: fmt.Sprintf("comp-execution-%d", time.Now().UnixNano())}
	runs.SetTerminalOutcomeFence(func(context.Context, *sql.Tx, sharedkernel.Scope) error {
		if !f.settled {
			return ErrExecutionOutcomeUnconfirmed
		}
		return nil
	})
	for _, fence := range cancellationFences {
		if err := runs.SetCancellationOutcomeFence(fence); err != nil {
			t.Fatal(err)
		}
	}
	f.coordinator, err = runs.EnableCancellationCompensation(ctx, CancellationCompensationPorts{
		ProgressFenceTx: func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
			if !f.progressEnabled {
				return runs.checkCancellationFenceTx(ctx, tx, scope)
			}
			f.progressChecks.Add(1)
			return runs.terminalOutcomeFence(ctx, tx, scope)
		},
		BuildCoordinator: func(ctx context.Context, authority compensation.Authority) (compensation.Coordinator, error) {
			if err := compensation.CheckSchema(ctx, runs.DB()); err != nil {
				return nil, err
			}
			if err := compensation.CheckEnrollmentSchema(ctx, runs.DB()); err != nil {
				return nil, err
			}
			return compensation.NewSQLStore(runs.DB(), authority)
		},
		ValidateStepTx: func(_ context.Context, _ *sql.Tx, step compensation.Step) error {
			if step.Root != step.Scope {
				return compensation.ErrConflict
			}
			return nil
		},
		ValidateCoverageTx: func(context.Context, *sql.Tx, sharedkernel.Scope) error {
			f.coverageChecks.Add(1)
			if !f.coverage {
				return compensation.ErrPending
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *cancellationFixture) create(t *testing.T, suffix string, running bool) platformruntime.Run {
	t.Helper()
	id := f.id + "-" + suffix
	scope := testScope(id).domain()
	scope.SessionID = f.id
	created, err := f.runs.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: id})
	if err != nil {
		t.Fatal(err)
	}
	if !running {
		return created.Run
	}
	claimed, err := f.runs.AcquireLease(id, "fixture-worker", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	run, err := f.runs.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func (f *cancellationFixture) register(t *testing.T, run platformruntime.Run) compensation.Step {
	t.Helper()
	step := compensation.Step{Root: run.Scope, Scope: run.Scope, Kind: "tool", Tool: "fixture.write", Provider: "execution-fixture", ProviderVersion: "v1", CallID: "write", Fingerprint: stopHash([]byte("owned-effect")), Ref: "owned-row"}
	step.ID = compensation.StepID(step.Scope, step.Kind, step.CallID)
	ctx := sharedkernel.BindExecutionLease(f.ctx, run.Revision, run.LeaseToken)
	tx, err := f.runs.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = f.coordinator.RegisterTx(ctx, tx, step); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS compensation_execution_fixture_effect(step_id TEXT PRIMARY KEY,value BIGINT NOT NULL,revision BIGINT NOT NULL DEFAULT 1,receipt_json JSONB NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO compensation_execution_fixture_effect(step_id,value) VALUES(?,1)`), step.ID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return step
}

var fixtureControllerStop = StopEvidence{Source: "runtime-process-stop/v1", Digest: strings.Repeat("d", 64), RuntimeID: strings.Repeat("a", 64)}

type executionFixtureCompensator struct{ f *cancellationFixture }

func (p executionFixtureCompensator) Lookup(ctx context.Context, s compensation.Step) (compensation.Receipt, bool, error) {
	var raw []byte
	err := p.f.runs.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT receipt_json FROM compensation_execution_fixture_effect WHERE step_id=?`), s.ID).Scan(&raw)
	if err != nil {
		return compensation.Receipt{}, false, err
	}
	if len(raw) == 0 {
		return compensation.Receipt{}, false, nil
	}
	var r compensation.Receipt
	err = json.Unmarshal(raw, &r)
	return r, err == nil, err
}
func (p executionFixtureCompensator) InspectOriginal(ctx context.Context, s compensation.Step) (compensation.OriginalEffect, error) {
	var value, revision int
	err := p.f.runs.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT value,revision FROM compensation_execution_fixture_effect WHERE step_id=?`), s.ID).Scan(&value, &revision)
	if err != nil {
		return compensation.OriginalEffect{}, err
	}
	if value != 1 || revision != 1 {
		return compensation.OriginalEffect{StepDigest: s.Digest(), State: "unknown"}, nil
	}
	return compensation.OriginalEffect{StepDigest: s.Digest(), State: "applied", EvidenceDigest: stopHash([]byte(s.Digest() + ":1:1"))}, nil
}
func (p executionFixtureCompensator) Compensate(ctx context.Context, s compensation.Step) (compensation.Receipt, error) {
	l, err := compensation.LeaseFromContext(ctx, s)
	if err != nil {
		return compensation.Receipt{}, err
	}
	tx, err := p.f.runs.db.BeginTx(ctx, nil)
	if err != nil {
		return compensation.Receipt{}, errors.Join(compensation.ErrNotSubmitted, err)
	}
	defer tx.Rollback()
	if err = p.f.coordinator.GuardLeaseTx(ctx, tx, l); err != nil {
		return compensation.Receipt{}, errors.Join(compensation.ErrNotSubmitted, err)
	}
	r := compensation.Receipt{Version: compensation.ContractVersion, StepDigest: s.Digest(), Key: s.CompensationKey(), Action: "rolled_back", EvidenceDigest: stopHash([]byte(s.Digest() + ":0:2"))}
	raw, _ := json.Marshal(r)
	res, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE compensation_execution_fixture_effect SET value=0,revision=2,receipt_json=?::jsonb WHERE step_id=? AND value=1 AND revision=1 AND receipt_json IS NULL`), string(raw), s.ID)
	if err != nil {
		return compensation.Receipt{}, errors.Join(compensation.ErrNotSubmitted, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return compensation.Receipt{}, compensation.ErrNotSubmitted
	}
	if err = tx.Commit(); err != nil {
		return compensation.Receipt{}, err
	}
	return r, nil
}

func TestCancellationCompensationNeverClaimedCompletesAtomicallyPostgres(t *testing.T) {
	f := newCancellationFixture(t)
	run := f.create(t, "never-claimed", false)
	pending, err := f.runs.BeginCancellation(run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	done, err := f.runs.Cancel(run.ID, pending.Revision)
	if err != nil || done.Status != platformruntime.StatusCancelled {
		t.Fatalf("never claimed cancellation: %v/%s", err, done.Status)
	}
	progress, found, err := f.coordinator.Progress(f.ctx, run.Scope)
	if err != nil || !found || progress.Phase != "complete" || !progress.StopConfirmed || progress.Total != 0 {
		t.Fatal("Run completed without matching coordinator proof")
	}
	var payload []byte
	if err = f.runs.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT event_payload FROM platform_execution_outcome WHERE run_id=?`), run.ID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var outcome map[string]any
	if json.Unmarshal(payload, &outcome) != nil || outcome["compensation_version"] != compensation.ContractVersion {
		t.Fatal("final outcome lost versioned completion proof")
	}
	actual, view, err := f.runs.ReadCancellationProjection(f.ctx, run.Scope)
	if err != nil || actual.Status != platformruntime.StatusCancelled || view == nil || view.Disposition != "verified" || view.Progress == nil || view.Progress.Phase != "complete" {
		t.Fatal("confirmed outcome lacks safe complete projection", err)
	}
}

func TestCancellationCompensationStopRetainsFIFOUntilActualUndoPostgres(t *testing.T) {
	f := newCancellationFixture(t)
	run := f.create(t, "owned-effect", true)
	step := f.register(t, run)
	pending, err := f.runs.BeginCancellation(run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	stopped, err := f.runs.CancelWithStopEvidence(run.ID, pending.Revision, fixtureControllerStop)
	if err != nil || stopped.Status != platformruntime.StatusCancelling {
		t.Fatalf("stop falsely completed cancellation: %v/%s", err, stopped.Status)
	}
	var value, leases int
	if err = f.runs.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT value FROM compensation_execution_fixture_effect WHERE step_id=?`), step.ID).Scan(&value); err != nil || value != 1 {
		t.Fatal("stop alone altered business state")
	}
	if err = f.runs.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_execution_session_lease WHERE run_id=?`), run.ID).Scan(&leases); err != nil || leases != 1 {
		t.Fatal("stop released FIFO before undo")
	}
	next := f.create(t, "next", false)
	if _, err = f.runs.AcquireLease(next.ID, "next-worker", time.Now().UTC(), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("next session Run admitted before cancellation completed")
	}
	if confirmed, err := f.runs.ReconcileCancellationCompensation(f.ctx, stopped); err != nil || !confirmed {
		t.Fatal("persisted stop could not resume without another remote acknowledgement")
	}
	_, view, err := f.runs.ReadCancellationProjection(f.ctx, run.Scope)
	if err != nil || view == nil || view.Disposition != "in_progress" || view.Progress == nil || view.Progress.Phase != "compensating" || view.Progress.Unresolved != 1 {
		t.Fatal("stopped but uncompensated Run projected as complete", err)
	}
	engine, err := compensation.NewEngine(f.coordinator, "fixture-compensator", compensation.Registration{Provider: step.Provider, Version: step.ProviderVersion, Timeout: time.Second, Port: executionFixtureCompensator{f}})
	if err != nil {
		t.Fatal(err)
	}
	if handled, err := engine.Tick(f.ctx, run.Scope); err != nil || !handled {
		t.Fatalf("actual inverse failed: %v", err)
	}
	if err = f.coordinator.TryFinalize(f.ctx, run.Scope); err != nil {
		t.Fatal(err)
	}
	done, err := f.runs.Get(run.ID)
	if err != nil || done.Status != platformruntime.StatusCancelled || done.LeaseToken != "" {
		t.Fatal("confirmed undo did not publish actual cancelled outcome")
	}
	if err = f.runs.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT value FROM compensation_execution_fixture_effect WHERE step_id=?`), step.ID).Scan(&value); err != nil || value != 0 {
		t.Fatal("cancelled without actual business undo")
	}
	if _, err = f.runs.AcquireLease(next.ID, "next-worker", time.Now().UTC(), time.Minute); err != nil {
		t.Fatal("confirmed cancellation failed to release FIFO", err)
	}
}

func TestCancellationCompensationRejectsBareStopOrUncoveredEffectsPostgres(t *testing.T) {
	f := newCancellationFixture(t)
	run := f.create(t, "uncovered", true)
	f.register(t, run)
	pending, err := f.runs.BeginCancellation(run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.runs.Cancel(run.ID, pending.Revision); !errors.Is(err, ErrStopEvidenceAbsent) {
		t.Fatal("bare leased Cancel invented stop proof")
	}
	f.coverage = false
	if _, err = f.runs.CancelWithStopEvidence(run.ID, pending.Revision, fixtureControllerStop); !errors.Is(err, compensation.ErrPending) {
		t.Fatal("uncovered business effects were accepted")
	}
	progress, found, err := f.coordinator.Progress(f.ctx, run.Scope)
	if err != nil || !found || progress.Phase != "stopping" || progress.StopConfirmed {
		t.Fatal("missing coverage committed a stop/complete proof")
	}
	current, _ := f.runs.Get(run.ID)
	if current.Status != platformruntime.StatusCancelling || current.LeaseToken != run.LeaseToken {
		t.Fatal("failed coverage released actual Run")
	}
	f.coverage = true
	f.settled = false
	if _, err = f.runs.CancelWithStopEvidence(run.ID, pending.Revision, fixtureControllerStop); !errors.Is(err, ErrExecutionOutcomeUnconfirmed) {
		t.Fatal("unsettled charge permitted cancellation")
	}
}

func TestCancellationCompensationRejectsNewWriteAfterIntentPostgres(t *testing.T) {
	f := newCancellationFixture(t)
	run := f.create(t, "late-write", true)
	step := f.register(t, run)
	if _, err := f.runs.BeginCancellation(run.ID, run.Revision); err != nil {
		t.Fatal(err)
	}
	ctx := sharedkernel.BindExecutionLease(f.ctx, run.Revision, run.LeaseToken)
	tx, err := f.runs.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	step.CallID = "late"
	step.ID = compensation.StepID(step.Scope, step.Kind, step.CallID)
	if err = f.coordinator.RegisterTx(ctx, tx, step); !errors.Is(err, compensation.ErrPending) {
		t.Fatal("late forward registration crossed cancellation fence")
	}
}

func TestCancellationCompensationFinalAuditFailureRollsBackWholeOutcomePostgres(t *testing.T) {
	f := newCancellationFixture(t)
	run := f.create(t, "final-fault", false)
	pending, err := f.runs.BeginCancellation(run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	name := "comp_cancel_fault_" + fmt.Sprintf("%d", time.Now().UnixNano())
	fn := pgx.Identifier{name}.Sanitize()
	if _, err = f.runs.db.ExecContext(f.ctx, "CREATE FUNCTION "+fn+"() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.run_id='"+run.ID+"' AND NEW.event_type='cancellation_complete' THEN RAISE EXCEPTION 'owned fixture fault'; END IF; RETURN NEW; END $$"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.runs.db.ExecContext(f.ctx, "CREATE TRIGGER "+fn+" BEFORE INSERT ON platform_compensation_event FOR EACH ROW EXECUTE FUNCTION "+fn+"()"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.runs.db.ExecContext(context.Background(), "DROP FUNCTION IF EXISTS "+fn+"() CASCADE") })
	if _, err = f.runs.Cancel(run.ID, pending.Revision); err == nil {
		t.Fatal("failed final audit reported cancelled")
	}
	current, _ := f.runs.Get(run.ID)
	if current.Status != platformruntime.StatusCancelling || current.Revision != pending.Revision {
		t.Fatal("partial final outcome committed")
	}
	progress, found, err := f.coordinator.Progress(f.ctx, run.Scope)
	if err != nil || !found || progress.Phase != "stopping" {
		t.Fatal("job completed independently of failed actual outcome")
	}
	var count int
	if err = f.runs.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_execution_outcome WHERE run_id=?`), run.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed final commit left cancelled outcome")
	}
	if _, err = f.runs.db.ExecContext(f.ctx, "DROP TRIGGER "+fn+" ON platform_compensation_event"); err != nil {
		t.Fatal(err)
	}
	if done, err := f.runs.Cancel(run.ID, pending.Revision); err != nil || done.Status != platformruntime.StatusCancelled {
		t.Fatal("unchanged cancellation could not safely retry final transaction")
	}
}

func TestCancellationCompensationConcurrentBusinessWriteIsPreservedPostgres(t *testing.T) {
	f := newCancellationFixture(t)
	run := f.create(t, "conflicting-write", true)
	step := f.register(t, run)
	pending, err := f.runs.BeginCancellation(run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.runs.CancelWithStopEvidence(run.ID, pending.Revision, fixtureControllerStop); err != nil {
		t.Fatal(err)
	}
	if _, err = f.runs.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE compensation_execution_fixture_effect SET value=9,revision=2 WHERE step_id=?`), step.ID); err != nil {
		t.Fatal(err)
	}
	engine, err := compensation.NewEngine(f.coordinator, "fixture-conflict", compensation.Registration{Provider: step.Provider, Version: step.ProviderVersion, Timeout: time.Second, Port: executionFixtureCompensator{f}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.Tick(f.ctx, run.Scope); err != nil {
		t.Fatal(err)
	}
	if err = f.coordinator.TryFinalize(f.ctx, run.Scope); !errors.Is(err, compensation.ErrPending) {
		t.Fatal("conflicting business change passed cancellation gate")
	}
	var value int
	if err = f.runs.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT value FROM compensation_execution_fixture_effect WHERE step_id=?`), step.ID).Scan(&value); err != nil || value != 9 {
		t.Fatal("another actor's newer value was overwritten")
	}
	progress, _, err := f.coordinator.Progress(f.ctx, run.Scope)
	if err != nil || progress.Phase != "needs_attention" {
		t.Fatal("unresolved business conflict lacks truthful projection")
	}
}

func TestCancellationCompensationEnableRequiresAllAuthorityPorts(t *testing.T) {
	var runs *SQLStore
	if _, err := runs.EnableCancellationCompensation(context.Background(), CancellationCompensationPorts{}); !errors.Is(err, compensation.ErrUnavailable) {
		t.Fatal("missing cancellation authority accepted")
	}
}

func TestCancellationCompensationPreparesCoverageAfterDurableIntentPostgres(t *testing.T) {
	f := newCancellationFixture(t)
	run := f.create(t, "coverage-order", false)
	prepared := false
	f.runs.cancellationPorts.PrepareCoverageTx = func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, store compensation.Coordinator) error {
		progress, found, err := store.ProgressTx(ctx, tx, scope)
		if err != nil || !found || progress.Phase != "stopping" {
			return compensation.ErrConflict
		}
		if err := store.EnrollStoppedTreeTx(ctx, tx, scope, []sharedkernel.Scope{scope}); err != nil {
			return err
		}
		prepared = true
		return nil
	}
	f.runs.cancellationPorts.ValidateCoverageTx = func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
		if !prepared {
			return compensation.ErrPending
		}
		return f.coordinator.VerifyStoppedTreeCoverageTx(ctx, tx, scope, []sharedkernel.Scope{scope})
	}
	pending, err := f.runs.BeginCancellation(run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	done, err := f.runs.Cancel(run.ID, pending.Revision)
	if err != nil || done.Status != platformruntime.StatusCancelled || !prepared {
		t.Fatalf("cancel coverage ordering failed: %v", err)
	}
	actual, projection, err := f.runs.ReadCancellationProjection(f.ctx, run.Scope)
	if err != nil || actual.Status != platformruntime.StatusCancelled || projection == nil || projection.Disposition != "verified" {
		t.Fatalf("prepared intent lost verified outcome: %v", err)
	}
}

func TestCancellationCompensationCannotBypassThroughTransitionOrEventPostgres(t *testing.T) {
	f := newCancellationFixture(t)
	run := f.create(t, "bypass", false)
	if _, err := f.runs.Transition(run.ID, platformruntime.StatusAccepted, platformruntime.StatusCancelled, run.Revision); !errors.Is(err, platformruntime.ErrInvalidTransition) {
		t.Fatal("generic transition bypassed dedicated compensation operation")
	}
	if _, err := f.runs.AppendEvent(run.ID, "cancellation_stop_verified", map[string]any{"version": "execution-cancellation-stop/v1"}); !errors.Is(err, platformruntime.ErrInvalidTransition) {
		t.Fatal("caller-controlled event invented a trusted stop proof")
	}
	current, _ := f.runs.Get(run.ID)
	if current.Status != platformruntime.StatusAccepted {
		t.Fatal("rejected public command changed Run")
	}
}

func TestCancellationCompensationHistoricalOutcomeNeverGetsInventedProofPostgres(t *testing.T) {
	f := newCancellationFixture(t)
	run := f.create(t, "historical", false)
	f.runs.cancellationSaga = nil
	if _, err := f.runs.Cancel(run.ID, run.Revision); err != nil {
		t.Fatal(err)
	}
	f.runs.cancellationSaga = f.coordinator
	actual, view, err := f.runs.ReadCancellationProjection(f.ctx, run.Scope)
	if err != nil || actual.Status != platformruntime.StatusCancelled || view == nil || view.Disposition != "historical_unverified" || view.Progress != nil {
		t.Fatal("historical stopped Run acquired fabricated business rollback proof", err)
	}
	other := run.Scope
	other.PrincipalID = "another-user"
	if _, _, err = f.runs.ReadCancellationProjection(f.ctx, other); !errors.Is(err, compensation.ErrConflict) {
		t.Fatal("cancellation proof crossed owner Scope")
	}
}

func TestCancellationCompensationProjectionRejectsMismatchedOutcomePostgres(t *testing.T) {
	f := newCancellationFixture(t)
	run := f.create(t, "wrong-projection", false)
	pending, err := f.runs.BeginCancellation(run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.runs.Cancel(run.ID, pending.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err = f.runs.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_execution_outcome SET event_payload='{}'::json WHERE run_id=?`), run.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.runs.ReadCancellationProjection(f.ctx, run.Scope); !errors.Is(err, compensation.ErrConflict) {
		t.Fatal("missing final transactional proof was accepted as verified cancellation")
	}
}
