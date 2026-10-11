package compensation

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// These fixtures exercise the coordinator on actual owned PostgreSQL. The
// production execution/IAM/Agent stop authority is separately integrated and
// tested; fixture stop facts must never be described as real Agent shutdown.
type fixtureAuthority struct{ failFinish bool }

func fixtureRun(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) (string, uint64, bool, bool, error) {
	var binding, status string
	var revision uint64
	var stopped, settled bool
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT scope_digest,status,revision,stopped,settled FROM compensation_test_run WHERE run_id=? FOR UPDATE`), scope.RunID).Scan(&binding, &status, &revision, &stopped, &settled)
	if err != nil {
		return "", 0, false, false, err
	}
	if binding != ScopeDigest(scope) {
		return "", 0, false, false, ErrConflict
	}
	return status, revision, stopped, settled, nil
}
func (a *fixtureAuthority) RegisterEffectTx(ctx context.Context, tx *sql.Tx, step Step) error {
	status, _, _, _, err := fixtureRun(ctx, tx, step.Root)
	if err != nil {
		return err
	}
	if status != "running" {
		return ErrPending
	}
	if step.Scope.RunID != step.Root.RunID {
		var root, binding string
		if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT root_run_id,scope_digest FROM compensation_test_run WHERE run_id=?`), step.Scope.RunID).Scan(&root, &binding); err != nil {
			return err
		}
		if root != step.Root.RunID || binding != ScopeDigest(step.Scope) {
			return ErrConflict
		}
	}
	return nil
}
func (a *fixtureAuthority) BeginCancellationTx(ctx context.Context, tx *sql.Tx, s sharedkernel.Scope, expected uint64) error {
	status, revision, _, _, err := fixtureRun(ctx, tx, s)
	if err != nil {
		return err
	}
	if status != "cancelling" || revision != expected {
		return ErrConflict
	}
	return nil
}
func (a *fixtureAuthority) ConfirmStoppedTx(ctx context.Context, tx *sql.Tx, s sharedkernel.Scope, proof StopProof) error {
	status, revision, stopped, _, err := fixtureRun(ctx, tx, s)
	if err != nil {
		return err
	}
	if status != "cancelling" || revision != proof.Revision || !stopped {
		return ErrPending
	}
	return nil
}
func (a *fixtureAuthority) GuardCompensationTx(ctx context.Context, tx *sql.Tx, s sharedkernel.Scope) error {
	status, _, stopped, _, err := fixtureRun(ctx, tx, s)
	if err != nil {
		return err
	}
	if status != "cancelling" || !stopped {
		return ErrPending
	}
	return nil
}
func (a *fixtureAuthority) FinishCancellationTx(ctx context.Context, tx *sql.Tx, s sharedkernel.Scope, p StopProof) error {
	status, revision, stopped, settled, err := fixtureRun(ctx, tx, s)
	if err != nil {
		return err
	}
	if status != "cancelling" || revision != p.Revision || !stopped || !settled {
		return ErrPending
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE compensation_test_run SET status='cancelled',revision=revision+1 WHERE run_id=? AND revision=?`), s.RunID, revision)
	if err != nil {
		return err
	}
	if a.failFinish {
		return errors.New("injected failure after real Run write")
	}
	return nil
}

const fixtureDDL = `
CREATE TABLE IF NOT EXISTS compensation_test_run(run_id TEXT PRIMARY KEY,root_run_id TEXT NOT NULL,scope_digest TEXT NOT NULL,status TEXT NOT NULL,revision BIGINT NOT NULL,stopped BOOLEAN NOT NULL DEFAULT FALSE,settled BOOLEAN NOT NULL DEFAULT TRUE,charged_fee NUMERIC(12,6) NOT NULL DEFAULT 0.015);
CREATE TABLE IF NOT EXISTS compensation_test_effect(step_id TEXT PRIMARY KEY,spec_digest TEXT NOT NULL,value BIGINT NOT NULL,before_value BIGINT NOT NULL,expected_value BIGINT NOT NULL,revision BIGINT NOT NULL DEFAULT 1,expected_revision BIGINT NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS compensation_test_receipt(compensation_key TEXT PRIMARY KEY,spec_digest TEXT NOT NULL,receipt_json JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS compensation_test_inverse_event(ordinal BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,step_id TEXT NOT NULL);
`

func ownedFixture(t *testing.T) (context.Context, *sql.DB, *SQLStore, *fixtureAuthority, sharedkernel.Scope) {
	t.Helper()
	dsn := os.Getenv("COMPENSATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated owned PostgreSQL compensation fixture required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(cfg.Database, "agentplug_compensation_test_") {
		t.Fatal("dedicated compensation test database required; connection details suppressed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err = Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, fixtureDDL); err != nil {
		t.Fatal(err)
	}
	a := &fixtureAuthority{}
	s, err := NewSQLStore(db, a)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	root := testScope()
	root.RunID = "run-" + hex.EncodeToString(nonce[:])
	root.SessionID = root.RunID + "-session"
	if _, err = db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO compensation_test_run(run_id,root_run_id,scope_digest,status,revision) VALUES(?,?,?,'running',1)`), root.RunID, root.RunID, ScopeDigest(root)); err != nil {
		t.Fatal(err)
	}
	return ctx, db, s, a, root
}
func runTx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
func fixtureStep(root, scope sharedkernel.Scope, call string) Step {
	s := testStep()
	s.Root = root
	s.Scope = scope
	s.CallID = call
	s.Ref = "owned-" + call
	s.ID = StepID(scope, s.Kind, call)
	return s
}
func registerFixture(ctx context.Context, db *sql.DB, s *SQLStore, step Step, write bool) error {
	return runTx(ctx, db, func(tx *sql.Tx) error {
		if err := s.RegisterTx(ctx, tx, step); err != nil {
			return err
		}
		if !write {
			return nil
		}
		_, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO compensation_test_effect(step_id,spec_digest,value,before_value,expected_value) VALUES(?,?,7,0,7)`), step.ID, step.Digest())
		return err
	})
}
func beginFixture(ctx context.Context, db *sql.DB, s *SQLStore, root sharedkernel.Scope, stopped bool) error {
	return runTx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE compensation_test_run SET status='cancelling',revision=2,stopped=? WHERE run_id=? AND status='running'`), stopped, root.RunID); err != nil {
			return err
		}
		if _, err := s.BeginTx(ctx, tx, root, 2); err != nil {
			return err
		}
		if !stopped {
			return nil
		}
		return s.ConfirmStoppedTx(ctx, tx, root, StopProof{Version: "cancellation-tree-stop/v1", ScopeDigest: ScopeDigest(root), Revision: 2, EvidenceDigest: hash("owned fixture stopped facts")})
	})
}

type fixturePort struct {
	db        *sql.DB
	store     *SQLStore
	lostReply bool
	calls     int
}

func (p *fixturePort) Lookup(ctx context.Context, step Step) (Receipt, bool, error) {
	var raw []byte
	var binding string
	err := p.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT spec_digest,receipt_json FROM compensation_test_receipt WHERE compensation_key=?`), step.CompensationKey()).Scan(&binding, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	var receipt Receipt
	if binding != step.Digest() || json.Unmarshal(raw, &receipt) != nil || receipt.Validate(step) != nil {
		return Receipt{}, false, ErrConflict
	}
	return receipt, true, nil
}
func (p *fixturePort) InspectOriginal(ctx context.Context, step Step) (OriginalEffect, error) {
	var binding string
	err := p.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT spec_digest FROM compensation_test_effect WHERE step_id=?`), step.ID).Scan(&binding)
	if errors.Is(err, sql.ErrNoRows) {
		// The root's cancellation fence prevents a later forward fixture write.
		var status string
		var stopped bool
		if err = p.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,stopped FROM compensation_test_run WHERE run_id=? AND scope_digest=?`), step.Root.RunID, ScopeDigest(step.Root)).Scan(&status, &stopped); err != nil {
			return OriginalEffect{}, err
		}
		if status != "cancelling" || !stopped {
			return OriginalEffect{}, ErrPending
		}
		return OriginalEffect{StepDigest: step.Digest(), State: "no_effect", EvidenceDigest: hash("owned DB absence and stopped fence:" + step.ID)}, nil
	}
	if err != nil {
		return OriginalEffect{}, err
	}
	if binding != step.Digest() {
		return OriginalEffect{}, ErrConflict
	}
	return OriginalEffect{StepDigest: step.Digest(), State: "applied", EvidenceDigest: hash("owned forward receipt:" + step.ID)}, nil
}
func (p *fixturePort) Compensate(ctx context.Context, step Step) (Receipt, error) {
	p.calls++
	l, err := LeaseFromContext(ctx, step)
	if err != nil {
		return Receipt{}, err
	}
	r := testReceipt(step, "rolled_back")
	err = runTx(ctx, p.db, func(tx *sql.Tx) error {
		if err := p.store.GuardLeaseTx(ctx, tx, l); err != nil {
			return err
		}
		var value, expected, revision, expectedRevision int64
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT value,expected_value,revision,expected_revision FROM compensation_test_effect WHERE step_id=? AND spec_digest=? FOR UPDATE`), step.ID, step.Digest()).Scan(&value, &expected, &revision, &expectedRevision); err != nil {
			return err
		}
		if value != expected || revision != expectedRevision {
			return ErrConflict
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE compensation_test_effect SET value=before_value,revision=revision+1 WHERE step_id=? AND revision=?`), step.ID, revision); err != nil {
			return err
		}
		raw, _ := json.Marshal(r)
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO compensation_test_receipt(compensation_key,spec_digest,receipt_json) VALUES(?,?,?::jsonb)`), step.CompensationKey(), step.Digest(), string(raw)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO compensation_test_inverse_event(step_id) VALUES(?)`), step.ID)
		return err
	})
	if err != nil {
		return Receipt{}, err
	}
	if p.lostReply {
		return Receipt{}, errors.New("injected lost response after committed inverse receipt")
	}
	return r, nil
}

func fixtureEngine(t *testing.T, db *sql.DB, s *SQLStore, p *fixturePort) *Engine {
	t.Helper()
	e, err := NewEngine(s, "owned-worker", Registration{Provider: "example", Version: "v1", Timeout: 5 * time.Second, Port: p})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSQLRegistrationParticipatesInBusinessTransactionPostgres(t *testing.T) {
	ctx, db, s, _, root := ownedFixture(t)
	step := fixtureStep(root, root, "rollback")
	err := runTx(ctx, db, func(tx *sql.Tx) error {
		if err := s.RegisterTx(ctx, tx, step); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO compensation_test_effect(step_id,spec_digest,value,before_value,expected_value) VALUES(?,?,7,0,7)`), step.ID, step.Digest()); err != nil {
			return err
		}
		return errors.New("injected business failure")
	})
	if err == nil {
		t.Fatal("injected rollback did not fail")
	}
	var steps, effects, events int
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT (SELECT COUNT(*) FROM platform_compensation_step WHERE step_id=?),(SELECT COUNT(*) FROM compensation_test_effect WHERE step_id=?),(SELECT COUNT(*) FROM platform_compensation_event WHERE step_id=?)`), step.ID, step.ID, step.ID).Scan(&steps, &effects, &events); err != nil {
		t.Fatal(err)
	}
	if steps != 0 || effects != 0 || events != 0 {
		t.Fatal("effect, enrollment or audit survived failed business transaction")
	}
	if err = registerFixture(ctx, db, s, step, true); err != nil {
		t.Fatal(err)
	}
	if err = runTx(ctx, db, func(tx *sql.Tx) error { return s.RegisterTx(ctx, tx, step) }); err != nil {
		t.Fatal("idempotent enrollment", err)
	}
	other := step
	other.ProviderVersion = "v2"
	if err = runTx(ctx, db, func(tx *sql.Tx) error { return s.RegisterTx(ctx, tx, other) }); !errors.Is(err, ErrConflict) {
		t.Fatal("changed inverse contract accepted", err)
	}
}

func TestSQLReverseOrderIncludesChildEffectsAndFinalOutcomeIsAtomicPostgres(t *testing.T) {
	ctx, db, s, a, root := ownedFixture(t)
	first := fixtureStep(root, root, "first")
	child := root
	child.RunID = root.RunID + "-child"
	child.ParentRunID = root.RunID
	child.AgentID = "child-agent"
	child.AgentInstanceID = "child-instance"
	child.InstallationID = "child-install"
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO compensation_test_run(run_id,root_run_id,scope_digest,status,revision,stopped) VALUES(?,?,?,'completed',1,TRUE)`), child.RunID, root.RunID, ScopeDigest(child)); err != nil {
		t.Fatal(err)
	}
	second := fixtureStep(root, child, "second")
	second.DependsOn = []string{first.ID}
	for _, step := range []Step{first, second} {
		if err := registerFixture(ctx, db, s, step, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := beginFixture(ctx, db, s, root, true); err != nil {
		t.Fatal(err)
	}
	late := fixtureStep(root, root, "late")
	if err := registerFixture(ctx, db, s, late, true); !errors.Is(err, ErrPending) {
		t.Fatal("late forward enrollment accepted", err)
	}
	p := &fixturePort{db: db, store: s}
	e := fixtureEngine(t, db, s, p)
	for i := 0; i < 2; i++ {
		if found, err := e.Tick(ctx, root); err != nil || !found {
			t.Fatal(found, err)
		}
	}
	var order []string
	rows, err := db.QueryContext(ctx, sqlutil.Bind(`SELECT x.step_id FROM compensation_test_inverse_event x JOIN platform_compensation_step s ON s.step_id=x.step_id WHERE s.root_run_id=? ORDER BY x.ordinal`), root.RunID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		order = append(order, id)
	}
	rows.Close()
	if len(order) != 2 || order[0] != second.ID || order[1] != first.ID {
		t.Fatal("child/parent inverse order", order)
	}
	a.failFinish = true
	if err = runTx(ctx, db, func(tx *sql.Tx) error { return s.FinalizeTx(ctx, tx, root) }); err == nil {
		t.Fatal("injected terminal failure accepted")
	}
	var status, fee string
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,charged_fee::text FROM compensation_test_run WHERE run_id=?`), root.RunID).Scan(&status, &fee); err != nil {
		t.Fatal(err)
	}
	if status != "cancelling" || fee != "0.015000" {
		t.Fatal("terminal rollback or fee retention failed", status, fee)
	}
	progress, found, err := s.Progress(ctx, root)
	if err != nil || !found || progress.Phase == "complete" || progress.Unresolved != 0 {
		t.Fatal(progress, found, err)
	}
	a.failFinish = false
	if err = runTx(ctx, db, func(tx *sql.Tx) error { return s.FinalizeTx(ctx, tx, root) }); err != nil {
		t.Fatal(err)
	}
	progress, found, err = s.Progress(ctx, root)
	if err != nil || !found || progress.Phase != "complete" || progress.Compensated != 2 {
		t.Fatal(progress, found, err)
	}
	var total int
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT SUM(value) FROM compensation_test_effect WHERE step_id IN (?,?)`), first.ID, second.ID).Scan(&total); err != nil || total != 0 {
		t.Fatal("actual business values not restored", total, err)
	}
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM compensation_test_run WHERE run_id=?`), root.RunID).Scan(&status); err != nil || status != "cancelled" {
		t.Fatal("actual Run outcome missing", status, err)
	}
	wrong := root
	wrong.PrincipalID = "outsider"
	if _, visible, err := s.Progress(ctx, wrong); err != nil || visible {
		t.Fatal("progress crossed scope", visible, err)
	}
}

func TestSQLLostInverseResponseRecoversReceiptWithoutReplayPostgres(t *testing.T) {
	ctx, db, s, a, root := ownedFixture(t)
	step := fixtureStep(root, root, "lost")
	if err := registerFixture(ctx, db, s, step, true); err != nil {
		t.Fatal(err)
	}
	if err := beginFixture(ctx, db, s, root, true); err != nil {
		t.Fatal(err)
	}
	p := &fixturePort{db: db, store: s, lostReply: true}
	e := fixtureEngine(t, db, s, p)
	if _, err := e.Tick(ctx, root); err != nil {
		t.Fatal(err)
	}
	progress, _, err := s.Progress(ctx, root)
	if err != nil || progress.Unresolved != 1 || progress.Attention != 1 {
		t.Fatal("lost response became completion", progress, err)
	}
	if err = runTx(ctx, db, func(tx *sql.Tx) error { return s.FinalizeTx(ctx, tx, root) }); !errors.Is(err, ErrPending) {
		t.Fatal("unknown inverse released outcome", err)
	}
	if _, err = db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_compensation_step SET retry_at=clock_timestamp()-interval '1 second' WHERE step_id=?`), step.ID); err != nil {
		t.Fatal(err)
	}
	// New coordinator instance observes the committed receipt from PostgreSQL.
	restarted, err := NewSQLStore(db, a)
	if err != nil {
		t.Fatal(err)
	}
	e = fixtureEngine(t, db, restarted, p)
	if _, err = e.Tick(ctx, root); err != nil {
		t.Fatal(err)
	}
	var inverses int
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM compensation_test_inverse_event WHERE step_id=?`), step.ID).Scan(&inverses); err != nil || inverses != 1 || p.calls != 1 {
		t.Fatal("inverse replayed", inverses, p.calls, err)
	}
	if err = runTx(ctx, db, func(tx *sql.Tx) error { return restarted.FinalizeTx(ctx, tx, root) }); err != nil {
		t.Fatal(err)
	}
}

func TestSQLExpiredSubmittedLeaseRemainsReadOnlyAndFencedPostgres(t *testing.T) {
	ctx, db, s, _, root := ownedFixture(t)
	step := fixtureStep(root, root, "unknown")
	if err := registerFixture(ctx, db, s, step, true); err != nil {
		t.Fatal(err)
	}
	if err := beginFixture(ctx, db, s, root, true); err != nil {
		t.Fatal(err)
	}
	old, found, err := s.Claim(ctx, root, "crashed-worker", time.Second)
	if err != nil || !found {
		t.Fatal(found, err)
	}
	if err = s.MarkSubmitted(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_compensation_step SET lease_until=clock_timestamp()-interval '1 second' WHERE step_id=?`), step.ID); err != nil {
		t.Fatal(err)
	}
	current, found, err := s.Claim(ctx, root, "replacement", time.Minute)
	if err != nil || !found || !current.Submitted || current.Fence != old.Fence+1 {
		t.Fatal(current, found, err)
	}
	r := testReceipt(step, "rolled_back")
	if err = s.Resolve(ctx, old, Resolution{Receipt: &r}); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale completion accepted", err)
	}
	if err = runTx(ctx, db, func(tx *sql.Tx) error { return s.GuardLeaseTx(ctx, tx, old) }); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale inverse commit guard accepted", err)
	}
	if err = s.Resolve(ctx, current, Resolution{Code: "COMPENSATION_RESULT_UNKNOWN", RetryAt: time.Now().Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	p := &fixturePort{db: db, store: s}
	e := fixtureEngine(t, db, s, p)
	if _, err = e.Tick(ctx, root); err != nil {
		t.Fatal(err)
	}
	if p.calls != 0 {
		t.Fatal("submitted inverse replayed after owner crash")
	}
	if err = runTx(ctx, db, func(tx *sql.Tx) error { return s.FinalizeTx(ctx, tx, root) }); !errors.Is(err, ErrPending) {
		t.Fatal("unconfirmed side effect fabricated as cancelled", err)
	}
}

func TestSQLCannotCompensateBeforeStopOrOverwriteConcurrentBusinessWritePostgres(t *testing.T) {
	ctx, db, s, _, root := ownedFixture(t)
	step := fixtureStep(root, root, "concurrent")
	if err := registerFixture(ctx, db, s, step, true); err != nil {
		t.Fatal(err)
	}
	if err := beginFixture(ctx, db, s, root, false); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.Claim(ctx, root, "premature", time.Second); err != nil || found {
		t.Fatal("inverse admitted before stopped tree", found, err)
	}
	proof := StopProof{Version: "cancellation-tree-stop/v1", ScopeDigest: ScopeDigest(root), Revision: 2, EvidenceDigest: hash("stop")}
	if err := runTx(ctx, db, func(tx *sql.Tx) error { return s.ConfirmStoppedTx(ctx, tx, root, proof) }); !errors.Is(err, ErrPending) {
		t.Fatal("invented stop evidence accepted", err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE compensation_test_run SET stopped=TRUE WHERE run_id=?`), root.RunID); err != nil {
		t.Fatal(err)
	}
	if err := runTx(ctx, db, func(tx *sql.Tx) error { return s.ConfirmStoppedTx(ctx, tx, root, proof) }); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE compensation_test_effect SET value=9,revision=2 WHERE step_id=?`), step.ID); err != nil {
		t.Fatal(err)
	}
	p := &fixturePort{db: db, store: s}
	e := fixtureEngine(t, db, s, p)
	if _, err := e.Tick(ctx, root); err != nil {
		t.Fatal(err)
	}
	var value int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT value FROM compensation_test_effect WHERE step_id=?`), step.ID).Scan(&value); err != nil || value != 9 {
		t.Fatal("concurrent user's write overwritten", value, err)
	}
	if err := runTx(ctx, db, func(tx *sql.Tx) error { return s.FinalizeTx(ctx, tx, root) }); !errors.Is(err, ErrPending) {
		t.Fatal("conflicted rollback became complete", err)
	}
}

func TestSQLConcurrentClaimsSerializeTheNextInversePostgres(t *testing.T) {
	ctx, db, s, _, root := ownedFixture(t)
	step := fixtureStep(root, root, "serialize")
	if err := registerFixture(ctx, db, s, step, true); err != nil {
		t.Fatal(err)
	}
	if err := beginFixture(ctx, db, s, root, true); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	found := make(chan bool, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := s.Claim(ctx, root, "worker", time.Minute)
			found <- ok
			errs <- err
		}()
	}
	wg.Wait()
	close(found)
	close(errs)
	count := 0
	for ok := range found {
		if ok {
			count++
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if count != 1 {
		t.Fatal("parallel controllers claimed same effect", count)
	}
}

func TestSQLMissingEffectRequiresNoEffectProofAndWrongStopRevisionIsDeniedPostgres(t *testing.T) {
	ctx, db, s, _, root := ownedFixture(t)
	step := fixtureStep(root, root, "unsubmitted")
	if err := registerFixture(ctx, db, s, step, false); err != nil {
		t.Fatal(err)
	}
	if err := beginFixture(ctx, db, s, root, true); err != nil {
		t.Fatal(err)
	}
	wrong := StopProof{Version: "cancellation-tree-stop/v1", ScopeDigest: ScopeDigest(root), Revision: 3, EvidenceDigest: hash("bad head")}
	if err := runTx(ctx, db, func(tx *sql.Tx) error { return s.ConfirmStoppedTx(ctx, tx, root, wrong) }); err == nil {
		t.Fatal("stop proof changed cancellation revision")
	}
	p := &fixturePort{db: db, store: s}
	e := fixtureEngine(t, db, s, p)
	if _, err := e.Tick(ctx, root); err != nil {
		t.Fatal(err)
	}
	progress, found, err := s.Progress(ctx, root)
	if err != nil || !found || progress.NoEffect != 1 || progress.Unresolved != 0 || p.calls != 0 {
		t.Fatal("proven absent effect", progress, p.calls, err)
	}
	if err = runTx(ctx, db, func(tx *sql.Tx) error { return s.FinalizeTx(ctx, tx, root) }); err != nil {
		t.Fatal(err)
	}
}
