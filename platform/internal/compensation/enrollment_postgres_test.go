package compensation

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Direct-edge authority is a component fixture, not the production routing
// owner. The production owner must inspect its durable admission reservations.
func (a *fixtureAuthority) EnrollRecordedEffectTx(ctx context.Context, tx *sql.Tx, control sharedkernel.Scope, step Step) error {
	status, _, _, _, err := fixtureRun(ctx, tx, control)
	if err != nil {
		return err
	}
	if status != "cancelling" {
		return ErrPending
	}
	if step.Root == control {
		return nil
	}
	if step.Root != step.Scope || step.Scope.ParentRunID != control.RunID {
		return ErrConflict
	}
	var parent, binding string
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT root_run_id,scope_digest FROM compensation_test_run WHERE run_id=?`), step.Scope.RunID).Scan(&parent, &binding); err != nil {
		return err
	}
	if parent != control.RunID || binding != ScopeDigest(step.Scope) {
		return ErrConflict
	}
	return nil
}

func TestSQLEnrolledParentReusesChildInverseAndExcludesSiblingFromChildCancelPostgres(t *testing.T) {
	ctx, db, store, _, root := ownedFixture(t)
	child := root
	child.RunID = root.RunID + "-child"
	child.ParentRunID = root.RunID
	sibling := child
	sibling.RunID = root.RunID + "-sibling"
	for _, scope := range []sharedkernel.Scope{child, sibling} {
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO compensation_test_run(run_id,root_run_id,scope_digest,status,revision) VALUES(?,?,?,'running',1)`), scope.RunID, root.RunID, ScopeDigest(scope)); err != nil {
			t.Fatal(err)
		}
	}
	first := fixtureStep(child, child, "owned-child")
	second := fixtureStep(sibling, sibling, "owned-sibling")
	for _, step := range []Step{first, second} {
		if err := registerFixture(ctx, db, store, step, true); err != nil {
			t.Fatal(err)
		}
	}
	port := &fixturePort{db: db, store: store}
	engine, err := NewEngine(store, "enrollment-worker", Registration{Provider: first.Provider, Version: first.ProviderVersion, Timeout: time.Second, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if err = beginFixture(ctx, db, store, child, true); err != nil {
		t.Fatal(err)
	}
	if _, err = engine.Tick(ctx, child); err != nil {
		t.Fatal(err)
	}
	if err = store.TryFinalize(ctx, child); err != nil {
		t.Fatal(err)
	}
	var value int
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT value FROM compensation_test_effect WHERE step_id=?`), second.ID).Scan(&value); err != nil || value != 7 {
		t.Fatal("child cancellation touched sibling")
	}
	originalKey := first.CompensationKey()
	err = runTx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE compensation_test_run SET status='cancelling',revision=2,stopped=TRUE WHERE run_id=?`), root.RunID); err != nil {
			return err
		}
		if _, err := store.BeginTx(ctx, tx, root, 2); err != nil {
			return err
		}
		for _, step := range []Step{first, second} {
			if err := store.EnrollRecordedTx(ctx, tx, root, step.ID); err != nil {
				return err
			}
		}
		return store.ConfirmStoppedTx(ctx, tx, root, StopProof{Version: "cancellation-tree-stop/v1", ScopeDigest: ScopeDigest(root), Revision: 2, EvidenceDigest: hash("parent fixture stopped")})
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.Tick(ctx, root); err != nil {
		t.Fatal(err)
	}
	if err = store.TryFinalize(ctx, root); err != nil {
		t.Fatal(err)
	}
	if first.CompensationKey() != originalKey || port.calls != 2 {
		t.Fatalf("child inverse replayed: %d", port.calls)
	}
	progress, found, err := store.Progress(ctx, root)
	if err != nil || !found || progress.Total != 2 || progress.Compensated != 2 || progress.Phase != "complete" {
		t.Fatalf("incomplete parent projection: %#v %v", progress, err)
	}
}

func TestSQLEnrollmentCannotCrossScopeOrHideMismatchedDigestPostgres(t *testing.T) {
	ctx, db, store, _, root := ownedFixture(t)
	step := fixtureStep(root, root, "mismatched-enrollment")
	if err := registerFixture(ctx, db, store, step, false); err != nil {
		t.Fatal(err)
	}
	if err := beginFixture(ctx, db, store, root, true); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_cancellation_effect SET spec_digest=? WHERE root_run_id=? AND step_id=?`), hash("corrupted enrollment"), root.RunID, step.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Progress(ctx, root); !errors.Is(err, ErrConflict) {
		t.Fatalf("bad enrollment concealed: %v", err)
	}
	if err := store.TryFinalize(ctx, root); !errors.Is(err, ErrPending) {
		t.Fatalf("bad enrollment completed cancellation: %v", err)
	}
}
