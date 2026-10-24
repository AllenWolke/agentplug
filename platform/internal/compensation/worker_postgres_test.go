package compensation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Other tests deliberately retain unresolved roots in the same fixture DB.
// Select only this test's root; Claim, inverse transactions and finalization
// still use the actual PostgreSQL implementation and its original fences.
type rootWorkerFixture struct {
	*SQLStore
	root sharedkernel.Scope
}

func (s rootWorkerFixture) ListPending(ctx context.Context, _ int) ([]sharedkernel.Scope, error) {
	p, found, err := s.Progress(ctx, s.root)
	if err != nil {
		return nil, err
	}
	if !found || p.Phase == "complete" {
		return nil, nil
	}
	return []sharedkernel.Scope{s.root}, nil
}

func TestSQLWorkerDrainsThousandUniqueInversesWithoutPerStepIdlePostgres(t *testing.T) {
	ctx, db, s, _, root := ownedFixture(t)
	ctx, cancelFixture := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelFixture()
	const count = 1000
	err := runTx(ctx, db, func(tx *sql.Tx) error {
		for i := 0; i < count; i++ {
			step := fixtureStep(root, root, fmt.Sprintf("drain-%04d", i))
			if err := s.RegisterTx(ctx, tx, step); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO compensation_test_effect(step_id,spec_digest,value,before_value,expected_value) VALUES(?,?,7,0,7)`), step.ID, step.Digest()); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = beginFixture(ctx, db, s, root, true); err != nil {
		t.Fatal(err)
	}
	p := &fixturePort{db: db, store: s}
	e := fixtureEngine(t, db, s, p)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	completed := false
	failed := false
	yields := 0
	started := time.Now()
	err = e.run(runCtx, rootWorkerFixture{s, root}, 5*time.Second, func(stats SweepStats, readFailed bool) {
		if stats.Failed != 0 || readFailed {
			failed = true
			cancel()
		}
		if stats.Completed != 0 {
			completed = true
			cancel()
		}
	}, func(ctx context.Context, d time.Duration) error {
		if d != 10*time.Millisecond {
			return fmt.Errorf("unexpected idle with an eligible known backlog: %v", d)
		}
		yields++
		return waitWorker(ctx, d)
	})
	if !errors.Is(err, context.Canceled) || !completed || failed || p.calls != count || yields == 0 {
		t.Fatalf("drain incomplete: completed=%t failed=%t calls=%d yields=%d error=%v", completed, failed, p.calls, yields, err)
	}
	var events, unique, restored int
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*),COUNT(DISTINCT i.step_id) FROM compensation_test_inverse_event i JOIN platform_cancellation_effect e ON e.step_id=i.step_id WHERE e.root_run_id=?`), root.RunID).Scan(&events, &unique); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM compensation_test_effect v JOIN platform_cancellation_effect e ON e.step_id=v.step_id WHERE e.root_run_id=? AND v.value=v.before_value AND v.revision=2`), root.RunID).Scan(&restored); err != nil {
		t.Fatal(err)
	}
	if events != count || unique != count || restored != count {
		t.Fatal("missing or duplicate inverse", events, unique, restored)
	}
	progress, found, err := s.Progress(ctx, root)
	if err != nil || !found || progress.Phase != "complete" || progress.Unresolved != 0 || progress.Compensated != count {
		t.Fatal(progress, found, err)
	}
	if handled, err := e.Tick(ctx, root); err != nil || handled || p.calls != count {
		t.Fatal("finished root replayed", handled, p.calls, err)
	}
	t.Logf("1000 distinct inverse receipts, no duplicates, %d bounded yields, elapsed=%s", yields, time.Since(started))
}

func TestSQLFinalizeFastPendingGateStillChecksEveryTerminalReceiptPostgres(t *testing.T) {
	ctx, db, s, _, root := ownedFixture(t)
	step := fixtureStep(root, root, "corrupted-receipt")
	if err := registerFixture(ctx, db, s, step, true); err != nil {
		t.Fatal(err)
	}
	if err := beginFixture(ctx, db, s, root, true); err != nil {
		t.Fatal(err)
	}
	if err := s.TryFinalize(ctx, root); !errors.Is(err, ErrPending) {
		t.Fatal("pending gate finalized", err)
	}
	p := &fixturePort{db: db, store: s}
	e := fixtureEngine(t, db, s, p)
	if handled, err := e.Tick(ctx, root); err != nil || !handled {
		t.Fatal(handled, err)
	}
	// Fixture-only corruption: a terminal phase alone is never completion proof.
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_compensation_step SET receipt_json='{}'::jsonb WHERE step_id=?`), step.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.TryFinalize(ctx, root); !errors.Is(err, ErrPending) {
		t.Fatal("invalid terminal receipt accepted", err)
	}
	var status string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM compensation_test_run WHERE run_id=?`), root.RunID).Scan(&status); err != nil || status != "cancelling" {
		t.Fatal("invalid receipt closed the root", status, err)
	}
}
