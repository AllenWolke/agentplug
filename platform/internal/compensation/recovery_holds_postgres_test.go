package compensation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLAutomaticRecoveryHoldsPreserveUnknownAndAdmitNewRootPostgres(t *testing.T) {
	ctx, db, s, _, old := ownedFixture(t)
	fresh := old
	fresh.RunID += "-new"
	fresh.SessionID = fresh.RunID
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO compensation_test_run(run_id,root_run_id,scope_digest,status,revision)VALUES(?,?,?,'running',1)`), fresh.RunID, fresh.RunID, ScopeDigest(fresh)); err != nil {
		t.Fatal(err)
	}
	for _, root := range []sharedkernel.Scope{old, fresh} {
		if err := registerFixture(ctx, db, s, fixtureStep(root, root, root.RunID+"-effect"), true); err != nil {
			t.Fatal(err)
		}
		if err := beginFixture(ctx, db, s, root, true); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.QueryContext(ctx, `SELECT root_run_id FROM platform_cancellation_operation WHERE root_run_id<>$1`, fresh.RunID)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	holds, err := sharedkernel.NewRecoveryHolds(ids)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetAutomaticRecoveryHolds(holds); err != nil {
		t.Fatal(err)
	}
	readOld := func() string {
		t.Helper()
		var raw string
		if err := db.QueryRowContext(ctx, `SELECT jsonb_build_object('job',(SELECT to_jsonb(j)FROM platform_cancellation_operation j WHERE root_run_id=$1),'steps',(SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id)FROM platform_compensation_step x WHERE root_run_id=$1),'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id)FROM platform_compensation_event e WHERE root_run_id=$1))::text`, old.RunID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := readOld()
	port := &fixturePort{db: db, store: s}
	engine := fixtureEngine(t, db, s, port)
	for restart := 0; restart < 2; restart++ {
		if restart != 0 {
			reopened, err := NewSQLStore(db, &fixtureAuthority{})
			if err != nil {
				t.Fatal(err)
			}
			if err = reopened.SetAutomaticRecoveryHolds(holds); err != nil {
				t.Fatal(err)
			}
			s = reopened
			engine = fixtureEngine(t, db, s, port)
		}
		for n := 0; n < 3; n++ {
			if _, err := engine.Sweep(ctx, s, 1); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := s.Claim(context.Background(), old, "must-not-run", time.Minute); !errors.Is(err, sharedkernel.ErrAutomaticRecoveryHeld) {
			t.Fatal("held inverse admitted", err)
		}
		if err := s.TryFinalize(ctx, old); !errors.Is(err, sharedkernel.ErrAutomaticRecoveryHeld) {
			t.Fatal("held unknown finalized", err)
		}
		if readOld() != before {
			t.Fatal("held history, lease, receipt or phase changed")
		}
	}
	progress, found, err := s.Progress(ctx, fresh)
	if err != nil || !found || progress.Phase != "complete" || port.calls != 1 {
		t.Fatal("new root did not finish exactly once", err)
	}
}
