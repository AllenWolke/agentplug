package compensation

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLStoppedTreeCoverageWithAppendOnlyRuntimeRolePostgres(t *testing.T) {
	ctx, db, store, _, root := ownedFixture(t)
	if err := registerFixture(ctx, db, store, fixtureStep(root, root, "read-only-enrollment"), false); err != nil {
		t.Fatal(err)
	}
	if err := beginFixture(ctx, db, store, root, true); err != nil {
		t.Fatal(err)
	}
	role := "coverage_reader_" + root.RunID[4:]
	quoted := pgx.Identifier{role}.Sanitize()
	if _, err := db.ExecContext(ctx, "CREATE ROLE "+quoted+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP OWNED BY "+quoted)
		_, _ = db.ExecContext(context.Background(), "DROP ROLE "+quoted)
	})
	for _, statement := range []string{
		"GRANT SELECT,UPDATE ON platform_compensation_step TO " + quoted,
		"GRANT SELECT ON platform_cancellation_effect TO " + quoted,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := runTx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE "+quoted); err != nil {
			return err
		}
		var mutable bool
		if err := tx.QueryRowContext(ctx, `SELECT has_table_privilege('platform_cancellation_effect','UPDATE,DELETE')`).Scan(&mutable); err != nil {
			return err
		}
		if mutable {
			t.Fatal("runtime role can mutate enrollment history")
		}
		return store.VerifyStoppedTreeCoverageTx(ctx, tx, root, []sharedkernel.Scope{root})
	}); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE "+quoted); err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `UPDATE platform_cancellation_effect SET spec_digest=spec_digest WHERE FALSE`)
	var database interface{ SQLState() string }
	if !errors.As(err, &database) || database.SQLState() != "42501" {
		t.Fatal("history UPDATE must remain forbidden")
	}
}

func TestSQLStoppedTreeCoverageRequiresExactRecordedSetPostgres(t *testing.T) {
	ctx, db, store, _, root := ownedFixture(t)
	child := root
	child.RunID, child.ParentRunID = root.RunID+"-coverage-child", root.RunID
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO compensation_test_run(run_id,root_run_id,scope_digest,status,revision) VALUES(?,?,?,'running',1)`), child.RunID, root.RunID, ScopeDigest(child)); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []sharedkernel.Scope{root, child} {
		if err := registerFixture(ctx, db, store, fixtureStep(scope, scope, "coverage-owned"), false); err != nil {
			t.Fatal(err)
		}
	}
	err := runTx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE compensation_test_run SET status='cancelling',revision=2,stopped=TRUE WHERE run_id=?`), root.RunID); err != nil {
			return err
		}
		if _, err := store.BeginTx(ctx, tx, root, 2); err != nil {
			return err
		}
		if err := store.VerifyStoppedTreeCoverageTx(ctx, tx, root, []sharedkernel.Scope{root, child}); !errors.Is(err, ErrConflict) {
			t.Fatalf("missing child effect accepted: %v", err)
		}
		if err := store.EnrollStoppedTreeTx(ctx, tx, root, []sharedkernel.Scope{root, child}); err != nil {
			return err
		}
		if err := store.VerifyStoppedTreeCoverageTx(ctx, tx, root, []sharedkernel.Scope{root}); !errors.Is(err, ErrConflict) {
			t.Fatalf("extra descendant concealed: %v", err)
		}
		return store.ConfirmStoppedTx(ctx, tx, root, StopProof{Version: "cancellation-tree-stop/v1", ScopeDigest: ScopeDigest(root), Revision: 2, EvidenceDigest: hash("coverage stopped fixture")})
	})
	if err != nil {
		t.Fatal(err)
	}
	err = runTx(ctx, db, func(tx *sql.Tx) error {
		var prior int
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_compensation_event WHERE root_run_id=?`), root.RunID).Scan(&prior); err != nil {
			return err
		}
		if err := store.EnrollStoppedTreeTx(ctx, tx, root, []sharedkernel.Scope{root, child}); err != nil {
			return err
		}
		var after int
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_compensation_event WHERE root_run_id=?`), root.RunID).Scan(&after); err != nil {
			return err
		}
		if prior != after {
			t.Fatal("confirmed coverage replay appended new enrollment")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSQLStoppedTreeCoverageRejectsScopeSubstitutionAndCorruptEffectsPostgres(t *testing.T) {
	ctx, db, store, _, root := ownedFixture(t)
	step := fixtureStep(root, root, "corrupt-coverage")
	if err := registerFixture(ctx, db, store, step, false); err != nil {
		t.Fatal(err)
	}
	if err := beginFixture(ctx, db, store, root, true); err != nil {
		t.Fatal(err)
	}
	if err := runTx(ctx, db, func(tx *sql.Tx) error {
		other := root
		other.PrincipalID = "wrong-owner"
		if err := store.VerifyStoppedTreeCoverageTx(ctx, tx, root, []sharedkernel.Scope{other}); !errors.Is(err, ErrConflict) {
			t.Fatalf("substituted owner accepted: %v", err)
		}
		if err := store.VerifyStoppedTreeCoverageTx(ctx, tx, root, []sharedkernel.Scope{root, root}); !errors.Is(err, ErrConflict) {
			t.Fatal("duplicate scope accepted")
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_compensation_step SET spec_digest=? WHERE step_id=?`), hash("bad-binding"), step.ID); err != nil {
			return err
		}
		if _, err := store.RecordedEffectsTx(ctx, tx, root); !errors.Is(err, ErrConflict) {
			t.Fatalf("invalid immutable binding accepted: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
