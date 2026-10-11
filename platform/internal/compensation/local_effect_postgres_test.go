package compensation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

type ownedLocalFixture struct{ calls int }

func (p *ownedLocalFixture) RestoreEffectTx(ctx context.Context, tx *sql.Tx, step Step, e LocalEffect) error {
	p.calls++
	var before struct {
		Value int `json:"value"`
	}
	if json.Unmarshal(e.Before, &before) != nil {
		return ErrInvalid
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE compensation_test_effect SET value=?,revision=revision+1 WHERE step_id=? AND spec_digest=? AND expected_value=value`), before.Value, step.ID, e.ExpectedToken)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}

func TestLocalEffectBeforeImageAndInverseReceiptAreAtomicPostgres(t *testing.T) {
	ctx, db, store, _, root := ownedFixture(t)
	if err := runTx(ctx, db, func(tx *sql.Tx) error {
		facade := sqlutil.TransactionDB(tx)
		defer facade.Close()
		return ApplyLocalEffectSchema(ctx, facade)
	}); err != nil {
		t.Fatal(err)
	}
	ledger, err := NewLocalEffectLedger(ctx, db, store)
	if err != nil {
		t.Fatal(err)
	}
	step := fixtureStep(root, root, "local-before-image")
	step.Provider = "local-fixture"
	step.ProviderVersion = "v1"
	effect := LocalEffect{Before: json.RawMessage(`{"value":0}`), ExpectedToken: hash("owned resource version")}
	rollback := errors.New("forward rollback")
	err = runTx(ctx, db, func(tx *sql.Tx) error {
		if err := ledger.RecordTx(ctx, tx, step, effect); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_compensation_local_effect WHERE step_id=?`), step.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial forward effect: %d %v", count, err)
	}
	err = runTx(ctx, db, func(tx *sql.Tx) error {
		if err := ledger.RecordTx(ctx, tx, step, effect); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO compensation_test_effect(step_id,spec_digest,value,before_value,expected_value) VALUES(?,?,7,0,7)`), step.ID, effect.ExpectedToken)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = beginFixture(ctx, db, store, root, true); err != nil {
		t.Fatal(err)
	}
	owner := &ownedLocalFixture{}
	port, err := ledger.Port(step.Provider, step.ProviderVersion, owner)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(store, "local-fixture-worker", Registration{Provider: step.Provider, Version: step.ProviderVersion, Timeout: time.Second, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.Tick(ctx, root); err != nil {
		t.Fatal(err)
	}
	if owner.calls != 1 {
		t.Fatalf("inverse calls=%d", owner.calls)
	}
	receipt, found, err := port.Lookup(ctx, step)
	if err != nil || !found || receipt.Validate(step) != nil {
		t.Fatalf("missing authoritative inverse receipt: %v", err)
	}
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT value FROM compensation_test_effect WHERE step_id=?`), step.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("resource not restored: %d %v", count, err)
	}
	if _, err = engine.Tick(ctx, root); err != nil || owner.calls != 1 {
		t.Fatalf("inverse replayed: %v", err)
	}
	wrong := step
	wrong.ProviderVersion = "v2"
	if _, _, err = port.Lookup(ctx, wrong); !errors.Is(err, ErrInvalid) {
		t.Fatalf("version crossed: %v", err)
	}
}

func TestLocalEffectConcurrentResourceWriteCannotBeOverwrittenPostgres(t *testing.T) {
	ctx, db, store, _, root := ownedFixture(t)
	if err := runTx(ctx, db, func(tx *sql.Tx) error {
		facade := sqlutil.TransactionDB(tx)
		defer facade.Close()
		return ApplyLocalEffectSchema(ctx, facade)
	}); err != nil {
		t.Fatal(err)
	}
	ledger, err := NewLocalEffectLedger(ctx, db, store)
	if err != nil {
		t.Fatal(err)
	}
	step := fixtureStep(root, root, "local-conflict")
	step.Provider = "local-fixture"
	step.ProviderVersion = "v1"
	effect := LocalEffect{Before: json.RawMessage(`{"value":0}`), ExpectedToken: hash("owned resource version")}
	err = runTx(ctx, db, func(tx *sql.Tx) error {
		if err := ledger.RecordTx(ctx, tx, step, effect); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO compensation_test_effect(step_id,spec_digest,value,before_value,expected_value) VALUES(?,?,99,0,7)`), step.ID, effect.ExpectedToken)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = beginFixture(ctx, db, store, root, true); err != nil {
		t.Fatal(err)
	}
	owner := &ownedLocalFixture{}
	port, _ := ledger.Port(step.Provider, step.ProviderVersion, owner)
	engine, _ := NewEngine(store, "local-conflict-worker", Registration{Provider: step.Provider, Version: step.ProviderVersion, Timeout: time.Second, Port: port})
	if _, err = engine.Tick(ctx, root); err != nil {
		t.Fatal(err)
	}
	if _, found, err := port.Lookup(ctx, step); err != nil || found {
		t.Fatal("conflict invented a receipt")
	}
	var value int
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT value FROM compensation_test_effect WHERE step_id=?`), step.ID).Scan(&value); err != nil || value != 99 {
		t.Fatalf("later write erased: %d %v", value, err)
	}
	if err = store.TryFinalize(ctx, root); !errors.Is(err, ErrPending) {
		t.Fatalf("conflict completed cancellation: %v", err)
	}
}
