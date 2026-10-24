package capability

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

const memoryCompensationProvider = "platform.memory"
const memoryCompensationVersion = "memory-undo.v1"

// Separate additive migration; never modify the earlier memory DDL checksum.
func MigrateMemoryCompensation(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `ALTER TABLE platform_memory_entry ADD COLUMN IF NOT EXISTS effect_stamp VARCHAR(64) NOT NULL DEFAULT (md5(random()::text||clock_timestamp()::text)||md5(random()::text||clock_timestamp()::text));
CREATE OR REPLACE FUNCTION platform_memory_effect_stamp() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.effect_stamp IS NOT DISTINCT FROM OLD.effect_stamp THEN
  NEW.effect_stamp=md5(random()::text||clock_timestamp()::text)||md5(random()::text||clock_timestamp()::text);
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS platform_memory_effect_stamp_trigger ON platform_memory_entry;
CREATE TRIGGER platform_memory_effect_stamp_trigger BEFORE UPDATE ON platform_memory_entry FOR EACH ROW EXECUTE FUNCTION platform_memory_effect_stamp();`)
	return err
}

type memoryCancellation struct {
	ledger compensation.LocalEffects
	root   func(context.Context, *sql.Tx, sharedkernel.Scope) (sharedkernel.Scope, error)
	bind   func(context.Context, *sql.Tx, sharedkernel.Scope) context.Context
}

// Startup-only binder joins current-authority callbacks to the caller's
// transaction. Child writes must not open another connection waiting on the
// ancestor fences held by their own effect transaction.
func (s *SQLMemoryStore) SetCancellationTransactionContext(bind func(context.Context, *sql.Tx, sharedkernel.Scope) context.Context) error {
	if s == nil || s.cancellation == nil || bind == nil || s.cancellation.bind != nil {
		return compensation.ErrInvalid
	}
	s.cancellation.bind = bind
	return nil
}

type memoryMutation struct {
	Scope               sharedkernel.Scope
	CallID, Fingerprint string
}
type memoryMutationKey struct{}
type memoryBeforeImage struct {
	Exists    bool            `json:"exists"`
	Prefix    string          `json:"prefix"`
	Value     json.RawMessage `json:"value,omitempty"`
	ExpiresAt time.Time       `json:"expires_at,omitempty"`
	CreatedAt time.Time       `json:"created_at,omitempty"`
	Stamp     string          `json:"stamp,omitempty"`
}

func (s *SQLMemoryStore) SetCancellationCompensation(ledger compensation.LocalEffects, root func(context.Context, *sql.Tx, sharedkernel.Scope) (sharedkernel.Scope, error)) error {
	if s == nil || ledger == nil || root == nil || s.cancellation != nil {
		return compensation.ErrInvalid
	}
	s.cancellation = &memoryCancellation{ledger: ledger, root: root}
	return nil
}

func (s *SQLMemoryStore) MemoryCompensationRegistration() (compensation.Registration, error) {
	if s == nil || s.cancellation == nil {
		return compensation.Registration{}, compensation.ErrUnavailable
	}
	port, err := s.cancellation.ledger.BindOwner(memoryCompensationProvider, memoryCompensationVersion, s)
	return compensation.Registration{Provider: memoryCompensationProvider, Version: memoryCompensationVersion, Timeout: 3 * time.Second, Port: port}, err
}

func (s *SQLMemoryStore) prepareMemoryEffectTx(ctx context.Context, tx *sql.Tx, hash string) (compensation.Step, bool, error) {
	if s.cancellation == nil {
		return compensation.Step{}, false, nil
	}
	mutation, ok := ctx.Value(memoryMutationKey{}).(memoryMutation)
	if !ok || mutation.Scope.ValidateTrusted() != nil {
		return compensation.Step{}, false, compensation.ErrInvalid
	}
	root, err := s.cancellation.root(ctx, tx, mutation.Scope)
	if err != nil {
		return compensation.Step{}, false, err
	}
	step := compensation.Step{Root: root, Scope: mutation.Scope, Kind: "memory", Tool: "memory.save", Provider: memoryCompensationProvider, ProviderVersion: memoryCompensationVersion, CallID: mutation.CallID, Fingerprint: mutation.Fingerprint, Ref: hash}
	step.ID = compensation.StepID(step.Scope, step.Kind, step.CallID)
	replay, err := s.cancellation.ledger.AppliedTx(ctx, tx, step)
	return step, replay, err
}

func (s *SQLMemoryStore) captureMemoryEffectTx(ctx context.Context, tx *sql.Tx, step compensation.Step, prefix string) (string, error) {
	before := memoryBeforeImage{Prefix: prefix}
	var value []byte
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT scope_prefix,value_json,expires_at,created_at,effect_stamp FROM platform_memory_entry WHERE scope_key=? FOR UPDATE`), step.Ref).Scan(&before.Prefix, &value, &before.ExpiresAt, &before.CreatedAt, &before.Stamp)
	before.Value = value
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	before.Exists = err == nil
	if before.Prefix != prefix {
		return "", compensation.ErrConflict
	}
	raw, err := json.Marshal(before)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte("memory-forward/v1\x00" + step.Digest()))
	stamp := hex.EncodeToString(h[:])
	if err = s.cancellation.ledger.RecordTx(ctx, tx, step, compensation.LocalEffect{Before: raw, ExpectedToken: stamp}); err != nil {
		return "", err
	}
	return stamp, nil
}

func (s *SQLMemoryStore) RestoreEffectTx(ctx context.Context, tx *sql.Tx, step compensation.Step, effect compensation.LocalEffect) error {
	if s == nil || s.cancellation == nil || step.Kind != "memory" || step.Tool != "memory.save" || step.Provider != memoryCompensationProvider || step.ProviderVersion != memoryCompensationVersion || len(step.Ref) != 64 {
		return compensation.ErrInvalid
	}
	var before memoryBeforeImage
	if json.Unmarshal(effect.Before, &before) != nil || len(before.Prefix) != 64 || (before.Exists && (!json.Valid(before.Value) || len(before.Stamp) != 64 || before.ExpiresAt.IsZero() || before.CreatedAt.IsZero())) {
		return compensation.ErrConflict
	}
	if err := lockLedgerScope(ctx, tx, "memory-prefix", before.Prefix); err != nil {
		return err
	}
	var changed sql.Result
	var err error
	if !before.Exists || !time.Now().UTC().Before(before.ExpiresAt) {
		changed, err = tx.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_memory_entry WHERE scope_key=? AND scope_prefix=? AND effect_stamp=?`), step.Ref, before.Prefix, effect.ExpectedToken)
	} else {
		// The causal stamp returns to its predecessor, so earlier inverses can
		// unwind in order. All ordinary writers, including legacy UPDATEs,
		// receive a fresh stamp from the trigger and cannot create an ABA.
		changed, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_memory_entry SET value_json=?,expires_at=?,created_at=?,updated_at=clock_timestamp(),effect_stamp=? WHERE scope_key=? AND scope_prefix=? AND effect_stamp=?`), string(before.Value), before.ExpiresAt, before.CreatedAt, before.Stamp, step.Ref, before.Prefix, effect.ExpectedToken)
	}
	if err != nil {
		return err
	}
	count, err := changed.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return compensation.ErrConflict
	}
	return nil
}
