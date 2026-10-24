package compensation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/lexagent/platform/internal/sqlutil"
)

const LocalEffectSchemaVersion uint64 = 2026100902

const localEffectDDL = `
CREATE TABLE IF NOT EXISTS platform_compensation_local_effect (
 step_id VARCHAR(64) PRIMARY KEY,
 spec_digest VARCHAR(64) NOT NULL,
 provider VARCHAR(128) NOT NULL,
 provider_version VARCHAR(128) NOT NULL,
 effect_ref VARCHAR(255) NOT NULL,
 before_image JSONB NOT NULL,
 expected_token VARCHAR(64) NOT NULL,
 receipt_json JSONB NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 compensated_at TIMESTAMPTZ NULL);
`

// ApplyLocalEffectSchema belongs to an explicit migration transaction. The
// original coordinator migration is immutable; this is a separate version.
func ApplyLocalEffectSchema(ctx context.Context, db *sql.DB) error {
	if ctx == nil || db == nil {
		return ErrInvalid
	}
	if _, err := db.ExecContext(ctx, `SELECT pg_advisory_xact_lock(2026100902,16)`); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, localEffectDDL); err != nil {
		return err
	}
	h := sha256.Sum256([]byte(localEffectDDL))
	sum := hex.EncodeToString(h[:])
	var prior string
	err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT checksum FROM platform_compensation_schema_version WHERE version=?`), LocalEffectSchemaVersion).Scan(&prior)
	if err == nil && prior != sum {
		return ErrConflict
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		_, err = db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_compensation_schema_version(version,checksum,applied_at) VALUES(?,?,clock_timestamp())`), LocalEffectSchemaVersion, sum)
		if err != nil {
			return err
		}
	}
	return protectHistoryGrants(ctx, db)
}

// LocalEffect contains private owner-module state. It is never serialized into
// the cancellation projection, audit payload or Evaluation report.
type LocalEffect struct {
	Before        json.RawMessage
	ExpectedToken string
}

// LocalEffectOwner restores only its own versioned resource, using a compare
// and swap on ExpectedToken. It must preserve later writes and append its own
// domain audit in this transaction. This port exposes no arbitrary SQL API.
type LocalEffectOwner interface {
	RestoreEffectTx(context.Context, *sql.Tx, Step, LocalEffect) error
}

type LocalEffectLedger struct {
	db          *sql.DB
	coordinator *SQLStore
}

// AppliedTx is a forward-side idempotency check, still under the original
// live execution authority. It never returns the sensitive before-image.
func (s *LocalEffectLedger) AppliedTx(ctx context.Context, tx *sql.Tx, step Step) (bool, error) {
	if s == nil || tx == nil || step.Validate() != nil {
		return false, ErrInvalid
	}
	if err := s.coordinator.RegisterTx(ctx, tx, step); err != nil {
		return false, err
	}
	var saved string
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT spec_digest FROM platform_compensation_local_effect WHERE step_id=? FOR UPDATE`), step.ID).Scan(&saved)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if saved != step.Digest() {
		return false, ErrConflict
	}
	return true, nil
}

func NewLocalEffectLedger(ctx context.Context, db *sql.DB, coordinator Coordinator) (*LocalEffectLedger, error) {
	store, ok := coordinator.(*SQLStore)
	if ctx == nil || db == nil || !ok || store == nil || store.db != db {
		return nil, ErrInvalid
	}
	var saved string
	h := sha256.Sum256([]byte(localEffectDDL))
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT checksum FROM platform_compensation_schema_version WHERE version=?`), LocalEffectSchemaVersion).Scan(&saved); err != nil {
		return nil, ErrUnavailable
	}
	if saved != hex.EncodeToString(h[:]) {
		return nil, ErrConflict
	}
	return &LocalEffectLedger{db: db, coordinator: store}, nil
}

// RecordTx registers the inverse before the owner's forward mutation. The
// caller must commit the resource, before-image and receipt in this SAME local
// transaction. A failed mutation must roll back this entire transaction.
func (s *LocalEffectLedger) RecordTx(ctx context.Context, tx *sql.Tx, step Step, effect LocalEffect) error {
	if s == nil || tx == nil || step.Validate() != nil || !digest(effect.ExpectedToken) || len(effect.Before) == 0 || len(effect.Before) > 256<<10 || !json.Valid(effect.Before) {
		return ErrInvalid
	}
	if err := s.coordinator.RegisterTx(ctx, tx, step); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_compensation_local_effect(step_id,spec_digest,provider,provider_version,effect_ref,before_image,expected_token) VALUES(?,?,?,?,?,?::jsonb,?) ON CONFLICT(step_id) DO NOTHING`), step.ID, step.Digest(), step.Provider, step.ProviderVersion, step.Ref, string(effect.Before), effect.ExpectedToken); err != nil {
		return err
	}
	var savedDigest, savedToken string
	var equal bool
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT spec_digest,expected_token,before_image=?::jsonb FROM platform_compensation_local_effect WHERE step_id=? FOR UPDATE`), string(effect.Before), step.ID).Scan(&savedDigest, &savedToken, &equal); err != nil {
		return err
	}
	if savedDigest != step.Digest() || savedToken != effect.ExpectedToken || !equal {
		return ErrConflict
	}
	return nil
}

type LocalEffectPort struct {
	ledger            *LocalEffectLedger
	provider, version string
	owner             LocalEffectOwner
}

func (s *LocalEffectLedger) Port(provider, version string, owner LocalEffectOwner) (*LocalEffectPort, error) {
	if s == nil || owner == nil || !token(provider, 128) || !token(version, 128) {
		return nil, ErrInvalid
	}
	return &LocalEffectPort{ledger: s, provider: provider, version: version, owner: owner}, nil
}

func (p *LocalEffectPort) check(step Step) error {
	if p == nil || step.Validate() != nil || step.Provider != p.provider || step.ProviderVersion != p.version {
		return ErrInvalid
	}
	return nil
}

func (p *LocalEffectPort) readTx(ctx context.Context, tx *sql.Tx, step Step, lock bool) (LocalEffect, *Receipt, bool, error) {
	query := `SELECT spec_digest,provider,provider_version,effect_ref,before_image,expected_token,receipt_json FROM platform_compensation_local_effect WHERE step_id=?`
	if lock {
		query += ` FOR UPDATE`
	}
	var savedDigest, provider, version, ref string
	var effect LocalEffect
	var raw []byte
	err := tx.QueryRowContext(ctx, sqlutil.Bind(query), step.ID).Scan(&savedDigest, &provider, &version, &ref, &effect.Before, &effect.ExpectedToken, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return LocalEffect{}, nil, false, nil
	}
	if err != nil {
		return LocalEffect{}, nil, false, err
	}
	if savedDigest != step.Digest() || provider != p.provider || version != p.version || ref != step.Ref || !digest(effect.ExpectedToken) || len(effect.Before) > 256<<10 || !json.Valid(effect.Before) {
		return LocalEffect{}, nil, false, ErrConflict
	}
	if len(raw) == 0 {
		return effect, nil, true, nil
	}
	var receipt Receipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.Validate(step) != nil || receipt.Action != "rolled_back" {
		return LocalEffect{}, nil, false, ErrConflict
	}
	return effect, &receipt, true, nil
}

func (p *LocalEffectPort) Lookup(ctx context.Context, step Step) (Receipt, bool, error) {
	if err := p.check(step); err != nil {
		return Receipt{}, false, err
	}
	tx, err := p.ledger.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Receipt{}, false, err
	}
	defer tx.Rollback()
	_, receipt, _, err := p.readTx(ctx, tx, step, false)
	if err != nil || receipt == nil {
		return Receipt{}, false, err
	}
	return *receipt, true, tx.Commit()
}

func (p *LocalEffectPort) InspectOriginal(ctx context.Context, step Step) (OriginalEffect, error) {
	if err := p.check(step); err != nil {
		return OriginalEffect{}, err
	}
	tx, err := p.ledger.db.BeginTx(ctx, nil)
	if err != nil {
		return OriginalEffect{}, err
	}
	defer tx.Rollback()
	// This stop/root fence prevents a concurrent or delayed forward RecordTx
	// from committing after an authoritative absence observation.
	if err = p.ledger.coordinator.GuardRegisteredStopTx(ctx, tx, step); err != nil {
		return OriginalEffect{}, err
	}
	_, _, found, err := p.readTx(ctx, tx, step, false)
	if err != nil {
		return OriginalEffect{}, err
	}
	state := "no_effect"
	if found {
		state = "applied"
	}
	h := sha256.Sum256([]byte("local-effect/v1\x00" + step.Digest() + "\x00" + state))
	return OriginalEffect{StepDigest: step.Digest(), State: state, EvidenceDigest: hex.EncodeToString(h[:])}, tx.Commit()
}

func (p *LocalEffectPort) Compensate(ctx context.Context, step Step) (Receipt, error) {
	if err := p.check(step); err != nil {
		return Receipt{}, errors.Join(ErrNotSubmitted, err)
	}
	lease, err := LeaseFromContext(ctx, step)
	if err != nil {
		return Receipt{}, errors.Join(ErrNotSubmitted, err)
	}
	tx, err := p.ledger.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, errors.Join(ErrNotSubmitted, err)
	}
	defer tx.Rollback()
	if err = p.ledger.coordinator.GuardLeaseTx(ctx, tx, lease); err != nil {
		return Receipt{}, errors.Join(ErrNotSubmitted, err)
	}
	effect, existing, found, err := p.readTx(ctx, tx, step, true)
	if err != nil || !found {
		return Receipt{}, errors.Join(ErrNotSubmitted, ErrConflict, err)
	}
	if existing != nil {
		return *existing, nil
	}
	if err = p.owner.RestoreEffectTx(ctx, tx, step, effect); err != nil {
		// Owner is local-only: rollback is synchronous and proves no inverse
		// commit. External APIs must implement their own receipt-based port.
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return Receipt{}, err
		}
		return Receipt{}, errors.Join(ErrNotSubmitted, err)
	}
	h := sha256.Sum256([]byte("local-inverse-commit/v1\x00" + step.Digest() + "\x00" + effect.ExpectedToken))
	receipt := Receipt{Version: ContractVersion, StepDigest: step.Digest(), Key: step.CompensationKey(), Action: "rolled_back", EvidenceDigest: hex.EncodeToString(h[:])}
	raw, _ := json.Marshal(receipt)
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_compensation_local_effect SET receipt_json=?::jsonb,compensated_at=clock_timestamp() WHERE step_id=? AND spec_digest=? AND receipt_json IS NULL`), string(raw), step.ID, step.Digest()); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return Receipt{}, err
		}
		return Receipt{}, errors.Join(ErrNotSubmitted, err)
	}
	if err = eventTx(ctx, tx, step.Root.RunID, step.Scope.RunID, step.ID, "local_inverse_committed", map[string]any{"spec_digest": step.Digest(), "receipt_digest": receipt.EvidenceDigest}); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return Receipt{}, err
		}
		return Receipt{}, errors.Join(ErrNotSubmitted, err)
	}
	// A lost COMMIT response is UNKNOWN: only Lookup may repair it.
	if err = tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

var _ Port = (*LocalEffectPort)(nil)
