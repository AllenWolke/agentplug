package compensation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

const EnrollmentSchemaVersion uint64 = 2026100904
const enrollmentDDL = `
CREATE TABLE IF NOT EXISTS platform_cancellation_effect (
 root_run_id VARCHAR(255) NOT NULL REFERENCES platform_cancellation_operation(root_run_id),
 step_id VARCHAR(64) NOT NULL REFERENCES platform_compensation_step(step_id),
 spec_digest VARCHAR(64) NOT NULL,
 enrolled_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(root_run_id,step_id));
CREATE INDEX IF NOT EXISTS idx_platform_cancel_effect_step ON platform_cancellation_effect(step_id,root_run_id);
`

func ApplyEnrollmentSchema(ctx context.Context, db *sql.DB) error {
	if ctx == nil || db == nil {
		return ErrInvalid
	}
	if _, err := db.ExecContext(ctx, `SELECT pg_advisory_xact_lock(2026100904,16)`); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, enrollmentDDL); err != nil {
		return err
	}
	h := sha256.Sum256([]byte(enrollmentDDL))
	sum := hex.EncodeToString(h[:])
	var prior string
	err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT checksum FROM platform_compensation_schema_version WHERE version=?`), EnrollmentSchemaVersion).Scan(&prior)
	if err == nil && prior != sum {
		return ErrConflict
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		if _, err = db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_compensation_schema_version VALUES(?,?,clock_timestamp())`), EnrollmentSchemaVersion, sum); err != nil {
			return err
		}
	}
	return protectHistoryGrants(ctx, db)
}

func CheckEnrollmentSchema(ctx context.Context, db *sql.DB) error {
	if ctx == nil || db == nil {
		return ErrInvalid
	}
	h := sha256.Sum256([]byte(enrollmentDDL))
	var prior string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT checksum FROM platform_compensation_schema_version WHERE version=?`), EnrollmentSchemaVersion).Scan(&prior); err != nil {
		return ErrUnavailable
	}
	if prior != hex.EncodeToString(h[:]) {
		return ErrConflict
	}
	return nil
}

// The actual execution/recorded-routing owner proves subtree membership. A
// parent field supplied by an Agent is insufficient. Enrollment does not
// rewrite a Step or change its inverse key/authoritative receipt.
type EnrollmentAuthority interface {
	EnrollRecordedEffectTx(context.Context, *sql.Tx, sharedkernel.Scope, Step) error
}

func (s *SQLStore) EnrollRecordedTx(ctx context.Context, tx *sql.Tx, control sharedkernel.Scope, stepID string) error {
	if s == nil || ctx == nil || tx == nil || control.ValidateTrusted() != nil || !digest(stepID) {
		return ErrInvalid
	}
	var raw []byte
	var saved string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT spec_json,spec_digest FROM platform_compensation_step WHERE step_id=?`), stepID).Scan(&raw, &saved); err != nil {
		return ErrConflict
	}
	var step Step
	if json.Unmarshal(raw, &step) != nil || step.Validate() != nil || step.ID != stepID || step.Digest() != saved {
		return ErrConflict
	}
	owner, ok := s.authority.(EnrollmentAuthority)
	if !ok {
		return ErrUnavailable
	}
	if err := owner.EnrollRecordedEffectTx(ctx, tx, control, step); err != nil {
		return err
	}
	phase, _, err := s.lockJob(ctx, tx, control)
	if err != nil {
		return err
	}
	if phase != "stopping" {
		return ErrConflict
	}
	var locked string
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT spec_digest FROM platform_compensation_step WHERE step_id=? FOR UPDATE`), step.ID).Scan(&locked); err != nil || locked != saved {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_cancellation_effect(root_run_id,step_id,spec_digest) VALUES(?,?,?) ON CONFLICT(root_run_id,step_id) DO NOTHING`), control.RunID, step.ID, saved); err != nil {
		return err
	}
	var binding string
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT spec_digest FROM platform_cancellation_effect WHERE root_run_id=? AND step_id=?`), control.RunID, step.ID).Scan(&binding); err != nil {
		return err
	}
	if binding != saved {
		return ErrConflict
	}
	var count int
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_cancellation_effect WHERE root_run_id=?`), control.RunID).Scan(&count); err != nil {
		return err
	}
	if count > MaxSteps {
		return ErrInvalid
	}
	return eventTx(ctx, tx, control.RunID, step.Scope.RunID, step.ID, "recorded_effect_enrolled", map[string]any{"spec_digest": saved})
}
