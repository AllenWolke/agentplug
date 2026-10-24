package compensation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Authority is composed from the existing execution/coordination modules.
// Every method locks the root Run first, verifies its immutable Scope and
// recorded ancestry, and grants only the specific control operation named.
// FinishTx rechecks stop/descendant/effect/model settlement and atomically
// writes the actual cancelled outcome, audit and projection intent.
type Authority interface {
	RegisterEffectTx(context.Context, *sql.Tx, Step) error
	BeginCancellationTx(context.Context, *sql.Tx, sharedkernel.Scope, uint64) error
	ConfirmStoppedTx(context.Context, *sql.Tx, sharedkernel.Scope, StopProof) error
	GuardCompensationTx(context.Context, *sql.Tx, sharedkernel.Scope) error
	FinishCancellationTx(context.Context, *sql.Tx, sharedkernel.Scope, StopProof) error
}

type SQLStore struct {
	db                      *sql.DB
	authority               Authority
	recoveryHolds           sharedkernel.RecoveryHolds
	recoveryHoldsConfigured bool
}

func NewSQLStore(db *sql.DB, authority Authority) (*SQLStore, error) {
	if db == nil || authority == nil {
		return nil, ErrUnavailable
	}
	return &SQLStore{db: db, authority: authority}, nil
}

const SchemaVersion uint64 = 2026100901

// CheckSchema is read-only and safe for the runtime DML account. Runtime
// startup never applies migrations or silently repairs a missing marker.
func CheckSchema(ctx context.Context, db *sql.DB) error {
	if ctx == nil || db == nil {
		return ErrInvalid
	}
	var saved string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT checksum FROM platform_compensation_schema_version WHERE version=?`), SchemaVersion).Scan(&saved); err != nil {
		return ErrUnavailable
	}
	digest := sha256.Sum256([]byte(schemaDDL))
	if saved != hex.EncodeToString(digest[:]) {
		return ErrConflict
	}
	return nil
}

const schemaDDL = `
CREATE TABLE IF NOT EXISTS platform_compensation_schema_version (
 version NUMERIC(20,0) PRIMARY KEY, checksum VARCHAR(64) NOT NULL, applied_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS platform_cancellation_operation (
 root_run_id VARCHAR(255) PRIMARY KEY,
 cancellation_id VARCHAR(64) UNIQUE NOT NULL,
 scope_digest VARCHAR(64) NOT NULL,
 scope_json JSONB NOT NULL,
 intent_revision NUMERIC(20,0) NOT NULL CHECK(intent_revision>0 AND intent_revision<=18446744073709551615),
 phase VARCHAR(32) NOT NULL CHECK(phase IN ('stopping','compensating','complete')),
 stop_proof JSONB NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS platform_compensation_step (
 step_id VARCHAR(64) PRIMARY KEY,
 root_run_id VARCHAR(255) NOT NULL,
 run_id VARCHAR(255) NOT NULL,
 ordinal BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
 spec_digest VARCHAR(64) NOT NULL,
 spec_json JSONB NOT NULL,
 phase VARCHAR(32) NOT NULL CHECK(phase IN ('prepared','leased','pending','blocked','compensated','no_effect')),
 submitted BOOLEAN NOT NULL DEFAULT FALSE,
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
 invocations INTEGER NOT NULL DEFAULT 0 CHECK(invocations>=0),
 lease_owner VARCHAR(64) NOT NULL DEFAULT '',
 lease_token VARCHAR(32) NOT NULL DEFAULT '',
 lease_fence NUMERIC(20,0) NOT NULL DEFAULT 0 CHECK(lease_fence>=0 AND lease_fence<=18446744073709551615),
 lease_until TIMESTAMPTZ NULL,
 retry_at TIMESTAMPTZ NULL,
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 receipt_json JSONB NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
CREATE INDEX IF NOT EXISTS idx_platform_compensation_root_order ON platform_compensation_step(root_run_id,ordinal DESC);
CREATE INDEX IF NOT EXISTS idx_platform_cancellation_pending ON platform_cancellation_operation(phase,updated_at,root_run_id);
CREATE TABLE IF NOT EXISTS platform_compensation_event (
 event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 root_run_id VARCHAR(255) NOT NULL,
 run_id VARCHAR(255) NOT NULL,
 step_id VARCHAR(64) NOT NULL,
 event_type VARCHAR(64) NOT NULL,
 payload JSONB NOT NULL,
 occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
CREATE INDEX IF NOT EXISTS idx_platform_compensation_event_root ON platform_compensation_event(root_run_id,event_id);
`

// Migrate is called only by the explicit maintenance migration command. It
// shares one transaction and advisory lock with the immutable version marker.
// Runtime construction never needs CREATE/ALTER privileges.
func Migrate(ctx context.Context, db *sql.DB) error {
	if ctx == nil || db == nil {
		return ErrInvalid
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	facade := sqlutil.TransactionDB(tx)
	defer facade.Close()
	if err = ApplySchema(ctx, facade); err != nil {
		return err
	}
	if err = ApplyEnrollmentSchema(ctx, facade); err != nil {
		return err
	}
	return tx.Commit()
}

// ApplySchema participates in the owning global migration transaction. It
// must not begin/commit a nested transaction on the TransactionDB facade.
func ApplySchema(ctx context.Context, db *sql.DB) error {
	if ctx == nil || db == nil {
		return ErrInvalid
	}
	if _, err := db.ExecContext(ctx, `SELECT pg_advisory_xact_lock(2026100901,16)`); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, schemaDDL); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(schemaDDL))
	sum := hex.EncodeToString(digest[:])
	var prior string
	err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT checksum FROM platform_compensation_schema_version WHERE version=?`), SchemaVersion).Scan(&prior)
	if err == nil && prior != sum {
		return ErrConflict
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		if _, err = db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_compensation_schema_version(version,checksum,applied_at) VALUES(?,?,clock_timestamp())`), SchemaVersion, sum); err != nil {
			return err
		}
	}
	return protectHistoryGrants(ctx, db)
}

// Strip mutation grants inherited from local default ACLs. Production grants
// must preserve the same marker/history boundary; runtime owns no schema.
func protectHistoryGrants(ctx context.Context, db *sql.DB) error {
	for table, permissions := range map[string]string{
		"platform_compensation_schema_version": "INSERT,UPDATE,DELETE",
		"platform_cancellation_operation":      "DELETE",
		"platform_compensation_step":           "DELETE",
		"platform_compensation_local_effect":   "DELETE",
		"platform_cancellation_effect":         "DELETE,UPDATE",
		"platform_compensation_event":          "UPDATE,DELETE",
	} {
		rows, err := db.QueryContext(ctx, sqlutil.Bind(`SELECT DISTINCT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid=to_regclass(?) AND a.grantee<>c.relowner AND a.privilege_type=ANY(string_to_array(?,','))`), "public."+table, permissions)
		if err != nil {
			return err
		}
		var roles []string
		for rows.Next() {
			var role string
			if err = rows.Scan(&role); err != nil {
				rows.Close()
				return err
			}
			roles = append(roles, role)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, role := range roles {
			name := pgx.Identifier{role}.Sanitize()
			if role == "PUBLIC" {
				name = "PUBLIC"
			}
			if _, err = db.ExecContext(ctx, "REVOKE "+permissions+" ON "+pgx.Identifier{"public", table}.Sanitize()+" FROM "+name); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *SQLStore) RegisterTx(ctx context.Context, tx *sql.Tx, step Step) error {
	if ctx == nil || tx == nil || step.Validate() != nil {
		return ErrInvalid
	}
	step = step.canonical()
	if err := s.authority.RegisterEffectTx(ctx, tx, step); err != nil {
		return err
	}
	var existingJob string
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT phase FROM platform_cancellation_operation WHERE root_run_id=? FOR UPDATE`), step.Root.RunID).Scan(&existingJob)
	if err == nil {
		return ErrPending
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var existing string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT spec_digest FROM platform_compensation_step WHERE step_id=? FOR UPDATE`), step.ID).Scan(&existing)
	if err == nil {
		if existing != step.Digest() {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var count int
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_compensation_step WHERE root_run_id=?`), step.Root.RunID).Scan(&count); err != nil {
		return err
	}
	if count >= MaxSteps {
		return ErrInvalid
	}
	for _, dependency := range step.DependsOn {
		var raw []byte
		if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT spec_json FROM platform_compensation_step WHERE step_id=? AND root_run_id=? FOR KEY SHARE`), dependency, step.Root.RunID).Scan(&raw); err != nil {
			return ErrConflict
		}
		var prior Step
		if json.Unmarshal(raw, &prior) != nil || prior.Validate() != nil || prior.Root != step.Root {
			return ErrConflict
		}
	}
	raw, err := json.Marshal(step)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_compensation_step(step_id,root_run_id,run_id,spec_digest,spec_json,phase) VALUES(?,?,?,?,?::jsonb,'prepared')`), step.ID, step.Root.RunID, step.Scope.RunID, step.Digest(), string(raw))
	if err != nil {
		return err
	}
	return eventTx(ctx, tx, step.Root.RunID, step.Scope.RunID, step.ID, "effect_registered", map[string]any{"spec_digest": step.Digest(), "kind": step.Kind, "tool_name": step.Tool, "provider_version": step.ProviderVersion})
}

// GuardRegisteredStopTx lets an owner adapter prove absence without racing
// delayed forward writes. It grants no forward business permissions.
func (s *SQLStore) GuardRegisteredStopTx(ctx context.Context, tx *sql.Tx, step Step) error {
	if s == nil || ctx == nil || tx == nil || step.Validate() != nil {
		return ErrInvalid
	}
	control := step.Root
	if lease, err := LeaseFromContext(ctx, step); err == nil {
		control = lease.CancellationScope()
	}
	if err := s.authority.GuardCompensationTx(ctx, tx, control); err != nil {
		return err
	}
	var phase string
	var proof []byte
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT phase,stop_proof FROM platform_cancellation_operation WHERE root_run_id=? AND scope_digest=? FOR UPDATE`), control.RunID, ScopeDigest(control)).Scan(&phase, &proof); err != nil {
		return ErrPending
	}
	var stopped StopProof
	if phase != "compensating" || json.Unmarshal(proof, &stopped) != nil || stopped.Validate(control) != nil {
		return ErrPending
	}
	var saved string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT x.spec_digest FROM platform_compensation_step x JOIN platform_cancellation_effect e ON e.step_id=x.step_id AND e.spec_digest=x.spec_digest WHERE x.step_id=? AND e.root_run_id=? FOR UPDATE OF x`), step.ID, control.RunID).Scan(&saved); err != nil {
		return ErrConflict
	}
	if saved != step.Digest() {
		return ErrConflict
	}
	return nil
}

func (s *SQLStore) BeginTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, revision uint64) (string, error) {
	if ctx == nil || tx == nil || scope.ValidateTrusted() != nil || revision == 0 {
		return "", ErrInvalid
	}
	if err := s.authority.BeginCancellationTx(ctx, tx, scope, revision); err != nil {
		return "", err
	}
	raw, _ := json.Marshal(scope)
	id := sha256.Sum256([]byte(ContractVersion + "\x00" + ScopeDigest(scope)))
	cancellationID := hex.EncodeToString(id[:])
	inserted, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_cancellation_operation(root_run_id,cancellation_id,scope_digest,scope_json,intent_revision,phase) VALUES(?,?,?,?::jsonb,?,'stopping') ON CONFLICT(root_run_id) DO NOTHING`), scope.RunID, cancellationID, ScopeDigest(scope), string(raw), revision)
	if err != nil {
		return "", err
	}
	var savedID, savedDigest string
	var savedRevision uint64
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT cancellation_id,scope_digest,intent_revision FROM platform_cancellation_operation WHERE root_run_id=? FOR UPDATE`), scope.RunID).Scan(&savedID, &savedDigest, &savedRevision); err != nil {
		return "", err
	}
	if savedID != cancellationID || savedDigest != ScopeDigest(scope) || savedRevision != revision {
		return "", ErrConflict
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_cancellation_effect(root_run_id,step_id,spec_digest)
SELECT ?,step_id,spec_digest FROM platform_compensation_step WHERE root_run_id=? ON CONFLICT(root_run_id,step_id) DO NOTHING`), scope.RunID, scope.RunID); err != nil {
		return "", err
	}
	if count, _ := inserted.RowsAffected(); count == 1 {
		if err = eventTx(ctx, tx, scope.RunID, scope.RunID, "", "cancel_intent_registered", map[string]any{"cancellation_id": cancellationID, "revision": revision}); err != nil {
			return "", err
		}
	}
	return cancellationID, nil
}

func (s *SQLStore) ConfirmStoppedTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, proof StopProof) error {
	if ctx == nil || tx == nil || proof.Validate(scope) != nil {
		return ErrInvalid
	}
	if err := s.authority.ConfirmStoppedTx(ctx, tx, scope, proof); err != nil {
		return err
	}
	phase, prior, err := s.lockJob(ctx, tx, scope)
	if err != nil {
		return err
	}
	var revision uint64
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT intent_revision FROM platform_cancellation_operation WHERE root_run_id=?`), scope.RunID).Scan(&revision); err != nil {
		return err
	}
	if proof.Revision != revision {
		return ErrConflict
	}
	if phase == "complete" {
		return ErrConflict
	}
	if prior != nil {
		if *prior != proof {
			return ErrConflict
		}
		return nil
	}
	if phase != "stopping" {
		return ErrConflict
	}
	raw, _ := json.Marshal(proof)
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_cancellation_operation SET phase='compensating',stop_proof=?::jsonb,updated_at=clock_timestamp() WHERE root_run_id=? AND phase='stopping' AND stop_proof IS NULL`), string(raw), scope.RunID)
	if err != nil {
		return err
	}
	return eventTx(ctx, tx, scope.RunID, scope.RunID, "", "tree_stop_confirmed", map[string]any{"revision": proof.Revision, "evidence_digest": proof.EvidenceDigest})
}

func (s *SQLStore) lockJob(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) (string, *StopProof, error) {
	var phase, binding string
	var raw, scopeRaw []byte
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT phase,scope_digest,scope_json,stop_proof FROM platform_cancellation_operation WHERE root_run_id=? FOR UPDATE`), scope.RunID).Scan(&phase, &binding, &scopeRaw, &raw); err != nil {
		return "", nil, err
	}
	var recorded sharedkernel.Scope
	if binding != ScopeDigest(scope) || json.Unmarshal(scopeRaw, &recorded) != nil || recorded != scope {
		return "", nil, ErrConflict
	}
	if len(raw) == 0 {
		return phase, nil, nil
	}
	var proof StopProof
	if json.Unmarshal(raw, &proof) != nil || proof.Validate(scope) != nil {
		return "", nil, ErrConflict
	}
	return phase, &proof, nil
}

func (s *SQLStore) Claim(ctx context.Context, scope sharedkernel.Scope, owner string, ttl time.Duration) (Lease, bool, error) {
	if s.recoveryHolds.Contains(scope.RunID) {
		return Lease{}, false, sharedkernel.ErrAutomaticRecoveryHeld
	}
	if ctx == nil || scope.ValidateTrusted() != nil || !token(owner, 64) || ttl < time.Second || ttl > 2*time.Minute {
		return Lease{}, false, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Lease{}, false, err
	}
	defer tx.Rollback()
	phase, proof, err := s.lockJob(ctx, tx, scope)
	if err != nil {
		return Lease{}, false, err
	}
	if phase == "stopping" || phase == "complete" {
		return Lease{}, false, nil
	}
	if phase != "compensating" || proof == nil {
		return Lease{}, false, ErrConflict
	}
	// Reject the entire cancellation if an enrollment is corrupt. Filtering
	// mismatched rows out of the next-step query could otherwise run an earlier
	// inverse before discovering the incomplete later dependency.
	var corrupt bool
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_cancellation_effect e LEFT JOIN platform_compensation_step x ON x.step_id=e.step_id WHERE e.root_run_id=? AND (x.step_id IS NULL OR e.spec_digest<>x.spec_digest))`), scope.RunID).Scan(&corrupt); err != nil {
		return Lease{}, false, err
	}
	if corrupt {
		return Lease{}, false, ErrConflict
	}
	var id, state, specDigest string
	var raw []byte
	var leaseUntil, retryAt sql.NullTime
	var now time.Time
	l := Lease{ControlScope: scope}
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT x.step_id,x.phase,x.spec_digest,x.spec_json,x.submitted,x.attempts,x.invocations,x.lease_fence,x.lease_until,x.retry_at,clock_timestamp() FROM platform_compensation_step x JOIN platform_cancellation_effect e ON e.step_id=x.step_id AND e.spec_digest=x.spec_digest WHERE e.root_run_id=? AND x.phase NOT IN ('compensated','no_effect') ORDER BY x.ordinal DESC LIMIT 1 FOR UPDATE OF x`), scope.RunID).Scan(&id, &state, &specDigest, &raw, &l.Submitted, &l.Attempts, &l.Invocations, &l.Fence, &leaseUntil, &retryAt, &now)
	if errors.Is(err, sql.ErrNoRows) {
		return Lease{}, false, nil
	}
	if err != nil {
		return Lease{}, false, err
	}
	if json.Unmarshal(raw, &l.Step) != nil || l.Step.Validate() != nil || l.Step.Root.TenantID != scope.TenantID || l.Step.Root.ApplicationID != scope.ApplicationID || l.Step.ID != id || l.Step.Digest() != specDigest {
		return Lease{}, false, ErrConflict
	}
	if leaseUntil.Valid && leaseUntil.Time.After(now) || retryAt.Valid && retryAt.Time.After(now) {
		return Lease{}, false, nil
	}
	if l.Fence == ^uint64(0) || l.Attempts >= 1000000 {
		return Lease{}, false, ErrConflict
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return Lease{}, false, err
	}
	l.Fence++
	l.Attempts++
	l.Owner = owner
	l.Token = hex.EncodeToString(nonce[:])
	l.Until = now.Add(ttl)
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_compensation_step SET phase='leased',lease_owner=?,lease_token=?,lease_fence=?,lease_until=?,attempts=?,retry_at=NULL,updated_at=clock_timestamp() WHERE step_id=? AND lease_fence=?`), l.Owner, l.Token, l.Fence, l.Until, l.Attempts, id, l.Fence-1)
	if err != nil {
		return Lease{}, false, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return Lease{}, false, ErrLeaseLost
	}
	if err = eventTx(ctx, tx, scope.RunID, l.Step.Scope.RunID, l.Step.ID, "compensation_claimed", map[string]any{"fence": l.Fence, "attempt": l.Attempts, "submitted": l.Submitted}); err != nil {
		return Lease{}, false, err
	}
	// Rotate visited roots for the bounded host worker. A permanently blocked
	// first batch must not starve a later cancellation operation indefinitely.
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_cancellation_operation SET updated_at=clock_timestamp() WHERE root_run_id=? AND phase='compensating'`), scope.RunID); err != nil {
		return Lease{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return Lease{}, false, err
	}
	return l, true, nil
}

func validateLease(l Lease) error {
	control := l.CancellationScope()
	if l.Step.Validate() != nil || control.ValidateTrusted() != nil || control.TenantID != l.Step.Root.TenantID || control.ApplicationID != l.Step.Root.ApplicationID || !token(l.Owner, 64) || len(l.Token) != 32 || l.Fence == 0 {
		return ErrInvalid
	}
	if _, err := hex.DecodeString(l.Token); err != nil {
		return ErrInvalid
	}
	return nil
}

// GuardLeaseTx is used by local business adapters in the same transaction as
// the inverse write and its receipt. It holds the root/operation/step locks,
// preventing a stale controller from committing after its lease is fenced.
func (s *SQLStore) GuardLeaseTx(ctx context.Context, tx *sql.Tx, l Lease) error {
	if ctx == nil || tx == nil || validateLease(l) != nil {
		return ErrInvalid
	}
	control := l.CancellationScope()
	if err := s.authority.GuardCompensationTx(ctx, tx, control); err != nil {
		return err
	}
	phase, proof, err := s.lockJob(ctx, tx, control)
	if err != nil {
		return err
	}
	if phase != "compensating" || proof == nil {
		return ErrPending
	}
	var binding string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT x.spec_digest FROM platform_compensation_step x JOIN platform_cancellation_effect e ON e.step_id=x.step_id AND e.spec_digest=x.spec_digest WHERE x.step_id=? AND e.root_run_id=? AND x.phase='leased' AND x.submitted=TRUE AND x.lease_owner=? AND x.lease_token=? AND x.lease_fence=? AND x.lease_until>clock_timestamp() FOR UPDATE OF x`), l.Step.ID, control.RunID, l.Owner, l.Token, l.Fence).Scan(&binding)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	if binding != l.Step.Digest() {
		return ErrConflict
	}
	return nil
}

func (s *SQLStore) MarkSubmitted(ctx context.Context, l Lease) error {
	if ctx == nil || validateLease(l) != nil {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_compensation_step SET submitted=TRUE,invocations=invocations+1,updated_at=clock_timestamp() WHERE step_id=? AND spec_digest=? AND phase='leased' AND submitted=FALSE AND invocations<5 AND lease_owner=? AND lease_token=? AND lease_fence=? AND lease_until>clock_timestamp()`), l.Step.ID, l.Step.Digest(), l.Owner, l.Token, l.Fence)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrLeaseLost
	}
	if err = eventTx(ctx, tx, l.CancellationScope().RunID, l.Step.Scope.RunID, l.Step.ID, "compensation_submitted", map[string]any{"fence": l.Fence, "compensation_key": l.Step.CompensationKey()}); err != nil {
		return err
	}
	return tx.Commit()
}

func resolutionCode(code string) bool {
	switch code {
	case "COMPENSATOR_UNAVAILABLE", "COMPENSATION_RECEIPT_UNCONFIRMED", "ORIGINAL_EFFECT_UNCONFIRMED", "COMPENSATION_RECEIPT_INVALID", "COMPENSATION_RESULT_UNKNOWN", "COMPENSATION_NOT_SUBMITTED", "COMPENSATION_RETRY_BUDGET_EXHAUSTED":
		return true
	}
	return false
}

func (s *SQLStore) Resolve(ctx context.Context, l Lease, r Resolution) error {
	if ctx == nil || validateLease(l) != nil {
		return ErrInvalid
	}
	if r.Receipt != nil {
		if r.Receipt.Validate(l.Step) != nil || r.Code != "" || r.NotSubmitted || !r.RetryAt.IsZero() {
			return ErrInvalid
		}
	} else if !resolutionCode(r.Code) || r.RetryAt.IsZero() || r.NotSubmitted && r.Code != "COMPENSATION_NOT_SUBMITTED" {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var binding string
	var submitted bool
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT spec_digest,submitted FROM platform_compensation_step WHERE step_id=? AND phase='leased' AND lease_owner=? AND lease_token=? AND lease_fence=? AND lease_until>clock_timestamp() FOR UPDATE`), l.Step.ID, l.Owner, l.Token, l.Fence).Scan(&binding, &submitted)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	if binding != l.Step.Digest() {
		return ErrConflict
	}
	phase := "blocked"
	var receipt any
	var retry any
	if r.Receipt != nil {
		phase = "compensated"
		if r.Receipt.Action == "no_effect" {
			phase = "no_effect"
		}
		raw, _ := json.Marshal(r.Receipt)
		receipt = string(raw)
	} else {
		if r.NotSubmitted {
			if !submitted {
				return ErrConflict
			}
			submitted = false
			phase = "prepared"
		} else if submitted {
			phase = "pending"
		}
		retry = r.RetryAt
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_compensation_step SET phase=?,submitted=?,receipt_json=?::jsonb,error_code=?,retry_at=?,lease_owner='',lease_token='',lease_until=NULL,updated_at=clock_timestamp() WHERE step_id=?`), phase, submitted, receipt, r.Code, retry, l.Step.ID)
	if err != nil {
		return err
	}
	metadata := map[string]any{"phase": phase, "fence": l.Fence, "error_code": r.Code, "submitted": submitted}
	if r.Receipt != nil {
		metadata["action"] = r.Receipt.Action
		metadata["evidence_digest"] = r.Receipt.EvidenceDigest
	}
	if err = eventTx(ctx, tx, l.CancellationScope().RunID, l.Step.Scope.RunID, l.Step.ID, "compensation_resolved", metadata); err != nil {
		return err
	}
	return tx.Commit()
}

// FinalizeTx is called while the composition root owns the cancellation
// transaction. A completed job and real Run cancelled outcome commit together.
func (s *SQLStore) FinalizeTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
	if ctx == nil || tx == nil || scope.ValidateTrusted() != nil {
		return ErrInvalid
	}
	if err := s.authority.GuardCompensationTx(ctx, tx, scope); err != nil {
		return err
	}
	phase, proof, err := s.lockJob(ctx, tx, scope)
	if err != nil {
		return err
	}
	if phase != "compensating" || proof == nil {
		return ErrPending
	}
	// Guard and job locks above remain the finalization fence. A pending step
	// cannot finalize the root: avoid locking/decoding every historical receipt
	// again after each inverse. Once none remain, the complete validation below
	// still checks all bindings, receipts and the original stop proof atomically.
	var pending bool
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_compensation_step x JOIN platform_cancellation_effect e ON e.step_id=x.step_id WHERE e.root_run_id=? AND x.phase NOT IN ('compensated','no_effect'))`), scope.RunID).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrPending
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT x.step_id,x.run_id,x.spec_json,x.spec_digest,x.phase,x.receipt_json,e.spec_digest FROM platform_compensation_step x JOIN platform_cancellation_effect e ON e.step_id=x.step_id WHERE e.root_run_id=? ORDER BY x.ordinal FOR UPDATE OF x`), scope.RunID)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var specRaw, receiptRaw []byte
		var id, runID, binding, state, enrolled string
		if err = rows.Scan(&id, &runID, &specRaw, &binding, &state, &receiptRaw, &enrolled); err != nil {
			rows.Close()
			return err
		}
		var step Step
		var receipt Receipt
		count++
		if count > MaxSteps || binding != enrolled || json.Unmarshal(specRaw, &step) != nil || step.Validate() != nil || step.Root.TenantID != scope.TenantID || step.Root.ApplicationID != scope.ApplicationID || step.Digest() != binding || step.ID != id || step.Scope.RunID != runID ||
			json.Unmarshal(receiptRaw, &receipt) != nil || receipt.Validate(step) != nil ||
			(state != "compensated" && state != "no_effect") || (state == "no_effect") != (receipt.Action == "no_effect") {
			rows.Close()
			return ErrPending
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	if err = s.authority.FinishCancellationTx(ctx, tx, scope, *proof); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_cancellation_operation SET phase='complete',updated_at=clock_timestamp() WHERE root_run_id=? AND phase='compensating'`), scope.RunID)
	if err != nil {
		return err
	}
	return eventTx(ctx, tx, scope.RunID, scope.RunID, "", "cancellation_complete", map[string]any{"steps": count, "stop_evidence_digest": proof.EvidenceDigest})
}

// TryFinalize owns only the final local transaction. It never executes an
// inverse operation; confirmed business receipts survive a failed commit.
func (s *SQLStore) TryFinalize(ctx context.Context, scope sharedkernel.Scope) error {
	if s.recoveryHolds.Contains(scope.RunID) {
		return sharedkernel.ErrAutomaticRecoveryHeld
	}
	if ctx == nil || scope.ValidateTrusted() != nil {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.FinalizeTx(ctx, tx, scope); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) Progress(ctx context.Context, scope sharedkernel.Scope) (Progress, bool, error) {
	return s.readProgress(ctx, s.db, scope)
}

// ProgressTx reads the cancellation projection beside a locked execution Run
// in the same snapshot; it owns no commit and never queries another connection.
func (s *SQLStore) ProgressTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) (Progress, bool, error) {
	if tx == nil {
		return Progress{}, false, ErrInvalid
	}
	return s.readProgress(ctx, tx, scope)
}

// CompletionProofTx is an internal owner-bound read for the execution outcome
// projection. It exposes no provider lease or sensitive business snapshot.
func (s *SQLStore) CompletionProofTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) (StopProof, error) {
	if ctx == nil || tx == nil || scope.ValidateTrusted() != nil {
		return StopProof{}, ErrInvalid
	}
	phase, proof, err := s.lockJob(ctx, tx, scope)
	if err != nil {
		return StopProof{}, err
	}
	if phase != "complete" || proof == nil {
		return StopProof{}, ErrPending
	}
	return *proof, nil
}

type progressQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *SQLStore) readProgress(ctx context.Context, query progressQueryer, scope sharedkernel.Scope) (Progress, bool, error) {
	if ctx == nil || scope.ValidateTrusted() != nil {
		return Progress{}, false, ErrInvalid
	}
	var p Progress
	var invalidEnrollment int
	var proof, scopeRaw []byte
	err := query.QueryRowContext(ctx, sqlutil.Bind(`SELECT j.cancellation_id,j.phase,j.stop_proof,j.scope_json,
COUNT(e.step_id),COUNT(e.step_id) FILTER(WHERE x.phase='compensated'),COUNT(e.step_id) FILTER(WHERE x.phase='no_effect'),
COUNT(e.step_id) FILTER(WHERE x.phase NOT IN ('compensated','no_effect')),COUNT(e.step_id) FILTER(WHERE x.phase IN ('pending','blocked')),
COUNT(e.step_id) FILTER(WHERE x.step_id IS NULL OR x.spec_digest<>e.spec_digest)
FROM platform_cancellation_operation j LEFT JOIN platform_cancellation_effect e ON e.root_run_id=j.root_run_id LEFT JOIN platform_compensation_step x ON x.step_id=e.step_id
WHERE j.root_run_id=? AND j.scope_digest=? GROUP BY j.cancellation_id,j.phase,j.stop_proof,j.scope_json`), scope.RunID, ScopeDigest(scope)).Scan(&p.CancellationID, &p.Phase, &proof, &scopeRaw, &p.Total, &p.Compensated, &p.NoEffect, &p.Unresolved, &p.Attention, &invalidEnrollment)
	if errors.Is(err, sql.ErrNoRows) {
		return Progress{}, false, nil
	}
	if err != nil {
		return Progress{}, false, err
	}
	if invalidEnrollment != 0 {
		return Progress{}, false, ErrConflict
	}
	var recorded sharedkernel.Scope
	if json.Unmarshal(scopeRaw, &recorded) != nil || recorded != scope {
		return Progress{}, false, ErrConflict
	}
	p.Version = ContractVersion
	if len(proof) > 0 {
		var stopped StopProof
		if json.Unmarshal(proof, &stopped) != nil || stopped.Validate(scope) != nil {
			return Progress{}, false, ErrConflict
		}
		p.StopConfirmed = true
	}
	if p.Attention > 0 && p.Phase != "complete" {
		p.Phase = "needs_attention"
	}
	if p.Phase == "complete" && (!p.StopConfirmed || p.Unresolved != 0) {
		return Progress{}, false, ErrConflict
	}
	return p, true, nil
}

func (s *SQLStore) ListPending(ctx context.Context, limit int) ([]sharedkernel.Scope, error) {
	if ctx == nil || limit < 1 || limit > 64 {
		return nil, ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`WITH picked AS (
SELECT root_run_id FROM platform_cancellation_operation WHERE phase='compensating'
AND root_run_id NOT IN (SELECT jsonb_array_elements_text(?::jsonb))
ORDER BY updated_at,root_run_id LIMIT ? FOR UPDATE SKIP LOCKED)
UPDATE platform_cancellation_operation j SET updated_at=clock_timestamp() FROM picked p
WHERE j.root_run_id=p.root_run_id AND j.phase='compensating' RETURNING j.scope_json,j.scope_digest`), s.recoveryHolds.RunIDsJSON(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var scopes []sharedkernel.Scope
	for rows.Next() {
		var raw []byte
		var binding string
		var scope sharedkernel.Scope
		if err = rows.Scan(&raw, &binding); err != nil {
			return nil, err
		}
		if json.Unmarshal(raw, &scope) != nil || scope.ValidateTrusted() != nil || ScopeDigest(scope) != binding {
			return nil, fmt.Errorf("%w: stored cancellation scope", ErrConflict)
		}
		scopes = append(scopes, scope)
	}
	return scopes, rows.Err()
}

var _ Queue = (*SQLStore)(nil)

func eventTx(ctx context.Context, tx *sql.Tx, rootRunID, runID, stepID, kind string, metadata map[string]any) error {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_compensation_event(root_run_id,run_id,step_id,event_type,payload) VALUES(?,?,?,?,?::jsonb)`), rootRunID, runID, stepID, kind, string(raw))
	return err
}
