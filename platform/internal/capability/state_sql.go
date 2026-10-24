package capability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type SQLCheckpointStore struct {
	db    *sql.DB
	guard func(context.Context, *sql.Tx, sharedkernel.Scope, sharedkernel.ExecutionLeaseBinding) error
	audit audit.TxRecorder
}

func NewSQLCheckpointStore(db *sql.DB) (*SQLCheckpointStore, error) {
	if db == nil {
		return nil, ErrStateUnavailable
	}
	return &SQLCheckpointStore{db: db}, nil
}
func (s *SQLCheckpointStore) SetContinuityGuard(guard func(context.Context, *sql.Tx, sharedkernel.Scope, sharedkernel.ExecutionLeaseBinding) error) {
	s.guard = guard
}
func (s *SQLCheckpointStore) SetAuditRecorder(recorder audit.TxRecorder) { s.audit = recorder }

func (s *SQLCheckpointStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_business_state_head (
 scope_key VARCHAR(64) PRIMARY KEY, scope_prefix VARCHAR(64) NOT NULL,
 schema_id VARCHAR(256) NOT NULL, revision BIGINT NOT NULL CHECK(revision>=0),
 expires_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS idx_business_state_quota ON platform_business_state_head(scope_prefix,expires_at);
CREATE TABLE IF NOT EXISTS platform_business_checkpoint (
 scope_key VARCHAR(64) NOT NULL REFERENCES platform_business_state_head(scope_key),
 revision BIGINT NOT NULL CHECK(revision>0), idempotency_key VARCHAR(128) NOT NULL,
 fingerprint VARCHAR(64) NOT NULL, schema_id VARCHAR(256) NOT NULL,
 value_json TEXT NOT NULL, content_hash VARCHAR(64) NOT NULL,
 execution_revision BIGINT NOT NULL CHECK(execution_revision>0),
 expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(scope_key,revision), UNIQUE(scope_key,idempotency_key));
CREATE TABLE IF NOT EXISTS platform_business_state_admission (
 scope_key VARCHAR(64) PRIMARY KEY, scope_prefix VARCHAR(64) NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS idx_business_state_admission_quota ON platform_business_state_admission(scope_prefix,expires_at);
CREATE INDEX IF NOT EXISTS idx_business_state_admission_expiry ON platform_business_state_admission(expires_at,scope_key);`)
	return err
}

func (s *SQLCheckpointStore) Load(ctx context.Context, scope sharedkernel.Scope, namespace, key, schema string, revision uint64) (Checkpoint, bool, error) {
	if revision > policyasset.MaximumCheckpointRevisions {
		return Checkpoint{}, false, ErrStateLimit
	}
	_, id, err := stateKeys(scope, namespace, key)
	if err != nil || !validStateSchema(schema) {
		return Checkpoint{}, false, ErrStateDenied
	}
	var record Checkpoint
	var raw []byte
	var headSchema string
	var headRevision uint64
	var headExpiry, now time.Time
	var checkpointRevision, executionRevision sql.NullInt64
	var checkpointSchema, contentHash sql.NullString
	var checkpointExpiry sql.NullTime
	// One statement distinguishes an absent lineage from expired/pruned state.
	// A retained head must never become checkpoint:null: callers interpret null
	// as permission to initialize a new loop and may repeat an external effect.
	err = s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT h.schema_id,h.revision,h.expires_at,clock_timestamp(),
 c.revision,c.schema_id,c.value_json,c.content_hash,c.expires_at,c.execution_revision
 FROM platform_business_state_head h LEFT JOIN platform_business_checkpoint c
 ON c.scope_key=h.scope_key AND c.revision=CASE WHEN ?=0 THEN h.revision ELSE ? END
 WHERE h.scope_key=?`), revision, revision, id).Scan(&headSchema, &headRevision, &headExpiry, &now,
		&checkpointRevision, &checkpointSchema, &raw, &contentHash, &checkpointExpiry, &executionRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return Checkpoint{}, false, nil
	}
	if err != nil {
		return Checkpoint{}, false, err
	}
	if headSchema != schema {
		return Checkpoint{}, false, ErrStateSchema
	}
	if !headExpiry.After(now) || !checkpointRevision.Valid || !checkpointExpiry.Valid || !checkpointExpiry.Time.After(now) {
		return Checkpoint{}, false, ErrStateContinuityLost
	}
	if headRevision == 0 || checkpointRevision.Int64 <= 0 || uint64(checkpointRevision.Int64) > headRevision ||
		!executionRevision.Valid || executionRevision.Int64 <= 0 || !checkpointSchema.Valid || checkpointSchema.String != headSchema || !contentHash.Valid {
		return Checkpoint{}, false, ErrStateUnavailable
	}
	record.Revision = uint64(checkpointRevision.Int64)
	record.SchemaID = checkpointSchema.String
	record.ContentHash = contentHash.String
	record.ExpiresAt = checkpointExpiry.Time
	record.ExecutionRevision = uint64(executionRevision.Int64)
	if decodeStateValue(raw, &record.Value) != nil {
		return Checkpoint{}, false, ErrStateUnavailable
	}
	hash, err := stateContentHash(record.SchemaID, record.Value)
	if err != nil || hash != record.ContentHash {
		return Checkpoint{}, false, ErrStateUnavailable
	}
	return record, true, nil
}

func (s *SQLCheckpointStore) Save(ctx context.Context, write StateWrite, check func(context.Context) error) (Checkpoint, error) {
	defer capabilityPhase(ctx, "state.total")()
	capabilityPhaseState(ctx, write.Namespace, "save")
	if s.guard == nil || s.audit == nil || check == nil {
		return Checkpoint{}, ErrStateUnavailable
	}
	prefix, id, err := stateKeys(write.Scope, write.Namespace, write.Key)
	if err != nil {
		return Checkpoint{}, err
	}
	limit := write.MaxRevisions
	if limit == 0 {
		limit = policyasset.DefaultCheckpointRevisions
	}
	if limit > policyasset.MaximumCheckpointRevisions || !stateName.MatchString(write.IdempotencyKey) || write.ExpectedRevision >= limit || write.TTLSeconds < 1 || write.TTLSeconds > 86400 || write.MaxEntries < 1 || write.MaxEntries > 10000 || write.Lease.Revision == 0 || len(write.Lease.TokenHash) != 64 {
		return Checkpoint{}, ErrStateLimit
	}
	finishEncode := capabilityPhase(ctx, "state.encode")
	defer finishEncode()
	hash, err := stateContentHash(write.SchemaID, write.Value)
	if err != nil {
		return Checkpoint{}, err
	}
	valueJSON, _ := json.Marshal(write.Value)
	var immutableValue map[string]any
	if decodeStateValue(valueJSON, &immutableValue) != nil {
		return Checkpoint{}, ErrStateUnavailable
	}
	fingerprintJSON, _ := json.Marshal([]any{write.SchemaID, write.ExpectedRevision, hash, write.TTLSeconds})
	fingerprintHash := sha256.Sum256(fingerprintJSON)
	fingerprint := hex.EncodeToString(fingerprintHash[:])
	finishEncode()
	if write.ReservedQuota {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, checkpointTransactionBound)
		defer cancel()
		// Split the transaction budget: the resource-admission transaction
		// gets half, so the data transaction below always keeps its own share
		// even when many writers queue on the scope quota mutex. An admission
		// deadline commits nothing, so it strands no quota slot.
		admissionCtx, admissionCancel := context.WithTimeout(ctx, checkpointTransactionBound/2)
		finishQuota := capabilityPhase(ctx, "state.quota")
		err = s.reserveCheckpointQuota(admissionCtx, write, prefix, id, check)
		finishQuota()
		admissionCancel()
		// Resource admission alone permits no State disclosure or effect. The
		// original full transaction guard and live checks run again below.
		if err != nil {
			return Checkpoint{}, err
		}
	}
	finishBegin := capabilityPhase(ctx, "state.begin_tx")
	tx, err := s.db.BeginTx(ctx, nil)
	finishBegin()
	if err != nil {
		return Checkpoint{}, err
	}
	defer tx.Rollback()
	ctx = sqlutil.WithContinuityTransaction(ctx, s.db, tx)
	finishGuard := capabilityPhase(ctx, "state.initial_guard")
	err = s.guard(ctx, tx, write.Scope, write.Lease)
	finishGuard()
	if err != nil {
		return Checkpoint{}, errors.Join(ErrStateDenied, err)
	}
	if !write.ReservedQuota {
		if err = check(ctx); err != nil {
			return Checkpoint{}, errors.Join(ErrStateDenied, err)
		}
	}
	// Reserved-quota writes have no scope quota lock or business-state read
	// before the per-head lock. The full live capability check below that lock
	// is the admission fence for State access; repeating it here cannot protect
	// against changes during the lock wait. The Run/IAM/lease guard above stays.
	// New lineages hold the scope quota exclusively. Existing lineages hold
	// that same fence shared, preventing quota races when their TTL extends,
	// and serialize only their own CAS/idempotency history.
	if write.ReservedQuota {
		// The short committed quota reservation covers this data transaction;
		// never hold the scope quota mutex across its live authority checks.
	} else if write.ExpectedRevision == 0 {
		err = lockLedgerScope(ctx, tx, "business-state", prefix)
	} else {
		err = shareLedgerScope(ctx, tx, "business-state", prefix)
	}
	if err != nil {
		return Checkpoint{}, err
	}
	finishHead := capabilityPhase(ctx, "state.head_lock")
	err = lockLedgerScope(ctx, tx, "business-state-head", id)
	finishHead()
	if err != nil {
		return Checkpoint{}, err
	}
	// A lock wait can outlive the execution lease. Recheck database time and
	// current capability authority after acquiring the serialization lock.
	checkContinuity := func() error {
		defer capabilityPhase(ctx, "state.guarded_check")()
		if err := s.guard(ctx, tx, write.Scope, write.Lease); err != nil {
			return errors.Join(ErrStateDenied, err)
		}
		if err := check(ctx); err != nil {
			return errors.Join(ErrStateDenied, err)
		}
		return nil
	}
	if err = checkContinuity(); err != nil {
		return Checkpoint{}, err
	}
	var quotaExpiry time.Time
	if write.ReservedQuota {
		// Authority checks may wait on upstream state. Read the resource proof
		// afterwards, so the saved TTL is checked against the current admission.
		finishCurrentQuota := capabilityPhase(ctx, "state.current_quota")
		quotaExpiry, err = s.checkpointQuotaExpiry(ctx, tx, prefix, id)
		finishCurrentQuota()
		if err != nil {
			return Checkpoint{}, err
		}
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return Checkpoint{}, err
	}
	var prior Checkpoint
	var headExpiry time.Time
	var priorFingerprint string
	var priorJSON []byte
	finishIdempotency := capabilityPhase(ctx, "state.idempotency")
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT c.revision,c.schema_id,c.value_json,c.content_hash,c.expires_at,c.execution_revision,c.fingerprint,h.expires_at FROM platform_business_checkpoint c JOIN platform_business_state_head h ON h.scope_key=c.scope_key WHERE c.scope_key=? AND c.idempotency_key=?`), id, write.IdempotencyKey).Scan(&prior.Revision, &prior.SchemaID, &priorJSON, &prior.ContentHash, &prior.ExpiresAt, &prior.ExecutionRevision, &priorFingerprint, &headExpiry)
	finishIdempotency()
	if err == nil {
		if priorFingerprint != fingerprint || !prior.ExpiresAt.After(now) || !headExpiry.After(now) {
			return Checkpoint{}, ErrStateConflict
		}
		if decodeStateValue(priorJSON, &prior.Value) != nil {
			return Checkpoint{}, ErrStateUnavailable
		}
		verified, verifyErr := stateContentHash(prior.SchemaID, prior.Value)
		if verifyErr != nil || verified != prior.ContentHash {
			return Checkpoint{}, ErrStateUnavailable
		}
		if err = checkContinuity(); err != nil {
			return Checkpoint{}, err
		}
		finishCommit := capabilityPhase(ctx, "state.commit")
		err = tx.Commit()
		finishCommit()
		return prior, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Checkpoint{}, err
	}
	var current uint64
	finishWrite := capabilityPhase(ctx, "state.cas_and_write")
	defer finishWrite()
	var existingSchema string
	var expiry time.Time
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,schema_id,expires_at FROM platform_business_state_head WHERE scope_key=? FOR UPDATE`), id).Scan(&current, &existingSchema, &expiry)
	if err == nil {
		if existingSchema != write.SchemaID {
			return Checkpoint{}, ErrStateSchema
		}
		if current != write.ExpectedRevision || !expiry.After(now) {
			return Checkpoint{}, ErrStateConflict
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if write.ExpectedRevision != 0 {
			return Checkpoint{}, ErrStateConflict
		}
		var count int
		if !write.ReservedQuota {
			if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM (
 SELECT scope_key FROM platform_business_state_head WHERE scope_prefix=? AND expires_at>?
 UNION SELECT scope_key FROM platform_business_state_admission WHERE scope_prefix=? AND expires_at>?
 ) admitted WHERE scope_key<>?`), prefix, now, prefix, now, id).Scan(&count); err != nil {
				return Checkpoint{}, err
			}
			if count >= write.MaxEntries {
				return Checkpoint{}, ErrStateLimit
			}
		}
	} else {
		return Checkpoint{}, err
	}
	checkpoint := Checkpoint{Revision: current + 1, SchemaID: write.SchemaID, Value: immutableValue, ContentHash: hash, ExpiresAt: now.Add(time.Duration(write.TTLSeconds) * time.Second), ExecutionRevision: write.Lease.Revision}
	if write.ReservedQuota && checkpoint.ExpiresAt.After(quotaExpiry) {
		return Checkpoint{}, ErrStateLimit
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_business_state_head(scope_key,scope_prefix,schema_id,revision,expires_at) VALUES(?,?,?,?,?) ON CONFLICT(scope_key) DO UPDATE SET revision=EXCLUDED.revision,expires_at=EXCLUDED.expires_at`), id, prefix, write.SchemaID, checkpoint.Revision, checkpoint.ExpiresAt)
	if err != nil {
		return Checkpoint{}, err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_business_checkpoint(scope_key,revision,idempotency_key,fingerprint,schema_id,value_json,content_hash,execution_revision,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`), id, checkpoint.Revision, write.IdempotencyKey, fingerprint, write.SchemaID, valueJSON, hash, write.Lease.Revision, checkpoint.ExpiresAt, now)
	if err != nil {
		return Checkpoint{}, err
	}
	eventHash := sha256.Sum256([]byte(id + ":" + write.IdempotencyKey))
	finishWrite()
	event := audit.Event{ID: "state-" + hex.EncodeToString(eventHash[:]), TenantID: write.Scope.TenantID, DepartmentID: write.Scope.DepartmentID, ApplicationID: write.Scope.ApplicationID, ActorType: write.Scope.PrincipalType, ActorID: write.Scope.PrincipalID, TraceID: write.Scope.TraceID, AggregateType: "business_checkpoint", AggregateID: id, Action: "state.checkpoint.save", Outcome: "success", Summary: fmt.Sprintf("revision=%d schema=%s content_hash=%s", checkpoint.Revision, checkpoint.SchemaID, checkpoint.ContentHash), CreatedAt: now}
	finishAudit := capabilityPhase(ctx, "state.audit")
	err = s.audit.RecordTx(tx, event)
	finishAudit()
	if err != nil {
		return Checkpoint{}, err
	}
	if err = checkContinuity(); err != nil {
		return Checkpoint{}, err
	}
	finishCommit := capabilityPhase(ctx, "state.commit")
	err = tx.Commit()
	finishCommit()
	return checkpoint, err
}

func (s *SQLCheckpointStore) PruneExpired(ctx context.Context, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrStateLimit
	}
	// Checkpoint expiry is immutable. SKIP LOCKED permits multiple platform
	// workers to drain separate bounded batches without blocking active writes.
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`WITH expired AS (
 SELECT scope_key,revision FROM platform_business_checkpoint
 WHERE expires_at<=clock_timestamp() ORDER BY expires_at,scope_key,revision
 LIMIT ? FOR UPDATE SKIP LOCKED), expired_admissions AS (
 SELECT scope_key FROM platform_business_state_admission
 WHERE expires_at<=clock_timestamp() ORDER BY expires_at,scope_key
 LIMIT ? FOR UPDATE SKIP LOCKED), removed_admissions AS (
 DELETE FROM platform_business_state_admission a USING expired_admissions e
 WHERE a.scope_key=e.scope_key AND a.expires_at<=clock_timestamp() RETURNING a.scope_key)
 DELETE FROM platform_business_checkpoint c USING expired e
 WHERE c.scope_key=e.scope_key AND c.revision=e.revision AND c.expires_at<=clock_timestamp()`), limit, limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func decodeStateValue(raw []byte, target *map[string]any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if *target == nil {
		return ErrStateUnavailable
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return ErrStateUnavailable
	}
	return nil
}
