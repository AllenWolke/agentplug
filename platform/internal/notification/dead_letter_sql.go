package notification

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/segmentio/kafka-go"
)

const DeadLetterSchemaVersion uint64 = 2026100906
const deadLetterDDL = `
CREATE TABLE IF NOT EXISTS platform_kafka_dead_letter_schema_version(version BIGINT PRIMARY KEY,checksum VARCHAR(64) NOT NULL,applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS platform_kafka_delivery_attempt(
 source_id VARCHAR(64) PRIMARY KEY,source_json TEXT NOT NULL,source_digest VARCHAR(64) NOT NULL,
 attempts INTEGER NOT NULL CHECK(attempts>=0 AND attempts<=1000000),quarantined BOOLEAN NOT NULL DEFAULT false,
 acknowledged BOOLEAN NOT NULL DEFAULT false,published BOOLEAN NOT NULL DEFAULT false,updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS platform_kafka_dead_letter(
 source_id VARCHAR(64) PRIMARY KEY REFERENCES platform_kafka_delivery_attempt(source_id),
 metadata_json TEXT NOT NULL,tenant_id VARCHAR(255) NOT NULL,department_id VARCHAR(255) NOT NULL,application_id VARCHAR(255) NOT NULL,
 raw_value BYTEA NOT NULL,raw_key BYTEA NOT NULL,raw_headers TEXT NOT NULL,
 status VARCHAR(32) NOT NULL CHECK(status IN ('quarantined','redrive_pending','closed')),
 revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0),created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
CREATE INDEX IF NOT EXISTS idx_platform_kafka_dlq_scope ON platform_kafka_dead_letter(tenant_id,department_id,application_id,source_id);
CREATE TABLE IF NOT EXISTS platform_kafka_dead_letter_action(
 action_id VARCHAR(64) PRIMARY KEY,source_id VARCHAR(64) NOT NULL REFERENCES platform_kafka_dead_letter(source_id),
 actor_digest VARCHAR(64) NOT NULL,request_digest VARCHAR(64) NOT NULL,action VARCHAR(32) NOT NULL,
 result_revision BIGINT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
`

func ApplyDeadLetterSchema(ctx context.Context, db *sql.DB) error {
	if ctx == nil || db == nil {
		return ErrDeadLetterUnavailable
	}
	if _, e := db.ExecContext(ctx, deadLetterDDL); e != nil {
		return e
	}
	h := sha256.Sum256([]byte(deadLetterDDL))
	checksum := hex.EncodeToString(h[:])
	var prior string
	e := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT checksum FROM platform_kafka_dead_letter_schema_version WHERE version=?`), DeadLetterSchemaVersion).Scan(&prior)
	if e == nil && prior != checksum {
		return ErrDeadLetterConflict
	}
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if errors.Is(e, sql.ErrNoRows) {
		if _, e = db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_kafka_dead_letter_schema_version(version,checksum) VALUES(?,?)`), DeadLetterSchemaVersion, checksum); e != nil {
			return e
		}
	}
	// Existing runtime roles may inherit the owner's default table grants.
	// Protect markers/history explicitly before the new schema is promoted.
	rows, e := db.QueryContext(ctx, `SELECT DISTINCT a.grantee FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE n.nspname='public' AND c.relname IN ('platform_kafka_dead_letter_schema_version','platform_kafka_dead_letter_action','platform_kafka_dead_letter') AND a.grantee<>c.relowner`)
	if e != nil {
		return e
	}
	var roles []uint32
	for rows.Next() {
		var id uint32
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		roles = append(roles, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	roles = append(roles, 0)
	for _, id := range roles {
		role := "PUBLIC"
		if id != 0 {
			var name string
			if e = db.QueryRowContext(ctx, `SELECT rolname FROM pg_roles WHERE oid=$1`, id).Scan(&name); e != nil {
				return e
			}
			role = pgx.Identifier{name}.Sanitize()
		}
		for _, q := range []string{`REVOKE INSERT,UPDATE,DELETE ON platform_kafka_dead_letter_schema_version FROM `, `REVOKE UPDATE,DELETE ON platform_kafka_dead_letter_action FROM `, `REVOKE DELETE ON platform_kafka_dead_letter FROM `} {
			if _, e = db.ExecContext(ctx, q+role); e != nil {
				return e
			}
		}
	}
	return nil
}
func CheckDeadLetterSchema(ctx context.Context, db *sql.DB) error {
	if ctx == nil || db == nil {
		return ErrDeadLetterUnavailable
	}
	var prior string
	h := sha256.Sum256([]byte(deadLetterDDL))
	if e := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT checksum FROM platform_kafka_dead_letter_schema_version WHERE version=?`), DeadLetterSchemaVersion).Scan(&prior); e != nil {
		return ErrDeadLetterUnavailable
	}
	if prior != hex.EncodeToString(h[:]) {
		return ErrDeadLetterConflict
	}
	return nil
}

type SQLDeadLetterStore struct {
	db        *sql.DB
	authorize func(context.Context, *sql.Tx, sharedkernel.Scope, string) error
	record    func(context.Context, *sql.Tx, sharedkernel.Scope, DeadLetterCommand, DeadLetterMetadata) error
	redrive   func(context.Context, *sql.Tx, sharedkernel.Scope, Event) error
}

func NewSQLDeadLetterStore(db *sql.DB) (*SQLDeadLetterStore, error) {
	if db == nil {
		return nil, ErrDeadLetterUnavailable
	}
	return &SQLDeadLetterStore{db: db}, nil
}
func (s *SQLDeadLetterStore) SetOperations(authorize func(context.Context, *sql.Tx, sharedkernel.Scope, string) error, record func(context.Context, *sql.Tx, sharedkernel.Scope, DeadLetterCommand, DeadLetterMetadata) error, redrive func(context.Context, *sql.Tx, sharedkernel.Scope, Event) error) error {
	if s == nil || authorize == nil || record == nil || s.authorize != nil {
		return ErrDeadLetterUnavailable
	}
	s.authorize, s.record, s.redrive = authorize, record, redrive
	return nil
}

func (s *SQLDeadLetterStore) StartAttempt(ctx context.Context, source DeadLetterSource, max int) (DeadLetterAttempt, error) {
	var result DeadLetterAttempt
	if s == nil || ctx == nil || source.Validate() != nil || max < 1 || max > 100 {
		return result, ErrDeadLetterConflict
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	raw, _ := json.Marshal(source)
	if _, e = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_kafka_delivery_attempt(source_id,source_json,source_digest,attempts) VALUES(?,?,?,0) ON CONFLICT(source_id) DO NOTHING`), source.ID(), string(raw), source.Digest); e != nil {
		return result, e
	}
	var digest string
	var quarantined bool
	if e = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT source_digest,attempts,quarantined,acknowledged,published FROM platform_kafka_delivery_attempt WHERE source_id=? FOR UPDATE`), source.ID()).Scan(&digest, &result.Attempts, &quarantined, &result.Acknowledged, &result.Published); e != nil {
		return result, e
	}
	if digest != source.Digest {
		return result, ErrDeadLetterConflict
	}
	result.Exhausted = quarantined || result.Attempts >= max
	if !result.Exhausted && !result.Acknowledged && !result.Published {
		result.Attempts++
		if _, e = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_kafka_delivery_attempt SET attempts=?,updated_at=clock_timestamp() WHERE source_id=?`), result.Attempts, source.ID()); e != nil {
			return result, e
		}
	}
	return result, tx.Commit()
}

func (s *SQLDeadLetterStore) Quarantine(ctx context.Context, record DeadLetterRecord) error {
	meta := record.Metadata
	actual, e := deadLetterSource(meta.Source.Group, record.Raw)
	if s == nil || e != nil || actual != meta.Source || meta.Version != DeadLetterVersion || meta.ID != actual.ID() || meta.Attempts < 1 {
		return ErrDeadLetterConflict
	}
	bound, e := newDeadLetterRecord(actual, record.Raw, nil, meta.Attempts)
	if e != nil || bound.Metadata.EventID != meta.EventID || bound.Metadata.TenantID != meta.TenantID || bound.Metadata.DepartmentID != meta.DepartmentID || bound.Metadata.ApplicationID != meta.ApplicationID || bound.Metadata.PayloadDigest != meta.PayloadDigest || bound.Metadata.PayloadBytes != meta.PayloadBytes {
		return ErrDeadLetterConflict
	}
	switch meta.ErrorCode {
	case "CANCELLED", "TIMEOUT", "INVALID_EVENT", "DELIVERY_EXHAUSTED", "DELIVERY_IN_PROGRESS", "ADAPTER_UNAVAILABLE", "CLAIM_LOST", "DELIVERY_FAILED":
	default:
		return ErrDeadLetterConflict
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var digest string
	var attempts int
	var ack bool
	if e = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT source_digest,attempts,acknowledged FROM platform_kafka_delivery_attempt WHERE source_id=? FOR UPDATE`), meta.ID).Scan(&digest, &attempts, &ack); e != nil {
		return e
	}
	if digest != meta.Source.Digest || attempts != meta.Attempts || ack {
		return ErrDeadLetterConflict
	}
	raw, _ := json.Marshal(meta)
	headers, _ := json.Marshal(record.Raw.Headers)
	if _, e = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_kafka_dead_letter(source_id,metadata_json,tenant_id,department_id,application_id,raw_value,raw_key,raw_headers,status) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(source_id) DO NOTHING`), meta.ID, string(raw), meta.TenantID, meta.DepartmentID, meta.ApplicationID, nonNilBytes(record.Raw.Value), nonNilBytes(record.Raw.Key), string(headers), "quarantined"); e != nil {
		return e
	}
	var prior string
	if e = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT metadata_json FROM platform_kafka_dead_letter WHERE source_id=?`), meta.ID).Scan(&prior); e != nil {
		return e
	}
	var old DeadLetterMetadata
	if json.Unmarshal([]byte(prior), &old) != nil || old.Source != meta.Source || old.PayloadDigest != meta.PayloadDigest || old.Attempts != meta.Attempts {
		return ErrDeadLetterConflict
	}
	if _, e = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_kafka_delivery_attempt SET quarantined=true,updated_at=clock_timestamp() WHERE source_id=?`), meta.ID); e != nil {
		return e
	}
	return tx.Commit()
}
func nonNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
func (s *SQLDeadLetterStore) MarkPublished(ctx context.Context, source DeadLetterSource) error {
	return s.mark(ctx, source, true)
}
func (s *SQLDeadLetterStore) MarkAcknowledged(ctx context.Context, source DeadLetterSource) error {
	return s.mark(ctx, source, false)
}
func (s *SQLDeadLetterStore) mark(ctx context.Context, source DeadLetterSource, published bool) error {
	if s == nil || source.Validate() != nil {
		return ErrDeadLetterConflict
	}
	query := `UPDATE platform_kafka_delivery_attempt SET acknowledged=true,updated_at=clock_timestamp() WHERE source_id=? AND source_digest=? AND NOT quarantined`
	if published {
		query = `UPDATE platform_kafka_delivery_attempt SET published=true,updated_at=clock_timestamp() WHERE source_id=? AND source_digest=? AND quarantined AND NOT acknowledged`
	}
	r, e := s.db.ExecContext(ctx, sqlutil.Bind(query), source.ID(), source.Digest)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrDeadLetterConflict
	}
	return nil
}

type DeadLetterQuery struct {
	AfterID         string
	Limit           int
	IncludeUnscoped bool
}

func (s *SQLDeadLetterStore) List(ctx context.Context, scope sharedkernel.Scope, q DeadLetterQuery) ([]DeadLetterMetadata, error) {
	if s == nil || s.authorize == nil || scope.Validate() != nil || q.Limit < 1 || q.Limit > 100 || q.AfterID != "" && !deadLetterDigest(q.AfterID) {
		return nil, ErrDeadLetterUnavailable
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	action := "inspect"
	if q.IncludeUnscoped {
		action = "inspect.unscoped"
	}
	if e = s.authorize(ctx, tx, scope, action); e != nil {
		return nil, e
	}
	where := `tenant_id=? AND department_id=? AND application_id=?`
	args := []any{scope.TenantID, scope.DepartmentID, scope.ApplicationID, q.AfterID, q.Limit}
	if q.IncludeUnscoped {
		where = "tenant_id=''"
		args = []any{q.AfterID, q.Limit}
	}
	rows, e := tx.QueryContext(ctx, sqlutil.Bind(`SELECT metadata_json,status,revision,created_at FROM platform_kafka_dead_letter WHERE `+where+` AND source_id>? ORDER BY source_id LIMIT ?`), args...)
	if e != nil {
		return nil, e
	}
	result := make([]DeadLetterMetadata, 0)
	for rows.Next() {
		var raw, status string
		var rev int64
		var created time.Time
		if e = rows.Scan(&raw, &status, &rev, &created); e != nil {
			rows.Close()
			return nil, e
		}
		var m DeadLetterMetadata
		if json.Unmarshal([]byte(raw), &m) != nil {
			rows.Close()
			return nil, ErrDeadLetterConflict
		}
		m.Status, m.Revision, m.CreatedAt = status, rev, created
		result = append(result, m)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return result, nil
}

type DeadLetterCommand struct {
	ID               string `json:"id"`
	ExpectedRevision int64  `json:"expected_revision"`
	IdempotencyKey   string `json:"idempotency_key"`
	Action           string `json:"action"`
	ReasonCode       string `json:"reason_code"`
	Unscoped         bool   `json:"unscoped,omitempty"`
}

// The producer/source event and delivery ledger are prepared only by their
// owner in this same transaction. No arbitrary payload/topic edits are allowed.
func (s *SQLDeadLetterStore) Act(ctx context.Context, scope sharedkernel.Scope, c DeadLetterCommand) (DeadLetterMetadata, error) {
	var empty DeadLetterMetadata
	if s == nil || s.authorize == nil || s.record == nil || scope.Validate() != nil || !deadLetterDigest(c.ID) || c.ExpectedRevision < 1 || !deadLetterToken(c.IdempotencyKey, 128) || !deadLetterToken(c.ReasonCode, 64) || (c.Action != "close" && c.Action != "redrive") {
		return empty, ErrDeadLetterUnavailable
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	authorityAction := c.Action
	if c.Unscoped {
		if c.Action != "close" {
			return empty, ErrDeadLetterUnavailable
		}
		authorityAction = "close.unscoped"
	}
	if e = s.authorize(ctx, tx, scope, authorityAction); e != nil {
		return empty, e
	}
	actorRaw, _ := json.Marshal(struct{ Tenant, Department, Application, Type, ID string }{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID})
	actorHash := sha256.Sum256(actorRaw)
	actorDigest := hex.EncodeToString(actorHash[:])
	h := sha256.Sum256([]byte(actorDigest + "\x00" + c.ID + "\x00" + c.IdempotencyKey))
	actionID := hex.EncodeToString(h[:])
	requestRaw, _ := json.Marshal(c)
	h = sha256.Sum256(requestRaw)
	requestDigest := hex.EncodeToString(h[:])
	var raw, status string
	var rev int64
	var value, key []byte
	var headers string
	tenant, department, application := scope.TenantID, scope.DepartmentID, scope.ApplicationID
	if c.Unscoped {
		tenant, department, application = "", "", ""
	}
	if e = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT metadata_json,status,revision,raw_value,raw_key,raw_headers FROM platform_kafka_dead_letter WHERE source_id=? AND tenant_id=? AND department_id=? AND application_id=? FOR UPDATE`), c.ID, tenant, department, application).Scan(&raw, &status, &rev, &value, &key, &headers); e != nil {
		return empty, ErrDeadLetterConflict
	}
	var meta DeadLetterMetadata
	if json.Unmarshal([]byte(raw), &meta) != nil {
		return empty, ErrDeadLetterConflict
	}
	var oldRequest string
	var oldRev int64
	e = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,result_revision FROM platform_kafka_dead_letter_action WHERE action_id=?`), actionID).Scan(&oldRequest, &oldRev)
	if e == nil {
		if oldRequest != requestDigest {
			return empty, ErrDeadLetterConflict
		}
		meta.Status, meta.Revision = status, oldRev
		return meta, tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return empty, e
	}
	if status != "quarantined" || rev != c.ExpectedRevision {
		return empty, ErrDeadLetterConflict
	}
	next := "closed"
	if c.Action == "redrive" {
		if s.redrive == nil {
			return empty, ErrDeadLetterUnavailable
		}
		var hs []kafka.Header
		if json.Unmarshal([]byte(headers), &hs) != nil {
			return empty, ErrDeadLetterConflict
		}
		m := kafka.Message{Topic: meta.Source.Topic, Partition: meta.Source.Partition, Offset: meta.Source.Offset, Key: key, Value: value, Headers: hs}
		bound, e := deadLetterSource(meta.Source.Group, m)
		if e != nil || bound != meta.Source {
			return empty, ErrDeadLetterConflict
		}
		event, e := decodeKafkaEvent(value)
		if e != nil || event.ValidateForDelivery() != nil || event.ID != meta.EventID || event.Topic != meta.Source.Topic || event.TenantID != scope.TenantID || event.DepartmentID != scope.DepartmentID || event.ApplicationID != scope.ApplicationID {
			return empty, ErrDeadLetterConflict
		}
		if e = s.redrive(ctx, tx, scope, event); e != nil {
			return empty, e
		}
		next = "redrive_pending"
	}
	meta.Status, meta.Revision = next, rev+1
	if _, e = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_kafka_dead_letter SET status=?,revision=? WHERE source_id=? AND revision=?`), next, meta.Revision, c.ID, rev); e != nil {
		return empty, e
	}
	if _, e = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_kafka_dead_letter_action(action_id,source_id,actor_digest,request_digest,action,result_revision) VALUES(?,?,?,?,?,?)`), actionID, c.ID, actorDigest, requestDigest, c.Action, meta.Revision); e != nil {
		return empty, e
	}
	if e = s.record(ctx, tx, scope, c, meta); e != nil {
		return empty, e
	}
	return meta, tx.Commit()
}
