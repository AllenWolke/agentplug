package evaluationproduct

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

// SQLStore persists a mutable head and append-only resource versions. The
// explicit scope columns keep tenant predicates visible in every query.
// SQLStore 持久化可变 Head 与只追加版本；所有查询都显式携带租户作用域。
type SQLStore struct{ db *sql.DB }

func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

// QueueSnapshot reads the durable run heads, including work left by a previous
// process. The resource_kind/status index bounds the scan to queued runs.
type QueueSnapshot struct {
	Depth          int64
	OldestQueuedAt time.Time
}

func (s *SQLStore) QueueSnapshot(ctx context.Context) (QueueSnapshot, error) {
	if s == nil || s.db == nil {
		return QueueSnapshot{}, errors.New("evaluation queue database is required")
	}
	var result QueueSnapshot
	var oldest sql.NullTime
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*),MIN(created_at) FROM platform_evaluation_product_head WHERE resource_kind='run' AND status='queued'`)).Scan(&result.Depth, &oldest)
	if err != nil {
		return QueueSnapshot{}, fmt.Errorf("read evaluation queue snapshot: %w", err)
	}
	if oldest.Valid {
		result.OldestQueuedAt = oldest.Time.UTC()
	}
	return result, nil
}

func (s *SQLStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("evaluation product database is required")
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS platform_evaluation_product_head (
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			resource_kind VARCHAR(24) COLLATE "C" NOT NULL,
			resource_id VARCHAR(128) COLLATE "C" NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			status VARCHAR(24) NOT NULL,
			idempotency_key VARCHAR(128) COLLATE "C" NULL,
			created_by VARCHAR(128) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL,
			PRIMARY KEY (tenant_id, department_id, application_id, resource_kind, resource_id),
			CONSTRAINT uq_eval_product_idempotency UNIQUE (tenant_id, department_id, application_id, resource_kind, idempotency_key));
CREATE INDEX IF NOT EXISTS idx_eval_product_scope_updated ON platform_evaluation_product_head (tenant_id, department_id, application_id, resource_kind, updated_at);
CREATE INDEX IF NOT EXISTS idx_eval_product_queue ON platform_evaluation_product_head (resource_kind, status, created_at);`,
		`CREATE TABLE IF NOT EXISTS platform_evaluation_product_version (
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			resource_kind VARCHAR(24) COLLATE "C" NOT NULL,
			resource_id VARCHAR(128) COLLATE "C" NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			status VARCHAR(24) NOT NULL,
			payload JSON NOT NULL,
			created_by VARCHAR(128) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			PRIMARY KEY (tenant_id, department_id, application_id, resource_kind, resource_id, revision));
CREATE INDEX IF NOT EXISTS idx_eval_product_versions ON platform_evaluation_product_version (tenant_id, department_id, application_id, resource_kind, created_at);`,
		`CREATE TABLE IF NOT EXISTS platform_evaluation_product_run_lease (
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			run_id VARCHAR(128) COLLATE "C" NOT NULL,
			lease_owner VARCHAR(128) NOT NULL,
			lease_token VARCHAR(128) COLLATE "C" NOT NULL,
			lease_expires_at TIMESTAMPTZ(6) NOT NULL,
			PRIMARY KEY (tenant_id,department_id,application_id,run_id));
CREATE INDEX IF NOT EXISTS idx_eval_product_lease_expiry ON platform_evaluation_product_run_lease (lease_expires_at);`,
		`CREATE TABLE IF NOT EXISTS platform_evaluation_product_output_artifact (
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			run_id VARCHAR(128) COLLATE "C" NOT NULL,
			case_id VARCHAR(128) COLLATE "C" NOT NULL,
			artifact_id VARCHAR(128) COLLATE "C" NOT NULL,
			sha256 VARCHAR(64) COLLATE "C" NOT NULL,
			size_bytes NUMERIC(20,0) CHECK (size_bytes>=0 AND size_bytes<=18446744073709551615) NOT NULL,
			payload BYTEA NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			PRIMARY KEY (tenant_id,department_id,application_id,run_id,case_id),
			CONSTRAINT uq_eval_product_artifact_id UNIQUE (artifact_id));
CREATE INDEX IF NOT EXISTS idx_eval_product_artifact_run ON platform_evaluation_product_output_artifact (tenant_id,department_id,application_id,run_id);`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(statement)); err != nil {
			return fmt.Errorf("ensure evaluation product schema: %w", err)
		}
	}
	return nil
}

func (s *SQLStore) Create(ctx context.Context, row Resource) error {
	if err := validateResource(row); err != nil || row.Revision != 1 {
		return ErrInvalid
	}
	now := row.CreatedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	row.CreatedAt, row.UpdatedAt = now, now
	payload, err := json.Marshal(row.Data)
	if err != nil || !json.Valid(payload) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin evaluation product create: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_evaluation_product_head
		(tenant_id,department_id,application_id,resource_kind,resource_id,revision,status,idempotency_key,created_by,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`), row.Scope.TenantID, row.Scope.DepartmentID, row.Scope.ApplicationID, row.Kind, row.ID, row.Revision, row.Status, nullableIdempotency(row), row.CreatedBy, now, now)
	if err != nil {
		if isDuplicate(err) {
			return ErrConflict
		}
		return fmt.Errorf("insert evaluation product head: %w", err)
	}
	if err := insertVersion(ctx, tx, row, payload); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		if isDuplicate(err) {
			return ErrConflict
		}
		return fmt.Errorf("commit evaluation product create: %w", err)
	}
	return nil
}

func (s *SQLStore) Get(ctx context.Context, scope Scope, kind Kind, id string) (Resource, error) {
	if !scope.valid() || !validKind(kind) || !validID(id) {
		return Resource{}, ErrInvalid
	}
	return scanResource(s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT v.resource_id,v.resource_kind,v.revision,v.status,v.payload,v.created_by,h.created_at,h.updated_at
		FROM platform_evaluation_product_head h JOIN platform_evaluation_product_version v
		ON v.tenant_id=h.tenant_id AND v.department_id=h.department_id AND v.application_id=h.application_id AND v.resource_kind=h.resource_kind AND v.resource_id=h.resource_id AND v.revision=h.revision
		WHERE h.tenant_id=? AND h.department_id=? AND h.application_id=? AND h.resource_kind=? AND h.resource_id=?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, kind, id), scope)
}

// GetTx reads a product resource using the caller's transaction. When lockHead
// is true it takes a shared lock on the scoped mutable head, so admission can
// hold the exact parent revision through its decision without opening a second
// transaction. Published dataset/metric versions remain append-only.
func (s *SQLStore) GetTx(ctx context.Context, tx *sql.Tx, scope Scope, kind Kind, id string, lockHead bool) (Resource, error) {
	if s == nil || tx == nil || !scope.valid() || !validKind(kind) || !validID(id) {
		return Resource{}, ErrInvalid
	}
	lock := ""
	if lockHead {
		lock = " FOR SHARE OF h"
	}
	query := `SELECT v.resource_id,v.resource_kind,v.revision,v.status,v.payload,v.created_by,h.created_at,h.updated_at
		FROM platform_evaluation_product_head h JOIN platform_evaluation_product_version v
		ON v.tenant_id=h.tenant_id AND v.department_id=h.department_id AND v.application_id=h.application_id AND v.resource_kind=h.resource_kind AND v.resource_id=h.resource_id AND v.revision=h.revision
		WHERE h.tenant_id=? AND h.department_id=? AND h.application_id=? AND h.resource_kind=? AND h.resource_id=?` + lock
	return scanResource(tx.QueryRowContext(ctx, sqlutil.Bind(query), scope.TenantID, scope.DepartmentID, scope.ApplicationID, kind, id), scope)
}

// CheckRunLeaseTx compares the published Run head's lease envelope with the
// separate durable lease row. A caller must already hold the scoped Run head
// lock so renewal/finalization cannot race this live admission check.
func (s *SQLStore) CheckRunLeaseTx(ctx context.Context, tx *sql.Tx, scope Scope, runID, owner, token string, until, now time.Time) error {
	if s == nil || tx == nil || !scope.valid() || !validID(runID) || !validID(owner) || !validID(token) || !until.After(now) {
		return ErrConflict
	}
	var storedOwner, storedToken string
	var storedUntil time.Time
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT lease_owner,lease_token,lease_expires_at
		FROM platform_evaluation_product_run_lease WHERE tenant_id=? AND department_id=? AND application_id=? AND run_id=? FOR SHARE`),
		scope.TenantID, scope.DepartmentID, scope.ApplicationID, runID).Scan(&storedOwner, &storedToken, &storedUntil)
	delta := storedUntil.Sub(until)
	if delta < 0 {
		delta = -delta
	}
	if err != nil || storedOwner != owner || storedToken != token || delta > time.Microsecond || !storedUntil.After(now) {
		return ErrConflict
	}
	return nil
}

func (s *SQLStore) FindByIdempotency(ctx context.Context, scope Scope, kind Kind, key string) (Resource, error) {
	if !scope.valid() || kind != KindRun || !validID(key) {
		return Resource{}, ErrInvalid
	}
	var id string
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT resource_id FROM platform_evaluation_product_head WHERE tenant_id=? AND department_id=? AND application_id=? AND resource_kind=? AND idempotency_key=?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, kind, key).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return Resource{}, ErrNotFound
	}
	if err != nil {
		return Resource{}, fmt.Errorf("find idempotent evaluation run: %w", err)
	}
	return s.Get(ctx, scope, kind, id)
}

func (s *SQLStore) List(ctx context.Context, scope Scope, kind Kind, page, pageSize int) ([]Resource, int64, error) {
	if !scope.valid() || !validKind(kind) || page < 1 || page > 100000 || pageSize < 1 || pageSize > MaxPageSize {
		return nil, 0, ErrInvalid
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_evaluation_product_head WHERE tenant_id=? AND department_id=? AND application_id=? AND resource_kind=?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, kind).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count evaluation product resources: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT v.resource_id,v.resource_kind,v.revision,v.status,v.payload,v.created_by,h.created_at,h.updated_at
		FROM platform_evaluation_product_head h JOIN platform_evaluation_product_version v
		ON v.tenant_id=h.tenant_id AND v.department_id=h.department_id AND v.application_id=h.application_id AND v.resource_kind=h.resource_kind AND v.resource_id=h.resource_id AND v.revision=h.revision
		WHERE h.tenant_id=? AND h.department_id=? AND h.application_id=? AND h.resource_kind=?
		ORDER BY h.updated_at DESC,h.resource_id DESC LIMIT ? OFFSET ?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, kind, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("list evaluation product resources: %w", err)
	}
	defer rows.Close()
	items := make([]Resource, 0)
	for rows.Next() {
		row, err := scanResource(rows, scope)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, row)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate evaluation product resources: %w", err)
	}
	return items, total, nil
}

func (s *SQLStore) UpdateCAS(ctx context.Context, scope Scope, kind Kind, id string, expected uint64, row Resource) error {
	if !scope.valid() || !validKind(kind) || !validID(id) || expected == 0 || row.Scope != scope || row.Kind != kind || row.ID != id || row.Revision != expected+1 || !json.Valid(row.Data) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin evaluation product update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var revision uint64
	var createdBy string
	var createdAt time.Time
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,created_by,created_at FROM platform_evaluation_product_head WHERE tenant_id=? AND department_id=? AND application_id=? AND resource_kind=? AND resource_id=? FOR UPDATE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, kind, id).Scan(&revision, &createdBy, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("lock evaluation product head: %w", err)
	}
	if revision != expected {
		return ErrConflict
	}
	now := time.Now().UTC()
	row.CreatedBy = createdBy
	row.CreatedAt = createdAt.UTC()
	row.UpdatedAt = now
	payload, err := json.Marshal(row.Data)
	if err != nil || !json.Valid(payload) {
		return ErrInvalid
	}
	if err := insertVersion(ctx, tx, row, payload); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_evaluation_product_head SET revision=?,status=?,updated_at=? WHERE tenant_id=? AND department_id=? AND application_id=? AND resource_kind=? AND resource_id=? AND revision=?`), row.Revision, row.Status, now, scope.TenantID, scope.DepartmentID, scope.ApplicationID, kind, id, expected)
	if err != nil {
		return fmt.Errorf("update evaluation product head: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return fmt.Errorf("check evaluation product revision: %w", err)
		}
		return ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit evaluation product update: %w", err)
	}
	return nil
}

func insertVersion(ctx context.Context, tx *sql.Tx, row Resource, payload []byte) error {
	_, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_evaluation_product_version
		(tenant_id,department_id,application_id,resource_kind,resource_id,revision,status,payload,created_by,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`), row.Scope.TenantID, row.Scope.DepartmentID, row.Scope.ApplicationID, row.Kind, row.ID, row.Revision, row.Status, string(payload), row.CreatedBy, row.UpdatedAt.UTC())
	if err != nil {
		return fmt.Errorf("insert evaluation product version: %w", err)
	}
	return nil
}

type rowScanner interface{ Scan(...any) error }

func scanResource(scanner rowScanner, scope Scope) (Resource, error) {
	var row Resource
	var payload []byte
	row.Scope = scope
	if err := scanner.Scan(&row.ID, &row.Kind, &row.Revision, &row.Status, &payload, &row.CreatedBy, &row.CreatedAt, &row.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Resource{}, ErrNotFound
		}
		return Resource{}, fmt.Errorf("scan evaluation product resource: %w", err)
	}
	row.Data = append(json.RawMessage(nil), payload...)
	row.CreatedAt, row.UpdatedAt = row.CreatedAt.UTC(), row.UpdatedAt.UTC()
	return row, nil
}

func nullableIdempotency(row Resource) any {
	if row.Kind == KindRun {
		var data RunData
		if json.Unmarshal(row.Data, &data) == nil && data.IdempotencyKey != "" {
			return data.IdempotencyKey
		}
	}
	return nil
}

func isDuplicate(err error) bool {
	return sqlutil.IsUniqueViolation(err)
}

var _ Store = (*SQLStore)(nil)
