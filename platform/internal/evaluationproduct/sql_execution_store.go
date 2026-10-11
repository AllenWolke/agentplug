package evaluationproduct

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"time"
)

// ClaimNextRun uses PostgreSQL head-row locking as the durable queue. The database row,
// rather than the in-process wake-up channel, decides ownership.
func (s *SQLStore) ClaimNextRun(ctx context.Context, owner, token string, now time.Time, lease time.Duration) (Resource, bool, error) {
	if s == nil || s.db == nil || !validID(owner) || !validID(token) || lease <= 0 {
		return Resource{}, false, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Resource{}, false, fmt.Errorf("begin evaluation run claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var row Resource
	var scope Scope
	var payload []byte
	query := `SELECT h.tenant_id,h.department_id,h.application_id,v.resource_id,v.revision,v.status,v.payload,v.created_by,h.created_at,h.updated_at
		FROM platform_evaluation_product_head h
		JOIN platform_evaluation_product_version v ON v.tenant_id=h.tenant_id AND v.department_id=h.department_id AND v.application_id=h.application_id AND v.resource_kind=h.resource_kind AND v.resource_id=h.resource_id AND v.revision=h.revision
		LEFT JOIN platform_evaluation_product_run_lease l ON l.tenant_id=h.tenant_id AND l.department_id=h.department_id AND l.application_id=h.application_id AND l.run_id=h.resource_id
		WHERE h.resource_kind='run' AND (h.status='queued' OR (h.status='running' AND (l.run_id IS NULL OR l.lease_expires_at<=?)))
		ORDER BY h.created_at ASC,h.resource_id ASC LIMIT 1 FOR UPDATE OF h SKIP LOCKED`
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(query), now.UTC()).Scan(&scope.TenantID, &scope.DepartmentID, &scope.ApplicationID, &row.ID, &row.Revision, &row.Status, &payload, &row.CreatedBy, &row.CreatedAt, &row.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Resource{}, false, nil
		}
		return Resource{}, false, fmt.Errorf("select evaluation run to claim: %w", err)
	}
	row.Scope, row.Kind = scope, KindRun
	if !scope.valid() || !validID(row.ID) || row.Revision == 0 {
		return Resource{}, false, snapshotInvalid("database returned invalid claimed run identity")
	}
	row.Data = append(json.RawMessage(nil), payload...)
	var data RunData
	if err := decodeSnapshotJSON(row.Data, &data); err != nil || !validID(data.SuiteID) || !validID(data.IdempotencyKey) {
		return Resource{}, false, snapshotInvalid("claimed run has invalid execution state")
	}
	data.ExecutionState = "running"
	data.LeaseOwner, data.LeaseToken = owner, token
	data.LeaseUntil, data.Attempt = now.UTC().Add(lease), data.Attempt+1
	row.Status, row.Revision, row.UpdatedAt = "running", row.Revision+1, now.UTC()
	row.Data, err = json.Marshal(data)
	if err != nil {
		return Resource{}, false, fmt.Errorf("encode claimed evaluation run: %w", err)
	}
	encoded, _ := json.Marshal(row.Data)
	if err := insertVersion(ctx, tx, row, encoded); err != nil {
		return Resource{}, false, err
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_evaluation_product_head SET revision=?,status='running',updated_at=? WHERE tenant_id=? AND department_id=? AND application_id=? AND resource_kind='run' AND resource_id=? AND revision=?`), row.Revision, row.UpdatedAt, scope.TenantID, scope.DepartmentID, scope.ApplicationID, row.ID, row.Revision-1)
	if err != nil {
		return Resource{}, false, fmt.Errorf("update claimed evaluation run: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return Resource{}, false, fmt.Errorf("check claimed evaluation run: %w", err)
		}
		return Resource{}, false, ErrConflict
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_evaluation_product_run_lease (tenant_id,department_id,application_id,run_id,lease_owner,lease_token,lease_expires_at)
		VALUES (?,?,?,?,?,?,?) ON CONFLICT (tenant_id,department_id,application_id,run_id) DO UPDATE SET lease_owner=EXCLUDED.lease_owner,lease_token=EXCLUDED.lease_token,lease_expires_at=EXCLUDED.lease_expires_at`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, row.ID, owner, token, data.LeaseUntil)
	if err != nil {
		return Resource{}, false, fmt.Errorf("persist evaluation run lease: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Resource{}, false, fmt.Errorf("commit evaluation run claim: %w", err)
	}
	return row, true, nil
}

func (s *SQLStore) RenewRunLease(ctx context.Context, scope Scope, runID string, expected uint64, token string, until time.Time) (Resource, error) {
	if !scope.valid() || !validID(runID) || expected == 0 || !validID(token) || !until.After(time.Now()) {
		return Resource{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Resource{}, fmt.Errorf("begin evaluation lease renewal: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	row, err := scanResource(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT v.resource_id,v.resource_kind,v.revision,v.status,v.payload,v.created_by,h.created_at,h.updated_at
		FROM platform_evaluation_product_head h JOIN platform_evaluation_product_version v ON v.tenant_id=h.tenant_id AND v.department_id=h.department_id AND v.application_id=h.application_id AND v.resource_kind=h.resource_kind AND v.resource_id=h.resource_id AND v.revision=h.revision
		WHERE h.tenant_id=? AND h.department_id=? AND h.application_id=? AND h.resource_kind='run' AND h.resource_id=? FOR UPDATE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, runID), scope)
	if err != nil {
		return Resource{}, err
	}
	if row.Revision != expected || row.Status != "running" {
		return Resource{}, ErrConflict
	}
	var data RunData
	if json.Unmarshal(row.Data, &data) != nil || data.LeaseToken != token {
		return Resource{}, ErrConflict
	}
	var currentToken string
	var expires time.Time
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT lease_token,lease_expires_at FROM platform_evaluation_product_run_lease WHERE tenant_id=? AND department_id=? AND application_id=? AND run_id=? FOR UPDATE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, runID).Scan(&currentToken, &expires); err != nil {
		return Resource{}, ErrConflict
	}
	if currentToken != token || !expires.After(time.Now()) {
		return Resource{}, ErrConflict
	}
	data.LeaseUntil = until.UTC()
	row.Revision++
	row.UpdatedAt = time.Now().UTC()
	row.Data, _ = json.Marshal(data)
	encoded, _ := json.Marshal(row.Data)
	if err := insertVersion(ctx, tx, row, encoded); err != nil {
		return Resource{}, err
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_evaluation_product_head SET revision=?,updated_at=? WHERE tenant_id=? AND department_id=? AND application_id=? AND resource_kind='run' AND resource_id=? AND revision=?`), row.Revision, row.UpdatedAt, scope.TenantID, scope.DepartmentID, scope.ApplicationID, runID, expected)
	if err != nil {
		return Resource{}, fmt.Errorf("update evaluation lease revision: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return Resource{}, fmt.Errorf("check evaluation lease revision: %w", err)
		}
		return Resource{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_evaluation_product_run_lease SET lease_expires_at=? WHERE tenant_id=? AND department_id=? AND application_id=? AND run_id=? AND lease_token=?`), until.UTC(), scope.TenantID, scope.DepartmentID, scope.ApplicationID, runID, token); err != nil {
		return Resource{}, fmt.Errorf("extend evaluation run lease: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Resource{}, fmt.Errorf("commit evaluation lease renewal: %w", err)
	}
	return row, nil
}

// FinalizeRun persists the terminal run state and report as one transaction.
// A worker that lost its token, revision, or expiry cannot publish evidence.
func (s *SQLStore) FinalizeRun(ctx context.Context, scope Scope, expected uint64, token string, row Resource, evidence *Resource) error {
	if !scope.valid() || row.Kind != KindRun || row.Scope != scope || !validID(row.ID) || expected == 0 || row.Revision != expected+1 || (row.Status != "succeeded" && row.Status != "failed") || !json.Valid(row.Data) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin evaluation finalization: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	current, err := scanResource(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT v.resource_id,v.resource_kind,v.revision,v.status,v.payload,v.created_by,h.created_at,h.updated_at
		FROM platform_evaluation_product_head h JOIN platform_evaluation_product_version v ON v.tenant_id=h.tenant_id AND v.department_id=h.department_id AND v.application_id=h.application_id AND v.resource_kind=h.resource_kind AND v.resource_id=h.resource_id AND v.revision=h.revision
		WHERE h.tenant_id=? AND h.department_id=? AND h.application_id=? AND h.resource_kind='run' AND h.resource_id=? FOR UPDATE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, row.ID), scope)
	if err != nil {
		return err
	}
	if current.Revision != expected || current.Status != "running" {
		return ErrConflict
	}
	var leaseToken string
	var expires time.Time
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT lease_token,lease_expires_at FROM platform_evaluation_product_run_lease WHERE tenant_id=? AND department_id=? AND application_id=? AND run_id=? FOR UPDATE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, row.ID).Scan(&leaseToken, &expires); err != nil || leaseToken != token || !expires.After(time.Now()) {
		return ErrConflict
	}
	var data RunData
	if json.Unmarshal(row.Data, &data) != nil || data.LeaseToken != "" || data.ExecutionState != row.Status {
		return ErrInvalid
	}
	row.CreatedBy, row.CreatedAt = current.CreatedBy, current.CreatedAt
	row.UpdatedAt = time.Now().UTC()
	encoded, _ := json.Marshal(row.Data)
	if err := insertVersion(ctx, tx, row, encoded); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_evaluation_product_head SET revision=?,status=?,updated_at=? WHERE tenant_id=? AND department_id=? AND application_id=? AND resource_kind='run' AND resource_id=? AND revision=?`), row.Revision, row.Status, row.UpdatedAt, scope.TenantID, scope.DepartmentID, scope.ApplicationID, row.ID, expected)
	if err != nil {
		return fmt.Errorf("update finalized evaluation run: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return fmt.Errorf("check finalized evaluation run: %w", err)
		}
		return ErrConflict
	}
	if evidence != nil {
		if evidence.Kind != KindEvidence || evidence.Scope != scope || evidence.Revision != 1 || evidence.Status != "completed" {
			return ErrInvalid
		}
		if err := insertResourceTx(ctx, tx, *evidence); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_evaluation_product_run_lease WHERE tenant_id=? AND department_id=? AND application_id=? AND run_id=? AND lease_token=?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, row.ID, token); err != nil {
		return fmt.Errorf("release evaluation run lease: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit evaluation finalization: %w", err)
	}
	return nil
}

func (s *SQLStore) ListRunCases(ctx context.Context, scope Scope, runID string, page, pageSize int) ([]Resource, int64, error) {
	if !scope.valid() || !validID(runID) || page < 1 || page > 100000 || pageSize < 1 || pageSize > MaxPageSize {
		return nil, 0, ErrInvalid
	}
	var total int64
	countQuery := `SELECT COUNT(*) FROM platform_evaluation_product_head h JOIN platform_evaluation_product_version v ON v.tenant_id=h.tenant_id AND v.department_id=h.department_id AND v.application_id=h.application_id AND v.resource_kind=h.resource_kind AND v.resource_id=h.resource_id AND v.revision=h.revision
		WHERE h.tenant_id=? AND h.department_id=? AND h.application_id=? AND h.resource_kind='case_result' AND v.payload->>'run_id'=?`
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(countQuery), scope.TenantID, scope.DepartmentID, scope.ApplicationID, runID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count evaluation case evidence: %w", err)
	}
	listQuery := `SELECT v.resource_id,v.resource_kind,v.revision,v.status,v.payload,v.created_by,h.created_at,h.updated_at
		FROM platform_evaluation_product_head h JOIN platform_evaluation_product_version v ON v.tenant_id=h.tenant_id AND v.department_id=h.department_id AND v.application_id=h.application_id AND v.resource_kind=h.resource_kind AND v.resource_id=h.resource_id AND v.revision=h.revision
		WHERE h.tenant_id=? AND h.department_id=? AND h.application_id=? AND h.resource_kind='case_result' AND v.payload->>'run_id'=?
		ORDER BY CAST(v.payload->>'index' AS NUMERIC(20,0)),v.resource_id LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(listQuery), scope.TenantID, scope.DepartmentID, scope.ApplicationID, runID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("list evaluation case evidence: %w", err)
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
		return nil, 0, fmt.Errorf("iterate evaluation case evidence: %w", err)
	}
	return items, total, nil
}

func insertResourceTx(ctx context.Context, tx *sql.Tx, row Resource) error {
	if err := validateResource(row); err != nil || row.Revision != 1 {
		return ErrInvalid
	}
	now := row.CreatedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	payload, err := json.Marshal(row.Data)
	if err != nil || !json.Valid(payload) {
		return ErrInvalid
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_evaluation_product_head
		(tenant_id,department_id,application_id,resource_kind,resource_id,revision,status,idempotency_key,created_by,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`), row.Scope.TenantID, row.Scope.DepartmentID, row.Scope.ApplicationID, row.Kind, row.ID, row.Revision, row.Status, nullableIdempotency(row), row.CreatedBy, now, now); err != nil {
		if isDuplicate(err) {
			return ErrConflict
		}
		return fmt.Errorf("insert evaluation product resource head: %w", err)
	}
	row.CreatedAt, row.UpdatedAt = now, now
	return insertVersion(ctx, tx, row, payload)
}

var _ ExecutionStore = (*SQLStore)(nil)
