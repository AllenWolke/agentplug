package evaluationproduct

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"time"
)

// CommitRunCase fences the result and insertion in one transaction.
// 在同一事务内锁定运行与租约并提交 Case，防止取消或接管后迟到写入。
func (s *SQLStore) CommitRunCase(ctx context.Context, scope Scope, runID string, expected uint64, token string, row Resource) error {
	data, err := decodeCaseResult(row)
	if err != nil || !scope.valid() || !validID(token) || expected == 0 || row.Kind != KindCaseResult || row.Scope != scope || row.Revision != 1 || data.RunID != runID || row.ID != caseResultID(runID, data.Index) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin evaluation case commit: %w", err)
	}
	defer tx.Rollback()
	var revision uint64
	var status string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,status FROM platform_evaluation_product_head WHERE tenant_id=? AND department_id=? AND application_id=? AND resource_kind='run' AND resource_id=? FOR UPDATE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, runID).Scan(&revision, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock evaluation case parent: %w", err)
	}
	if revision != expected || status != "running" {
		return ErrConflict
	}
	var actualToken string
	var expiry time.Time
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT lease_token,lease_expires_at FROM platform_evaluation_product_run_lease WHERE tenant_id=? AND department_id=? AND application_id=? AND run_id=? FOR UPDATE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, runID).Scan(&actualToken, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("lock evaluation case lease: %w", err)
	}
	if actualToken != token || !expiry.After(time.Now()) {
		return ErrConflict
	}
	if err := insertResourceTx(ctx, tx, row); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit evaluation case: %w", err)
	}
	return nil
}
