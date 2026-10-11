package execution

import (
	"context"
	"database/sql"
	"errors"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

// EvaluationBatchParent names an already locked product batch. This internal
// read port is not browser authorization: composition verifies every returned
// child's frozen request, creator, trace, case index and scope before control.
type EvaluationBatchParent struct {
	TenantID, DepartmentID, ApplicationID, EvaluationID string
}

// EvaluationBatchChildIDsTx shares the caller's admission-fencing transaction.
// Never return a partial list that could conceal an uncompensated child.
func (s *SQLStore) EvaluationBatchChildIDsTx(ctx context.Context, tx *sql.Tx, parent EvaluationBatchParent) ([]string, error) {
	if s == nil || s.db == nil || ctx == nil || tx == nil || parent.TenantID == "" || parent.DepartmentID == "" || parent.ApplicationID == "" || parent.EvaluationID == "" {
		return nil, platformruntime.ErrInvalidRequest
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT run_id FROM platform_execution_run WHERE tenant_id=? AND department_id=? AND application_id=? AND request_json IS NOT NULL AND request_json<>'' AND request_json::jsonb->'scope'->>'parent_run_id'=? ORDER BY run_id LIMIT 10001`), parent.TenantID, parent.DepartmentID, parent.ApplicationID, parent.EvaluationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) > 10000 {
		return nil, errors.New("evaluation batch children limit exceeded")
	}
	return ids, nil
}
