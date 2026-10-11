package execution

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Same-database transaction port: lock known run facts before conversation
// payload erasure. Waiting/recovering/cancelling and leased runs are not terminal.
func (s *SQLStore) SessionQuiescentTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, sessionID string) (bool, error) {
	if s == nil || tx == nil || scope.TenantID == "" || scope.DepartmentID == "" || scope.ApplicationID == "" || sessionID == "" {
		return false, sql.ErrNoRows
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT status,lease_token FROM platform_execution_run WHERE tenant_id=? AND department_id=? AND application_id=? AND session_id=? FOR SHARE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, sessionID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	quiet := true
	for rows.Next() {
		var status, lease string
		if err := rows.Scan(&status, &lease); err != nil {
			return false, err
		}
		if (status != "succeeded" && status != "failed" && status != "cancelled") || lease != "" {
			quiet = false
		}
	}
	return quiet, rows.Err()
}
