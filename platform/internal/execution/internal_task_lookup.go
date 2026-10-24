package execution

import (
	"context"
	"database/sql"
	"strings"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// FindInternalTaskTx reads existing tasks only. The composition owner holds
// current IAM continuity and validates the task input before exposing a receipt.
// Multiple matches across old versions/epochs are an ambiguity, never a retry.
func (s *SQLStore) FindInternalTaskTx(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, installation, key string) (platformruntime.Run, error) {
	empty := platformruntime.Run{}
	if s == nil || s.db == nil || tx == nil || actor.Validate() != nil || actor.PrincipalType != "user" || installation == "" || len(installation) > 128 || strings.TrimSpace(installation) != installation || key == "" || len(key) > 128 || strings.TrimSpace(key) != key {
		return empty, platformruntime.ErrInvalidRequest
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT run_id FROM platform_execution_run WHERE tenant_id=? AND department_id=? AND application_id=? AND principal_type=? AND principal_id=? AND installation_id=? AND idempotency_key=? AND agent_endpoint='' ORDER BY run_id LIMIT 2`), actor.TenantID, actor.DepartmentID, actor.ApplicationID, actor.PrincipalType, actor.PrincipalID, installation, key)
	if err != nil {
		return empty, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return empty, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	if closeErr := rows.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return empty, err
	}
	if len(ids) == 0 {
		return empty, platformruntime.ErrRunNotFound
	}
	if len(ids) != 1 {
		return empty, platformruntime.ErrIdempotencyConflict
	}
	return readExecutionRun(ctx, tx, ids[0], "")
}
