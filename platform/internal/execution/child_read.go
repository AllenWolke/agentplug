package execution

import (
	"context"
	"database/sql"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

// DirectChildRunIDsTx 仅投影组织内已记录的直接子 Run。控制方仍须核验
// 每个子运行的冻结请求及创建者，不能凭返回ID获得停止或补偿权限。
func (s *SQLStore) DirectChildRunIDsTx(ctx context.Context, tx *sql.Tx, tenant, department, application, parent string, limit int) ([]string, error) {
	if s == nil || tx == nil || tenant == "" || department == "" || application == "" || parent == "" || limit < 1 || limit > 10000 {
		return nil, platformruntime.ErrInvalidRequest
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT run_id FROM platform_execution_run WHERE tenant_id=? AND department_id=? AND application_id=? AND request_json IS NOT NULL AND request_json<>'' AND request_json::jsonb->'scope'->>'parent_run_id'=? ORDER BY run_id LIMIT ?`), tenant, department, application, parent, limit+1)
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
	if len(ids) > limit {
		return nil, platformruntime.ErrInvalidRequest
	}
	return ids, nil
}
