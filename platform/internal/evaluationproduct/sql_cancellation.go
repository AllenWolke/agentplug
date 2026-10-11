package evaluationproduct

import (
	"context"
	"encoding/json"

	"github.com/lexagent/platform/internal/sqlutil"
)

func (s *SQLStore) PendingCancellationRuns(ctx context.Context, cursor string, limit int) ([]Resource, error) {
	if s == nil || s.db == nil || ctx == nil || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT h.tenant_id,h.department_id,h.application_id,v.resource_id,v.resource_kind,v.revision,v.status,v.payload,v.created_by,h.created_at,h.updated_at
FROM platform_evaluation_product_head h JOIN platform_evaluation_product_version v
ON v.tenant_id=h.tenant_id AND v.department_id=h.department_id AND v.application_id=h.application_id AND v.resource_kind=h.resource_kind AND v.resource_id=h.resource_id AND v.revision=h.revision
WHERE h.resource_kind='run' AND h.status='cancelling' AND (h.tenant_id||'|'||h.department_id||'|'||h.application_id||'|'||h.resource_id)>?
ORDER BY (h.tenant_id||'|'||h.department_id||'|'||h.application_id||'|'||h.resource_id) LIMIT ?`), cursor, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Resource{}
	for rows.Next() {
		var row Resource
		var encoded []byte
		if err := rows.Scan(&row.Scope.TenantID, &row.Scope.DepartmentID, &row.Scope.ApplicationID, &row.ID, &row.Kind, &row.Revision, &row.Status, &encoded, &row.CreatedBy, &row.CreatedAt, &row.UpdatedAt); err != nil {
			return nil, err
		}
		row.Data = append(json.RawMessage(nil), encoded...)
		result = append(result, row)
	}
	return result, rows.Err()
}
