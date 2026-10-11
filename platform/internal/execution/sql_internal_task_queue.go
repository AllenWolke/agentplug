package execution

import (
	"context"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

// ListInternalPending uses execution-owned storage; no separate task table or
// queue credentials. IS JSON protects historical malformed request rows.
func (s *SQLStore) ListInternalPending(ctx context.Context, schema string, limit int) ([]string, error) {
	if schema != KnowledgeIndexInputSchema || limit < 1 || limit > 100 {
		return nil, platformruntime.ErrInvalidRequest
	}
	rows, err := s.db.QueryContext(ctx, `SELECT run_id FROM platform_execution_run WHERE agent_endpoint='' AND (status='accepted' OR (status='running' AND lease_token='')) AND CASE WHEN request_json IS JSON OBJECT THEN request_json::jsonb->>'input_schema' ELSE NULL END=$1 ORDER BY created_at,run_id LIMIT $2`, schema, limit)
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
	return ids, rows.Err()
}
