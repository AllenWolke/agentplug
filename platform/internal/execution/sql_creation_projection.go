package execution

import (
	"context"
	"database/sql"
	"errors"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

func (s *SQLStore) GetCreation(id string) (platformruntime.CreationProjection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var p platformruntime.CreationProjection
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id, message_id, conversation_pending, task_pending FROM platform_execution_creation_projection WHERE run_id=?`), id).Scan(&p.RunID, &p.MessageID, &p.ConversationPending, &p.TaskPending)
	if errors.Is(err, sql.ErrNoRows) {
		return p, platformruntime.ErrRunNotFound
	}
	return p, err
}

func (s *SQLStore) PendingCreations(limit int) ([]platformruntime.CreationProjection, error) {
	return s.PendingCreationsAfter("", limit)
}

// Keyset scans retain failed intents while allowing later tenants to progress.
// 游标扫描保留失败待办，同时允许后续租户的任务继续补偿。
func (s *SQLStore) PendingCreationsAfter(after string, limit int) ([]platformruntime.CreationProjection, error) {
	if limit < 1 {
		return nil, nil
	}
	if limit > 256 {
		limit = 256
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT run_id, message_id, conversation_pending, task_pending FROM platform_execution_creation_projection WHERE (conversation_pending=TRUE OR task_pending=TRUE) AND run_id>? ORDER BY run_id LIMIT ?`), after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []platformruntime.CreationProjection
	for rows.Next() {
		var p platformruntime.CreationProjection
		if err := rows.Scan(&p.RunID, &p.MessageID, &p.ConversationPending, &p.TaskPending); err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

func (s *SQLStore) AcknowledgeCreation(id, kind string) error {
	statement := ""
	switch kind {
	case "conversation":
		statement = `UPDATE platform_execution_creation_projection SET conversation_pending=FALSE WHERE run_id=?`
	case "task":
		statement = `UPDATE platform_execution_creation_projection SET task_pending=FALSE WHERE run_id=?`
	default:
		return platformruntime.ErrInvalidRequest
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(statement), id)
	return err
}
