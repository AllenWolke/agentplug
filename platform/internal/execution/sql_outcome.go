package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

func (s *SQLStore) FinalizeLeased(id string, status platformruntime.Status, revision uint64, token string, output map[string]any, payload map[string]any) (platformruntime.Run, error) {
	if token == "" {
		return platformruntime.Run{}, platformruntime.ErrLeaseConflict
	}
	outcome, err := platformruntime.NewOutcome(status, output, payload)
	if err != nil {
		return platformruntime.Run{}, err
	}
	return s.transitionOutcome(id, platformruntime.StatusRunning, status, revision, token, &outcome)
}

func (s *SQLStore) GetOutcome(id string) (platformruntime.Outcome, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var outcome platformruntime.Outcome
	var payload []byte
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id,revision,output_json,event_type,event_payload,projection_pending FROM platform_execution_outcome WHERE run_id=?`), id).Scan(&outcome.RunID, &outcome.Revision, &outcome.OutputJSON, &outcome.EventType, &payload, &outcome.ProjectionPending)
	if errors.Is(err, sql.ErrNoRows) {
		return outcome, platformruntime.ErrRunNotFound
	}
	if err != nil {
		return outcome, err
	}
	if err := json.Unmarshal(payload, &outcome.EventPayload); err != nil {
		return platformruntime.Outcome{}, err
	}
	return outcome, nil
}

// PendingOutcomes reads bounded durable intents, never reruns an Agent.
// PendingOutcomes 有界读取持久化待办，禁止通过重跑 Agent 修补历史。
func (s *SQLStore) PendingOutcomes(limit int) ([]platformruntime.Outcome, error) {
	return s.PendingOutcomesAfter("", limit)
}

// Keyset scans advance past failed records; persistence remains authoritative.
// 游标分页越过失败记录；持久化待办仍为权威事实，不因翻页被删除。
func (s *SQLStore) PendingOutcomesAfter(after string, limit int) ([]platformruntime.Outcome, error) {
	if limit < 1 {
		return nil, nil
	}
	if limit > 256 {
		limit = 256
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT run_id, revision, output_json, event_type, event_payload FROM platform_execution_outcome WHERE projection_pending=TRUE AND run_id>? ORDER BY run_id LIMIT ?`), after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var outcomes []platformruntime.Outcome
	for rows.Next() {
		var outcome platformruntime.Outcome
		var payload []byte
		if err := rows.Scan(&outcome.RunID, &outcome.Revision, &outcome.OutputJSON, &outcome.EventType, &payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &outcome.EventPayload); err != nil {
			return nil, err
		}
		outcome.ProjectionPending = true
		outcomes = append(outcomes, outcome)
	}
	return outcomes, rows.Err()
}

func (s *SQLStore) AcknowledgeOutcome(id string, revision uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_outcome SET projection_pending=FALSE WHERE run_id=? AND revision=?`), id, revision)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return platformruntime.ErrRevisionConflict
	}
	return nil
}
