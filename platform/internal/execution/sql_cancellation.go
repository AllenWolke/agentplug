package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func (s *SQLStore) PendingCancellations(limit int) ([]platformruntime.Run, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.pendingCancellations(ctx, "", limit, false)
}

// Stable Run-ID keyset traversal rotates past unresolved old generations.
// It is read-only: retries neither rewrite timestamps nor erase UNKNOWN.
func (s *SQLStore) ListPendingCancellationsAfter(parent context.Context, after string, limit int) ([]platformruntime.Run, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	return s.pendingCancellations(ctx, after, limit, true)
}

// ListPendingCancellationHeadersAfter returns only the fields the retry
// scheduler compares (status, revision, lease). Backed-off rows therefore no
// longer transfer request_json; a due row is reread in full before any stop.
func (s *SQLStore) ListPendingCancellationHeadersAfter(parent context.Context, after string, limit int) ([]platformruntime.Run, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	if limit < 1 {
		return nil, nil
	}
	if limit > 256 {
		limit = 256
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT run_id,status,revision,lease_token FROM platform_execution_run WHERE status IN ('cancelling','recovering') AND run_id>? ORDER BY run_id LIMIT ?`), after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []platformruntime.Run
	for rows.Next() {
		var run platformruntime.Run
		var status string
		if err := rows.Scan(&run.ID, &status, &run.Revision, &run.LeaseToken); err != nil {
			return nil, err
		}
		run.Status = platformruntime.Status(status)
		result = append(result, run)
	}
	return result, rows.Err()
}

func (s *SQLStore) pendingCancellations(ctx context.Context, after string, limit int, keyset bool) ([]platformruntime.Run, error) {
	if limit < 1 {
		return nil, nil
	}
	if limit > 256 {
		limit = 256
	}
	query := `SELECT run_id FROM platform_execution_run WHERE status IN ('cancelling','recovering') ORDER BY updated_at,run_id LIMIT ?`
	args := []any{limit}
	if keyset {
		query = `SELECT run_id FROM platform_execution_run WHERE status IN ('cancelling','recovering') AND run_id>? ORDER BY run_id LIMIT ?`
		args = []any{after, limit}
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	result := make([]platformruntime.Run, 0, len(ids))
	for _, id := range ids {
		run, err := s.GetContext(ctx, id)
		if err != nil {
			return nil, err
		}
		if run.Status == platformruntime.StatusCancelling || run.Status == platformruntime.StatusRecovering {
			result = append(result, run)
		}
	}
	return result, nil
}

// BeginCancellation persists intent and its event atomically; no lease is
// released here. A remote stop acknowledgement is required for final Cancel.
// 取消意图与事件原子保存；这里不释放租约，最终取消必须等待远程停止确认。
func (s *SQLStore) BeginCancellation(id string, expected uint64) (platformruntime.Run, error) {
	return s.BeginCancellationWithReason(id, expected, "USER_CANCEL_REQUESTED")
}

func (s *SQLStore) BeginCancellationWithReason(id string, expected uint64, reason string) (platformruntime.Run, error) {
	run, err := s.Get(id)
	if err != nil {
		return platformruntime.Run{}, err
	}
	if run.Status == platformruntime.StatusCancelling || run.Status == platformruntime.StatusCancelled {
		return run, nil
	}
	if expected != 0 && run.Revision != expected {
		return platformruntime.Run{}, platformruntime.ErrRevisionConflict
	}
	if run.Status != platformruntime.StatusAccepted && run.Status != platformruntime.StatusRunning && run.Status != platformruntime.StatusWaiting {
		return platformruntime.Run{}, platformruntime.ErrInvalidTransition
	}
	tx, err := s.db.Begin()
	if err != nil {
		return platformruntime.Run{}, err
	}
	defer func() { _ = tx.Rollback() }()
	changed, err := s.beginCancellationTx(context.Background(), tx, run, reason)
	if err != nil {
		return platformruntime.Run{}, err
	}
	if err = tx.Commit(); err != nil {
		return platformruntime.Run{}, err
	}
	return changed, nil
}

// BeginInternalTaskCancellationTx lets management intent and its audit commit
// together. Only immutable, platform-owned indexing commands are accepted.
// It never acknowledges a running worker stopped or releases its session.
func (s *SQLStore) BeginInternalTaskCancellationTx(ctx context.Context, tx *sql.Tx, owner sharedkernel.Scope, expected uint64) (platformruntime.Run, bool, error) {
	if tx == nil || owner.ValidateTrusted() != nil || expected == 0 {
		return platformruntime.Run{}, false, platformruntime.ErrInvalidRequest
	}
	run, err := s.GetContext(ctx, owner.RunID)
	if err != nil {
		return platformruntime.Run{}, false, err
	}
	var command contract.ExecuteRequest
	if run.Scope != owner || run.AgentEndpoint != "" || json.Unmarshal(run.RequestJSON, &command) != nil || command.ProtocolVersion != contract.ProtocolVersion || command.InputSchema != KnowledgeIndexInputSchema || command.ContextToken != "" || (command.Operation != "run" && command.Operation != "invoke") || command.Scope.DelegationDepth != 0 {
		return platformruntime.Run{}, false, platformruntime.ErrInvalidRequest
	}
	c := command.Scope
	bound := sharedkernel.Scope{TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID, AgentID: c.AgentID, AgentInstanceID: c.AgentInstanceID, InstallationID: c.InstallationID, AgentVersionID: c.AgentVersionID, PrincipalID: c.PrincipalID, PrincipalType: c.PrincipalType, SessionID: c.SessionID, RunID: c.RunID, ParentRunID: c.ParentRunID, TraceID: c.TraceID, AuthorizationEpoch: c.AuthorizationEpoch}
	if bound != owner {
		return platformruntime.Run{}, false, platformruntime.ErrInvalidRequest
	}
	if run.Status == platformruntime.StatusCancelling || run.Status == platformruntime.StatusCancelled {
		return run, false, nil
	}
	if run.Revision != expected {
		return platformruntime.Run{}, false, platformruntime.ErrRevisionConflict
	}
	if run.Status != platformruntime.StatusAccepted && run.Status != platformruntime.StatusRunning {
		return platformruntime.Run{}, false, platformruntime.ErrInvalidTransition
	}
	changed, err := s.beginCancellationTx(ctx, tx, run, "KNOWLEDGE_INDEX_CANCEL_REQUESTED")
	return changed, err == nil, err
}

func (s *SQLStore) beginCancellationTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run, reason string) (platformruntime.Run, error) {
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET status=?, revision=revision+1, updated_at=? WHERE run_id=? AND revision=? AND status=?`), platformruntime.StatusCancelling, now, run.ID, run.Revision, run.Status)
	if err != nil {
		return platformruntime.Run{}, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return platformruntime.Run{}, err
	}
	if count != 1 {
		return platformruntime.Run{}, platformruntime.ErrRevisionConflict
	}
	payload, err := json.Marshal(map[string]any{"revision": run.Revision + 1, "code": reason})
	if err != nil {
		return platformruntime.Run{}, err
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES (?,?,?,?)`), run.ID, "cancel_requested", payload, now); err != nil {
		return platformruntime.Run{}, err
	}
	run.Status = platformruntime.StatusCancelling
	run.Revision++
	run.UpdatedAt = now
	if s.cancellationSaga != nil {
		if _, err := s.cancellationSaga.BeginTx(ctx, tx, run.Scope, run.Revision); err != nil {
			return platformruntime.Run{}, err
		}
	}
	return run, nil
}
