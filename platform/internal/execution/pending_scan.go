package execution

import (
	"context"
	"database/sql"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Explicit deployment migration only. Runtime users need no index/DDL rights.
func MigratePendingScanSchema(ctx context.Context, db *sql.DB) error {
	return (&SQLStore{db: db}).EnsurePendingScanSchema(ctx)
}

func (s *SQLStore) EnsurePendingScanSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS platform_execution_pending_run_scan ON platform_execution_run(run_id) WHERE (status='accepted' OR (status='running' AND lease_token='')) AND request_json IS NOT NULL AND request_json<>'' AND agent_endpoint<>''`)
	return err
}

// ListPendingAfter advances beyond busy roots to discover descendants. The
// execution store still enforces per-session FIFO and exact leases on claim.
func (s *SQLStore) ListPendingAfter(ctx context.Context, after string, limit int) ([]platformruntime.Run, error) {
	if s == nil || s.db == nil || len(after) > 128 || limit < 1 || limit > 128 {
		return nil, platformruntime.ErrInvalidRequest
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT run_id,tenant_id,department_id,application_id,agent_instance_id,agent_id,principal_id,principal_type,installation_id,agent_version_id,session_id,authorization_epoch,trace_id,idempotency_key,request_json,trace_context,resume_input_json,agent_endpoint,status,revision,lease_token,lease_until,created_at,updated_at FROM platform_execution_run WHERE (status='accepted' OR (status='running' AND lease_token='')) AND request_json IS NOT NULL AND request_json<>'' AND agent_endpoint<>'' AND run_id>? ORDER BY run_id LIMIT ?`), after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]platformruntime.Run, 0, limit)
	for rows.Next() {
		var run platformruntime.Run
		var status string
		var leaseUntil sql.NullTime
		if err := rows.Scan(&run.ID, &run.Scope.TenantID, &run.Scope.DepartmentID, &run.Scope.ApplicationID, &run.Scope.AgentInstanceID, &run.Scope.AgentID, &run.Scope.PrincipalID, &run.Scope.PrincipalType, &run.Scope.InstallationID, &run.Scope.AgentVersionID, &run.Scope.SessionID, &run.Scope.AuthorizationEpoch, &run.Scope.TraceID, &run.IdempotencyKey, &run.RequestJSON, &run.TraceContext, &run.ResumeInputJSON, &run.AgentEndpoint, &status, &run.Revision, &run.LeaseToken, &leaseUntil, &run.CreatedAt, &run.UpdatedAt); err != nil {
			return nil, err
		}
		run.Scope.RunID = run.ID
		restoreParentRunID(&run)
		run.AgentVersionID, run.Status, run.LeaseUntil = run.Scope.AgentVersionID, platformruntime.Status(status), leaseUntil.Time
		result = append(result, run)
	}
	return result, rows.Err()
}
