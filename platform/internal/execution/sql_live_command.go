package execution

import (
	"context"
	"database/sql"
	"errors"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// ReadLiveCapabilityCommand is one fresh statement for the same Run, session
// and dispatch-command checks used by validatedLiveCommand. Growing recovery
// documents are deliberately not selected. It caches no authority and locks
// no Run row; transaction/send/disclosure fences remain separate checks.
func (s *SQLStore) ReadLiveCapabilityCommand(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string) (platformruntime.Run, error) {
	if s == nil || s.db == nil || scope.ValidateTrusted() != nil {
		return platformruntime.Run{}, platformruntime.ErrInvalidRequest
	}
	reader, err := sqlutil.ContinuityReader(ctx, s.db)
	if err != nil {
		return platformruntime.Run{}, err
	}
	var run platformruntime.Run
	err = reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT r.run_id,r.tenant_id,r.department_id,r.application_id,
 r.agent_instance_id,r.agent_id,r.principal_id,r.principal_type,r.installation_id,r.agent_version_id,
 r.session_id,r.authorization_epoch,r.trace_id,r.request_json,r.agent_endpoint,r.revision,r.lease_token,r.lease_until
 FROM platform_execution_run r
 JOIN platform_execution_session_lease l ON l.run_id=r.run_id AND l.session_key=?
 AND l.lease_token=r.lease_token AND l.lease_until>clock_timestamp()
 JOIN platform_execution_dispatch_command c ON c.run_id=r.run_id AND c.revision=r.revision
 AND c.operation=? AND c.body_hash=? AND c.policy_hash=?
 WHERE r.run_id=? AND r.status='running' AND r.lease_token<>'' AND r.lease_until>clock_timestamp()`),
		platformruntime.SessionExecutionKey(scope), operation, bodyHash, policyHash, scope.RunID).Scan(
		&run.ID, &run.Scope.TenantID, &run.Scope.DepartmentID, &run.Scope.ApplicationID, &run.Scope.AgentInstanceID,
		&run.Scope.AgentID, &run.Scope.PrincipalID, &run.Scope.PrincipalType, &run.Scope.InstallationID, &run.Scope.AgentVersionID,
		&run.Scope.SessionID, &run.Scope.AuthorizationEpoch, &run.Scope.TraceID, &run.RequestJSON, &run.AgentEndpoint,
		&run.Revision, &run.LeaseToken, &run.LeaseUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return platformruntime.Run{}, platformruntime.ErrLeaseConflict
	}
	if err != nil {
		return platformruntime.Run{}, err
	}
	run.Scope.RunID = run.ID
	restoreParentRunID(&run)
	if run.Scope != scope {
		return platformruntime.Run{}, platformruntime.ErrLeaseConflict
	}
	run.AgentVersionID = run.Scope.AgentVersionID
	run.Status = platformruntime.StatusRunning
	return run, nil
}
