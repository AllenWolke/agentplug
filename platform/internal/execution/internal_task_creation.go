package execution

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// CreateInternalTaskTx must be called inside the management-authorized
// admission transaction. Execution owns Run/events; the caller owns policy
// materialization, IAM continuity and audit/Outbox, then commits them together.
// No business conversation/task projection is created for platform-owned work.
func (s *SQLStore) CreateInternalTaskTx(ctx context.Context, tx *sql.Tx, req platformruntime.CreateRequest) (platformruntime.CreateResult, error) {
	empty := platformruntime.CreateResult{}
	if tx == nil || req.Scope.ValidateTrusted() != nil || req.ID != req.Scope.RunID || req.AgentVersionID != req.Scope.AgentVersionID || req.AgentEndpoint != "" || req.MessageID != "" || len(req.IdempotencyKey) < 8 || len(req.IdempotencyKey) > 128 {
		return empty, platformruntime.ErrInvalidRequest
	}
	var command contract.ExecuteRequest
	if json.Unmarshal(req.RequestJSON, &command) != nil || command.ProtocolVersion != contract.ProtocolVersion || command.ContextToken != "" || command.InputSchema != KnowledgeIndexInputSchema || command.Input == nil || command.ResumeInput != nil || (command.Operation != "invoke" && command.Operation != "run") || command.IdempotencyKey != req.IdempotencyKey || command.Scope.DelegationDepth != 0 {
		return empty, platformruntime.ErrInvalidRequest
	}
	c := command.Scope
	owner := sharedkernel.Scope{TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID, AgentID: c.AgentID, AgentInstanceID: c.AgentInstanceID, InstallationID: c.InstallationID, AgentVersionID: c.AgentVersionID, PrincipalID: c.PrincipalID, PrincipalType: c.PrincipalType, SessionID: c.SessionID, RunID: c.RunID, ParentRunID: c.ParentRunID, TraceID: c.TraceID, AuthorizationEpoch: c.AuthorizationEpoch}
	if owner != req.Scope {
		return empty, platformruntime.ErrInvalidRequest
	}
	digest, err := contract.CanonicalExecuteBodyHash(command)
	if err != nil || digest != req.Fingerprint {
		return empty, platformruntime.ErrIdempotencyConflict
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(platformruntime.ScopeIdempotencyHash(req.Scope, req.IdempotencyKey))))
	return s.createRunTx(ctx, tx, req, hash, true)
}
