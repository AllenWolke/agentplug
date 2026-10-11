package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// CreateCoordinatedRunTx is an admission Port, not an HTTP bypass. The
// composition must atomically own the matching child reservation, current
// caller/parent-machine/target-machine IAM intersection, immutable target
// policy and shared root budget admission in this same transaction. Each model
// send separately reserves its exact shared-root provider hold. No dispatch occurs
// here; only the normal fenced execution dispatcher may execute the child.
func (s *SQLStore) CreateCoordinatedRunTx(ctx context.Context, tx *sql.Tx, parent sharedkernel.Scope, lease sharedkernel.ExecutionLeaseBinding, req platformruntime.CreateRequest) (platformruntime.CreateResult, error) {
	empty := platformruntime.CreateResult{}
	if tx == nil || parent.ValidateTrusted() != nil || req.Scope.ValidateTrusted() != nil || req.ID != req.Scope.RunID || req.AgentVersionID != req.Scope.AgentVersionID || req.MessageID != "" || req.AgentEndpoint == "" || len(req.RequestJSON) > 1<<20 || len(req.IdempotencyKey) < 8 || len(req.IdempotencyKey) > 128 {
		return empty, platformruntime.ErrInvalidRequest
	}
	child := req.Scope
	if child.TenantID != parent.TenantID || child.DepartmentID != parent.DepartmentID || child.ApplicationID != parent.ApplicationID || child.PrincipalType != parent.PrincipalType || child.PrincipalID != parent.PrincipalID || child.SessionID != parent.SessionID || child.ParentRunID != parent.RunID || child.RunID == parent.RunID || child.InstallationID == parent.InstallationID || child.AgentID == parent.AgentID || child.AgentInstanceID != child.InstallationID {
		return empty, platformruntime.ErrInvalidRequest
	}
	if err := s.CheckCapabilityLeaseTx(ctx, tx, parent, lease); err != nil {
		return empty, err
	}
	var command contract.ExecuteRequest
	decoder := json.NewDecoder(bytes.NewReader(req.RequestJSON))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF || command.ProtocolVersion != contract.ProtocolVersion || command.ContextToken != "" || command.Input == nil || command.ResumeInput != nil || command.Operation != "run" || command.IdempotencyKey != req.IdempotencyKey || command.Scope.DelegationDepth < 1 || command.Scope.DelegationDepth > 4 {
		return empty, platformruntime.ErrInvalidRequest
	}
	c := command.Scope
	owner := sharedkernel.Scope{TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID, AgentID: c.AgentID, AgentInstanceID: c.AgentInstanceID, InstallationID: c.InstallationID, AgentVersionID: c.AgentVersionID, PrincipalID: c.PrincipalID, PrincipalType: c.PrincipalType, SessionID: c.SessionID, RunID: c.RunID, ParentRunID: c.ParentRunID, TraceID: c.TraceID, AuthorizationEpoch: c.AuthorizationEpoch}
	if owner != child || command.InputSchema == "" {
		return empty, platformruntime.ErrInvalidRequest
	}
	fingerprint, err := contract.CanonicalExecuteBodyHash(command)
	if err != nil || fingerprint != req.Fingerprint {
		return empty, platformruntime.ErrIdempotencyConflict
	}
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(platformruntime.ScopeIdempotencyHash(child, req.IdempotencyKey))))
	// Children do not create a duplicate human conversation message. Their
	// metadata/events belong to execution; the parent owns result aggregation.
	return s.createRunTx(ctx, tx, req, key, true)
}
