package agentcoordination

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// ChildStopIdentity is assembled only by the platform composition root after
// signature, current lease, and workload credential verification. It is not a
// request DTO and must never be populated from Agent JSON.
type ChildStopIdentity struct {
	Lease              sharedkernel.ExecutionLeaseBinding
	PolicyHash         string
	MachinePrincipalID string
}

type SQLChildStopAuthority interface {
	ParentForChildStop(context.Context, *sql.Tx, sharedkernel.Scope, ChildStopIdentity) (ParentFacts, error)
}

type ChildExecutionStopOnlyCanceller interface {
	CancelChildForStop(context.Context, *sql.Tx, ChildExecutionRead, ChildStopIdentity, uint64) (ChildExecutionResult, error)
}

type ChildStopOnlyStore interface {
	CancelChildStopOnly(context.Context, sharedkernel.Scope, ChildCancelRequest, ChildStopIdentity) (ChildCancellation, error)
}

func (r *Router) CancelChildStopOnly(ctx context.Context, scope sharedkernel.Scope, request ChildCancelRequest, identity ChildStopIdentity) (ChildCancellation, error) {
	if r == nil || scope.ValidateTrusted() != nil || identity.Lease.Revision == 0 || !hashValue(identity.Lease.TokenHash) || !hashValue(identity.PolicyHash) || !identifier(identity.MachinePrincipalID) {
		return ChildCancellation{}, ErrDenied
	}
	store, ok := r.store.(ChildStopOnlyStore)
	if !ok {
		return ChildCancellation{}, ErrUnavailable
	}
	return store.CancelChildStopOnly(ctx, scope, request, identity)
}

func (s *SQLRouteStore) CancelChildStopOnly(ctx context.Context, scope sharedkernel.Scope, request ChildCancelRequest, identity ChildStopIdentity) (ChildCancellation, error) {
	empty := ChildCancellation{}
	if s == nil || s.db == nil || s.authority == nil || s.audit == nil || scope.ValidateTrusted() != nil ||
		!identifier(request.OperationKey) || request.Ordinal < 0 || request.Ordinal > 15 || request.ExpectedExecutionRevision == 0 || request.ExpectedExecutionRevision > 1<<63-1 ||
		identity.Lease.Revision == 0 || !hashValue(identity.Lease.TokenHash) || !hashValue(identity.PolicyHash) || !identifier(identity.MachinePrincipalID) {
		return empty, ErrDenied
	}
	authority, ok := s.authority.(SQLChildStopAuthority)
	if !ok {
		return empty, ErrUnavailable
	}
	control, ok := s.children.(ChildExecutionStopOnlyCanceller)
	if !ok {
		return empty, ErrUnavailable
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	key := routeScopeKey(scope)
	lock := sha256.Sum256([]byte("agent-route/v1\x00" + key))
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`SELECT pg_advisory_xact_lock(?)`), int64(binary.BigEndian.Uint64(lock[:8]))); err != nil {
		return empty, err
	}
	parent, err := authority.ParentForChildStop(ctx, tx, scope, identity)
	if err != nil || parent.Scope != scope || !parent.Active || parent.PolicyHash != identity.PolicyHash || parent.Depth < 0 || parent.Depth > 3 {
		return empty, ErrDenied
	}
	unit := &sqlRouteTransaction{ctx: ctx, tx: tx, store: s, scope: scope, key: key, parent: &parent}
	plan, found, err := unit.Existing(request.OperationKey)
	if err != nil {
		return empty, err
	}
	if !found || plan.Version != "agent-route/v1" || plan.ParentRunID != scope.RunID || plan.PolicyHash != identity.PolicyHash || plan.ChildDepth != parent.Depth+1 || !identifier(plan.TaskType) || len(plan.Targets) < 1 || len(plan.Targets) > 16 || plan.EvidenceDigest != digest(plan.Targets) || request.Ordinal >= len(plan.Targets) {
		return empty, ErrDenied
	}
	target := plan.Targets[request.Ordinal]
	if !recordedStopTarget(scope, target, plan.TaskType) {
		return empty, ErrDenied
	}
	var keyValue, status, installation, version, manifest string
	var childID, fingerprint sql.NullString
	var revision uint64
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT child_key,status,revision,child_run_id,request_fingerprint,target_installation_id,target_version_id,target_manifest_hash FROM platform_agent_child_reservation WHERE parent_key=? AND operation_key=? AND ordinal=? FOR UPDATE`), key, request.OperationKey, request.Ordinal).Scan(&keyValue, &status, &revision, &childID, &fingerprint, &installation, &version, &manifest)
	if err != nil {
		return empty, err
	}
	if keyValue != digest([]any{key, plan.OperationKey, request.Ordinal, plan.Fingerprint}) || installation != target.InstallationID || version != target.VersionID || manifest != target.ManifestHash || !childID.Valid || childID.String != "child-"+keyValue[:48] || !fingerprint.Valid || !hashValue(fingerprint.String) || revision < 3 {
		return empty, ErrConflict
	}
	switch status {
	case "accepted", "running", "completed", "failed", "cancelled", "uncertain":
	default:
		return empty, ErrConflict
	}
	cancelled, err := control.CancelChildForStop(ctx, tx, ChildExecutionRead{Parent: parent, Target: target, Depth: plan.ChildDepth, RunID: childID.String}, identity, request.ExpectedExecutionRevision)
	if err != nil {
		return empty, err
	}
	child := cancelled.Scope
	if child.ValidateTrusted() != nil || child.RunID != childID.String || child.ParentRunID != scope.RunID || child.TenantID != scope.TenantID || child.DepartmentID != scope.DepartmentID || child.ApplicationID != scope.ApplicationID || child.PrincipalType != scope.PrincipalType || child.PrincipalID != scope.PrincipalID || child.SessionID != scope.SessionID || child.InstallationID != target.InstallationID || child.AgentInstanceID != target.InstallationID || child.AgentID != target.AgentID || child.AgentVersionID != target.VersionID || cancelled.Revision == 0 {
		return empty, ErrDenied
	}
	switch cancelled.Status {
	case "cancelling", "recovering", "cancelled", "completed", "failed":
	default:
		return empty, ErrConflict
	}
	result := ChildCancellation{Version: "agent-child-cancellation/v1", ParentRunID: scope.RunID, ChildRunID: child.RunID, ChildKey: keyValue, OperationKey: request.OperationKey, Ordinal: request.Ordinal, Status: cancelled.Status, ExecutionRevision: cancelled.Revision}
	unit.auditAction = "agent.child_cancel_requested"
	if err := unit.Audit(plan); err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return result, nil
}

func recordedStopTarget(parent sharedkernel.Scope, target Target, taskType string) bool {
	if target.TenantID != parent.TenantID || target.DepartmentID != parent.DepartmentID || target.ApplicationID != parent.ApplicationID ||
		!identifier(target.AgentID) || !identifier(target.InstallationID) || target.InstallationID == parent.InstallationID || target.AgentID == parent.AgentID ||
		target.InstallationRevision == 0 || !identifier(target.VersionID) || !identifier(target.DeploymentID) || target.DeploymentRevision == 0 ||
		!hashValue(strings.TrimPrefix(target.ManifestHash, "sha256:")) || target.ManifestHash != "sha256:"+strings.TrimPrefix(target.ManifestHash, "sha256:") ||
		!validStopSchemaURI(target.InputSchema) || !validStopSchemaURI(target.OutputSchema) || !target.Published || !target.Ready || !contains(target.TaskTypes, taskType) {
		return false
	}
	return true
}

func validStopSchemaURI(value string) bool {
	return strings.HasPrefix(value, "schema://") && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "*\x00\r\n\t ")
}
