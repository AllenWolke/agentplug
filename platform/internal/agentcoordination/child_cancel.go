package agentcoordination

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

const ChildStopControlConflictVersion = "agent-child-stop-control-conflict/v1"

// ChildStopRevisionConflict carries only the locked current lifecycle facts
// needed to retry the caller's existing positive-revision stop CAS. It never
// contains output, history, the request body, or an authorization decision.
type ChildStopRevisionConflict struct {
	Status            string
	ExecutionRevision uint64
}

func (e *ChildStopRevisionConflict) Error() string { return "child stop revision changed" }

type ChildCancelRequest struct {
	OperationKey              string `json:"operation_key"`
	Ordinal                   int    `json:"ordinal"`
	ExpectedExecutionRevision uint64 `json:"expected_execution_revision"`
}

type ChildCancellation struct {
	Version           string `json:"version"`
	ParentRunID       string `json:"parent_run_id"`
	ChildRunID        string `json:"child_run_id"`
	ChildKey          string `json:"child_key"`
	OperationKey      string `json:"operation_key"`
	Ordinal           int    `json:"ordinal"`
	Status            string `json:"status"`
	ExecutionRevision uint64 `json:"execution_revision"`
}

type ChildExecutionCanceller interface {
	CancelChild(context.Context, *sql.Tx, ChildExecutionRead, uint64) (ChildExecutionResult, error)
}

type ChildCancellationStore interface {
	CancelChild(context.Context, sharedkernel.Scope, ChildCancelRequest) (ChildCancellation, error)
}

func (r *Router) CancelChild(ctx context.Context, scope sharedkernel.Scope, request ChildCancelRequest) (ChildCancellation, error) {
	if r == nil || scope.ValidateTrusted() != nil {
		return ChildCancellation{}, ErrDenied
	}
	store, ok := r.store.(ChildCancellationStore)
	if !ok {
		return ChildCancellation{}, ErrUnavailable
	}
	return store.CancelChild(ctx, scope, request)
}

func (s *SQLRouteStore) CancelChild(ctx context.Context, scope sharedkernel.Scope, request ChildCancelRequest) (ChildCancellation, error) {
	empty := ChildCancellation{}
	if s == nil {
		return empty, ErrUnavailable
	}
	control, ok := s.children.(ChildExecutionCanceller)
	if !ok {
		return empty, ErrUnavailable
	}
	if !identifier(request.OperationKey) || request.Ordinal < 0 || request.Ordinal > 15 || request.ExpectedExecutionRevision == 0 || request.ExpectedExecutionRevision > 1<<63-1 {
		return empty, ErrDenied
	}
	var result ChildCancellation
	err := s.Transact(ctx, scope, func(port RouteTransaction) error {
		unit, ok := port.(*sqlRouteTransaction)
		if !ok {
			return ErrUnavailable
		}
		parent, err := unit.Parent(ctx, scope)
		if err != nil {
			return err
		}
		plan, found, err := unit.Existing(request.OperationKey)
		if err != nil {
			return err
		}
		if !found || !parent.Active || parent.Policy == nil || plan.Version != "agent-route/v1" || plan.ParentRunID != scope.RunID || plan.PolicyHash != parent.PolicyHash || plan.ChildDepth != parent.Depth+1 || plan.EvidenceDigest != digest(plan.Targets) || request.Ordinal >= len(plan.Targets) {
			return ErrDenied
		}
		target := plan.Targets[request.Ordinal]
		// Stop is pinned to this already-admitted reservation. It does not
		// request a new child execution permission, so revoked target grants
		// cannot prevent the owning parent from stopping its recorded child.
		if !eligible(parent, target, plan.TaskType) {
			return ErrDenied
		}
		var key, status string
		var childID, fingerprint sql.NullString
		var revision uint64
		err = unit.tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT child_key,status,revision,child_run_id,request_fingerprint FROM platform_agent_child_reservation WHERE parent_key=? AND operation_key=? AND ordinal=? FOR UPDATE`), unit.key, request.OperationKey, request.Ordinal).Scan(&key, &status, &revision, &childID, &fingerprint)
		if err != nil {
			return err
		}
		if key != digest([]any{unit.key, plan.OperationKey, request.Ordinal, plan.Fingerprint}) || !childID.Valid || childID.String != "child-"+key[:48] || !fingerprint.Valid || !hashValue(fingerprint.String) || revision < 3 {
			return ErrConflict
		}
		switch status {
		case "accepted", "running", "completed", "failed", "cancelled", "uncertain":
		default:
			return ErrConflict
		}
		cancelled, err := control.CancelChild(ctx, unit.tx, ChildExecutionRead{Parent: parent, Target: target, Depth: plan.ChildDepth, RunID: childID.String}, request.ExpectedExecutionRevision)
		if err != nil {
			return err
		}
		child := cancelled.Scope
		if child.ValidateTrusted() != nil || child.RunID != childID.String || child.ParentRunID != scope.RunID || child.TenantID != scope.TenantID || child.DepartmentID != scope.DepartmentID || child.ApplicationID != scope.ApplicationID || child.PrincipalType != scope.PrincipalType || child.PrincipalID != scope.PrincipalID || child.SessionID != scope.SessionID || child.InstallationID != target.InstallationID || child.AgentInstanceID != target.InstallationID || child.AgentID != target.AgentID || child.AgentVersionID != target.VersionID || cancelled.Revision == 0 {
			return ErrDenied
		}
		switch cancelled.Status {
		case "cancelling", "recovering", "cancelled", "completed", "failed":
		default:
			return ErrConflict
		}
		// Preserve the coordination edge and fan-out; only Execution owns stop
		// state, and no cancellation request implies remote acknowledgement.
		result = ChildCancellation{Version: "agent-child-cancellation/v1", ParentRunID: scope.RunID, ChildRunID: child.RunID, ChildKey: key, OperationKey: request.OperationKey, Ordinal: request.Ordinal, Status: cancelled.Status, ExecutionRevision: cancelled.Revision}
		unit.auditAction = "agent.child_cancel_requested"
		return unit.Audit(plan)
	})
	if err != nil {
		return empty, err
	}
	return result, nil
}
