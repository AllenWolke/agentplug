package agentcoordination

import (
	"context"
	"database/sql"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type ChildExecutionStopBarrier interface {
	CheckChildStopQuiescence(context.Context, sharedkernel.Scope) error
}

type AgentGroupWaitAuthority interface {
	ParentForGroupWaitTx(context.Context, *sql.Tx, sharedkernel.Scope) (ParentFacts, error)
}

// ValidateGroupWaitTx proves all exact planned slots were admitted under the
// current parent and target authority. It never admits, reads outputs or
// dispatches. The caller commits its waiting outcome in this transaction.
func (s *SQLRouteStore) ValidateGroupWaitTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, receipt contract.AgentGroupHandoff) error {
	if s == nil || s.authority == nil || tx == nil || receipt.RunID != scope.RunID || len(receipt.ChildKeys) < 1 || len(receipt.ChildKeys) > 16 {
		return ErrDenied
	}
	unit := &sqlRouteTransaction{ctx: ctx, tx: tx, store: s, scope: scope, key: routeScopeKey(scope)}
	control, ok := s.authority.(AgentGroupWaitAuthority)
	if !ok {
		return ErrUnavailable
	}
	parent, err := control.ParentForGroupWaitTx(ctx, tx, scope)
	if err != nil {
		return err
	}
	if parent.Scope != scope || !parent.Active {
		return ErrDenied
	}
	unit.parent = &parent
	plan, found, err := unit.Existing(receipt.OperationKey)
	if err != nil {
		return err
	}
	if !found || parent.Policy == nil || plan.Version != "agent-route/v1" || plan.ParentRunID != scope.RunID || plan.PolicyHash != parent.PolicyHash || plan.ChildDepth != parent.Depth+1 || plan.EvidenceDigest != digest(plan.Targets) || len(plan.Targets) != len(receipt.ChildKeys) {
		return ErrDenied
	}
	for ordinal, target := range plan.Targets {
		if !eligible(parent, target, plan.TaskType) || s.authority.AuthorizeTarget(ctx, tx, parent, target) != nil {
			return ErrDenied
		}
		var key, status string
		var childID, fingerprint sql.NullString
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT child_key,status,child_run_id,request_fingerprint FROM platform_agent_child_reservation WHERE parent_key=? AND operation_key=? AND ordinal=? FOR SHARE`), unit.key, plan.OperationKey, ordinal).Scan(&key, &status, &childID, &fingerprint); err != nil {
			return err
		}
		if key != receipt.ChildKeys[ordinal] || key != digest([]any{unit.key, plan.OperationKey, ordinal, plan.Fingerprint}) || !childID.Valid || childID.String != "child-"+key[:48] || !fingerprint.Valid || !hashValue(fingerprint.String) {
			return ErrDenied
		}
		switch status {
		case "accepted", "running", "completed", "failed", "cancelled":
		default:
			return ErrDenied
		}
	}
	return nil
}

// CheckWaitingGroupChildTx allows only an already admitted live child in this
// exact waiting group. Historical edges and another group are insufficient.
func (s *SQLRouteStore) CheckWaitingGroupChildTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope, depth int, receipt contract.AgentGroupHandoff) error {
	if receipt.RunID != parent.RunID {
		return ErrDenied
	}
	if err := s.CheckChildEdgeTx(ctx, tx, parent, child, depth); err != nil {
		if lockWaitError(err) {
			return err
		}
		return ErrDenied
	}
	var key, operation string
	var ordinal int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT child_key,operation_key,ordinal FROM platform_agent_child_reservation WHERE parent_key=? AND child_run_id=? FOR SHARE`), routeScopeKey(parent), child.RunID).Scan(&key, &operation, &ordinal); err != nil {
		return err
	}
	if operation != receipt.OperationKey || ordinal < 0 || ordinal >= len(receipt.ChildKeys) || key != receipt.ChildKeys[ordinal] {
		return ErrDenied
	}
	return nil
}

// WaitingGroupTerminalTx observes actual durable execution terminal proofs,
// with no outputs, capability minting or admission. Lifecycle projection may
// be synchronized in the same caller transaction; uncertain is never terminal.
func (s *SQLRouteStore) WaitingGroupTerminalTx(ctx context.Context, tx *sql.Tx, parent ParentFacts, receipt contract.AgentGroupHandoff) (bool, error) {
	return s.observeWaitingGroupTx(ctx, tx, parent, receipt, true, false)
}

// WaitingGroupTerminalShareTx is the non-terminal poll. It must not take the
// route FOR UPDATE while the child still needs to share that same row.
func (s *SQLRouteStore) WaitingGroupTerminalShareTx(ctx context.Context, tx *sql.Tx, parent ParentFacts, receipt contract.AgentGroupHandoff) (bool, error) {
	return s.observeWaitingGroupTx(ctx, tx, parent, receipt, true, true)
}

// GroupStopQuiescentTx uses historical ownership for stop/accounting only.
// Revocation cannot prevent stopping, but every child still needs actual
// durable terminal proof. No expired grant is reused for business execution.
func (s *SQLRouteStore) GroupStopQuiescentTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, receipt contract.AgentGroupHandoff) error {
	terminal, err := s.observeWaitingGroupTx(ctx, tx, ParentFacts{Scope: scope}, receipt, false, false)
	if err != nil {
		return err
	}
	if !terminal {
		return ErrConflict
	}
	return nil
}

func (s *SQLRouteStore) observeWaitingGroupTx(ctx context.Context, tx *sql.Tx, parent ParentFacts, receipt contract.AgentGroupHandoff, authorization bool, shareRoute bool) (bool, error) {
	if s == nil || s.authority == nil || tx == nil || (authorization && parent.Policy == nil) || receipt.RunID != parent.Scope.RunID {
		return false, ErrDenied
	}
	observer, ok := s.children.(ChildExecutionLifecycleObserver)
	if !ok {
		return false, ErrUnavailable
	}
	unit := &sqlRouteTransaction{ctx: ctx, tx: tx, store: s, scope: parent.Scope, key: routeScopeKey(parent.Scope), parent: &parent}
	var plan RoutePlan
	var found bool
	var err error
	if shareRoute {
		plan, found, err = unit.ExistingShared(receipt.OperationKey)
	} else {
		plan, found, err = unit.Existing(receipt.OperationKey)
	}
	if err != nil {
		return false, err
	}
	if !found || plan.Version != "agent-route/v1" || plan.ParentRunID != parent.Scope.RunID || plan.ChildDepth < 1 || plan.ChildDepth > 4 || len(plan.Targets) != len(receipt.ChildKeys) || plan.EvidenceDigest != digest(plan.Targets) || (authorization && (plan.PolicyHash != parent.PolicyHash || plan.ChildDepth != parent.Depth+1 || plan.ChildDepth > parent.Policy.MaxDepth)) {
		return false, ErrDenied
	}
	terminal := true
	for ordinal, target := range plan.Targets {
		if authorization && (!eligible(parent, target, plan.TaskType) || s.authority.AuthorizeTarget(ctx, tx, parent, target) != nil) {
			return false, ErrDenied
		}
		var key string
		var childID, fingerprint sql.NullString
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT child_key,child_run_id,request_fingerprint FROM platform_agent_child_reservation WHERE parent_key=? AND operation_key=? AND ordinal=? FOR SHARE`), unit.key, plan.OperationKey, ordinal).Scan(&key, &childID, &fingerprint); err != nil {
			return false, err
		}
		if key != receipt.ChildKeys[ordinal] || key != digest([]any{unit.key, plan.OperationKey, ordinal, plan.Fingerprint}) || !childID.Valid || childID.String != "child-"+key[:48] || !fingerprint.Valid || !hashValue(fingerprint.String) {
			return false, ErrDenied
		}
		observed, err := observer.ObserveChildLifecycle(ctx, tx, ChildExecutionRead{Parent: parent, Target: target, Depth: plan.ChildDepth, RunID: childID.String})
		if err != nil {
			return false, err
		}
		if observed.RequestFingerprint != fingerprint.String || observed.Revision == 0 || observed.Scope.RunID != childID.String {
			return false, ErrDenied
		}
		if !observed.TerminalVerified {
			terminal = false
			continue
		}
		if !authorization {
			barrier, ok := s.children.(ChildExecutionStopBarrier)
			if !ok || barrier.CheckChildStopQuiescence(ctx, observed.Scope) != nil {
				return false, ErrConflict
			}
		}
		switch observed.Status {
		case "completed", "failed", "cancelled":
		default:
			return false, ErrConflict
		}
		if _, err := s.SyncChildLifecycleTx(ctx, tx, parent.Scope, observed.Scope, plan.ChildDepth); err != nil {
			return false, err
		}
	}
	return terminal, nil
}
