package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/identity"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// ancestryLockWait is an unfinished ancestor row lock. context.Canceled is the
// caller's stop and is not a wait. A finished permission mismatch is neither.
func ancestryLockWait(err error) bool {
	if err == nil {
		return false
	}
	switch sqlutil.SQLState(err) {
	case "55P03", "57014":
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func ancestryDeny(err error) error {
	if err == nil || ancestryLockWait(err) {
		return err
	}
	return agentcoordination.ErrDenied
}

type budgetAncestryTransactionKey struct{}

// withBudgetAncestryTransaction joins a delegated ancestry check to the caller
// transaction. The caller commits or rolls that transaction back; Check must
// not. A second connection would wait on ancestor share locks this transaction
// already holds, and that wait is not a finished permission denial.
func withBudgetAncestryTransaction(ctx context.Context, tx *sql.Tx) context.Context {
	if ctx == nil || tx == nil {
		return ctx
	}
	return context.WithValue(ctx, budgetAncestryTransactionKey{}, tx)
}

func budgetAncestryTransaction(ctx context.Context) *sql.Tx {
	if ctx == nil {
		return nil
	}
	tx, _ := ctx.Value(budgetAncestryTransactionKey{}).(*sql.Tx)
	return tx
}

// The same ancestry policy is consumed by dispatch, heartbeat and every live
// capability/renewal check. Client JSON cannot install or override this guard.
type coordinatedAncestryGuard struct {
	route      agentRouteAuthority
	evaluation *evaluationExecutionAuthority
}

// IsDelegatedBusinessRun distinguishes SQL-coordinated business children from
// existing depth-zero evaluation provenance. Callers use it only after their
// ordinary live-lease validation; permission checks still require Check.
func (g coordinatedAncestryGuard) IsDelegatedBusinessRun(ctx context.Context, scope sharedkernel.Scope) bool {
	if scope.ParentRunID == "" || g.route.runs == nil || scope.ValidateTrusted() != nil {
		return false
	}
	run, err := g.route.runs.BudgetRunContext(ctx, scope.RunID)
	if err != nil || !sameBudgetOwner(run.Scope, scope) || len(run.RequestJSON) > 1<<20 {
		return false
	}
	var command contract.ExecuteRequest
	decoder := json.NewDecoder(bytes.NewReader(run.RequestJSON))
	decoder.UseNumber()
	if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF || command.ProtocolVersion != contract.ProtocolVersion || command.Scope.RunID != scope.RunID || command.Scope.ParentRunID != scope.ParentRunID {
		return false
	}
	return command.Scope.DelegationDepth > 0 && command.Scope.DelegationDepth <= 4
}

func (g coordinatedAncestryGuard) Check(ctx context.Context, scope sharedkernel.Scope) error {
	if scope.ParentRunID == "" {
		return nil
	}
	a := g.route
	if a.runs == nil || a.identity == nil || a.routes == nil || scope.ValidateTrusted() != nil {
		return agentcoordination.ErrDenied
	}
	initial, err := a.runs.BudgetRunContext(ctx, scope.RunID)
	if err != nil {
		return err
	}
	if !sameBudgetOwner(initial.Scope, scope) {
		return agentcoordination.ErrDenied
	}
	var command contract.ExecuteRequest
	decoder := json.NewDecoder(bytes.NewReader(initial.RequestJSON))
	decoder.UseNumber()
	if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF || command.Scope.RunID != scope.RunID {
		return agentcoordination.ErrDenied
	}
	// Evaluation children have depth zero, but a parent string alone is not
	// provenance. Their durable request must bind to a live product Run/case.
	if command.Scope.DelegationDepth == 0 {
		if g.evaluation == nil {
			return agentcoordination.ErrDenied
		}
		return g.evaluation.VerifyPersisted(ctx, scope)
	}
	if command.ProtocolVersion != contract.ProtocolVersion || command.Scope.DelegationDepth > 4 || command.Scope.ParentRunID != scope.ParentRunID {
		return agentcoordination.ErrDenied
	}
	joined := budgetAncestryTransaction(ctx)
	var tx *sql.Tx
	if joined != nil {
		tx = joined
	} else {
		var beginErr error
		tx, beginErr = a.runs.DB().BeginTx(ctx, nil)
		if beginErr != nil {
			return beginErr
		}
		defer tx.Rollback()
	}
	ctx = withEpochMemo(ctx, tx)
	if err := a.identity.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return err
	}
	if err := lockBudgetAncestors(ctx, tx, a.runs, scope); err != nil {
		return err
	}
	if err := g.CheckTx(ctx, tx, scope); err != nil {
		return err
	}
	if joined != nil {
		return nil
	}
	return tx.Commit()
}

// CheckTx requires caller-owned IAM continuity and root-first ancestor locks.
// It rechecks all original plans, not just the most recent direct parent.
func (g coordinatedAncestryGuard) CheckTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
	return g.checkActorTx(ctx, tx, scope, false)
}

// CheckWaitingTx is the human approval boundary for a parked child. It does
// not grant that child a live lease; all parent plans and live leases still apply.
func (g coordinatedAncestryGuard) CheckWaitingTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
	if scope.ParentRunID == "" {
		return nil
	}
	return g.checkActorTx(ctx, tx, scope, true)
}

func (g coordinatedAncestryGuard) checkActorTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, waiting bool) error {
	a := g.route
	if tx == nil || a.runs == nil || a.identity == nil || a.routes == nil || a.catalog == nil {
		return agentcoordination.ErrDenied
	}
	ctx = withEpochMemo(ctx, tx)
	// Live capability/dispatch authority already owns the actor fence. This
	// callback can run inside another transaction holding its UPDATE lock, so
	// a second transaction must not attempt SHARE on that same actor row.
	actor, err := a.runs.BudgetRunContext(ctx, scope.RunID)
	if err != nil {
		return err
	}
	if !sameBudgetOwner(actor.Scope, scope) {
		return agentcoordination.ErrDenied
	}
	command, policy, err := budgetRunPolicy(ctx, tx, actor)
	if err != nil {
		return err
	}
	depth := int(command.Scope.DelegationDepth)
	if depth < 1 || depth > 4 || (waiting && actor.Status != platformruntime.StatusWaiting) ||
		(!waiting && (actor.Status != platformruntime.StatusRunning || !actor.HasLease || !actor.LeaseUntil.After(time.Now().UTC()))) {
		return agentcoordination.ErrDenied
	}
	rootParent, err := a.runs.BudgetRunTx(ctx, tx, actor.Scope.ParentRunID)
	if err != nil {
		return ancestryDeny(err)
	}
	proof, err := a.routes.DelegationAuthorityProofTx(ctx, tx, rootParent.Scope, actor.Scope, depth)
	if err != nil {
		return ancestryDeny(err)
	}
	if err := a.checkDelegationAuthorityProofForLiveActorTx(ctx, tx, proof, scope.RunID); err != nil {
		return ancestryDeny(err)
	}
	seen := map[string]bool{actor.Scope.RunID: true}
	child := actor
	for remaining := depth; remaining > 0; remaining-- {
		parentID := command.Scope.ParentRunID
		if parentID == "" || seen[parentID] {
			return agentcoordination.ErrDenied
		}
		seen[parentID] = true
		parent, err := a.runs.BudgetRunTx(ctx, tx, parentID)
		if err != nil {
			return err
		}
		parentCommand, parentPolicy, err := budgetRunPolicy(ctx, tx, parent)
		if err != nil {
			return err
		}
		if parentCommand.Scope.DelegationDepth != uint32(remaining-1) {
			return agentcoordination.ErrDenied
		}
		if err := a.checkActiveParentChildTx(ctx, tx, parent, child.Scope, remaining); err != nil {
			return ancestryDeny(err)
		}
		delegation := parentPolicy.Runtime.Delegation
		if delegation == nil || delegation.Validate() != nil || depth > delegation.MaxDepth {
			return agentcoordination.ErrDenied
		}
		binding, err := a.routes.ChildRoutingFactsTx(ctx, tx, parent.Scope, child.Scope, remaining)
		if err != nil {
			return err
		}
		if binding.PolicyHash != parentPolicy.Hash || binding.RequestFingerprint != child.RequestFingerprint || !delegatedContains(delegation.AllowedAgentIDs, child.Scope.AgentID) || !delegatedContains(delegation.TaskTypes, binding.TaskType) {
			return agentcoordination.ErrDenied
		}
		if _, err := a.currentPrincipalPermissionTx(ctx, tx, parent.Scope, "agent.delegate"); err != nil {
			return ancestryDeny(err)
		}
		parentMachine, err := a.workloadMachine(ctx, parent.Scope)
		if err != nil {
			return ancestryDeny(err)
		}
		parentMachineScope := parent.Scope
		parentMachineScope.PrincipalType, parentMachineScope.PrincipalID = string(identity.PrincipalServicePrincipal), parentMachine.PrincipalID
		if _, err := a.currentPrincipalPermissionTx(ctx, tx, parentMachineScope, "agent.delegate"); err != nil {
			return ancestryDeny(err)
		}
		if err := a.routeTargetAuthority(ctx, tx, parent.Scope, parentPolicy.Hash, binding.Target); err != nil {
			return ancestryDeny(err)
		}
		child, command, policy = parent, parentCommand, parentPolicy
	}
	if child.Scope.ParentRunID != "" || command.Scope.DelegationDepth != 0 || policy.Runtime.RunBudget == nil || policy.Runtime.RunBudget.Validate() != nil {
		return agentcoordination.ErrDenied
	}
	return nil
}

func (a agentRouteAuthority) routeTargetAuthority(ctx context.Context, tx *sql.Tx, parent sharedkernel.Scope, policyHash string, target agentcoordination.Target) error {
	return a.AuthorizeTarget(ctx, tx, agentcoordination.ParentFacts{Scope: parent, PolicyHash: policyHash}, target)
}

func delegatedContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
