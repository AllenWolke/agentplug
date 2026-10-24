package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

// The composition root consumes module-owned Ports only. Accounting preserves
// original ownership after revocation; admission requires live dual authority.
type runTreeBudgetAuthority struct {
	route         agentRouteAuthority
	evaluation    *evaluationExecutionAuthority
	verifyOutcome func(context.Context, *sql.Tx, sharedkernel.Scope, usagecost.RunTreeBudgetCommand) error
}

// Lock ancestor metadata root-first before taking the actor's UPDATE fence.
// A parent reading child results must not deadlock with a child taking its
// own fence and then waiting for that same parent. The later authority checks
// still verify every immutable command and coordination edge after these locks.
func lockBudgetAncestors(ctx context.Context, tx *sql.Tx, runs *execution.SQLStore, scope sharedkernel.Scope) error {
	if tx == nil || runs == nil {
		return usagecost.ErrBudgetScopeMismatch
	}
	ids := []string{}
	seen := map[string]bool{scope.RunID: true}
	parentID := scope.ParentRunID
	for parentID != "" {
		if len(ids) >= 4 || seen[parentID] {
			return usagecost.ErrBudgetScopeMismatch
		}
		seen[parentID] = true
		ancestor, err := runs.GetContext(ctx, parentID)
		if err != nil {
			return err
		}
		p := ancestor.Scope
		if p.TenantID != scope.TenantID || p.DepartmentID != scope.DepartmentID || p.ApplicationID != scope.ApplicationID || p.PrincipalType != scope.PrincipalType || p.PrincipalID != scope.PrincipalID || p.SessionID != scope.SessionID {
			return usagecost.ErrBudgetScopeMismatch
		}
		ids = append(ids, parentID)
		parentID = p.ParentRunID
	}
	for i := len(ids) - 1; i >= 0; i-- {
		if _, err := runs.BudgetRunTx(ctx, tx, ids[i]); err != nil {
			return err
		}
	}
	return nil
}

// A row-lock wait is not a scope mismatch. Callers retry it; every other
// admission failure stays a closed budget denial.
func budgetLockOrMismatch(err error) error {
	if err == nil || ancestryLockWait(err) {
		return err
	}
	return usagecost.ErrBudgetScopeMismatch
}

func sameBudgetOwner(a, b sharedkernel.Scope) bool {
	a.AuthorizationEpoch, a.TraceID = 0, ""
	b.AuthorizationEpoch, b.TraceID = 0, ""
	return a == b
}

// evaluationBudgetCandidate is only a routing hint from immutable execution
// request data. Facts still verifies the complete product/case/IAM provenance
// in the caller's transaction before assigning Evaluation-root semantics.
func evaluationBudgetCandidate(ctx context.Context, runs *execution.SQLStore, scope sharedkernel.Scope) bool {
	if runs == nil || scope.ParentRunID == "" || scope.ValidateTrusted() != nil {
		return false
	}
	run, err := runs.BudgetRunContext(ctx, scope.RunID)
	if err != nil || run.Scope != scope || len(run.RequestJSON) == 0 || len(run.RequestJSON) > 1<<20 {
		return false
	}
	var command contract.ExecuteRequest
	decoder := json.NewDecoder(bytes.NewReader(run.RequestJSON))
	decoder.UseNumber()
	return decoder.Decode(&command) == nil && decoder.Decode(new(any)) == io.EOF && command.ProtocolVersion == contract.ProtocolVersion &&
		command.Scope == budgetContractScope(scope) && command.Scope.DelegationDepth == 0 && command.Scope.ParentRunID != ""
}

func budgetContractScope(scope sharedkernel.Scope) contract.ScopeKey {
	return contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
		AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
		PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID,
		RunID: scope.RunID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID,
		ParentRunID: scope.ParentRunID, DelegationDepth: 0, InstallationID: scope.InstallationID}
}

func budgetRunPolicy(ctx context.Context, tx *sql.Tx, run execution.BudgetRunFacts) (contract.ExecuteRequest, policyasset.Snapshot, error) {
	var command contract.ExecuteRequest
	decoder := json.NewDecoder(bytes.NewReader(run.RequestJSON))
	decoder.UseNumber()
	if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF || command.ProtocolVersion != contract.ProtocolVersion || command.Scope.DelegationDepth > 4 {
		return command, policyasset.Snapshot{}, usagecost.ErrBudgetScopeMismatch
	}
	wire := command.Scope
	declared := sharedkernel.Scope{TenantID: wire.TenantID, DepartmentID: wire.DepartmentID, ApplicationID: wire.ApplicationID, AgentInstanceID: wire.AgentInstanceID, AgentID: wire.AgentID, PrincipalType: wire.PrincipalType, PrincipalID: wire.PrincipalID, InstallationID: wire.InstallationID, AgentVersionID: wire.AgentVersionID, SessionID: wire.SessionID, RunID: wire.RunID, ParentRunID: wire.ParentRunID, AuthorizationEpoch: wire.AuthorizationEpoch, TraceID: wire.TraceID}
	if !sameBudgetOwner(declared, run.Scope) || (wire.DelegationDepth == 0) != (wire.ParentRunID == "") {
		return command, policyasset.Snapshot{}, usagecost.ErrBudgetScopeMismatch
	}
	policy, err := policyasset.NewSQLResolver(tx).Resolve(ctx, run.Scope, run.Scope.AgentVersionID)
	if err != nil {
		return command, policyasset.Snapshot{}, err
	}
	input := command.Input
	if input == nil {
		return command, policyasset.Snapshot{}, usagecost.ErrBudgetScopeMismatch
	}
	saved, ok := input["policy_snapshot"].(map[string]any)
	if !ok || saved["content_hash"] != policy.Hash {
		return command, policyasset.Snapshot{}, usagecost.ErrBudgetScopeMismatch
	}
	return command, policy, nil
}

func (a runTreeBudgetAuthority) Facts(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, admission bool) (usagecost.RunTreeBudgetFacts, error) {
	return a.facts(ctx, tx, scope, admission, false)
}

func (a runTreeBudgetAuthority) ReadFacts(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) (usagecost.RunTreeBudgetFacts, error) {
	return a.facts(ctx, tx, scope, true, true)
}

func (a runTreeBudgetAuthority) facts(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, admission, sharedRead bool) (usagecost.RunTreeBudgetFacts, error) {
	empty := usagecost.RunTreeBudgetFacts{}
	if tx == nil || a.route.runs == nil || a.route.identity == nil || scope.ValidateTrusted() != nil {
		return empty, usagecost.ErrBudgetScopeMismatch
	}
	// Model-budget admission rechecks Skill bindings and delegated ancestry from
	// inside this transaction. Join both so neither opens a second transaction
	// that waits on ancestor share locks this transaction already holds.
	ctx = withEpochMemo(ctx, tx)
	ctx = withBudgetAncestryTransaction(ctx, tx)
	ctx = sqlutil.WithContinuityTransaction(ctx, a.route.runs.DB(), tx)
	ctx = capability.WithSQLSkillTransaction(ctx, a.route.runs.DB(), tx, scope)
	evaluationRoot := a.evaluation != nil && evaluationBudgetCandidate(ctx, a.route.runs, scope)
	// Evaluation's product-parent lock protocol has a separate provenance
	// boundary. Retain its established exclusive path until that protocol also
	// supplies a shared read contract; never silently bypass its parent fence.
	if evaluationRoot {
		sharedRead = false
	}
	if admission && !evaluationRoot {
		if err := a.route.identity.AcquirePermissionReadContinuity(ctx, tx); err != nil {
			return empty, budgetLockOrMismatch(err)
		}
	}
	var boundPolicy policyasset.Snapshot
	// Accounting also follows root-first ordering. A revoked/ended owner still
	// retains real fees, but bottom-up locks can deadlock with parent stop control.
	var run execution.BudgetRunFacts
	var evaluationParent evaluationBudgetParent
	var err error
	if evaluationRoot {
		evaluationParent, err = a.evaluation.LockBudgetParentTx(ctx, tx, scope, admission)
		if err != nil {
			return empty, err
		}
		if admission {
			run, err = a.route.runs.BudgetRunForUpdateTx(ctx, tx, scope.RunID)
		} else {
			run, err = a.route.runs.BudgetRunTx(ctx, tx, scope.RunID)
		}
		if err != nil {
			return empty, err
		}
	} else if err := lockBudgetAncestors(ctx, tx, a.route.runs, scope); err != nil {
		return empty, err
	}
	if admission {
		// Select the execution fence before reading actor metadata. A model
		// reservation reads Run/Session but writes separate budget/invocation
		// rows, whose own exclusive locks serialize money and send admission.
		// Sharing this execution fence prevents its SQL accounting transaction
		// from blocking independent checkpoint writers on the same actor.
		// Only the private model admission binding can select this path;
		// coordination/effect admission and Evaluation keep their old protocol.
		lease, currentPolicy, err := capability.ModelBudgetExecutionAuthority(ctx, scope)
		if err == nil && !evaluationRoot {
			sharedRead = true
		}
		if ancestryLockWait(err) {
			return empty, err
		}
		if err != nil {
			lease, currentPolicy, err = capability.AgentCoordinationAuthority(ctx, scope)
		}
		if err != nil && !ancestryLockWait(err) {
			lease, currentPolicy, err = capability.RuntimeBudgetExecutionAuthority(ctx, scope)
		}
		if ancestryLockWait(err) {
			return empty, err
		}
		if err != nil {
			return empty, usagecost.ErrBudgetScopeMismatch
		}
		if sharedRead {
			err = a.route.runs.CheckCapabilityReadLeaseTx(ctx, tx, scope, lease)
		} else {
			err = a.route.runs.CheckCapabilityLeaseTx(ctx, tx, scope, lease)
		}
		if err != nil {
			return empty, budgetLockOrMismatch(err)
		}
		boundPolicy = currentPolicy
	}
	if run.Scope.RunID == "" {
		if admission && !sharedRead {
			run, err = a.route.runs.BudgetRunForUpdateTx(ctx, tx, scope.RunID)
		} else {
			run, err = a.route.runs.BudgetRunTx(ctx, tx, scope.RunID)
		}
		if err != nil {
			return empty, err
		}
	}
	if !sameBudgetOwner(run.Scope, scope) {
		return empty, usagecost.ErrBudgetScopeMismatch
	}
	var command contract.ExecuteRequest
	var policy policyasset.Snapshot
	if evaluationRoot {
		decoder := json.NewDecoder(bytes.NewReader(run.RequestJSON))
		decoder.UseNumber()
		if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF {
			return empty, usagecost.ErrBudgetScopeMismatch
		}
		policy, err = a.evaluation.VerifyBudgetTx(ctx, tx, scope, run, evaluationParent, admission)
	} else {
		command, policy, err = budgetRunPolicy(ctx, tx, run)
	}
	if err != nil {
		return empty, err
	}
	if admission {
		if boundPolicy.Hash != policy.Hash || run.Scope != scope || run.Status != platformruntime.StatusRunning {
			return empty, usagecost.ErrBudgetScopeMismatch
		}
		facts, err := a.route.identity.PrincipalPolicyFactsTx(ctx, tx, identity.PrincipalType(scope.PrincipalType), scope.PrincipalID)
		if err != nil {
			return empty, budgetLockOrMismatch(err)
		}
		if facts.Mode != "v2" {
			return empty, usagecost.ErrBudgetScopeMismatch
		}
	}
	depth := int(command.Scope.DelegationDepth)
	if admission && depth > 0 {
		if a.route.routes == nil {
			return empty, usagecost.ErrBudgetScopeMismatch
		}
		parent, parentErr := a.route.runs.BudgetRunTx(ctx, tx, command.Scope.ParentRunID)
		if parentErr != nil {
			return empty, budgetLockOrMismatch(parentErr)
		}
		proof, proofErr := a.route.routes.DelegationAuthorityProofTx(ctx, tx, parent.Scope, run.Scope, depth)
		if proofErr != nil {
			return empty, budgetLockOrMismatch(proofErr)
		}
		// The lease guard already holds this actor in the current transaction.
		// The proof must reuse that fence rather than open another transaction
		// whose locks could wait on this transaction's own actor.
		if err := a.route.checkDelegationAuthorityProofForLiveActorTx(ctx, tx, proof, scope.RunID); err != nil {
			return empty, budgetLockOrMismatch(err)
		}
	}
	seen := map[string]bool{scope.RunID: true}
	child := run
	for remaining := depth; remaining > 0; remaining-- {
		parentID := command.Scope.ParentRunID
		if parentID == "" || seen[parentID] || a.route.routes == nil {
			return empty, usagecost.ErrBudgetScopeMismatch
		}
		seen[parentID] = true
		parent, err := a.route.runs.BudgetRunTx(ctx, tx, parentID)
		if err != nil {
			if !admission {
				return empty, err
			}
			return empty, budgetLockOrMismatch(err)
		}
		parentCommand, parentPolicy, err := budgetRunPolicy(ctx, tx, parent)
		if err != nil {
			return empty, budgetLockOrMismatch(err)
		}
		if parentCommand.Scope.DelegationDepth != uint32(remaining-1) {
			return empty, usagecost.ErrBudgetScopeMismatch
		}
		if admission {
			if err := a.route.checkActiveParentChildTx(ctx, tx, parent, child.Scope, remaining); err != nil {
				return empty, budgetLockOrMismatch(err)
			}
			if parentPolicy.Runtime.Delegation == nil || parentPolicy.Runtime.Delegation.Validate() != nil || depth > parentPolicy.Runtime.Delegation.MaxDepth || a.route.catalog == nil {
				return empty, usagecost.ErrBudgetScopeMismatch
			}
			if err := a.route.resources.AuthorizeCapabilityResource(ctx, parent.Scope, capability.CapabilityResourceAccess{Action: "agent.delegate", ResourceType: "agent_installation", ResourceID: parent.Scope.InstallationID}); err != nil {
				return empty, budgetLockOrMismatch(err)
			}
			binding, err := a.route.routes.ChildRoutingFactsTx(ctx, tx, parent.Scope, child.Scope, remaining)
			if err != nil {
				return empty, budgetLockOrMismatch(err)
			}
			if binding.PolicyHash != parentPolicy.Hash || binding.RequestFingerprint != child.RequestFingerprint || !delegatedContains(parentPolicy.Runtime.Delegation.AllowedAgentIDs, child.Scope.AgentID) || !delegatedContains(parentPolicy.Runtime.Delegation.TaskTypes, binding.TaskType) {
				return empty, usagecost.ErrBudgetScopeMismatch
			}
			if err := a.route.AuthorizeTarget(ctx, tx, agentcoordination.ParentFacts{Scope: parent.Scope, PolicyHash: parentPolicy.Hash}, binding.Target); err != nil {
				return empty, budgetLockOrMismatch(err)
			}
		} else if err := a.route.routes.CheckRecordedChildEdgeTx(ctx, tx, parent.Scope, child.Scope, remaining); err != nil {
			return empty, budgetLockOrMismatch(err)
		}
		child, command, policy = parent, parentCommand, parentPolicy
	}
	if command.Scope.DelegationDepth != 0 || policy.Runtime.RunBudget == nil || policy.Runtime.RunBudget.Validate() != nil {
		return empty, usagecost.ErrBudgetScopeMismatch
	}
	if evaluationRoot {
		if child.Scope.RunID != scope.RunID || child.Scope.ParentRunID != scope.ParentRunID || !sameBudgetOwner(child.Scope, scope) {
			return empty, usagecost.ErrBudgetScopeMismatch
		}
	} else if child.Scope.ParentRunID != "" {
		return empty, usagecost.ErrBudgetScopeMismatch
	}
	return usagecost.RunTreeBudgetFacts{ActorScope: scope, RootScope: child.Scope, PolicyHash: policy.Hash, LimitMicros: policy.Runtime.RunBudget.LimitMicros, LimitTokens: policy.Runtime.RunBudget.LimitTokens, EvaluationRoot: evaluationRoot}, nil
}

func (a runTreeBudgetAuthority) VerifyOutcome(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, command usagecost.RunTreeBudgetCommand) error {
	if a.verifyOutcome == nil {
		return usagecost.ErrBudgetReservationConflict
	}
	return a.verifyOutcome(ctx, tx, scope, command)
}

var _ usagecost.RunTreeBudgetAuthority = runTreeBudgetAuthority{}
var _ usagecost.RunTreeBudgetReadAuthority = runTreeBudgetAuthority{}
