package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/evaluationproduct"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type evaluationProductTxReader interface {
	GetTx(context.Context, *sql.Tx, evaluationproduct.Scope, evaluationproduct.Kind, string, bool) (evaluationproduct.Resource, error)
	CheckRunLeaseTx(context.Context, *sql.Tx, evaluationproduct.Scope, string, string, string, time.Time, time.Time) error
}

type evaluationBudgetParent struct {
	resource evaluationproduct.Resource
	lease    evaluationRunLease
	snapshot evaluationproduct.ExecutionRequest
}

// LockBudgetParentTx establishes product-parent, immutable-suite and live IAM
// provenance before the caller locks the child execution Run. Keeping this
// order prevents stop/finalize from holding the product parent while budget
// admission waits on it after taking a child lock.
func (a evaluationExecutionAuthority) LockBudgetParentTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, admission bool) (evaluationBudgetParent, error) {
	return a.readBudgetParentTx(ctx, tx, scope, admission, true)
}

func (a evaluationExecutionAuthority) readBudgetParentTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, admission, lockHead bool) (evaluationBudgetParent, error) {
	deny := func() (evaluationBudgetParent, error) { return evaluationBudgetParent{}, agentcoordination.ErrDenied }
	if tx == nil || a.products == nil || a.route.identity == nil || a.route.runs == nil || scope.ValidateTrusted() != nil || scope.ParentRunID == "" {
		return deny()
	}
	txReader, ok := a.products.(evaluationProductTxReader)
	if !ok {
		return deny()
	}
	productScope := evaluationProductScope(scope)
	parent, err := txReader.GetTx(ctx, tx, productScope, evaluationproduct.KindRun, scope.ParentRunID, lockHead)
	if err != nil || !evaluationCreatorMatches(parent, scope) {
		return deny()
	}
	var lease evaluationRunLease
	if json.Unmarshal(parent.Data, &lease) != nil || lease.IdempotencyKey == "" || lease.AgentID == "" || lease.AgentVersionID == "" {
		return deny()
	}
	if !evaluationParentBudgetStateMatches(parent, lease, admission, time.Now().UTC()) {
		return deny()
	}
	if admission {
		if txReader.CheckRunLeaseTx(ctx, tx, productScope, parent.ID, lease.LeaseOwner, lease.LeaseToken, lease.LeaseUntil, time.Now().UTC()) != nil {
			return deny()
		}
		principal, principalErr := a.route.identity.GetPrincipal(ctx, identity.PrincipalUser, parent.CreatedBy)
		if principalErr != nil || !principal.IsActive || principal.ID != scope.PrincipalID || principal.Type != identity.PrincipalUser || principal.TenantID != scope.TenantID {
			return deny()
		}
		if err := a.route.identity.AcquirePermissionReadContinuity(ctx, tx); err != nil {
			return deny()
		}
		actorEpoch, epochErr := a.route.currentPrincipalPermissionTx(ctx, tx, scope, "run")
		if epochErr != nil || !evaluationRunEpochMatches(scope.AuthorizationEpoch, actorEpoch) {
			return deny()
		}
		machine, machineErr := a.route.workloadMachine(ctx, scope)
		if machineErr != nil || !evaluationWorkloadBindingMatches(scope, machine) {
			return deny()
		}
		machineScope := scope
		machineScope.PrincipalType, machineScope.PrincipalID = string(identity.PrincipalServicePrincipal), machine.PrincipalID
		if epoch, machineEpochErr := a.route.currentPrincipalPermissionTx(ctx, tx, machineScope, "run"); machineEpochErr != nil || epoch == 0 {
			return deny()
		}
	}
	var snapshot evaluationproduct.ExecutionRequest
	if admission {
		snapshot, err = evaluationproduct.ResolveExecutionSnapshot(ctx, a.products, productScope, parent)
	} else {
		snapshot, err = evaluationproduct.ResolveHistoricalExecutionSnapshot(ctx, a.products, productScope, parent)
	}
	if err != nil || snapshot.RunID() != parent.ID || snapshot.Scope() != productScope || snapshot.AgentID() != lease.AgentID ||
		snapshot.AgentVersionID() != lease.AgentVersionID || !evaluationScopeMatchesSnapshot(scope, snapshot.AgentID(), snapshot.AgentVersionID()) {
		return deny()
	}
	return evaluationBudgetParent{resource: parent, lease: lease, snapshot: snapshot}, nil
}

// VerifyBudgetTx returns the policy that fixes one Evaluation case's budget.
// The child execution row and Evaluation product head are read through the
// caller's transaction. Admission requires a live Evaluation lease and current
// user/workload authority; settlement verifies the same immutable lineage but
// deliberately survives later parent completion or revocation.
func (a evaluationExecutionAuthority) VerifyBudgetTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, runFacts execution.BudgetRunFacts, parent evaluationBudgetParent, admission bool) (policyasset.Snapshot, error) {
	deny := func() (policyasset.Snapshot, error) { return policyasset.Snapshot{}, agentcoordination.ErrDenied }
	if tx == nil || a.route.runs == nil || a.catalog == nil || a.policies == nil ||
		scope.ValidateTrusted() != nil || scope.ParentRunID == "" || runFacts.Scope != scope ||
		(runFacts.Status != platformruntime.StatusRunning && !(runFacts.Status == platformruntime.StatusSucceeded || runFacts.Status == platformruntime.StatusFailed || runFacts.Status == platformruntime.StatusCancelled || (!admission && runFacts.Status == platformruntime.StatusCancelling))) {
		return deny()
	}
	var request contract.ExecuteRequest
	decoder := json.NewDecoder(bytes.NewReader(runFacts.RequestJSON))
	decoder.UseNumber()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.ProtocolVersion != contract.ProtocolVersion ||
		request.Validate() != nil || request.Operation != "invoke" || request.ResumeInput != nil || request.Scope != evaluationContractScope(scope) ||
		request.Scope.DelegationDepth != 0 {
		return deny()
	}
	fingerprint, err := contract.CanonicalExecuteBodyHash(request)
	if err != nil || fingerprint != runFacts.RequestFingerprint {
		return deny()
	}
	if !evaluationCreatorMatches(parent.resource, scope) || parent.resource.ID != scope.ParentRunID || parent.lease.IdempotencyKey == "" {
		return deny()
	}
	if admission {
		if runFacts.Status != platformruntime.StatusRunning || !runFacts.HasLease || !runFacts.LeaseUntil.After(time.Now().UTC()) || !evaluationParentBudgetStateMatches(parent.resource, parent.lease, true, time.Now().UTC()) {
			return deny()
		}
	} else {
		// Running with an expired lease, or terminal product parents, remain
		// valid only as historical accounting provenance.
		if !evaluationParentBudgetStateMatches(parent.resource, parent.lease, false, time.Now().UTC()) {
			return deny()
		}
	}
	if parent.snapshot.RunID() != parent.resource.ID || parent.snapshot.AgentID() != parent.lease.AgentID ||
		parent.snapshot.AgentVersionID() != parent.lease.AgentVersionID || !evaluationScopeMatchesSnapshot(scope, parent.snapshot.AgentID(), parent.snapshot.AgentVersionID()) {
		return deny()
	}
	dataset := parent.snapshot.Dataset()
	if parent.snapshot.InstallationID() != "" && parent.snapshot.InstallationID() != scope.InstallationID {
		return deny()
	}
	index, ok := evaluationInvocationIndex(parent.resource.ID, parent.lease.IdempotencyKey, scope, request, len(dataset.Cases))
	if !ok || scope.TraceID != evaluationTraceID(parent.resource.ID, index) || !evaluationCaseRequestMatches(dataset.Cases[index], request.Input) {
		return deny()
	}
	policy, ok := policyFromEvaluationInput(request.Input)
	if !ok || policy.Runtime.RunBudget == nil || policy.Runtime.RunBudget.Validate() != nil {
		return deny()
	}
	if admission {
		currentPolicy, policyErr := a.policies.Resolve(ctx, scope, scope.AgentVersionID)
		if policyErr != nil || !evaluationPolicyInputMatchesCurrent(request.Input["policy_snapshot"], currentPolicy) {
			return deny()
		}
		target, targetErr := a.catalog.ResolveEvaluationAgentTarget(ctx, scope, scope.AgentID, scope.AgentVersionID)
		if targetErr != nil || target.InstallationID != scope.InstallationID || (parent.snapshot.InstallationID() != "" && target.Revision != parent.snapshot.InstallationRevision()) || target.AgentID != scope.AgentID || target.AgentVersionID != scope.AgentVersionID ||
			request.InputSchema != target.InputSchemaURI || !evaluationEndpointMatches(target.Endpoint, runFacts.AgentEndpoint) {
			return deny()
		}
		if a.verifyJudgeSource(ctx, scope, request.Input) != nil {
			return deny()
		}
	}
	var runData evaluationproduct.RunData
	if json.Unmarshal(parent.resource.Data, &runData) != nil {
		return deny()
	}
	if runData.Limits != nil {
		count := int64(len(dataset.Cases))
		if count <= 0 || runData.Limits.LimitTokens < 0 || runData.Limits.LimitMicros < 0 {
			return deny()
		}
		budget := *policy.Runtime.RunBudget
		if tokens := runData.Limits.LimitTokens / count; tokens < budget.LimitTokens {
			budget.LimitTokens = tokens
		}
		if cost := runData.Limits.LimitMicros / count; cost < budget.LimitMicros {
			budget.LimitMicros = cost
		}
		policy.Runtime.RunBudget = &budget
	}
	return policy, nil
}

// VerifyExternalRootTx proves a persisted depth-zero Evaluation case against
// its immutable product snapshot. Terminal settlement already owns the child
// UPDATE lock, so read historical provenance without taking the product head
// lock in reverse order. This grants no new work and survives later revocation;
// the caller still fences every descendant and unsettled model/tool receipt.
func (a evaluationExecutionAuthority) VerifyExternalRootTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
	if tx == nil || a.route.runs == nil {
		return agentcoordination.ErrDenied
	}
	facts, err := a.route.runs.BudgetRunReadTx(ctx, tx, scope.RunID)
	if err != nil || facts.Scope != scope {
		return agentcoordination.ErrDenied
	}
	parent, err := a.readBudgetParentTx(ctx, tx, scope, false, false)
	if err != nil {
		return err
	}
	_, err = a.VerifyBudgetTx(ctx, tx, scope, facts, parent, false)
	return err
}

func evaluationTraceID(parentID string, index int) string {
	return conversation.NewContextTraceID(fmt.Sprintf("evaluation:%s:%d", parentID, index))
}

func policyFromEvaluationInput(input map[string]any) (policyasset.Snapshot, bool) {
	actual, ok := input["policy_snapshot"].(map[string]any)
	if !ok || len(actual) == 0 {
		return policyasset.Snapshot{}, false
	}
	contentHash, ok := actual["content_hash"].(string)
	if !ok || !evaluationPolicyHashValid(contentHash) {
		return policyasset.Snapshot{}, false
	}
	wire := make(map[string]any, len(actual)+2)
	for key, value := range actual {
		if key != "content_hash" && key != "rule_bundle" {
			wire[key] = value
		}
	}
	wire["hash"] = contentHash
	if rule, exists := actual["rule_bundle"]; exists {
		wire["rule"] = rule
		if values, valid := rule.(map[string]any); valid {
			wire["rule_bundle_version"] = values["version"]
			wire["rule_bundle_checksum"] = values["checksum"]
		}
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return policyasset.Snapshot{}, false
	}
	var policy policyasset.Snapshot
	if json.Unmarshal(raw, &policy) != nil || policy.Validate() != nil || policy.ValidateDetails() != nil || policy.Hash != contentHash {
		return policyasset.Snapshot{}, false
	}
	canonical, err := policy.ExecutionInput()
	if err != nil || evaluationCanonicalJSONHash(canonical) != evaluationCanonicalJSONHash(actual) {
		return policyasset.Snapshot{}, false
	}
	return policy, true
}

func evaluationPolicyInputMatchesCurrent(saved any, current policyasset.Snapshot) bool {
	expected, err := current.ExecutionInput()
	return err == nil && evaluationCanonicalJSONHash(expected) == evaluationCanonicalJSONHash(saved)
}

func evaluationPolicyHashValid(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
