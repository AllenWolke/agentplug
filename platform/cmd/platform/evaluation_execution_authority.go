package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	agenteval "github.com/lexagent/agent-evaluation"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/evaluationproduct"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// evaluationExecutionAuthority is the narrow bridge between the persisted
// Evaluation product Run and its depth-zero governed Agent child. It is used
// both before the child is created and on every later dispatch/continuation.
type evaluationExecutionAuthority struct {
	products evaluationproduct.ExecutionStore
	route    agentRouteAuthority
	policies policyasset.Resolver
	catalog  *catalog.Module
}

type evaluationRunLease struct {
	SuiteID        string    `json:"suite_id"`
	AgentID        string    `json:"agent_id"`
	AgentVersionID string    `json:"agent_version_id"`
	IdempotencyKey string    `json:"idempotency_key"`
	ExecutionState string    `json:"execution_state"`
	LeaseOwner     string    `json:"lease_owner"`
	LeaseToken     string    `json:"lease_token"`
	LeaseUntil     time.Time `json:"lease_until"`
}

func evaluationProductScope(scope sharedkernel.Scope) evaluationproduct.Scope {
	return evaluationproduct.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}
}

func evaluationCreatorMatches(parent evaluationproduct.Resource, scope sharedkernel.Scope) bool {
	return scope.PrincipalType == string(identity.PrincipalUser) && parent.Scope == evaluationProductScope(scope) &&
		parent.Kind == evaluationproduct.KindRun && parent.ID == scope.ParentRunID && parent.CreatedBy != "" && parent.CreatedBy == scope.PrincipalID
}

func evaluationRunEpochMatches(expected, current uint64) bool {
	return expected != 0 && current == expected
}

func evaluationEndpointMatches(catalogEndpoint, requestEndpoint string) bool {
	return catalogEndpoint != "" && requestEndpoint == catalogEndpoint
}

func evaluationScopeMatchesSnapshot(scope sharedkernel.Scope, agentID, versionID string) bool {
	return agentID != "" && versionID != "" && scope.AgentID == agentID && scope.AgentVersionID == versionID
}

func evaluationParentLeaseMatches(parent evaluationproduct.Resource, lease evaluationRunLease, now time.Time) bool {
	return parent.Status == "running" && lease.ExecutionState == "running" && lease.LeaseOwner != "" &&
		lease.LeaseToken != "" && lease.LeaseUntil.After(now) && lease.AgentID != "" &&
		lease.AgentVersionID != "" && lease.IdempotencyKey != ""
}

func evaluationParentBudgetStateMatches(parent evaluationproduct.Resource, lease evaluationRunLease, admission bool, now time.Time) bool {
	if admission {
		return evaluationParentLeaseMatches(parent, lease, now)
	}
	// Accounting provenance remains valid after the product lease expires or
	// the parent completes. The persisted state must still agree with its head.
	switch parent.Status {
	case "running", "succeeded", "failed", "cancelling", "cancelled":
		return lease.ExecutionState == parent.Status
	default:
		return false
	}
}

func evaluationWorkloadBindingMatches(scope sharedkernel.Scope, binding identity.WorkloadBinding) bool {
	return binding.Status == "active" && binding.Revision > 0 && binding.TenantID == scope.TenantID &&
		binding.DepartmentID == scope.DepartmentID && binding.ApplicationID == scope.ApplicationID &&
		binding.InstallationID == scope.InstallationID && binding.AgentID == scope.AgentID &&
		binding.AgentVersionID == scope.AgentVersionID && binding.PrincipalID != ""
}

// AuthorizeSynchronous admits the first, not-yet-persisted Evaluation child.
// It fails closed unless the parent product Run is currently leased and the
// exact frozen case, target, IAM epochs and machine binding all agree.
func (a evaluationExecutionAuthority) AuthorizeSynchronous(ctx context.Context, scope sharedkernel.Scope, endpoint string, request contract.ExecuteRequest) error {
	if request.Scope.ParentRunID == "" || request.Scope.DelegationDepth != 0 {
		return agentcoordination.ErrDenied
	}
	return a.authorize(ctx, scope, endpoint, request, false)
}

// ParentAborted is a stop-control check, not a new business admission. A worker
// disconnect must not destroy an otherwise recoverable waiting child.
func (a evaluationExecutionAuthority) ParentAborted(ctx context.Context, scope sharedkernel.Scope) (bool, error) {
	if a.products == nil || scope.ValidateTrusted() != nil || scope.ParentRunID == "" {
		return false, agentcoordination.ErrDenied
	}
	parent, err := a.products.Get(ctx, evaluationProductScope(scope), evaluationproduct.KindRun, scope.ParentRunID)
	if err != nil {
		return false, err
	}
	if !evaluationCreatorMatches(parent, scope) {
		return false, agentcoordination.ErrDenied
	}
	return parent.Status == "cancelling" || parent.Status == "cancelled" || parent.Status == "failed", nil
}

// VerifyPersisted is used for dispatch, heartbeat, capability and renewal
// checks. A parent string is insufficient: the durable child envelope must
// match a live product Evaluation Run and its immutable suite case.
func (a evaluationExecutionAuthority) VerifyPersisted(ctx context.Context, scope sharedkernel.Scope) error {
	if a.route.runs == nil || scope.ValidateTrusted() != nil || scope.ParentRunID == "" {
		return agentcoordination.ErrDenied
	}
	child, err := a.route.runs.BudgetRunContext(ctx, scope.RunID)
	if err != nil || child.Scope != scope || child.Status != "running" || !child.HasLease || !child.LeaseUntil.After(time.Now().UTC()) {
		return agentcoordination.ErrDenied
	}
	var request contract.ExecuteRequest
	decoder := json.NewDecoder(bytes.NewReader(child.RequestJSON))
	decoder.UseNumber()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		return agentcoordination.ErrDenied
	}
	fingerprint, err := contract.CanonicalExecuteBodyHash(request)
	stored, storedErr := a.route.runs.Get(scope.RunID)
	if err != nil || child.RequestFingerprint != fingerprint || storedErr != nil || stored.Scope != scope || stored.AgentEndpoint == "" {
		return agentcoordination.ErrDenied
	}
	return a.authorize(ctx, scope, stored.AgentEndpoint, request, true)
}

func (a evaluationExecutionAuthority) authorize(ctx context.Context, scope sharedkernel.Scope, endpoint string, request contract.ExecuteRequest, persisted bool) error {
	if a.products == nil || a.route.identity == nil || a.route.runs == nil || a.catalog == nil || a.policies == nil ||
		scope.ValidateTrusted() != nil || request.Validate() != nil || request.Operation != "invoke" || request.ResumeInput != nil ||
		scope.PrincipalType != string(identity.PrincipalUser) || scope.ParentRunID == "" || request.Scope.DelegationDepth != 0 || request.Scope != evaluationContractScope(scope) {
		return agentcoordination.ErrDenied
	}
	productScope := evaluationProductScope(scope)
	parent, err := a.products.Get(ctx, productScope, evaluationproduct.KindRun, scope.ParentRunID)
	if err != nil || !evaluationCreatorMatches(parent, scope) {
		return agentcoordination.ErrDenied
	}
	var lease evaluationRunLease
	if json.Unmarshal(parent.Data, &lease) != nil || !evaluationParentLeaseMatches(parent, lease, time.Now().UTC()) {
		return agentcoordination.ErrDenied
	}
	principal, err := a.route.identity.GetPrincipal(ctx, identity.PrincipalUser, parent.CreatedBy)
	if err != nil || !principal.IsActive || principal.ID != scope.PrincipalID || principal.Type != identity.PrincipalUser || principal.TenantID != scope.TenantID {
		return agentcoordination.ErrDenied
	}
	snapshot, err := evaluationproduct.ResolveExecutionSnapshot(ctx, a.products, productScope, parent)
	if err != nil || snapshot.RunID() != parent.ID || snapshot.Scope() != productScope || snapshot.AgentID() != lease.AgentID || snapshot.AgentVersionID() != lease.AgentVersionID || !evaluationScopeMatchesSnapshot(scope, snapshot.AgentID(), snapshot.AgentVersionID()) {
		return agentcoordination.ErrDenied
	}
	if snapshot.InstallationID() != "" && snapshot.InstallationID() != scope.InstallationID {
		return agentcoordination.ErrDenied
	}
	dataset := snapshot.Dataset()
	index, ok := evaluationInvocationIndex(parent.ID, lease.IdempotencyKey, scope, request, len(dataset.Cases))
	if !ok || scope.TraceID != conversation.NewContextTraceID(fmt.Sprintf("evaluation:%s:%d", parent.ID, index)) || !evaluationCaseRequestMatches(dataset.Cases[index], request.Input) {
		return agentcoordination.ErrDenied
	}
	if persisted && (request.Scope.RunID != scope.RunID || request.Scope.ParentRunID != parent.ID || request.Scope.DelegationDepth != 0) {
		return agentcoordination.ErrDenied
	}

	target, err := a.catalog.ResolveEvaluationAgentTarget(ctx, scope, scope.AgentID, scope.AgentVersionID)
	if err != nil || target.InstallationID != scope.InstallationID || (snapshot.InstallationID() != "" && target.Revision != snapshot.InstallationRevision()) || target.AgentVersionID != scope.AgentVersionID || target.AgentID != scope.AgentID || request.InputSchema != target.InputSchemaURI || !evaluationEndpointMatches(target.Endpoint, endpoint) {
		return agentcoordination.ErrDenied
	}
	if err = a.verifyJudgeSource(ctx, scope, request.Input); err != nil {
		return err
	}
	policy, err := a.policies.Resolve(ctx, scope, scope.AgentVersionID)
	if err != nil {
		return agentcoordination.ErrDenied
	}
	policyInput, err := policy.ExecutionInput()
	if err != nil || !evaluationInputHasPolicy(request.Input, policyInput) {
		return agentcoordination.ErrDenied
	}

	// Pin both the creator's and the exact installed workload's current run
	// grants/epochs under IAM read continuity. The workload credential and
	// binding are independently resolved against this exact installation.
	tx, borrowed, err := sqlutil.ContinuityTransaction(ctx, a.route.runs.DB())
	if err != nil {
		return err
	}
	if !borrowed {
		tx, err = a.route.runs.DB().BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
	}
	txReader, ok := a.products.(evaluationProductTxReader)
	if !ok {
		return agentcoordination.ErrDenied
	}
	lockedParent, err := txReader.GetTx(ctx, tx, productScope, evaluationproduct.KindRun, parent.ID, true)
	if err != nil || lockedParent.Revision != parent.Revision || lockedParent.Status != parent.Status || !bytes.Equal(lockedParent.Data, parent.Data) ||
		!evaluationCreatorMatches(lockedParent, scope) || !evaluationParentBudgetStateMatches(lockedParent, lease, true, time.Now().UTC()) ||
		txReader.CheckRunLeaseTx(ctx, tx, productScope, parent.ID, lease.LeaseOwner, lease.LeaseToken, lease.LeaseUntil, time.Now().UTC()) != nil {
		return agentcoordination.ErrDenied
	}
	if err := a.route.identity.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return err
	}
	actorEpoch, err := a.route.currentPrincipalPermissionTx(ctx, tx, scope, "run")
	if err != nil || !evaluationRunEpochMatches(scope.AuthorizationEpoch, actorEpoch) {
		return agentcoordination.ErrDenied
	}
	machine, err := a.route.workloadMachine(ctx, scope)
	if err != nil || !evaluationWorkloadBindingMatches(scope, machine) {
		return agentcoordination.ErrDenied
	}
	machineScope := scope
	machineScope.PrincipalType, machineScope.PrincipalID = string(identity.PrincipalServicePrincipal), machine.PrincipalID
	machineEpoch, err := a.route.currentPrincipalPermissionTx(ctx, tx, machineScope, "run")
	if err != nil || machineEpoch == 0 {
		return agentcoordination.ErrDenied
	}
	if borrowed {
		return nil
	}
	return tx.Commit()
}

func (a evaluationExecutionAuthority) verifyJudgeSource(ctx context.Context, scope sharedkernel.Scope, input map[string]any) error {
	if !agenteval.IsJudgeInputVersion(input["version"]) {
		return nil
	}
	copy := make(map[string]any, len(input))
	for key, value := range input {
		if key != "policy_snapshot" {
			copy[key] = value
		}
	}
	b, err := json.Marshal(copy)
	var frozen agenteval.JudgeInput
	if err != nil || json.Unmarshal(b, &frozen) != nil {
		return agentcoordination.ErrDenied
	}
	ref, err := frozen.SourceReference()
	if err != nil || scope.AgentID != "agent-eval-judge" {
		return agentcoordination.ErrDenied
	}
	sources := evaluationInspection{runs: a.route.runs, identity: a.route.identity}
	if sources.AuthorizeSources(ctx, evaluationproduct.Actor{Scope: evaluationProductScope(scope), PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID}, []agenteval.SourceReference{ref}) != nil {
		return agentcoordination.ErrDenied
	}
	return nil
}

func evaluationContractScope(scope sharedkernel.Scope) contract.ScopeKey {
	return contract.ScopeKey{
		TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
		AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
		PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID,
		RunID: scope.RunID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID,
		ParentRunID: scope.ParentRunID, DelegationDepth: 0, InstallationID: scope.InstallationID,
	}
}

func evaluationInvocationIndex(parentID, parentKey string, scope sharedkernel.Scope, request contract.ExecuteRequest, count int) (int, bool) {
	found := -1
	for index := 0; index < count; index++ {
		if evaluationExecutionRunID(parentID, index) == scope.RunID {
			if found >= 0 {
				return 0, false
			}
			found = index
		}
	}
	if found < 0 || request.Scope.RunID != scope.RunID || request.Scope.ParentRunID != parentID || request.Scope.DelegationDepth != 0 ||
		scope.SessionID != evaluationSessionID(parentID, found) || request.IdempotencyKey != evaluationCaseIdempotencyKey(parentKey, found) {
		return 0, false
	}
	return found, true
}

func evaluationCaseIdempotencyKey(parentKey string, index int) string {
	return parentKey + ".case." + strconv.Itoa(index)
}

func evaluationCaseRequestMatches(raw json.RawMessage, requestInput map[string]any) bool {
	var sample struct {
		CaseID   string          `json:"case_id"`
		Input    json.RawMessage `json:"input"`
		Expected json.RawMessage `json:"expected"`
		Split    string          `json:"split,omitempty"`
		Weight   *float64        `json:"weight,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&sample) != nil || decoder.Decode(new(any)) != io.EOF || sample.CaseID == "" || len(bytes.TrimSpace(sample.Input)) == 0 || len(requestInput) == 0 {
		return false
	}
	var expected map[string]any
	decoder = json.NewDecoder(bytes.NewReader(sample.Input))
	decoder.UseNumber()
	if decoder.Decode(&expected) != nil || expected == nil {
		return false
	}
	if _, supplied := expected["policy_snapshot"]; supplied {
		return false
	}
	actual := make(map[string]any, len(requestInput))
	for key, value := range requestInput {
		actual[key] = value
	}
	delete(actual, "policy_snapshot")
	return evaluationCanonicalJSONHash(expected) == evaluationCanonicalJSONHash(actual) && evaluationCanonicalJSONHash(expected) != ""
}

func evaluationInputHasPolicy(input map[string]any, expected map[string]any) bool {
	actual, ok := input["policy_snapshot"].(map[string]any)
	return ok && evaluationCanonicalJSONHash(actual) != "" && evaluationCanonicalJSONHash(actual) == evaluationCanonicalJSONHash(expected)
}

func evaluationCanonicalJSONHash(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	var normalized any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&normalized) != nil {
		return ""
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}
