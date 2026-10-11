// Package agentcoordination owns business routing and child orchestration,
// separate from HTTP/gRPC transport selection and Agent business code.
package agentcoordination

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrDenied = errors.New("agent coordination denied")
var ErrConflict = errors.New("agent coordination command conflict")
var ErrUnavailable = errors.New("agent coordination unavailable")

type RouteDenialStage string
type RouteDenialReason string

const (
	RouteDenialRequest             RouteDenialStage = "request"
	RouteDenialParent              RouteDenialStage = "parent"
	RouteDenialCandidates          RouteDenialStage = "candidates"
	RouteDenialEligibility         RouteDenialStage = "eligibility"
	RouteDenialTargetAuthorization RouteDenialStage = "target_authorization"
)

const (
	RouteReasonInvalidRequest           RouteDenialReason = "invalid_request"
	RouteReasonParentUnavailable        RouteDenialReason = "parent_unavailable"
	RouteReasonParentScope              RouteDenialReason = "parent_scope_mismatch"
	RouteReasonParentIAMContinuity      RouteDenialReason = "parent_iam_continuity"
	RouteReasonParentAncestorBudget     RouteDenialReason = "parent_ancestor_budget"
	RouteReasonParentBoundContext       RouteDenialReason = "parent_capability_context"
	RouteReasonParentLiveCheck          RouteDenialReason = "parent_live_capability_check"
	RouteReasonParentLease              RouteDenialReason = "parent_execution_lease"
	RouteReasonParentPermissionMode     RouteDenialReason = "parent_permission_mode"
	RouteReasonParentDelegate           RouteDenialReason = "parent_delegate_authority"
	RouteReasonParentRunFacts           RouteDenialReason = "parent_run_facts"
	RouteReasonParentCommand            RouteDenialReason = "parent_command_scope"
	RouteReasonParentAncestry           RouteDenialReason = "parent_ancestry"
	RouteReasonParentPolicy             RouteDenialReason = "parent_policy"
	RouteReasonParentTask               RouteDenialReason = "parent_task_policy"
	RouteReasonParentFanout             RouteDenialReason = "parent_fanout_limit"
	RouteReasonCandidateCatalog         RouteDenialReason = "candidate_catalog_unavailable"
	RouteReasonCandidateEmpty           RouteDenialReason = "candidate_set_empty"
	RouteReasonCandidateIneligible      RouteDenialReason = "candidate_ineligible"
	RouteReasonCandidateIneligibleMixed RouteDenialReason = "candidate_ineligible_mixed"
	RouteReasonCandidateInsufficient    RouteDenialReason = "candidate_count_insufficient"
	RouteReasonCandidateAuthorization   RouteDenialReason = "candidate_authorization_denied"
	RouteReasonCandidateShape           RouteDenialReason = "candidate_shape"
	RouteReasonCandidateScope           RouteDenialReason = "candidate_scope"
	RouteReasonCandidatePolicy          RouteDenialReason = "candidate_policy"
	RouteReasonCandidateTask            RouteDenialReason = "candidate_task_type"
	RouteReasonCandidateAncestor        RouteDenialReason = "candidate_ancestor_cycle"
	RouteReasonTargetResolve            RouteDenialReason = "target_resolve_failed"
	RouteReasonTargetFacts              RouteDenialReason = "target_facts_changed"
	RouteReasonTargetAuthority          RouteDenialReason = "target_authority_denied"
	RouteReasonCallerDelegate           RouteDenialReason = "caller_target_delegate"
	RouteReasonParentMachineDelegate    RouteDenialReason = "parent_machine_target_delegate"
	RouteReasonParentMachineBinding     RouteDenialReason = "parent_machine_binding"
	RouteReasonTargetMachineBinding     RouteDenialReason = "target_machine_binding"
	RouteReasonTargetMachineRun         RouteDenialReason = "target_machine_run"
)

// classifiedRouteError carries only fixed internal stage/reason enums. Its
// Error string and unwrap chain preserve the existing public error identity;
// the underlying database or authorization message is never rendered here.
type classifiedRouteError struct {
	stage  RouteDenialStage
	reason RouteDenialReason
	cause  error
}

func (e *classifiedRouteError) Error() string {
	if e == nil || e.cause == nil || errors.Is(e.cause, ErrDenied) {
		return ErrDenied.Error()
	}
	if errors.Is(e.cause, ErrConflict) {
		return ErrConflict.Error()
	}
	if errors.Is(e.cause, ErrUnavailable) {
		return ErrUnavailable.Error()
	}
	return ErrUnavailable.Error()
}

func (e *classifiedRouteError) Unwrap() error {
	if e == nil || e.cause == nil {
		return ErrDenied
	}
	return e.cause
}

func validRouteDenial(stage RouteDenialStage, reason RouteDenialReason) bool {
	switch stage {
	case RouteDenialRequest:
		return reason == RouteReasonInvalidRequest
	case RouteDenialParent:
		return reason == RouteReasonParentUnavailable || reason == RouteReasonParentScope || reason == RouteReasonParentIAMContinuity || reason == RouteReasonParentAncestorBudget || reason == RouteReasonParentBoundContext || reason == RouteReasonParentLiveCheck || reason == RouteReasonParentLease || reason == RouteReasonParentPermissionMode || reason == RouteReasonParentDelegate || reason == RouteReasonParentRunFacts || reason == RouteReasonParentCommand || reason == RouteReasonParentAncestry || reason == RouteReasonParentPolicy || reason == RouteReasonParentTask || reason == RouteReasonParentFanout
	case RouteDenialCandidates:
		return reason == RouteReasonCandidateCatalog || reason == RouteReasonCandidateEmpty
	case RouteDenialEligibility:
		return reason == RouteReasonCandidateIneligible || reason == RouteReasonCandidateIneligibleMixed || reason == RouteReasonCandidateInsufficient || reason == RouteReasonCandidateShape || reason == RouteReasonCandidateScope || reason == RouteReasonCandidatePolicy || reason == RouteReasonCandidateTask || reason == RouteReasonCandidateAncestor
	case RouteDenialTargetAuthorization:
		return reason == RouteReasonCandidateAuthorization || reason == RouteReasonTargetResolve || reason == RouteReasonTargetFacts || reason == RouteReasonTargetAuthority || reason == RouteReasonCallerDelegate || reason == RouteReasonParentMachineDelegate || reason == RouteReasonParentMachineBinding || reason == RouteReasonTargetMachineBinding || reason == RouteReasonTargetMachineRun
	default:
		return false
	}
}

// ClassifyRouteError returns an error with an allowlisted internal category.
// A nil cause means the existing ErrDenied condition. A non-nil cause remains
// discoverable by errors.Is/errors.As without exposing its message.
func ClassifyRouteError(stage RouteDenialStage, reason RouteDenialReason, cause error) error {
	if !validRouteDenial(stage, reason) {
		if cause != nil {
			return cause
		}
		return ErrDenied
	}
	if cause == nil {
		cause = ErrDenied
	}
	return &classifiedRouteError{stage: stage, reason: reason, cause: cause}
}

// RouteErrorClassification exposes only fixed safe labels for internal logs.
func RouteErrorClassification(err error) (RouteDenialStage, RouteDenialReason, bool) {
	var classified *classifiedRouteError
	if !errors.As(err, &classified) || classified == nil || !validRouteDenial(classified.stage, classified.reason) {
		return "", "", false
	}
	return classified.stage, classified.reason, true
}

type Target struct {
	TenantID             string   `json:"tenant_id"`
	DepartmentID         string   `json:"department_id"`
	ApplicationID        string   `json:"application_id"`
	AgentID              string   `json:"agent_id"`
	InstallationID       string   `json:"installation_id"`
	InstallationRevision uint64   `json:"installation_revision"`
	VersionID            string   `json:"version_id"`
	DeploymentID         string   `json:"deployment_id"`
	DeploymentRevision   uint64   `json:"deployment_revision"`
	ManifestHash         string   `json:"manifest_hash"`
	InputSchema          string   `json:"input_schema"`
	OutputSchema         string   `json:"output_schema"`
	TaskTypes            []string `json:"task_types"`
	Published            bool     `json:"published"`
	Ready                bool     `json:"ready"`
}

// ParentFacts must come from the current fenced execution and immutable
// published policy, not from request fields or a client-provided ancestor list.
type ParentFacts struct {
	Scope                 sharedkernel.Scope
	PolicyHash            string
	Policy                *policyasset.AgentDelegationPolicy
	Depth                 int
	AncestorInstallations []string
	AncestorAgentIDs      []string
	CurrentChildren       int
	Active                bool
}

type RouteRequest struct {
	OperationKey string `json:"operation_key"`
	TaskType     string `json:"task_type"`
	Count        int    `json:"count"`
}

type RoutePlan struct {
	Version        string   `json:"version"`
	OperationKey   string   `json:"operation_key"`
	Fingerprint    string   `json:"fingerprint"`
	ParentRunID    string   `json:"parent_run_id"`
	PolicyHash     string   `json:"policy_hash"`
	TaskType       string   `json:"task_type"`
	ChildDepth     int      `json:"child_depth"`
	Targets        []Target `json:"targets"`
	EvidenceDigest string   `json:"evidence_digest"`
}

// Implementations must serialize planning per parent, enforce caller AND
// parent-machine permission intersections on each target, and repeat current
// authorization before commit. ReservedChildren counts existing reservations
// including pending/uncertain children; failed RPCs never release a reservation.
type RouteTransaction interface {
	Parent(context.Context, sharedkernel.Scope) (ParentFacts, error)
	Candidates(context.Context, ParentFacts, string) ([]Target, error)
	AuthorizeTarget(context.Context, ParentFacts, Target) error
	Existing(string) (RoutePlan, bool, error)
	Reserve(RoutePlan) error
	Audit(RoutePlan) error
}
type RouteStore interface {
	Transact(context.Context, sharedkernel.Scope, func(RouteTransaction) error) error
}
type Router struct{ store RouteStore }

func NewRouter(store RouteStore) (*Router, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	return &Router{store: store}, nil
}
func identifier(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "*\x00\r\n")
}
func digest(value any) string {
	raw, _ := json.Marshal(value)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func hashValue(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && value == hex.EncodeToString(raw)
}
func eligible(parent ParentFacts, target Target, task string) bool {
	return eligibilityDenial(parent, target, task) == ""
}

func eligibilityDenial(parent ParentFacts, target Target, task string) RouteDenialReason {
	if len(target.TaskTypes) < 1 || len(target.TaskTypes) > 16 {
		return RouteReasonCandidateShape
	}
	seen := map[string]bool{}
	for _, value := range target.TaskTypes {
		if !identifier(value) || seen[value] {
			return RouteReasonCandidateShape
		}
		seen[value] = true
	}
	if target.TenantID != parent.Scope.TenantID || target.DepartmentID != parent.Scope.DepartmentID || target.ApplicationID != parent.Scope.ApplicationID {
		return RouteReasonCandidateScope
	}
	if !identifier(target.AgentID) || !identifier(target.InstallationID) || target.InstallationRevision == 0 || !identifier(target.VersionID) || !identifier(target.DeploymentID) || target.DeploymentRevision == 0 || !strings.HasPrefix(target.ManifestHash, "sha256:") || !hashValue(strings.TrimPrefix(target.ManifestHash, "sha256:")) || !strings.HasPrefix(target.InputSchema, "schema://") || len(target.InputSchema) > 256 || strings.TrimSpace(target.InputSchema) != target.InputSchema || strings.ContainsAny(target.InputSchema, "*\x00\r\n\t ") || !strings.HasPrefix(target.OutputSchema, "schema://") || len(target.OutputSchema) > 256 || strings.TrimSpace(target.OutputSchema) != target.OutputSchema || strings.ContainsAny(target.OutputSchema, "*\x00\r\n\t ") || !target.Published || !target.Ready {
		return RouteReasonCandidateShape
	}
	if parent.Policy == nil || !contains(parent.Policy.AllowedAgentIDs, target.AgentID) {
		return RouteReasonCandidatePolicy
	}
	if !contains(target.TaskTypes, task) {
		return RouteReasonCandidateTask
	}
	if target.InstallationID == parent.Scope.InstallationID || target.AgentID == parent.Scope.AgentID || contains(parent.AncestorInstallations, target.InstallationID) || contains(parent.AncestorAgentIDs, target.AgentID) {
		return RouteReasonCandidateAncestor
	}
	return ""
}

// Plan deterministically selects eligible targets, persists evidence and
// reserves fan-out atomically. It does not dispatch a child or manufacture a
// permission token. A replay rechecks current parent and selected targets.
func (r *Router) Plan(ctx context.Context, scope sharedkernel.Scope, request RouteRequest) (RoutePlan, error) {
	if scope.ValidateTrusted() != nil || !identifier(request.OperationKey) || !identifier(request.TaskType) || request.Count < 1 || request.Count > 16 {
		return RoutePlan{}, ClassifyRouteError(RouteDenialRequest, RouteReasonInvalidRequest, nil)
	}
	var result RoutePlan
	err := r.store.Transact(ctx, scope, func(tx RouteTransaction) error {
		parent, err := tx.Parent(ctx, scope)
		if err != nil {
			if _, _, ok := RouteErrorClassification(err); ok {
				return err
			}
			return ClassifyRouteError(RouteDenialParent, RouteReasonParentUnavailable, err)
		}
		if !parent.Active || parent.Scope != scope {
			return ClassifyRouteError(RouteDenialParent, RouteReasonParentScope, nil)
		}
		if parent.Policy == nil || parent.Policy.Validate() != nil || !hashValue(parent.PolicyHash) {
			return ClassifyRouteError(RouteDenialParent, RouteReasonParentPolicy, nil)
		}
		if parent.Depth < 0 || parent.Depth >= parent.Policy.MaxDepth || len(parent.AncestorInstallations) != parent.Depth || len(parent.AncestorAgentIDs) != parent.Depth {
			return ClassifyRouteError(RouteDenialParent, RouteReasonParentAncestry, nil)
		}
		if !contains(parent.Policy.TaskTypes, request.TaskType) {
			return ClassifyRouteError(RouteDenialParent, RouteReasonParentTask, nil)
		}
		if parent.CurrentChildren < 0 {
			return ClassifyRouteError(RouteDenialParent, RouteReasonParentFanout, nil)
		}
		fingerprint := digest([]any{routeScopeKey(scope), parent.PolicyHash, request})
		existing, found, err := tx.Existing(request.OperationKey)
		if err != nil {
			return err
		}
		if found {
			if existing.Version != "agent-route/v1" || existing.Fingerprint != fingerprint || existing.ParentRunID != scope.RunID || existing.PolicyHash != parent.PolicyHash || existing.TaskType != request.TaskType || existing.ChildDepth != parent.Depth+1 || len(existing.Targets) != request.Count || existing.EvidenceDigest != digest(existing.Targets) {
				return ErrConflict
			}
			for _, target := range existing.Targets {
				if reason := eligibilityDenial(parent, target, request.TaskType); reason != "" {
					return ClassifyRouteError(RouteDenialEligibility, reason, nil)
				}
				if err := tx.AuthorizeTarget(ctx, parent, target); err != nil {
					if _, _, ok := RouteErrorClassification(err); ok {
						return err
					}
					return ClassifyRouteError(RouteDenialTargetAuthorization, RouteReasonTargetAuthority, ErrDenied)
				}
			}
			result = existing
			return tx.Audit(result)
		}
		if parent.CurrentChildren+request.Count > parent.Policy.MaxChildren {
			return ClassifyRouteError(RouteDenialParent, RouteReasonParentFanout, nil)
		}
		candidates, err := tx.Candidates(ctx, parent, request.TaskType)
		if err != nil {
			if _, _, ok := RouteErrorClassification(err); ok {
				return err
			}
			return ClassifyRouteError(RouteDenialCandidates, RouteReasonCandidateCatalog, err)
		}
		if len(candidates) > 128 {
			return ErrUnavailable
		}
		filtered := []Target{}
		seen := map[string]bool{}
		eligibleCount, authorizationDenied := 0, 0
		firstEligibilityReason := RouteDenialReason("")
		mixedEligibilityReasons := false
		firstTargetAuthorizationReason := RouteDenialReason("")
		mixedTargetAuthorizationReasons := false
		for _, candidate := range candidates {
			if reason := eligibilityDenial(parent, candidate, request.TaskType); reason != "" {
				if firstEligibilityReason == "" {
					firstEligibilityReason = reason
				} else if firstEligibilityReason != reason {
					mixedEligibilityReasons = true
				}
				continue
			}
			eligibleCount++
			if seen[candidate.InstallationID] {
				return ErrConflict
			}
			seen[candidate.InstallationID] = true
			if err := tx.AuthorizeTarget(ctx, parent, candidate); err != nil {
				authorizationDenied++
				stage, reason, classified := RouteErrorClassification(err)
				if !classified || stage != RouteDenialTargetAuthorization {
					mixedTargetAuthorizationReasons = true
				} else if firstTargetAuthorizationReason == "" {
					firstTargetAuthorizationReason = reason
				} else if firstTargetAuthorizationReason != reason {
					mixedTargetAuthorizationReasons = true
				}
				continue
			}
			filtered = append(filtered, candidate)
		}
		sort.Slice(filtered, func(i, j int) bool { return filtered[i].InstallationID < filtered[j].InstallationID })
		if len(filtered) < request.Count {
			if authorizationDenied > 0 {
				if firstTargetAuthorizationReason != "" && !mixedTargetAuthorizationReasons {
					return ClassifyRouteError(RouteDenialTargetAuthorization, firstTargetAuthorizationReason, ErrDenied)
				}
				return ClassifyRouteError(RouteDenialTargetAuthorization, RouteReasonCandidateAuthorization, nil)
			}
			if eligibleCount > 0 {
				return ClassifyRouteError(RouteDenialEligibility, RouteReasonCandidateInsufficient, nil)
			}
			if len(candidates) == 0 {
				return ClassifyRouteError(RouteDenialCandidates, RouteReasonCandidateEmpty, nil)
			}
			if mixedEligibilityReasons || firstEligibilityReason == "" {
				return ClassifyRouteError(RouteDenialEligibility, RouteReasonCandidateIneligibleMixed, nil)
			}
			return ClassifyRouteError(RouteDenialEligibility, firstEligibilityReason, nil)
		}
		selected := filtered[:request.Count]
		result = RoutePlan{Version: "agent-route/v1", OperationKey: request.OperationKey, Fingerprint: fingerprint, ParentRunID: scope.RunID, PolicyHash: parent.PolicyHash, TaskType: request.TaskType, ChildDepth: parent.Depth + 1, Targets: selected, EvidenceDigest: digest(selected)}
		if err := tx.Reserve(result); err != nil {
			return err
		}
		return tx.Audit(result)
	})
	if err != nil {
		return RoutePlan{}, err
	}
	return result, nil
}
