package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

const permissionBatchLimit = 50

type PermissionBatchItemCommand struct {
	Authorization *AuthorizationChangeCommand `json:"authorization,omitempty"`
	Decision      *PermissionRequestDecision  `json:"decision,omitempty"`
}

type PermissionBatchCommand struct {
	Scope          ManagementScope              `json:"scope"`
	Kind           string                       `json:"kind"`
	Items          []PermissionBatchItemCommand `json:"items"`
	IdempotencyKey string                       `json:"idempotency_key"`
	Reason         string                       `json:"reason"`
	PlanDigest     string                       `json:"plan_digest,omitempty"`
	PlanExpiresAt  time.Time                    `json:"plan_expires_at,omitempty"`
}

type PermissionBatchItem struct {
	Index         int                               `json:"index"`
	SubjectID     string                            `json:"subject_id"`
	Status        string                            `json:"status"`
	FailureCode   string                            `json:"failure_code,omitempty"`
	Command       PermissionBatchItemCommand        `json:"command"`
	Authorization *AuthorizationChangeReceipt       `json:"authorization,omitempty"`
	Decision      *PermissionRequestDecisionReceipt `json:"decision,omitempty"`
	Impact        *PermissionBatchItemImpact        `json:"impact,omitempty"`
}

// Preview information comes from the actual authorization planner, including
// its automatic revocations. It never changes the prepared command or rights.
type PermissionBatchItemImpact struct {
	AgentDisplayName     string         `json:"agent_display_name,omitempty"`
	AddedRoles           int            `json:"added_roles"`
	AddedResourceGrants  int            `json:"added_resource_grants"`
	ChangedMemberships   int            `json:"changed_memberships"`
	RevokedBindingIDs    []string       `json:"revoked_binding_ids,omitempty"`
	RevokedGrantIDs      []string       `json:"revoked_grant_ids,omitempty"`
	RevokedAssignmentIDs []string       `json:"revoked_assignment_ids,omitempty"`
	ApprovedItems        int            `json:"approved_items"`
	RejectedItems        int            `json:"rejected_items"`
	ResourceCounts       map[string]int `json:"resource_counts,omitempty"`
}

func permissionBatchAuthorizationImpact(plan AuthorizationChangePlan) *PermissionBatchItemImpact {
	counts := map[string]int{}
	seen := map[string]bool{}
	for _, grant := range plan.ExpandedGrants {
		key := grant.ResourceType + "\x00" + grant.ResourceID
		if !seen[key] {
			seen[key] = true
			counts[grant.ResourceType]++
		}
	}
	return &PermissionBatchItemImpact{
		AgentDisplayName: plan.AgentUseDisplayName,
		ResourceCounts:   counts,
		AddedRoles:       len(plan.ExpandedBindings), AddedResourceGrants: len(plan.ExpandedGrants), ChangedMemberships: len(plan.ExpandedMemberships),
		RevokedBindingIDs:    mergePermissionRevocations(plan.Command.RevokeBindingIDs, plan.AutomaticRevokeBindingIDs),
		RevokedGrantIDs:      mergePermissionRevocations(plan.Command.RevokeGrantIDs, plan.AutomaticRevokeGrantIDs),
		RevokedAssignmentIDs: mergePermissionRevocations(plan.Command.RevokeAssignmentIDs, plan.AutomaticRevokeAssignmentIDs),
	}
}

type PermissionBatch struct {
	ID            string                 `json:"batch_id"`
	ActorID       string                 `json:"actor_id"`
	ActorTenantID string                 `json:"actor_tenant_id"`
	RequestDigest string                 `json:"request_digest"`
	Command       PermissionBatchCommand `json:"change"`
	Items         []PermissionBatchItem  `json:"items"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

type PermissionBatchPlan struct {
	Digest    string                 `json:"plan_digest"`
	ExpiresAt time.Time              `json:"plan_expires_at"`
	Change    PermissionBatchCommand `json:"change"`
	Items     []PermissionBatchItem  `json:"items"`
}

func validPermissionBatchKey(key string) bool {
	return key != "" && len(key) <= 128 && strings.TrimSpace(key) == key && !strings.ContainsAny(key, "\x00\r\n/\\:")
}

func normalizedPermissionBatchCommand(actor sharedkernel.Scope, command PermissionBatchCommand) (PermissionBatchCommand, string, error) {
	if actor.Validate() != nil || actor.PrincipalType != "user" || command.Scope.Validate() != nil || !slices.Contains([]string{"tenant", "department", "application"}, command.Scope.Type) || !validPermissionBatchKey(command.IdempotencyKey) || strings.TrimSpace(command.Reason) == "" || len(command.Reason) > 1000 || len(command.Items) == 0 || len(command.Items) > permissionBatchLimit || command.Kind != "authorization" && command.Kind != "decision" {
		return PermissionBatchCommand{}, "", ErrInvalidResource
	}
	raw, err := json.Marshal(command)
	if err != nil {
		return PermissionBatchCommand{}, "", err
	}
	var normalized PermissionBatchCommand
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return PermissionBatchCommand{}, "", err
	}
	normalized.PlanDigest, normalized.PlanExpiresAt = "", time.Time{}
	seen := map[string]bool{}
	for index := range normalized.Items {
		item := &normalized.Items[index]
		itemKey := "batch-item-" + permissionHash([]byte(actor.PrincipalID+"\x00"+normalized.IdempotencyKey+"\x00"+strconv.Itoa(index)))
		var distinct string
		if normalized.Kind == "authorization" {
			if item.Authorization == nil || item.Decision != nil || item.Authorization.SubjectType != PrincipalUser || !validPermissionResourceID(item.Authorization.SubjectID) || item.Authorization.ExpectedRevision == 0 {
				return PermissionBatchCommand{}, "", ErrInvalidResource
			}
			distinct = item.Authorization.SubjectID
			item.Authorization.IdempotencyKey, item.Authorization.Reason = itemKey, normalized.Reason
			item.Authorization.PlanDigest, item.Authorization.PlanExpiresAt = "", time.Time{}
		} else {
			if item.Decision == nil || item.Authorization != nil {
				return PermissionBatchCommand{}, "", ErrInvalidResource
			}
			distinct = item.Decision.RequestID
			item.Decision.IdempotencyKey, item.Decision.Reason = itemKey, normalized.Reason
			item.Decision.PlanDigest, item.Decision.PlanExpiresAt = "", time.Time{}
			if _, err := permissionRequestDecisionDigest(*item.Decision); err != nil {
				return PermissionBatchCommand{}, "", err
			}
		}
		if seen[distinct] {
			return PermissionBatchCommand{}, "", ErrInvalidResource
		}
		seen[distinct] = true
	}
	raw, err = json.Marshal(normalized)
	if err != nil {
		return PermissionBatchCommand{}, "", err
	}
	return normalized, permissionHash(raw), nil
}

func authorizePermissionBatch(owner PermissionSnapshot, actor sharedkernel.Scope, command PermissionBatchCommand, now time.Time) error {
	if owner.Mode != "v2" || owner.Principal.Validate() != nil || owner.Principal.Type != PrincipalUser || owner.Principal.ID != actor.PrincipalID || owner.Principal.TenantID != actor.TenantID || actor.PrincipalType != "user" || actor.Validate() != nil {
		return ErrPermissionDenied
	}
	action := "authorization.change"
	if command.Kind == "decision" {
		action = "access_request.decide"
	}
	decision, err := EvaluatePermission(owner, PermissionQuery{Action: action, Scope: command.Scope, Now: now})
	if err != nil || !decision.Allowed {
		return ErrPermissionDenied
	}
	return nil
}

func permissionBatchFailureCode(err error) string {
	switch {
	case errors.Is(err, ErrIdentityConflict), errors.Is(err, ErrPermissionPlanStale):
		return "CONFLICT_REVIEW_REQUIRED"
	case errors.Is(err, ErrPermissionDenied), errors.Is(err, ErrScopeMismatch):
		return "PERMISSION_DENIED"
	case errors.Is(err, ErrInvalidResource), errors.Is(err, ErrInvalidPrincipal), errors.Is(err, ErrPrincipalNotFound), errors.Is(err, sql.ErrNoRows), errors.Is(err, ErrAgentInstallationNotFound):
		return "INVALID_OR_UNAVAILABLE"
	default:
		return "" // A database/audit fault is not a confirmed business refusal.
	}
}

func permissionBatchPlanWithinScope(plan AuthorizationChangePlan, target PermissionSnapshot, scope ManagementScope) bool {
	if target.Principal.TenantID != scope.TenantID {
		return false
	}
	for _, member := range plan.ExpandedMemberships {
		if !scope.Contains(member.Scope) {
			return false
		}
	}
	for _, binding := range plan.ExpandedBindings {
		if !scope.Contains(binding.Scope) {
			return false
		}
	}
	for _, grant := range plan.ExpandedGrants {
		if !scope.Contains(grantAuthorizationScope(grant)) {
			return false
		}
	}
	for _, assignment := range plan.ExpandedAssignments {
		if !scope.Contains(assignment.Scope) {
			return false
		}
	}
	for _, binding := range target.Bindings {
		if slices.Contains(mergePermissionRevocations(plan.Command.RevokeBindingIDs, plan.AutomaticRevokeBindingIDs), binding.ID) && !scope.Contains(binding.Scope) {
			return false
		}
	}
	for _, grant := range target.Grants {
		if slices.Contains(mergePermissionRevocations(plan.Command.RevokeGrantIDs, plan.AutomaticRevokeGrantIDs), grant.ID) && !scope.Contains(grantAuthorizationScope(grant)) {
			return false
		}
	}
	for _, assignment := range target.Assignments {
		if slices.Contains(mergePermissionRevocations(plan.Command.RevokeAssignmentIDs, plan.AutomaticRevokeAssignmentIDs), assignment.ID) && !scope.Contains(assignment.Scope) {
			return false
		}
	}
	return true
}

func (s *SQLStore) planPermissionBatch(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, command PermissionBatchCommand, deadline time.Time) (PermissionBatchPlan, error) {
	command, _, err := normalizedPermissionBatchCommand(actor, command)
	if err != nil {
		return PermissionBatchPlan{}, err
	}
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return PermissionBatchPlan{}, err
	}
	now := s.clock().UTC()
	if err := authorizePermissionBatch(owner, actor, command, now); err != nil {
		return PermissionBatchPlan{}, err
	}
	if !deadline.After(now) || deadline.After(now.Add(5*time.Minute)) {
		return PermissionBatchPlan{}, ErrPermissionPlanStale
	}
	if err := validatePermissionScope(ctx, tx, command.Scope); err != nil {
		return PermissionBatchPlan{}, err
	}
	plan := PermissionBatchPlan{ExpiresAt: deadline, Change: command, Items: make([]PermissionBatchItem, 0, len(command.Items))}
	for index, commandItem := range command.Items {
		item := PermissionBatchItem{Index: index, Status: "pending", Command: commandItem}
		if command.Kind == "authorization" {
			item.SubjectID = commandItem.Authorization.SubjectID
			target, targetErr := loadPermissionSnapshot(ctx, tx, PrincipalUser, item.SubjectID)
			if targetErr != nil {
				err = targetErr
			} else {
				var grantPlan AuthorizationChangePlan
				grantPlan, err = s.planAuthorizationChange(ctx, tx, actor, *commandItem.Authorization, deadline)
				if err == nil && !permissionBatchPlanWithinScope(grantPlan, target, command.Scope) {
					err = ErrPermissionDenied
				}
				if err == nil {
					prepared := *commandItem.Authorization
					prepared.PlanDigest, prepared.PlanExpiresAt = grantPlan.Digest, grantPlan.ExpiresAt
					item.Command.Authorization = &prepared
					item.Impact = permissionBatchAuthorizationImpact(grantPlan)
				}
			}
		} else {
			var request PermissionRequest
			request, err = permissionRequestFromRow(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_identity_permission_request WHERE id=?`), commandItem.Decision.RequestID))
			if err == nil {
				item.SubjectID = request.SubjectID
				if !command.Scope.Contains(request.Scope) {
					err = ErrPermissionDenied
				} else {
					var decisionPlan PermissionRequestDecisionPlan
					decisionPlan, err = s.planPermissionRequestDecision(ctx, tx, actor, *commandItem.Decision, deadline)
					if err == nil && decisionPlan.Authorization != nil {
						target, targetErr := loadPermissionSnapshot(ctx, tx, PrincipalUser, request.SubjectID)
						if targetErr != nil {
							err = targetErr
						} else if !permissionBatchPlanWithinScope(*decisionPlan.Authorization, target, command.Scope) {
							err = ErrPermissionDenied
						}
					}
					if err == nil {
						prepared := *commandItem.Decision
						prepared.PlanDigest, prepared.PlanExpiresAt = decisionPlan.Digest, decisionPlan.ExpiresAt
						item.Command.Decision = &prepared
						item.Impact = &PermissionBatchItemImpact{}
						if decisionPlan.Authorization != nil {
							item.Impact = permissionBatchAuthorizationImpact(*decisionPlan.Authorization)
						}
						for _, requested := range decisionPlan.Items {
							if requested.Outcome == "approved" {
								item.Impact.ApprovedItems++
							} else if requested.Outcome == "rejected" {
								item.Impact.RejectedItems++
							}
						}
					}
				}
			}
		}
		if err != nil {
			code := permissionBatchFailureCode(err)
			if code == "" {
				return PermissionBatchPlan{}, err
			}
			item.Status, item.FailureCode = "blocked", code
		}
		plan.Items = append(plan.Items, item)
	}
	ownerDigest, err := EffectivePermissionSnapshotDigest(owner, now)
	if err != nil {
		return PermissionBatchPlan{}, err
	}
	raw, err := json.Marshal([]any{"permission-batch-plan/v1", ownerDigest, plan.Change, plan.Items, deadline})
	if err != nil {
		return PermissionBatchPlan{}, err
	}
	plan.Digest = permissionHash(raw)
	plan.Change.PlanDigest, plan.Change.PlanExpiresAt = plan.Digest, deadline
	return plan, nil
}

func (s *SQLStore) PreviewPermissionBatch(ctx context.Context, actor sharedkernel.Scope, command PermissionBatchCommand) (PermissionBatchPlan, error) {
	if s == nil || s.db == nil {
		return PermissionBatchPlan{}, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return PermissionBatchPlan{}, err
	}
	defer tx.Rollback()
	return s.planPermissionBatch(ctx, tx, actor, command, s.clock().UTC().Add(5*time.Minute))
}
