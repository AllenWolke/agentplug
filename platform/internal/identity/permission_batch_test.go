package identity

import (
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestPermissionBatchNormalizationOwnsCommandsAndPinsOriginalItems(t *testing.T) {
	actor := sharedkernel.Scope{TenantID: "company", DepartmentID: "department", ApplicationID: "application", PrincipalID: "administrator", PrincipalType: "user"}
	deadline := time.Now().UTC().Add(time.Minute)
	input := PermissionBatchCommand{Scope: ManagementScope{Type: "department", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID}, Kind: "authorization", IdempotencyKey: "original-batch", Reason: "common reason", Items: []PermissionBatchItemCommand{{Authorization: &AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: "member-a", ExpectedRevision: 1, IdempotencyKey: "untrusted-key", Reason: "untrusted reason", PlanDigest: "untrusted-plan", PlanExpiresAt: deadline, Memberships: []MembershipMutation{{ID: "membership", Scope: ManagementScope{Type: "department", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID}, Status: "active"}}}}}}
	normalized, digest, err := normalizedPermissionBatchCommand(actor, input)
	if err != nil || digest == "" || normalized.Items[0].Authorization.IdempotencyKey == "untrusted-key" || normalized.Items[0].Authorization.Reason != input.Reason || normalized.Items[0].Authorization.PlanDigest != "" || !normalized.Items[0].Authorization.PlanExpiresAt.IsZero() {
		t.Fatal("caller could select an unrelated per-item identity or preview", err)
	}
	normalized.Items[0].Authorization.Memberships[0].Status = "revoked"
	if input.Items[0].Authorization.Memberships[0].Status != "active" {
		t.Fatal("normalization mutated the caller's shared command")
	}
	retry := input
	retry.PlanDigest, retry.PlanExpiresAt = "another-preview", deadline
	retry.Items = []PermissionBatchItemCommand{{Authorization: &AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: "member-a", ExpectedRevision: 1, Memberships: input.Items[0].Authorization.Memberships}}}
	_, retriedDigest, err := normalizedPermissionBatchCommand(actor, retry)
	if err != nil || retriedDigest != digest {
		t.Fatal("new preview metadata changed original command identity", err)
	}
	retry.Items[0].Authorization.SubjectID = "member-b"
	_, changedDigest, err := normalizedPermissionBatchCommand(actor, retry)
	if err != nil || changedDigest == digest {
		t.Fatal("changing the selected user did not change the semantic digest", err)
	}
	input.Items = append(input.Items, input.Items[0])
	if _, _, err := normalizedPermissionBatchCommand(actor, input); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("duplicated recipient would receive two conflicting operations", err)
	}
	if validPermissionBatchKey("original-batch:continue") || validPermissionBatchKey("../other") {
		t.Fatal("batch key could masquerade as a recovery route")
	}
}

func TestPermissionBatchScopeIncludesAutomaticRevocations(t *testing.T) {
	scope := ManagementScope{Type: "application", TenantID: "company", DepartmentID: "department", ApplicationID: "selected-application"}
	other := ManagementScope{Type: "application", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: "other-application"}
	target := PermissionSnapshot{Principal: Principal{TenantID: scope.TenantID}, Bindings: []RoleBinding{{ID: "other-role", Scope: other}}, Grants: []Grant{{ID: "other-grant", TenantID: other.TenantID, DepartmentID: other.DepartmentID, ApplicationID: other.ApplicationID, ResourceType: "agent_installation", ResourceID: "other-agent", AgentInstanceID: "other-agent"}}, Assignments: []TaskAssignment{{ID: "other-assignment", Scope: other}}}
	if !permissionBatchPlanWithinScope(AuthorizationChangePlan{}, target, scope) {
		t.Fatal("unchanged unrelated coverage was treated as a mutation")
	}
	for _, plan := range []AuthorizationChangePlan{{AutomaticRevokeBindingIDs: []string{"other-role"}}, {AutomaticRevokeGrantIDs: []string{"other-grant"}}, {AutomaticRevokeAssignmentIDs: []string{"other-assignment"}}} {
		if permissionBatchPlanWithinScope(plan, target, scope) {
			t.Fatal("automatic cleanup exceeded the batch's reviewed application")
		}
		if !permissionBatchPlanWithinScope(plan, target, ManagementScope{Type: "department", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID}) {
			t.Fatal("authorized department-wide scope lost its own application coverage")
		}
	}
	if permissionBatchFailureCode(errors.New("audit or database failure")) != "" {
		t.Fatal("infrastructure outage became a confirmed per-user refusal")
	}
}
