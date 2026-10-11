package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLDepartmentAdministratorMembershipAndAgentBoundary(t *testing.T) {
	f := newAdministratorFixture(t)
	s, actor, company := f.store, f.actors[2], f.actors[0]
	s.SetPermissionResourceResolver(enrollmentFixtureResolver{})
	s.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	department := ManagementScope{Type: "department", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID}
	member := Membership{ID: "department-manager-membership", SubjectID: actor.PrincipalID, Scope: department, Status: "active", Revision: 1}
	raw, _ := json.Marshal(member)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES(?,?,?,?,?,'active',1,?,?)`), member.ID, actor.PrincipalID, actor.TenantID, actor.DepartmentID, "", string(raw), permissionHash([]byte(member.ID))); err != nil {
		t.Fatal(err)
	}
	appointment := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: actor.PrincipalID, ExpectedRevision: 1, IdempotencyKey: "company-appoint-department-manager", Reason: "company assigns department administration", Preset: &PresetSelection{Code: "department_admin", Version: 2, Scope: department}}
	appointmentPlan, err := s.PreviewAuthorizationChange(f.ctx, company, appointment)
	if err != nil {
		t.Fatal("company could not appoint department manager", err)
	}
	appointment.PlanDigest, appointment.PlanExpiresAt = appointmentPlan.Digest, appointmentPlan.ExpiresAt
	if _, err := s.CommitAuthorizationChange(f.ctx, company, appointment); err != nil {
		t.Fatal(err)
	}
	profile, err := s.PermissionSnapshot(f.ctx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	if administrationKind(profile, f.now) != "department" {
		t.Fatal("department manager not recognized")
	}
	appScope := ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	if available, err := managementCapabilityAvailable(profile, PermissionQuery{Action: "authorization.change", Scope: appScope, Now: f.now}); err != nil || available {
		t.Fatal("department role bypassed company delegation", available, err)
	}
	userID := "department-business-user"
	if err := s.CreatePrincipal(f.ctx, Principal{Type: PrincipalUser, ID: userID, TenantID: actor.TenantID, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',?,'v2',1,1)`), userID); err != nil {
		t.Fatal(err)
	}
	candidates, err := s.PageMembershipCandidates(f.ctx, actor, userID, 1, 20)
	if err != nil || len(candidates.Items) != 1 || len(candidates.Items[0].Roles) != 0 {
		t.Fatal("candidate search leaked or rejected minimal company identity", candidates, err)
	}
	change := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: userID, ExpectedRevision: 1, IdempotencyKey: "admit-department-user", Reason: "admit into managed department", Memberships: []MembershipMutation{{ID: "department-user-membership", Scope: department, Status: "active"}}}
	plan, err := s.PreviewAuthorizationChange(f.ctx, actor, change)
	if err != nil {
		t.Fatal("department administrator could not admit a member", err)
	}
	change.PlanDigest, change.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	if _, err := s.CommitAuthorizationChange(f.ctx, actor, change); err != nil {
		t.Fatal(err)
	}
	userProfile, err := s.PermissionSnapshot(f.ctx, PrincipalUser, userID)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := EvaluatePermission(userProfile, PermissionQuery{Action: "run", Scope: appScope, ResourceType: "agent_installation", ResourceID: "fixture-installation", Now: f.now})
	if err != nil || decision.Allowed {
		t.Fatal("joining department conferred Agent use", decision, err)
	}
	delegation := Delegation{ID: "company-agent-ceiling", SubjectID: actor.PrincipalID, Scope: appScope, ManagementActions: []string{"authorization.change", "access_request.decide"}, Roles: []string{"operator"}, Actions: []string{"discover", "run", "cancel", "history.read", "history.continue"}, Resources: []string{"fixture-installation"}, DataScopeTypes: []string{"owner"}, MaxDurationSeconds: 86400, AllowPermanent: true, Status: "active", Revision: 1}
	command := DelegationCommand{SubjectID: actor.PrincipalID, ExpectedRevision: profile.Principal.Revision, IdempotencyKey: "company-department-agent-limit", Reason: "company authorizes one departmental Agent", Delegation: &delegation}
	if _, err := s.PreviewDelegation(f.ctx, company, command); err != nil {
		t.Fatal("company cannot define department Agent ceiling", err)
	}
	raw, _ = json.Marshal(delegation)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_delegation(id,subject_id,tenant_id,department_id,application_id,status,revision,payload) VALUES(?,?,?,?,?,'active',1,?)`), delegation.ID, actor.PrincipalID, actor.TenantID, actor.DepartmentID, actor.ApplicationID, string(raw)); err != nil {
		t.Fatal(err)
	}
	grant := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: userID, ExpectedRevision: userProfile.Principal.Revision, IdempotencyKey: "department-basic-agent", Reason: "assign company-approved Agent", Preset: &PresetSelection{Code: "operator", Version: 1, Scope: appScope, ResourceIDs: []string{"fixture-installation"}}}
	plan, err = s.PreviewAuthorizationChange(f.ctx, actor, grant)
	if err != nil {
		t.Fatal("department administrator cannot grant approved basic Agent use", err)
	}
	grant.PlanDigest, grant.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	if _, err := s.CommitAuthorizationChange(f.ctx, actor, grant); err != nil {
		t.Fatal(err)
	}
	userProfile, err = s.PermissionSnapshot(f.ctx, PrincipalUser, userID)
	if err != nil {
		t.Fatal(err)
	}
	decision, err = EvaluatePermission(userProfile, PermissionQuery{Action: "run", Scope: appScope, ResourceType: "agent_installation", ResourceID: "fixture-installation", Now: f.now})
	if err != nil || !decision.Allowed {
		t.Fatal("assigned Agent is unusable", decision, err)
	}
	for _, tc := range []struct{ name, preset, resource string }{{"outside company Agent list", "operator", "outside-installation"}, {"appoint another manager", "department_admin", ""}, {"grant development", "agent_developer", ""}} {
		next := grant
		next.ExpectedRevision, next.IdempotencyKey = userProfile.Principal.Revision, tc.name
		next.Preset = &PresetSelection{Code: tc.preset, Version: 1, Scope: appScope}
		if tc.resource != "" {
			next.Preset.ResourceIDs = []string{tc.resource}
		}
		if _, err := s.PreviewAuthorizationChange(f.ctx, actor, next); !errors.Is(err, ErrPermissionDenied) && !errors.Is(err, ErrInvalidResource) {
			t.Fatal(tc.name, err)
		}
	}
	other := ManagementScope{Type: "department", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID + "-other"}
	if err := s.CreateDepartmentWithAdministrationContext(f.ctx, Department{ID: other.DepartmentID, TenantID: other.TenantID, Code: "other", Name: "Other department", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	change.ExpectedRevision, change.IdempotencyKey = userProfile.Principal.Revision, "outside-department-membership"
	change.Memberships = []MembershipMutation{{ID: "outside-department-member", Scope: other, Status: "active"}}
	if _, err := s.PreviewAuthorizationChange(f.ctx, actor, change); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("department manager admitted user into another department", err)
	}
	if _, err := s.PageMembershipCandidates(f.ctx, sharedkernel.Scope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, PrincipalType: "user", PrincipalID: userID}, "", 1, 20); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("ordinary user could search departmental invitation candidates", err)
	}
	// A company administrator can configure a department before any application
	// or Agent exists, and assign membership and the administrator role atomically.
	departments, err := s.ListAdministrationDepartments(f.ctx, company.PrincipalID)
	if err != nil || len(departments) != 2 {
		t.Fatal("empty department missing from company administration", departments, err)
	}
	managerProfile, err := s.PermissionSnapshot(f.ctx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	admitManager := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: actor.PrincipalID, ExpectedRevision: managerProfile.Principal.Revision, IdempotencyKey: "empty-department-administrator", Reason: "admit and appoint in an empty department", Memberships: []MembershipMutation{{ID: "empty-department-manager-membership", Scope: other, Status: "active"}}, Preset: &PresetSelection{Code: "department_admin", Version: 2, Scope: other}}
	emptyPlan, err := s.PreviewAuthorizationChange(f.ctx, company, admitManager)
	if err != nil || len(emptyPlan.ExpandedBindings) != 1 {
		t.Fatal("cannot preview empty department admission and appointment", err)
	}
	admitManager.PlanDigest, admitManager.PlanExpiresAt = emptyPlan.Digest, emptyPlan.ExpiresAt
	if _, err := s.CommitAuthorizationChange(f.ctx, company, admitManager); err != nil {
		t.Fatal(err)
	}
	departments, err = s.ListAdministrationDepartments(f.ctx, actor.PrincipalID)
	if err != nil || len(departments) != 2 {
		t.Fatal("appointed department administrator cannot manage the empty department", departments, err)
	}
	contexts, err := s.ListAdministrationWorkspaces(f.ctx, actor.PrincipalID)
	if err != nil || len(contexts) != 2 {
		t.Fatal("new department lacks an actionable management context", contexts, err)
	}
	var emptyContext ApplicationWorkspace
	for _, item := range contexts {
		if item.DepartmentID == other.DepartmentID {
			emptyContext = item
		}
	}
	if emptyContext.ApplicationID == "" {
		t.Fatal("department management context missing")
	}
	if err := validateWorkspaceSelection(f.ctx, f.db, actor.PrincipalID, EnrollmentScope{TenantID: other.TenantID, DepartmentID: other.DepartmentID, ApplicationID: emptyContext.ApplicationID}, f.now); err != nil {
		t.Fatal("new department administrator cannot select the department", err)
	}
	ordinary := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: userID, ExpectedRevision: userProfile.Principal.Revision, IdempotencyKey: "empty-department-ordinary-member", Reason: "join without administrator authority", Memberships: []MembershipMutation{{ID: "empty-department-user-membership", Scope: other, Status: "active"}}}
	emptyPlan, err = s.PreviewAuthorizationChange(f.ctx, company, ordinary)
	if err != nil {
		t.Fatal(err)
	}
	ordinary.PlanDigest, ordinary.PlanExpiresAt = emptyPlan.Digest, emptyPlan.ExpiresAt
	if _, err := s.CommitAuthorizationChange(f.ctx, company, ordinary); err != nil {
		t.Fatal(err)
	}
	userProfile, err = s.PermissionSnapshot(f.ctx, PrincipalUser, userID)
	if err != nil {
		t.Fatal(err)
	}
	if allowed, err := managementCapabilityAvailable(userProfile, PermissionQuery{Action: "membership.manage", Scope: other, Now: f.now}); err != nil || allowed {
		t.Fatal("ordinary department member acquired administrator authority", allowed, err)
	}
	promote := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: userID, ExpectedRevision: userProfile.Principal.Revision, IdempotencyKey: "empty-department-peer-administrator", Reason: "company explicitly changes departmental role", Preset: &PresetSelection{Code: "department_admin", Version: 2, Scope: other}}
	promotePlan, err := s.PreviewAuthorizationChange(f.ctx, company, promote)
	if err != nil {
		t.Fatal(err)
	}
	promote.PlanDigest, promote.PlanExpiresAt = promotePlan.Digest, promotePlan.ExpiresAt
	if _, err := s.CommitAuthorizationChange(f.ctx, company, promote); err != nil {
		t.Fatal(err)
	}
	userProfile, err = s.PermissionSnapshot(f.ctx, PrincipalUser, userID)
	if err != nil {
		t.Fatal(err)
	}
	peerRemoval := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: userID, ExpectedRevision: userProfile.Principal.Revision, IdempotencyKey: "peer-manager-removal", Reason: "cannot remove an equal administrator", Memberships: []MembershipMutation{{ID: "empty-department-user-membership", Scope: other, Status: "revoked", ExpectedRevision: 1}}}
	if _, err := s.PreviewAuthorizationChange(f.ctx, actor, peerRemoval); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("department administrator removed a peer administrator", err)
	}
	demote := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: userID, ExpectedRevision: userProfile.Principal.Revision, IdempotencyKey: "company-department-demotion", Reason: "company returns administrator to ordinary member", RevokeBindingIDs: []string{promotePlan.ExpandedBindings[0].ID}}
	demotePlan, err := s.PreviewAuthorizationChange(f.ctx, company, demote)
	if err != nil {
		t.Fatal(err)
	}
	demote.PlanDigest, demote.PlanExpiresAt = demotePlan.Digest, demotePlan.ExpiresAt
	if _, err := s.CommitAuthorizationChange(f.ctx, company, demote); err != nil {
		t.Fatal(err)
	}
	userProfile, err = s.PermissionSnapshot(f.ctx, PrincipalUser, userID)
	if err != nil {
		t.Fatal(err)
	}
	if allowed, err := managementCapabilityAvailable(userProfile, PermissionQuery{Action: "membership.manage", Scope: other, Now: f.now}); err != nil || allowed {
		t.Fatal("demoted department user retained administrator authority", allowed, err)
	}
	broken := Department{ID: actor.DepartmentID + "-rollback", TenantID: actor.TenantID, Code: "rollback", Name: "Rollback fixture", Status: "active", Revision: 1}
	collision := Application{ID: "department-home-" + permissionHash([]byte(broken.ID)), TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, Code: "collision", Name: "Existing context", Status: "active", Revision: 1}
	if err := s.CreateApplication(f.ctx, collision); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateDepartmentWithAdministrationContext(f.ctx, broken); err == nil {
		t.Fatal("duplicate administration context did not roll back department creation")
	}
	remaining, err := s.ListDepartments(f.ctx, broken.TenantID, broken.ID, "")
	if err != nil || len(remaining) != 0 {
		t.Fatal("failed administration context left a partially created department", remaining, err)
	}
}
