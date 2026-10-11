package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLAdministratorWorkspacesFollowLiveAuthority(t *testing.T) {
	f := newAdministratorFixture(t)
	s := f.store
	a := f.actors[0]
	second := EnrollmentScope{TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID + "-managed"}
	if err := s.CreateApplication(f.ctx, Application{ID: second.ApplicationID, TenantID: second.TenantID, DepartmentID: second.DepartmentID, Code: "managed", Name: "Managed application", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	spaces, err := s.ListAdministrationWorkspaces(f.ctx, a.PrincipalID)
	if err != nil || len(spaces) != 2 {
		t.Fatal("global management scopes were confused with memberships", spaces, err)
	}
	joined, err := s.ListApplicationWorkspaces(f.ctx, a.PrincipalID)
	if err != nil || len(joined) != 1 {
		t.Fatal("management entry created a business membership", joined, err)
	}
	if _, err := s.ValidateEnrollmentSession(f.ctx, a.PrincipalID, second, 1); err != nil {
		t.Fatal("authorized management context rejected", err)
	}
	decision, err := s.ResolvePermission(f.ctx, PrincipalUser, a.PrincipalID, PermissionQuery{Action: "run", Scope: ManagementScope{Type: "application", TenantID: second.TenantID, DepartmentID: second.DepartmentID, ApplicationID: second.ApplicationID}, ResourceType: "agent_installation", ResourceID: "fixture-installation", Now: f.now})
	if err != nil || decision.Allowed {
		t.Fatal("management workspace granted business execution", decision, err)
	}
	user := f.actors[2]
	if _, err := s.ValidateEnrollmentSession(f.ctx, user.PrincipalID, second, 1); err == nil {
		t.Fatal("ordinary user entered an unjoined application")
	}
	spaces, err = s.ListAdministrationWorkspaces(f.ctx, user.PrincipalID)
	if err != nil || len(spaces) != 0 {
		t.Fatal("business user received administration workspaces", spaces, err)
	}
	// Broader membership and administrator qualification still confer no delegation.
	member := Membership{ID: "scope-review-tenant", SubjectID: user.PrincipalID, Scope: ManagementScope{Type: "tenant", TenantID: user.TenantID}, Status: "active", Revision: 1}
	raw, _ := json.Marshal(member)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES(?,?,?,?,?,'active',1,?,?)`), member.ID, user.PrincipalID, user.TenantID, "", "", string(raw), permissionHash([]byte(member.ID))); err != nil {
		t.Fatal(err)
	}
	command := f.command(2, "scope-review-appointment")
	command.Scope = member.Scope
	if _, err := s.AppointAdministrator(f.ctx, a, f.authenticate(t, 0, command)); err != nil {
		t.Fatal(err)
	}
	spaces, err = s.ListAdministrationWorkspaces(f.ctx, user.PrincipalID)
	if err != nil || len(spaces) != 0 {
		t.Fatal("qualification without delegation enabled management", spaces, err)
	}
	s.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, RefreshSessionEvent) error { return nil })
	home := EnrollmentScope{TenantID: user.TenantID, DepartmentID: user.DepartmentID, ApplicationID: user.ApplicationID}
	family, err := s.CreateRefreshSession(f.ctx, user.PrincipalID, home, 1)
	if err != nil {
		t.Fatal("read-only authentication origin was lost", err)
	}
	if _, err := s.SwitchRefreshWorkspace(f.ctx, family.RefreshToken, user.PrincipalID, 1, second); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("broad membership bypassed an undelegated management selection", err)
	}
	expires := f.now.Add(time.Minute)
	delegation := Delegation{ID: "scope-review-delegation", SubjectID: user.PrincipalID, Scope: ManagementScope{Type: "application", TenantID: user.TenantID, DepartmentID: user.DepartmentID, ApplicationID: user.ApplicationID}, ManagementActions: []string{"authorization.change", "access_request.decide"}, Roles: []string{"operator"}, DataScopeTypes: []string{"owner"}, MaxDurationSeconds: 3600, Validity: Validity{ExpiresAt: &expires}, Status: "active", Revision: 1}
	raw, _ = json.Marshal(delegation)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_delegation(id,subject_id,tenant_id,department_id,application_id,status,revision,starts_at,expires_at,payload) VALUES(?,?,?,?,?,'active',1,NULL,?,?)`), delegation.ID, user.PrincipalID, user.TenantID, user.DepartmentID, user.ApplicationID, expires, string(raw)); err != nil {
		t.Fatal(err)
	}
	spaces, err = s.ListAdministrationWorkspaces(f.ctx, user.PrincipalID)
	if err != nil || len(spaces) != 1 || spaces[0].ApplicationID != user.ApplicationID || len(spaces[0].ManagementActions) != 2 {
		t.Fatal("delegation leaked into an unrelated application", spaces, err)
	}
	selected, err := s.SwitchRefreshWorkspace(f.ctx, family.RefreshToken, user.PrincipalID, 1, home)
	if err != nil {
		t.Fatal("valid delegated management selection rejected", err)
	}
	if _, err := s.SwitchRefreshWorkspace(f.ctx, selected.RefreshToken, user.PrincipalID, 1, second); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("limited delegation admitted an unrelated management selection", err)
	}
	s.clock = func() time.Time { return expires.Add(time.Second) }
	spaces, err = s.ListAdministrationWorkspaces(f.ctx, user.PrincipalID)
	if err != nil || len(spaces) != 0 {
		t.Fatal("expired delegation remained selectable", spaces, err)
	}
	if _, err := s.SwitchRefreshWorkspace(f.ctx, selected.RefreshToken, user.PrincipalID, 1, home); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("expired delegation remained selectable through the backend", err)
	}
}

func TestSQLAdministratorsCannotAddOwnBusinessAuthority(t *testing.T) {
	f := newAdministratorFixture(t)
	s := f.store
	s.SetPermissionResourceResolver(enrollmentFixtureResolver{})
	s.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	request, err := s.CreatePermissionRequest(f.ctx, f.actors[2], permissionApplicationCommand(f, "before-appointment"))
	if err != nil {
		t.Fatal("ordinary user could not request access", err)
	}
	if _, err := s.AppointAdministrator(f.ctx, f.actors[0], f.authenticate(t, 0, f.command(2, "scope-self-appointment"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PreviewPermissionRequestDecision(f.ctx, f.actors[2], applicationDecision(f, request, "self-review")); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("administrator could approve their pre-appointment request", err)
	}
	for _, index := range []int{0, 2} {
		actor := f.actors[index]
		command := permissionApplicationCommand(f, "admin-self-request-"+actor.PrincipalID)
		if _, err := s.CreatePermissionRequest(f.ctx, actor, command); !errors.Is(err, ErrPermissionDenied) {
			t.Fatal("administrative account could create a personal permission request", index, err)
		}
		profile, err := s.PermissionSnapshot(f.ctx, PrincipalUser, actor.PrincipalID)
		if err != nil {
			t.Fatal(err)
		}
		scope := ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
		change := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: actor.PrincipalID, ExpectedRevision: profile.Principal.Revision, IdempotencyKey: "self-direct-" + actor.PrincipalID, Reason: "must not add own business authority", Bindings: []RoleBinding{{ID: "self-business-role", SubjectID: actor.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: scope, Status: "active", Revision: 1}}}
		if _, err := s.PreviewAuthorizationChange(f.ctx, actor, change); !errors.Is(err, ErrPermissionDenied) {
			t.Fatal("direct self-grant bypassed administrative account separation", index, err)
		}
		if _, err := s.CommitAuthorizationChange(f.ctx, actor, change); !errors.Is(err, ErrPermissionDenied) {
			t.Fatal("direct commit bypassed self-grant denial", index, err)
		}
		after, err := s.PermissionSnapshot(f.ctx, PrincipalUser, actor.PrincipalID)
		if err != nil || after.Principal.Revision != profile.Principal.Revision || len(after.Bindings) != len(profile.Bindings) || len(after.Grants) != len(profile.Grants) {
			t.Fatal("rejected self-grant mutated authority", index, err)
		}
	}
}
