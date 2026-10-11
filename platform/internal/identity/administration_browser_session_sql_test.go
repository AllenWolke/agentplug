package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLManagementWorkspaceBrowserSessionWithoutBusinessMembership(t *testing.T) {
	for _, kind := range []string{"platform", "company"} {
		t.Run(kind, func(t *testing.T) {
			f := newAdministratorFixture(t)
			s := f.store
			actor, bindingID := f.actors[0], f.bindings[0]
			if kind == "company" {
				actor = f.actors[1]
				command := f.command(1, "browser-company-appointment")
				command.RoleCode, command.RoleVersion = "tenant_admin", 2
				command.Scope = ManagementScope{Type: "tenant", TenantID: actor.TenantID}
				command.RevokeBindingIDs = []string{f.bindings[1]}
				receipt, err := s.AppointAdministrator(f.ctx, f.actors[0], f.authenticate(t, 0, command))
				if err != nil {
					t.Fatal(err)
				}
				bindingID = receipt.Binding.ID
			}
			// A management role does not enroll the administrator as a business member.
			if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`DELETE FROM platform_identity_membership WHERE subject_id=?`), actor.PrincipalID); err != nil {
				t.Fatal(err)
			}
			s.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, RefreshSessionEvent) error { return nil })
			home := EnrollmentScope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
			family, err := s.CreateRefreshSession(f.ctx, actor.PrincipalID, home, 1)
			if err != nil {
				t.Fatal(err)
			}
			target := home
			target.ApplicationID += "-management-only"
			if err := s.CreateApplication(f.ctx, Application{ID: target.ApplicationID, TenantID: target.TenantID, DepartmentID: target.DepartmentID, Code: "management-only", Name: "Management only", Status: "active", Revision: 1}); err != nil {
				t.Fatal(err)
			}
			next, err := s.SwitchRefreshWorkspace(f.ctx, family.RefreshToken, actor.PrincipalID, 1, target)
			if err != nil {
				t.Fatal("valid management switch failed", err)
			}
			switched := actor
			switched.ApplicationID = target.ApplicationID
			if err := s.ValidateBrowserSession(f.ctx, switched, next.SessionID, 1); err != nil {
				t.Fatal("management selection invalidated the browser session", err)
			}
			if err := s.ValidateBrowserSession(f.ctx, actor, next.SessionID, 1); !errors.Is(err, ErrRefreshSessionRejected) {
				t.Fatal("old workspace assertion remained valid", err)
			}
			business, err := s.ResolvePermission(f.ctx, PrincipalUser, actor.PrincipalID, PermissionQuery{Action: "run", Scope: ManagementScope{Type: "application", TenantID: target.TenantID, DepartmentID: target.DepartmentID, ApplicationID: target.ApplicationID}, ResourceType: "agent_installation", ResourceID: "fixture-agent", Now: f.now})
			if err != nil || business.Allowed {
				t.Fatal("management context conferred business execution", err)
			}
			var encoded string
			if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT payload FROM platform_identity_role_binding WHERE id=?`), bindingID).Scan(&encoded); err != nil {
				t.Fatal(err)
			}
			var binding RoleBinding
			if err := json.Unmarshal([]byte(encoded), &binding); err != nil {
				t.Fatal(err)
			}
			binding.Status = "revoked"
			raw, err := json.Marshal(binding)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_role_binding SET status='revoked',payload=? WHERE id=?`), string(raw), bindingID); err != nil {
				t.Fatal(err)
			}
			if err := s.ValidateBrowserSession(f.ctx, switched, next.SessionID, 1); !errors.Is(err, ErrRefreshSessionRejected) {
				t.Fatal("revoked management authority survived in the browser", err)
			}
		})
	}
}

func TestSQLDelegatedManagementWorkspaceWithNoDepartmentBusinessMembership(t *testing.T) {
	f := newDepartmentAgentFixture(t)
	s := f.store
	departmentAgentFixtureCommit(t, f, departmentAgentFixtureCommand(f, 0, "delegated-workspace-ceiling"))
	actor := f.actors[2]
	command := f.command(2, "delegated-workspace-appointment")
	command.Scope = ManagementScope{Type: "tenant", TenantID: actor.TenantID}
	target := EnrollmentScope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID + "-delegated"}
	if err := s.CreateApplication(f.ctx, Application{ID: target.ApplicationID, TenantID: target.TenantID, DepartmentID: target.DepartmentID, Code: "delegated", Name: "Delegated management", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`DELETE FROM platform_identity_membership WHERE subject_id=?`), actor.PrincipalID); err != nil {
		t.Fatal(err)
	}
	member := Membership{ID: "delegated-company-member", SubjectID: actor.PrincipalID, Scope: command.Scope, Status: "active", Revision: 1}
	raw, _ := json.Marshal(member)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES(?,?,?,'','','active',1,?,?)`), member.ID, actor.PrincipalID, actor.TenantID, string(raw), permissionHash([]byte(member.ID))); err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.PermissionSnapshot(f.ctx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	command.ExpectedRevision = snapshot.Principal.Revision
	if _, err := s.AppointAdministrator(f.ctx, f.actors[0], f.authenticate(t, 0, command)); err != nil {
		t.Fatal(err)
	}
	expires := f.now.Add(time.Minute)
	delegation := Delegation{ID: "delegated-management-entry", SubjectID: actor.PrincipalID, Scope: ManagementScope{Type: "application", TenantID: target.TenantID, DepartmentID: target.DepartmentID, ApplicationID: target.ApplicationID}, ManagementActions: []string{"authorization.change", "access_request.decide"}, Roles: []string{"operator"}, DataScopeTypes: []string{"owner"}, MaxDurationSeconds: 3600, Validity: Validity{ExpiresAt: &expires}, Status: "active", Revision: 1}
	raw, _ = json.Marshal(delegation)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_delegation(id,subject_id,tenant_id,department_id,application_id,status,revision,starts_at,expires_at,payload) VALUES(?,?,?,?,?,'active',1,NULL,?,?)`), delegation.ID, actor.PrincipalID, target.TenantID, target.DepartmentID, target.ApplicationID, expires, string(raw)); err != nil {
		t.Fatal(err)
	}
	spaces, err := s.ListAdministrationWorkspaces(f.ctx, actor.PrincipalID)
	if err != nil || len(spaces) != 1 || spaces[0].ApplicationID != target.ApplicationID {
		t.Fatal("delegated context missing or unbounded", spaces, err)
	}
	s.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, RefreshSessionEvent) error { return nil })
	home := EnrollmentScope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	family, err := s.CreateRefreshSession(f.ctx, actor.PrincipalID, home, 1)
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.SwitchRefreshWorkspace(f.ctx, family.RefreshToken, actor.PrincipalID, 1, target)
	if err != nil {
		t.Fatal("delegated management was confused with business membership", err)
	}
	switched := actor
	switched.ApplicationID = target.ApplicationID
	if err := s.ValidateBrowserSession(f.ctx, switched, next.SessionID, 1); err != nil {
		t.Fatal("valid delegated management browser session rejected", err)
	}
	business, err := s.ResolvePermission(f.ctx, PrincipalUser, actor.PrincipalID, PermissionQuery{Action: "run", Scope: delegation.Scope, ResourceType: "agent_installation", ResourceID: "fixture-installation", Now: f.now})
	if err != nil || business.Allowed {
		t.Fatal("delegated management granted business execution", err)
	}
	s.clock = func() time.Time { return expires.Add(time.Second) }
	if err := s.ValidateBrowserSession(f.ctx, switched, next.SessionID, 1); !errors.Is(err, ErrRefreshSessionRejected) {
		t.Fatal("expired delegation remained a valid browser context", err)
	}
}
