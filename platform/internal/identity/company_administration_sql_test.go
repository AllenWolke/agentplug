package identity

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLCompanyAdministratorAppointmentAndBoundaries(t *testing.T) {
	f := newAdministratorFixture(t)
	// An explicit appointment replaces one former global administrator. The
	// independent permanent global administrator remains for recovery.
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`DELETE FROM platform_identity_membership WHERE subject_id=?`), f.actors[1].PrincipalID); err != nil {
		t.Fatal(err)
	}
	command := f.command(1, "company-explicit-appointment")
	command.RoleCode, command.RoleVersion = "tenant_admin", 2
	command.Scope = ManagementScope{Type: "tenant", TenantID: f.actors[1].TenantID}
	command.RevokeBindingIDs = []string{f.bindings[1]}
	receipt, err := f.store.AppointAdministrator(f.ctx, f.actors[0], f.authenticate(t, 0, command))
	if err != nil || receipt.Binding == nil || receipt.Binding.RoleVersion != 2 || receipt.Binding.Scope != command.Scope {
		t.Fatalf("explicit company appointment failed: %v", err)
	}
	company := f.actors[1]
	scope := ManagementScope{Type: "application", TenantID: company.TenantID, DepartmentID: company.DepartmentID, ApplicationID: company.ApplicationID}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, company.PrincipalID)
	if err != nil || len(snapshot.Memberships) != 0 || administrationKind(snapshot, f.now) != "company" {
		t.Fatal("appointment invented business membership or lost company purpose")
	}
	for _, action := range []string{"organization.manage", "membership.manage", "principal.read", "authorization.change", "access_request.decide", "delegation.manage", "catalog.manage", "machine.manage"} {
		d, err := f.store.ResolvePermission(f.ctx, PrincipalUser, company.PrincipalID, PermissionQuery{Action: action, Scope: scope, Now: f.now})
		if err != nil || !d.Allowed {
			t.Fatalf("company management %s unavailable without business membership: %v", action, err)
		}
	}
	for _, target := range []ManagementScope{{Type: "global"}, {Type: "tenant", TenantID: "another-company"}} {
		for _, action := range []string{"organization.manage", "authorization.change", "administrator.appoint", "delegation.manage"} {
			d, err := EvaluatePermission(snapshot, PermissionQuery{Action: action, Scope: target, Now: f.now})
			if err != nil || d.Allowed {
				t.Fatalf("company role escaped company for %s: %v", action, err)
			}
		}
	}
	for _, action := range []string{"run", "knowledge.search", "model.generate"} {
		d, err := EvaluatePermission(snapshot, PermissionQuery{Action: action, Scope: scope, ResourceID: "not-authorized", Now: f.now})
		if err != nil || d.Allowed {
			t.Fatal("company administration inherited business access")
		}
	}
	workspaces, err := f.store.ListAdministrationWorkspaces(f.ctx, company.PrincipalID)
	if err != nil || len(workspaces) != 1 || workspaces[0].TenantID != company.TenantID {
		t.Fatal("company management workspace missing or outside company", err)
	}
	business, err := f.store.ListApplicationWorkspaces(f.ctx, company.PrincipalID)
	if err != nil || len(business) != 0 {
		t.Fatal("management workspace invented business membership", err)
	}
	if err := validateWorkspaceSelection(f.ctx, f.db, company.PrincipalID, EnrollmentScope{TenantID: company.TenantID, DepartmentID: company.DepartmentID, ApplicationID: company.ApplicationID}, f.now); err != nil {
		t.Fatal("company cannot enter its management workspace", err)
	}
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	change := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: f.actors[2].PrincipalID, ExpectedRevision: 1, IdempotencyKey: "company-department-admin", Reason: "company appoints department administrator", Bindings: []RoleBinding{{ID: "company-department-binding", SubjectID: f.actors[2].PrincipalID, RoleCode: "department_admin", RoleVersion: 2, Scope: ManagementScope{Type: "department", TenantID: company.TenantID, DepartmentID: company.DepartmentID}, Status: "active", Revision: 1, SourceID: "company-department-source"}}}
	change.Memberships = []MembershipMutation{{ID: "company-department-member", Scope: change.Bindings[0].Scope, Status: "active"}}
	plan, err := f.store.PreviewAuthorizationChange(f.ctx, company, change)
	if err != nil {
		t.Fatal("company cannot preview department identity", err)
	}
	change.PlanDigest, change.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	changed, err := f.store.CommitAuthorizationChange(f.ctx, company, change)
	if err != nil {
		t.Fatal("company cannot atomically admit department administrator", err)
	}
	delegation := DelegationCommand{SubjectID: f.actors[2].PrincipalID, ExpectedRevision: changed.Revision, IdempotencyKey: "company-department-delegation", Reason: "company delegates department admission", Delegation: &Delegation{ID: "company-department-delegation", SubjectID: f.actors[2].PrincipalID, Scope: change.Bindings[0].Scope, Status: "active", Revision: 1, Roles: []string{"operator"}, ManagementActions: []string{"membership.manage", "authorization.change"}, AllowPermanent: true}}
	if _, err := f.store.PreviewDelegation(f.ctx, company, delegation); err != nil {
		t.Fatal("company cannot preview department delegation", err)
	}
	digest, err := DelegationCommandDigest(delegation)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.store.CreateLocalStepUp(f.ctx, company, StepUpRequest{CurrentPassword: "fixture-administrator-password", Action: "delegation.manage", RequestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	delegation.StepUpToken = proof.Token
	if _, err := f.store.ChangeDelegation(f.ctx, company, delegation); err != nil {
		t.Fatal("fresh company delegation failed", err)
	}
	// Sensitive company identity cannot be issued through ordinary grants or
	// delegation. Its only path is the authenticated global appointment above.
	change.Bindings[0].RoleCode, change.Bindings[0].RoleVersion, change.Bindings[0].Scope = "tenant_admin", 2, command.Scope
	target, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, change.SubjectID)
	if err != nil {
		t.Fatal(err)
	}
	change.ExpectedRevision = target.Principal.Revision
	change.Memberships = nil
	change.Bindings[0].ID = "forbidden-company-peer"
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, company, change); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("ordinary authorization did not reject a protected company role", err)
	}
	if _, err := f.store.CreateLocalStepUp(f.ctx, company, StepUpRequest{CurrentPassword: "fixture-administrator-password", Action: "administrator.appoint", RequestDigest: permissionHash([]byte("forbidden-global-action"))}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("company minted global administrator appointment proof", err)
	}
	if _, err := f.store.CreateLocalStepUp(f.ctx, company, StepUpRequest{CurrentPassword: "fixture-administrator-password", Action: "delegation.manage", RequestDigest: permissionHash([]byte("company-delegation-action"))}); err != nil {
		t.Fatal("company cannot freshly authenticate delegated management", err)
	}
}

func TestCompanyAdministratorScopeAndDelegationQualification(t *testing.T) {
	now := time.Now().UTC()
	owner := PermissionSnapshot{Principal: Principal{Type: PrincipalUser, ID: "company-admin", TenantID: "company", IsActive: true}, Mode: "v2", Roles: BuiltinRoleDefinitions(), Bindings: []RoleBinding{{ID: "company-role", SubjectID: "company-admin", RoleCode: "tenant_admin", RoleVersion: 2, Scope: ManagementScope{Type: "tenant", TenantID: "company"}, Status: "active", Revision: 1}}}
	other := PermissionSnapshot{Principal: Principal{Type: PrincipalUser, ID: "department-admin", TenantID: "company", IsActive: true}}
	d := Delegation{Scope: ManagementScope{Type: "department", TenantID: "company", DepartmentID: "department"}, AllowPermanent: true}
	if err := authorizeCompanyDelegation(owner, other, d, true, now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*PermissionSnapshot, *PermissionSnapshot, *Delegation){
		func(o, _ *PermissionSnapshot, _ *Delegation) { o.Bindings[0].Scope.TenantID = "another-company" },
		func(_, target *PermissionSnapshot, _ *Delegation) { target.Principal.TenantID = "another-company" },
		func(_, target *PermissionSnapshot, _ *Delegation) { target.Principal.ID = "company-admin" },
		func(_, target *PermissionSnapshot, _ *Delegation) {
			target.Bindings = []RoleBinding{{RoleCode: "super_admin", Status: "active"}}
		},
		func(_, target *PermissionSnapshot, _ *Delegation) {
			target.Bindings = []RoleBinding{{RoleCode: "tenant_admin", RoleVersion: 2, Scope: ManagementScope{Type: "tenant", TenantID: "company"}, Status: "active"}}
		},
		func(o, _ *PermissionSnapshot, _ *Delegation) {
			expiry := now.Add(time.Hour)
			o.Bindings[0].ExpiresAt = &expiry
		},
	} {
		candidate, target, proposed := owner, other, d
		candidate.Bindings = append([]RoleBinding(nil), owner.Bindings...)
		mutate(&candidate, &target, &proposed)
		if err := authorizeCompanyDelegation(candidate, target, proposed, true, now); !errors.Is(err, ErrPermissionDenied) {
			t.Fatal("invalid company/delegation boundary accepted", err)
		}
	}
}

func TestSQLCompanyAdministratorLifecycleAndRevocation(t *testing.T) {
	f := newAdministratorFixture(t)
	command := f.command(2, "company-lifecycle-appointment")
	command.RoleCode, command.RoleVersion = "tenant_admin", 2
	command.Scope = ManagementScope{Type: "tenant", TenantID: f.actors[2].TenantID}
	appointment, err := f.store.AppointAdministrator(f.ctx, f.actors[0], f.authenticate(t, 0, command))
	if err != nil {
		t.Fatal(err)
	}
	company := f.actors[2]
	recorded := 0
	recorder := func(context.Context, *sql.Tx, sharedkernel.Scope, PrincipalLifecycleDecision) error {
		recorded++
		return nil
	}
	f.store.SetPrincipalLifecycleRecorder(recorder)
	// There are two permanent global logins here: rejection must come from the
	// company's target boundary, rather than the last-administrator guard.
	if _, err := f.store.DisablePrincipal(f.ctx, company, f.actors[0].PrincipalID, 1); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("company could disable a recoverable global administrator", err)
	}
	peer := f.command(1, "company-lifecycle-peer")
	peer.RoleCode, peer.RoleVersion, peer.Scope = "tenant_admin", 2, command.Scope
	peer.RevokeBindingIDs = []string{f.bindings[1]}
	if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], f.authenticate(t, 0, peer)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DisablePrincipal(f.ctx, company, f.actors[1].PrincipalID, 2); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("company could disable an appointed company peer", err)
	}
	if _, err := f.store.DisablePrincipal(f.ctx, company, company.PrincipalID, 2); !errors.Is(err, ErrPrincipalLifecycleSelfDisable) {
		t.Fatal("company could disable itself", err)
	}
	member := company.PrincipalID + "-ordinary"
	if err := f.store.CreatePrincipal(f.ctx, Principal{Type: PrincipalUser, ID: member, TenantID: company.TenantID, IsActive: true, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	foreign := company.TenantID + "-foreign"
	if err := f.store.CreateTenant(f.ctx, Tenant{ID: foreign, Code: foreign, Name: "foreign fixture", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	foreignMember := member + "-foreign"
	if err := f.store.CreatePrincipal(f.ctx, Principal{Type: PrincipalUser, ID: foreignMember, TenantID: foreign, IsActive: true, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	forged := company
	forged.TenantID = foreign
	if _, err := f.store.DisablePrincipal(f.ctx, forged, foreignMember, 1); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("forged company scope disabled a foreign account", err)
	}
	if recorded != 0 {
		t.Fatal("denied lifecycle mutations recorded success")
	}
	f.store.SetPrincipalLifecycleRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, PrincipalLifecycleDecision) error {
		return errors.New("fixture lifecycle audit unavailable")
	})
	if _, err := f.store.DisablePrincipal(f.ctx, company, member, 1); err == nil {
		t.Fatal("company disable committed without audit")
	}
	if value, err := f.store.GetPrincipal(f.ctx, PrincipalUser, member); err != nil || !value.IsActive || value.Revision != 1 {
		t.Fatal("failed company lifecycle did not roll back", err)
	}
	f.store.SetPrincipalLifecycleRecorder(recorder)
	if value, err := f.store.DisablePrincipal(f.ctx, company, member, 1); err != nil || value.IsActive || value.Revision != 2 || recorded != 1 {
		t.Fatal("company could not disable its ordinary member", err)
	}
	// A later transaction must read the revoked role, even if its actor context
	// was created before the revocation.
	revoke := AdministratorCommand{SubjectID: company.PrincipalID, ExpectedRevision: 2, IdempotencyKey: "company-lifecycle-revoke", Reason: "revoke company authority", Scope: ManagementScope{Type: "global"}, RevokeBindingIDs: []string{appointment.Binding.ID}}
	if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], f.authenticate(t, 0, revoke)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DisablePrincipal(f.ctx, company, f.actors[1].PrincipalID, 2); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("revoked company role used stale HTTP authorization", err)
	}
	if recorded != 1 {
		t.Fatal("revoked company authority changed audit count")
	}
}

func TestSQLCompanyAdministratorOIDCDelegationAndRevocation(t *testing.T) {
	f := newOIDCStepUpFixtureForActor(t, 2)
	company := f.actors[2]
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`DELETE FROM platform_identity_membership WHERE subject_id=?`), company.PrincipalID); err != nil {
		t.Fatal(err)
	}
	appointment := f.command(2, "company-oidc-appointment")
	appointment.RoleCode, appointment.RoleVersion = "tenant_admin", 2
	appointment.Scope = ManagementScope{Type: "tenant", TenantID: company.TenantID}
	appointed, err := f.store.AppointAdministrator(f.ctx, f.actors[0], f.authenticate(t, 0, appointment))
	if err != nil {
		t.Fatal(err)
	}
	target := company.PrincipalID + "-department-admin"
	if err := f.store.CreatePrincipal(f.ctx, Principal{Type: PrincipalUser, ID: target, TenantID: company.TenantID, IsActive: true, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',?,'v2',1,1)`), target); err != nil {
		t.Fatal(err)
	}
	scope := ManagementScope{Type: "department", TenantID: company.TenantID, DepartmentID: company.DepartmentID}
	admission := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: target, ExpectedRevision: 1, IdempotencyKey: "company-oidc-admission", Reason: "company admits delegated department administrator", Preset: &PresetSelection{Code: "department_admin", Version: 2, Scope: scope}, Memberships: []MembershipMutation{{ID: "company-oidc-member", Scope: scope, Status: "active"}}}
	plan, err := f.store.PreviewAuthorizationChange(f.ctx, company, admission)
	if err != nil {
		t.Fatal(err)
	}
	admission.PlanDigest, admission.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	admitted, err := f.store.CommitAuthorizationChange(f.ctx, company, admission)
	if err != nil {
		t.Fatal(err)
	}
	delegation := DelegationCommand{SubjectID: target, ExpectedRevision: admitted.Revision, IdempotencyKey: "company-oidc-delegation", Reason: "fresh SSO company delegation", Delegation: &Delegation{ID: "company-oidc-delegation", SubjectID: target, Scope: scope, Status: "active", Revision: 1, Roles: []string{"operator"}, ManagementActions: []string{"membership.manage", "authorization.change"}, AllowPermanent: true}}
	preview, err := f.store.PreviewDelegation(f.ctx, company, delegation)
	if err != nil {
		t.Fatal(err)
	}
	f.session, err = f.store.CreateOIDCRefreshSession(f.ctx, f.binding.Issuer, f.binding.Subject)
	if err != nil {
		t.Fatal("OIDC company without business membership cannot log in", err)
	}
	request := OIDCStepUpRequest{Scope: company, SessionID: f.session.SessionID, AuthRevision: f.session.Identity.AuthRevision, Action: "delegation.manage", RequestDigest: preview.RequestDigest}
	completion := f.completion(t, request)
	proof, err := f.store.CompleteOIDCStepUp(f.ctx, completion)
	if err != nil {
		t.Fatal("OIDC-only company cannot authenticate its exact delegation", err)
	}
	delegation.StepUpToken = proof.Token
	changed, err := f.store.ChangeDelegation(f.ctx, company, delegation)
	if err != nil {
		t.Fatal("OIDC-only company delegation did not commit", err)
	}
	delegation.ExpectedRevision = changed.Revision
	delegation.IdempotencyKey, delegation.Delegation.ID = "company-oidc-second-delegation", "company-oidc-second-delegation"
	if _, err := f.store.ChangeDelegation(f.ctx, company, delegation); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal("company reused OIDC proof for another command", err)
	}
	request.Action = "administrator.appoint"
	if _, err := f.store.CreateOIDCStepUpChallenge(f.ctx, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("company minted a global appointment OIDC proof", err)
	}
	revoke := AdministratorCommand{SubjectID: company.PrincipalID, ExpectedRevision: 2, IdempotencyKey: "company-oidc-revoke", Reason: "revoke company authority", Scope: ManagementScope{Type: "global"}, RevokeBindingIDs: []string{appointed.Binding.ID}}
	if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], f.authenticate(t, 0, revoke)); err != nil {
		t.Fatal(err)
	}
	request.Action = "delegation.manage"
	if _, err := f.store.CreateOIDCStepUpChallenge(f.ctx, request); err == nil {
		t.Fatal("revoked company authenticated a new SSO delegation")
	}
}
