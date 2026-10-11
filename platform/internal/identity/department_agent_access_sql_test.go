package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func newDepartmentAgentFixture(t *testing.T) administratorFixture {
	t.Helper()
	f := newAdministratorFixture(t)
	f.store.SetPermissionResourceResolver(enrollmentFixtureResolver{})
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	appointment := f.command(1, "department-agent-company-appointment")
	appointment.RoleCode, appointment.RoleVersion = "tenant_admin", 2
	appointment.Scope = ManagementScope{Type: "tenant", TenantID: f.actors[1].TenantID}
	appointment.RevokeBindingIDs = []string{f.bindings[1]}
	if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], f.authenticate(t, 0, appointment)); err != nil {
		t.Fatal(err)
	}
	return f
}

func departmentAgentFixtureCommand(f administratorFixture, revision uint64, key string) DepartmentAgentChangeCommand {
	return DepartmentAgentChangeCommand{TenantID: f.actors[1].TenantID, DepartmentID: f.actors[1].DepartmentID, ExpectedRevision: revision, MigrateExisting: revision == 0, IdempotencyKey: key, Reason: "reviewed company department Agent ceiling", Entries: []DepartmentAgentPolicyEntry{{ApplicationID: f.actors[1].ApplicationID, InstallationID: "fixture-installation", Actions: []string{"discover", "run", "cancel", "history.read", "history.continue"}}}}
}

func departmentAgentFixtureProof(t *testing.T, f administratorFixture, actor int, plan DepartmentAgentChangePlan) DepartmentAgentChangeCommand {
	t.Helper()
	proof, err := f.store.CreateLocalStepUp(f.ctx, f.actors[actor], StepUpRequest{CurrentPassword: "fixture-administrator-password", Action: plan.StepUpAction, RequestDigest: plan.Digest})
	if err != nil {
		t.Fatal(err)
	}
	command := plan.Command
	command.StepUpToken = proof.Token
	return command
}

func departmentAgentFixtureCommit(t *testing.T, f administratorFixture, command DepartmentAgentChangeCommand) DepartmentAgentChangeReceipt {
	t.Helper()
	plan, err := f.store.PreviewDepartmentAgentChange(f.ctx, f.actors[1], command)
	if err != nil {
		t.Fatal("preview department Agent ceiling", err)
	}
	receipt, err := f.store.CommitDepartmentAgentChange(f.ctx, f.actors[1], departmentAgentFixtureProof(t, f, 1, plan))
	if err != nil {
		t.Fatal("commit department Agent ceiling", err)
	}
	return receipt
}

func departmentAgentFixtureAuthorize(t *testing.T, f administratorFixture, actor sharedkernel.Scope, command AuthorizationChangeCommand) AuthorizationChangeReceipt {
	t.Helper()
	plan, err := f.store.PreviewAuthorizationChange(f.ctx, actor, command)
	if err != nil {
		t.Fatal("preview personal authorization", err)
	}
	command.PlanDigest, command.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	receipt, err := f.store.CommitAuthorizationChange(f.ctx, actor, command)
	if err != nil {
		t.Fatal("commit personal authorization", err)
	}
	return receipt
}

func departmentAgentFixtureManager(t *testing.T, f administratorFixture) {
	t.Helper()
	actor := f.actors[2]
	department := ManagementScope{Type: "department", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID}
	departmentAgentFixtureAuthorize(t, f, f.actors[1], AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: actor.PrincipalID, ExpectedRevision: 1, IdempotencyKey: "appoint-managed-department-manager", Reason: "company appoints department manager", Memberships: []MembershipMutation{{ID: "managed-department-manager-member", Scope: department, Status: "active"}}, Preset: &PresetSelection{Code: "department_admin", Version: 2, Scope: department}})
}

func departmentAgentFixtureUser(t *testing.T, f administratorFixture, id string) sharedkernel.Scope {
	t.Helper()
	actor := f.actors[1]
	if err := f.store.CreatePrincipal(f.ctx, Principal{Type: PrincipalUser, ID: id, TenantID: actor.TenantID, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',?,'v2',1,1)`), id); err != nil {
		t.Fatal(err)
	}
	actor.PrincipalID = id
	return actor
}

func departmentAgentFixtureDecision(t *testing.T, f administratorFixture, user sharedkernel.Scope, action string, allowed bool) {
	t.Helper()
	d, err := f.store.ResolvePermission(f.ctx, PrincipalUser, user.PrincipalID, PermissionQuery{Action: action, Scope: ManagementScope{Type: "agent_installation", TenantID: user.TenantID, DepartmentID: user.DepartmentID, ApplicationID: user.ApplicationID, ResourceID: "fixture-installation"}, ResourceType: "agent_installation", ResourceID: "fixture-installation", Now: f.now})
	if err != nil || d.Allowed != allowed {
		t.Fatalf("%s allowed=%v expected=%v reason=%s error=%v", action, d.Allowed, allowed, d.Reason, err)
	}
}

func TestSQLDepartmentAgentPolicyFreshProofAtomicRetryAndRevocation(t *testing.T) {
	f := newDepartmentAgentFixture(t)
	command := departmentAgentFixtureCommand(f, 0, "department-agent-migration")
	state, err := f.store.DepartmentAgentPolicy(f.ctx, f.actors[1], command.TenantID, command.DepartmentID)
	if err != nil || state.Managed || !state.CanManage || state.Policy.Revision != 0 {
		t.Fatal("old department was silently migrated", state, err)
	}
	plan, err := f.store.PreviewDepartmentAgentChange(f.ctx, f.actors[1], command)
	if err != nil || plan.After.Revision != 1 || plan.Impact.ActiveAllowRecords != 0 {
		t.Fatal("read-only preview failed", plan, err)
	}
	if _, err := f.store.CommitDepartmentAgentChange(f.ctx, f.actors[1], plan.Command); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal("fresh authentication not required", err)
	}
	command = departmentAgentFixtureProof(t, f, 1, plan)
	fault := errors.New("fixture audit failure")
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return fault })
	if _, err := f.store.CommitDepartmentAgentChange(f.ctx, f.actors[1], command); !errors.Is(err, fault) {
		t.Fatal("atomic audit failure was ignored", err)
	}
	state, err = f.store.DepartmentAgentPolicy(f.ctx, f.actors[1], command.TenantID, command.DepartmentID)
	if err != nil || state.Managed {
		t.Fatal("failed audit retained policy head", err)
	}
	var used bool
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT used FROM platform_identity_step_up WHERE token_hash=?`), refreshHash(command.StepUpToken)).Scan(&used); err != nil || used {
		t.Fatal("failed transaction consumed authentication proof", err)
	}
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return nil })
	receipt, err := f.store.CommitDepartmentAgentChange(f.ctx, f.actors[1], command)
	if err != nil || receipt.Policy.Revision != 1 || receipt.Command.StepUpToken != "" || receipt.SubjectType != "" {
		t.Fatal("atomic retry failed or receipt leaked proof", err)
	}
	retry, err := f.store.CommitDepartmentAgentChange(f.ctx, f.actors[1], command)
	if err != nil || retry.ID != receipt.ID {
		t.Fatal("same-key retry performed another change", err)
	}
	recovered, err := f.store.DepartmentAgentChangeReceipt(f.ctx, f.actors[1], command.IdempotencyKey)
	if err != nil || recovered.ID != receipt.ID {
		t.Fatal("uncertain submit cannot recover original receipt", err)
	}
	command.Reason = "different command under an existing key"
	if _, err := f.store.CommitDepartmentAgentChange(f.ctx, f.actors[1], command); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("same-key command mismatch accepted", err)
	}
	withdraw := departmentAgentFixtureCommand(f, 1, "department-agent-empty")
	withdraw.Entries = nil
	empty := departmentAgentFixtureCommit(t, f, withdraw)
	if empty.Policy.Revision != 2 || len(empty.Policy.Entries) != 0 {
		t.Fatal("empty ceiling not persisted")
	}
	if _, err := f.store.PreviewDepartmentAgentChange(f.ctx, f.actors[1], departmentAgentFixtureCommand(f, 1, "stale-head")); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("stale ceiling revision accepted", err)
	}
}

func TestSQLDepartmentAgentManagedDelegationSourceAndRestoration(t *testing.T) {
	f := newDepartmentAgentFixture(t)
	departmentAgentFixtureManager(t, f)
	departmentAgentFixtureCommit(t, f, departmentAgentFixtureCommand(f, 0, "managed-department-agent-pool"))
	manager := f.actors[2]
	state, err := f.store.DepartmentAgentPolicy(f.ctx, manager, manager.TenantID, manager.DepartmentID)
	if err != nil || !state.Managed || state.CanManage || len(state.Policy.Entries) != 1 {
		t.Fatal("department manager cannot read company ceiling or can expand it", err)
	}
	user := departmentAgentFixtureUser(t, f, "managed-department-user")
	scope := ManagementScope{Type: "application", TenantID: user.TenantID, DepartmentID: user.DepartmentID, ApplicationID: user.ApplicationID}
	command := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: user.PrincipalID, ExpectedRevision: 1, IdempotencyKey: "managed-user-agent", Reason: "admit departmental user and grant approved Agent", Memberships: []MembershipMutation{{ID: "managed-user-department-member", Scope: ManagementScope{Type: "department", TenantID: user.TenantID, DepartmentID: user.DepartmentID}, Status: "active"}}, Preset: &PresetSelection{Code: "operator", Version: 1, Scope: scope, ResourceIDs: []string{"fixture-installation"}}}
	departmentAgentFixtureAuthorize(t, f, manager, command)
	profile, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, user.PrincipalID)
	if err != nil || len(profile.Grants) == 0 {
		t.Fatal("approved basic Agent permission missing", err)
	}
	for _, grant := range profile.Grants {
		if grant.DepartmentAgentActionVersion != 1 {
			t.Fatal("department grant missing server-derived source generation")
		}
	}
	departmentAgentFixtureDecision(t, f, user, "run", true)
	for _, tc := range []struct{ code, resource string }{{"operator", "outside-installation"}, {"agent_developer", ""}, {"department_admin", ""}} {
		outside := command
		outside.ExpectedRevision, outside.IdempotencyKey, outside.Memberships = profile.Principal.Revision, "forbidden-"+tc.code+tc.resource, nil
		outside.Preset = &PresetSelection{Code: tc.code, Version: 1, Scope: scope}
		if tc.resource != "" {
			outside.Preset.ResourceIDs = []string{tc.resource}
		}
		if _, err := f.store.PreviewAuthorizationChange(f.ctx, manager, outside); !errors.Is(err, ErrPermissionDenied) && !errors.Is(err, ErrInvalidResource) {
			t.Fatal("department manager exceeded company approval", tc, err)
		}
	}
	command.ExpectedRevision, command.IdempotencyKey, command.Memberships = profile.Principal.Revision, "pending-old-pool-grant", nil
	pending, err := f.store.PreviewAuthorizationChange(f.ctx, manager, command)
	if err != nil {
		t.Fatal(err)
	}
	withdraw := departmentAgentFixtureCommand(f, 1, "withdraw-managed-pool")
	withdraw.Entries = nil
	receipt := departmentAgentFixtureCommit(t, f, withdraw)
	if receipt.Impact.PotentialRestrictedSubjects != 1 || receipt.Impact.PotentialRestrictedGrants == 0 {
		t.Fatal("withdrawal preview omitted affected personal permissions", receipt.Impact)
	}
	departmentAgentFixtureDecision(t, f, user, "run", false)
	departmentAgentFixtureDecision(t, f, user, "cancel", true)
	command.PlanDigest, command.PlanExpiresAt = pending.Digest, pending.ExpiresAt
	if _, err := f.store.CommitAuthorizationChange(f.ctx, manager, command); !errors.Is(err, ErrPermissionDenied) && !errors.Is(err, ErrPermissionPlanStale) {
		t.Fatal("pending grant survived ceiling withdrawal", err)
	}
	departmentAgentFixtureCommit(t, f, departmentAgentFixtureCommand(f, 2, "restore-managed-pool"))
	departmentAgentFixtureDecision(t, f, user, "run", false)
	command.IdempotencyKey = "explicitly-regrant-after-restore"
	departmentAgentFixtureAuthorize(t, f, manager, command)
	departmentAgentFixtureDecision(t, f, user, "run", true)
}

func TestSQLDepartmentAgentScopeAndConcurrentChange(t *testing.T) {
	f := newDepartmentAgentFixture(t)
	departmentAgentFixtureManager(t, f)
	command := departmentAgentFixtureCommand(f, 0, "company-ceiling-race")
	if _, err := f.store.PreviewDepartmentAgentChange(f.ctx, f.actors[2], command); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("department manager could raise company ceiling", err)
	}
	outside := command
	outside.TenantID = "another-company"
	if _, err := f.store.PreviewDepartmentAgentChange(f.ctx, f.actors[1], outside); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("company manager escaped company", err)
	}
	plans := make([]DepartmentAgentChangeCommand, 2)
	for i := range plans {
		candidate := command
		if i == 0 {
			candidate.IdempotencyKey = "global-ceiling-race"
		}
		plan, err := f.store.PreviewDepartmentAgentChange(f.ctx, f.actors[i], candidate)
		if err != nil {
			t.Fatal(err)
		}
		plans[i] = departmentAgentFixtureProof(t, f, i, plan)
	}
	start := make(chan struct{})
	outcomes := make(chan error, 2)
	var workers sync.WaitGroup
	for i := range plans {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			<-start
			_, err := f.store.CommitDepartmentAgentChange(f.ctx, f.actors[i], plans[i])
			outcomes <- err
		}(i)
	}
	close(start)
	workers.Wait()
	close(outcomes)
	succeeded, rejected := 0, 0
	for err := range outcomes {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrIdentityConflict) {
			rejected++
		} else {
			t.Fatal("unexpected concurrent outcome", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatal("concurrent revision committed twice", succeeded, rejected)
	}
	state, err := f.store.DepartmentAgentPolicy(f.ctx, f.actors[1], command.TenantID, command.DepartmentID)
	if err != nil || state.Policy.Revision != 1 {
		t.Fatal("concurrent writes left an inconsistent policy", err)
	}
}

func TestSQLDepartmentAgentMembershipLegacyAndCorruptPolicy(t *testing.T) {
	f := newDepartmentAgentFixture(t)
	departmentAgentFixtureManager(t, f)
	departmentAgentFixtureCommit(t, f, departmentAgentFixtureCommand(f, 0, "legacy-ceiling-migration"))
	user := departmentAgentFixtureUser(t, f, "legacy-ceiling-user")
	scope := ManagementScope{Type: "application", TenantID: user.TenantID, DepartmentID: user.DepartmentID, ApplicationID: user.ApplicationID}
	change := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: user.PrincipalID, ExpectedRevision: 1, IdempotencyKey: "legacy-user-admission", Reason: "company admits user", Memberships: []MembershipMutation{{ID: "legacy-user-company-membership", Scope: ManagementScope{Type: "tenant", TenantID: user.TenantID}, Status: "active"}}}
	departmentAgentFixtureAuthorize(t, f, f.actors[1], change)
	change.ExpectedRevision, change.IdempotencyKey, change.Memberships = 2, "tenant-only-agent-forbidden", nil
	change.Preset = &PresetSelection{Code: "operator", Version: 1, Scope: scope, ResourceIDs: []string{"fixture-installation"}}
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, f.actors[2], change); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("company-only membership counted as departmental admission", err)
	}
	workspaces, err := f.store.ListApplicationWorkspaces(f.ctx, user.PrincipalID)
	if err != nil || len(workspaces) != 0 {
		t.Fatal("company-only member could select managed department", err)
	}
	change.IdempotencyKey = "legacy-user-department-admission"
	change.Memberships = []MembershipMutation{{ID: "legacy-user-department-membership", Scope: ManagementScope{Type: "department", TenantID: user.TenantID, DepartmentID: user.DepartmentID}, Status: "active"}}
	departmentAgentFixtureAuthorize(t, f, f.actors[2], change)
	departmentAgentFixtureDecision(t, f, user, "run", true)
	user.AgentInstanceID = "fixture-installation"
	principal, err := f.store.GetPrincipal(f.ctx, PrincipalUser, user.PrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"legacy", "shadow"} {
		if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_policy_migration SET policy_mode=?,revision=revision+1 WHERE subject_id=?`), mode, user.PrincipalID); err != nil {
			t.Fatal(err)
		}
		decision, err := checkPrincipalAccess(f.ctx, f.store, user, principal, "run")
		if err != nil || decision.Allowed || decision.Reason != "DEPARTMENT_PERMISSION_MIGRATION_REQUIRED" {
			t.Fatal("old policy mode bypassed managed ceiling", mode, decision, err)
		}
		// Cancellation is a recovery exception, not an exemption from an
		// existing personal grant's expiry or explicit denial.
		if decision, err := checkPrincipalAccess(f.ctx, f.store, user, principal, "cancel"); err != nil || !decision.Allowed {
			t.Fatal("valid legacy cancellation recovery was lost", mode, err)
		}
		if _, err := f.store.CurrentAuthorizationEpoch(f.ctx, user, "cancel"); err != nil {
			t.Fatal("effective legacy cancellation did not receive a runtime fence", mode, err)
		}
		if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET effect='deny' WHERE subject_id=? AND action='cancel'`), user.PrincipalID); err != nil {
			t.Fatal(err)
		}
		if decision, err := checkPrincipalAccess(f.ctx, f.store, user, principal, "cancel"); err != nil || decision.Allowed {
			t.Fatal("legacy cancellation ignored explicit denial", mode, err)
		}
		if _, err := f.store.CurrentAuthorizationEpoch(f.ctx, user, "cancel"); err == nil {
			t.Fatal("denied legacy cancellation received an authorization epoch", mode)
		}
		if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET effect='allow' WHERE subject_id=? AND action='cancel'`), user.PrincipalID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET permission_json=jsonb_set(permission_json::jsonb,'{expires_at}',to_jsonb(?::text))::json WHERE subject_id=? AND action='cancel'`), f.now.Add(-time.Hour).Format(time.RFC3339Nano), user.PrincipalID); err != nil {
			t.Fatal(err)
		}
		if decision, err := checkPrincipalAccess(f.ctx, f.store, user, principal, "cancel"); err != nil || decision.Allowed {
			t.Fatal("expired legacy cancellation grant was revived", mode, err)
		}
		if _, err := f.store.CurrentAuthorizationEpoch(f.ctx, user, "cancel"); err == nil {
			t.Fatal("expired legacy cancellation received an authorization epoch", mode)
		}
		if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET permission_json=(permission_json::jsonb-'expires_at')::json WHERE subject_id=? AND action='cancel'`), user.PrincipalID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_policy_migration SET policy_mode='v2',revision=revision+1 WHERE subject_id=?`), user.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_department_agent_entry SET action_versions_json='{}' WHERE tenant_id=? AND department_id=?`), user.TenantID, user.DepartmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, user.PrincipalID); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("invalid persisted source generations were accepted", err)
	}
	// Verify newly created company departments start managed and empty. The
	// older generic fixture creation above deliberately remains a migration case.
	department := Department{ID: user.DepartmentID + "-new", TenantID: user.TenantID, Code: "new", Name: "New department", Status: "active", Revision: 1}
	if err := f.store.CreateDepartmentWithAdministrationContext(f.ctx, department); err != nil {
		t.Fatal(err)
	}
	state, err := f.store.DepartmentAgentPolicy(f.ctx, f.actors[1], department.TenantID, department.ID)
	if err != nil || !state.Managed || state.Policy.Revision != 1 || len(state.Policy.Entries) != 0 {
		encoded, _ := json.Marshal(state)
		t.Fatal("new department did not default to an empty managed ceiling", string(encoded), err)
	}
}
