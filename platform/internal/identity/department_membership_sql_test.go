package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type scopedDepartmentInstallations map[string]ManagementScope

func (r scopedDepartmentInstallations) ResolveAgentInstallation(_ context.Context, scope sharedkernel.Scope, id string) (AgentInstallation, error) {
	selected, ok := r[id]
	if !ok || selected.TenantID != scope.TenantID || selected.DepartmentID != scope.DepartmentID || selected.ApplicationID != scope.ApplicationID {
		return AgentInstallation{}, ErrAgentInstallationNotFound
	}
	return AgentInstallation{AgentID: "fixture-agent"}, nil
}

func TestSQLDepartmentCreationMembershipAppointmentMultiEntryUseAndRemoval(t *testing.T) {
	f := newAdministratorFixture(t)
	s, root, manager := f.store, f.actors[0], f.actors[2]
	s.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	s.SetCapabilityResourceResolver(departmentAvailabilityFixture{})
	department := ManagementScope{Type: "department", TenantID: root.TenantID, DepartmentID: "created-department"}
	handler := NewModule(s, "fixture-private-token").Handler()
	call := func(actor sharedkernel.Scope, method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
		principal, err := s.GetPrincipal(f.ctx, PrincipalUser, actor.PrincipalID)
		if err != nil {
			t.Fatal(err)
		}
		setBrowserIdentityHeaders(r, principal, actor.DepartmentID, actor.ApplicationID)
		r.Header.Set("Authorization", "Bearer fixture-private-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	created := call(root, http.MethodPost, "/departments", Department{ID: department.DepartmentID, TenantID: department.TenantID, Code: "created", Name: "Created department", Status: "active", Revision: 1})
	if created.Code != http.StatusCreated {
		t.Fatalf("system administrator creation: %d %s", created.Code, created.Body.String())
	}
	apps := []ManagementScope{}
	for _, id := range []string{"entry-first", "entry-second"} {
		entry := call(root, http.MethodPost, "/applications", Application{ID: id, TenantID: department.TenantID, DepartmentID: department.DepartmentID, Code: id, Name: id, Status: "active", Revision: 1})
		if entry.Code != http.StatusCreated {
			t.Fatalf("system administrator target entry creation: %d %s", entry.Code, entry.Body.String())
		}
		apps = append(apps, ManagementScope{Type: "application", TenantID: department.TenantID, DepartmentID: department.DepartmentID, ApplicationID: id})
	}
	resources := scopedDepartmentInstallations{"agent-first": apps[0], "agent-second": apps[1]}
	s.SetPermissionResourceResolver(resources)
	commit := func(actor sharedkernel.Scope, c AuthorizationChangeCommand) AuthorizationChangeReceipt {
		t.Helper()
		plan, err := s.PreviewAuthorizationChange(f.ctx, actor, c)
		if err != nil {
			t.Fatal("preview", c.IdempotencyKey, err)
		}
		c.PlanDigest, c.PlanExpiresAt = plan.Digest, plan.ExpiresAt
		receipt, err := s.CommitAuthorizationChange(f.ctx, actor, c)
		if err != nil {
			t.Fatal("commit", c.IdempotencyKey, err)
		}
		return receipt
	}
	commit(root, AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: manager.PrincipalID, ExpectedRevision: 1, IdempotencyKey: "appoint-manager", Reason: "create department manager",
		// Complete Agent selection is explicitly assigned with the new role;
		// published v2 department administrators retain their old privileges.
		Memberships: []MembershipMutation{{ID: "manager-created-department", Scope: department, Status: "active"}}, Preset: &PresetSelection{Code: "department_admin", Version: 3, Scope: department}})
	projected := call(manager, http.MethodGet, "/me/permissions", nil)
	var management struct {
		Scopes       []ManagementScope `json:"department_management_scopes"`
		Capabilities []string          `json:"capabilities"`
	}
	if projected.Code != http.StatusOK || json.Unmarshal(projected.Body.Bytes(), &management) != nil || len(management.Scopes) != 1 || management.Scopes[0] != department || slices.Contains(management.Capabilities, "department.agent_access.manage") {
		t.Fatalf("new department management missing or current application broadened: %d %s", projected.Code, projected.Body.String())
	}
	directory := call(manager, http.MethodGet, "/departments?"+url.Values{"tenant_id": {department.TenantID}, "department_id": {department.DepartmentID}, "view": {"member-targets"}}.Encode(), nil)
	var departmentPage struct {
		Items []Department `json:"items"`
	}
	if directory.Code != http.StatusOK || json.Unmarshal(directory.Body.Bytes(), &departmentPage) != nil || len(departmentPage.Items) != 1 || departmentPage.Items[0].ID != department.DepartmentID {
		t.Fatalf("new department outside login context unavailable: %d %s", directory.Code, directory.Body.String())
	}
	creation := previewCreation(t, f, creationFixtureCommand(f, "company.member.user"))
	account, err := s.CreatePermissionPrincipal(f.ctx, root, creation)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := "/principals/" + creation.Username + "/membership-profile?" + url.Values{"tenant_id": {department.TenantID}, "department_id": {department.DepartmentID}}.Encode()
	profile := call(manager, http.MethodGet, profilePath, nil)
	var minimal PermissionSnapshot
	if profile.Code != http.StatusOK || json.Unmarshal(profile.Body.Bytes(), &minimal) != nil || minimal.Principal.Revision != account.Revision || len(minimal.Memberships)+len(minimal.Bindings)+len(minimal.Grants)+len(minimal.Principal.Roles) != 0 {
		t.Fatalf("candidate profile leaked other department or lacks revision: %d %s", profile.Code, profile.Body.String())
	}
	otherDepartmentPath := strings.Replace(profilePath, url.QueryEscape(department.DepartmentID), url.QueryEscape(root.DepartmentID), 1)
	if value := call(manager, http.MethodGet, otherDepartmentPath, nil); value.Code != http.StatusForbidden {
		t.Fatalf("cross department profile accepted: %d %s", value.Code, value.Body.String())
	}
	before, err := s.PageDepartmentMembers(f.ctx, manager, department, creation.Username, 1, 20)
	if err != nil || before.Total != 0 {
		t.Fatal("candidate prematurely a department member", before, err)
	}
	command := AuthorizationChangeCommand{Purpose: departmentAgentAccessPurpose, SubjectType: PrincipalUser, SubjectID: creation.Username, ExpectedRevision: account.Revision, IdempotencyKey: "two-agents-join", Reason: "join department and use selected agents",
		AgentSelection: &DepartmentAgentSelection{Scope: department, Targets: []DepartmentAgentTarget{{ApplicationID: apps[0].ApplicationID, InstallationIDs: []string{"agent-first"}}, {ApplicationID: apps[1].ApplicationID, InstallationIDs: []string{"agent-second"}}}},
		Memberships:    []MembershipMutation{{ID: "join-department", Scope: department, Status: "active"}, {ID: "join-first", Scope: apps[0], Status: "active"}, {ID: "join-second", Scope: apps[1], Status: "active"}}}
	// New native departments start with an explicit empty ceiling. The scoped
	// package workflow cannot bypass it, even with an explicitly assigned v3 role.
	if _, err := s.PreviewAuthorizationChange(f.ctx, manager, command); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("empty department ceiling permitted Agent selection", err)
	}
	ceiling := DepartmentAgentChangeCommand{TenantID: department.TenantID, DepartmentID: department.DepartmentID, ExpectedRevision: 1, IdempotencyKey: "company-approve-two-agents", Reason: "company approves exact basic Agent use", Entries: []DepartmentAgentPolicyEntry{
		{ApplicationID: apps[0].ApplicationID, InstallationID: "agent-first", Actions: append([]string(nil), basicAgentUseActions...)},
		{ApplicationID: apps[1].ApplicationID, InstallationID: "agent-second", Actions: append([]string(nil), basicAgentUseActions...)},
	}}
	ceilingPlan, err := s.PreviewDepartmentAgentChange(f.ctx, root, ceiling)
	if err != nil {
		t.Fatal("company ceiling preview", err)
	}
	if _, err := s.CommitDepartmentAgentChange(f.ctx, root, departmentAgentFixtureProof(t, f, 0, ceilingPlan)); err != nil {
		t.Fatal("company ceiling approval", err)
	}
	withoutJoin := command
	withoutJoin.Memberships = command.Memberships[1:]
	if _, err := s.PreviewAuthorizationChange(f.ctx, manager, withoutJoin); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("grant without department join accepted", err)
	}
	plan, err := s.PreviewAuthorizationChange(f.ctx, manager, command)
	if err != nil || len(plan.ExpandedBindings) != 2 || len(plan.ExpandedGrants) != 10 || len(plan.ExpandedMemberships) != 3 {
		t.Fatal("multi-entry atomic preview", err, len(plan.ExpandedBindings), len(plan.ExpandedGrants), len(plan.ExpandedMemberships))
	}
	grantReceipt := commit(manager, command)
	for id, scope := range resources {
		decision, err := s.ResolvePermission(f.ctx, PrincipalUser, creation.Username, PermissionQuery{Action: "run", Scope: scope, ResourceType: "agent_installation", ResourceID: id})
		if err != nil || !decision.Allowed {
			t.Fatal("selected Agent not authorized", id, decision, err)
		}
	}
	joined, err := s.PageDepartmentMembers(f.ctx, manager, department, creation.Username, 1, 20)
	if err != nil || joined.Total != 1 || len(joined.Items) != 1 || len(joined.Items[0].Roles) != 0 {
		t.Fatal("member directory incomplete or over-projecting", joined, err)
	}
	appointed := commit(root, AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: creation.Username, ExpectedRevision: grantReceipt.Revision, IdempotencyKey: "appoint-peer", Reason: "appoint department administrator", Preset: &PresetSelection{Code: "department_admin", Version: 2, Scope: department}})
	snapshot, _ := s.PermissionSnapshot(f.ctx, PrincipalUser, creation.Username)
	deptAdmin := slices.IndexFunc(snapshot.Bindings, func(b RoleBinding) bool {
		return b.Status == "active" && b.RoleCode == "department_admin" && b.Scope == department
	})
	if deptAdmin < 0 {
		t.Fatal("department administrator missing")
	}
	demotion := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: creation.Username, ExpectedRevision: appointed.Revision, IdempotencyKey: "demote-to-member", Reason: "set ordinary department member", RevokeBindingIDs: []string{snapshot.Bindings[deptAdmin].ID}}
	if _, err := s.PreviewAuthorizationChange(f.ctx, manager, demotion); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("department manager demoted peer", err)
	}
	removal := AuthorizationChangeCommand{Purpose: departmentRemovalPurpose, DepartmentRemoval: &department, SubjectType: PrincipalUser, SubjectID: creation.Username, ExpectedRevision: appointed.Revision, IdempotencyKey: "peer-removal", Reason: "remove member"}
	for _, member := range snapshot.Memberships {
		if member.Status == "active" && department.Contains(member.Scope) {
			removal.Memberships = append(removal.Memberships, MembershipMutation{ID: member.ID, Scope: member.Scope, Status: "revoked", ExpectedRevision: member.Revision})
		}
	}
	if _, err := s.PreviewAuthorizationChange(f.ctx, manager, removal); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("department manager removed peer administrator", err)
	}
	demoted := commit(root, demotion)
	snapshot, _ = s.PermissionSnapshot(f.ctx, PrincipalUser, creation.Username)
	if len(snapshot.Grants) != 10 || slices.ContainsFunc(snapshot.Bindings, func(b RoleBinding) bool { return b.RoleCode == "department_admin" && b.Status == "active" }) {
		t.Fatal("ordinary member designation lost business usage or retained management")
	}
	companyScope := ManagementScope{Type: "tenant", TenantID: department.TenantID}
	company := commit(root, AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: creation.Username, ExpectedRevision: demoted.Revision, IdempotencyKey: "company-membership", Reason: "retain company membership", Memberships: []MembershipMutation{{ID: "company-member", Scope: companyScope, Status: "active"}}})
	// A future relationship and an explicit deny must retain their distinct
	// semantics. Removal revokes the former and preserves the deny.
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	deny := snapshot.Grants[0]
	deny.ID, deny.Effect, deny.SourceID = "keep-deny", "deny", "department-removal-fixture"
	if err := insertPermissionGrant(f.ctx, tx, deny, f.now); err != nil {
		t.Fatal(err)
	}
	assignmentScope := apps[0]
	assignmentScope.Type, assignmentScope.ResourceID = "agent_installation", "agent-first"
	if err := insertTaskAssignment(f.ctx, tx, TaskAssignment{ID: "department-task", SubjectID: creation.Username, TaskID: "fixture-task", Action: "history.read", Scope: assignmentScope, Status: "active", Revision: 1, SourceID: "fixture"}); err != nil {
		t.Fatal(err)
	}
	future := f.now.Add(time.Hour)
	member := snapshot.Memberships[slices.IndexFunc(snapshot.Memberships, func(m Membership) bool { return m.Scope == apps[1] })]
	member.StartsAt, member.Revision = &future, member.Revision+1
	if err := persistMembershipMutation(f.ctx, tx, member, member.Revision-1); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = s.PermissionSnapshot(f.ctx, PrincipalUser, creation.Username)
	removal.ExpectedRevision, removal.IdempotencyKey, removal.Memberships = company.Revision, "remove-with-company-coverage", nil
	for _, member := range snapshot.Memberships {
		if member.Status == "active" && department.Contains(member.Scope) {
			removal.Memberships = append(removal.Memberships, MembershipMutation{ID: member.ID, Scope: member.Scope, Status: "revoked", ExpectedRevision: member.Revision})
		}
	}
	plan, err = s.PreviewAuthorizationChange(f.ctx, manager, removal)
	if err != nil || len(plan.AutomaticRevokeGrantIDs) != 10 || len(plan.AutomaticRevokeBindingIDs) != 2 || len(plan.AutomaticRevokeAssignmentIDs) != 1 {
		t.Fatal("company membership retained removed department permissions", err, len(plan.AutomaticRevokeGrantIDs), len(plan.AutomaticRevokeBindingIDs), len(plan.AutomaticRevokeAssignmentIDs))
	}
	removed := commit(manager, removal)
	snapshot, _ = s.PermissionSnapshot(f.ctx, PrincipalUser, creation.Username)
	for _, member := range snapshot.Memberships {
		if department.Contains(member.Scope) && member.Status != "revoked" || member.Scope == companyScope && member.Status != "active" {
			t.Fatal("department/company membership boundary incorrect", member)
		}
	}
	for _, binding := range snapshot.Bindings {
		if department.Contains(binding.Scope) && binding.Status != "revoked" || binding.Scope == creation.Scope && binding.Status != "active" {
			t.Fatal("other department roles altered or removed department retained", binding)
		}
	}
	if !slices.ContainsFunc(snapshot.Grants, func(g Grant) bool { return g.ID == deny.ID && g.Status == "active" && g.Effect == "deny" }) {
		t.Fatal("explicit deny lost during department removal")
	}
	member = snapshot.Memberships[slices.IndexFunc(snapshot.Memberships, func(m Membership) bool { return m.Scope == department })]
	commit(manager, AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: creation.Username, ExpectedRevision: removed.Revision, IdempotencyKey: "rejoin-without-old-grants", Reason: "rejoin as member", Memberships: []MembershipMutation{{ID: member.ID, Scope: department, Status: "active", ExpectedRevision: member.Revision}}})
	decision, err := s.ResolvePermission(f.ctx, PrincipalUser, creation.Username, PermissionQuery{Action: "run", Scope: apps[1], ResourceType: "agent_installation", ResourceID: "agent-second"})
	if err != nil || decision.Allowed {
		t.Fatal("rejoining restored old Agent access", decision, err)
	}
}
