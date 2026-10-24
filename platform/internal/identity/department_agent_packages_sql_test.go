package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type completeAgentRequirementsFixture struct {
	version            string
	requirementsError  error
	availabilityReason string
	availabilityError  error
}

func (r *completeAgentRequirementsFixture) ResolveAgentInstallation(_ context.Context, _ sharedkernel.Scope, id string) (AgentInstallation, error) {
	if !strings.HasPrefix(id, "fixture-installation") {
		return AgentInstallation{}, ErrAgentInstallationNotFound
	}
	return AgentInstallation{AgentID: "requested-agent"}, nil
}

func (r *completeAgentRequirementsFixture) ResolvePermissionRunAvailability(context.Context, sharedkernel.Scope) (string, error) {
	return r.availabilityReason, r.availabilityError
}

func (r *completeAgentRequirementsFixture) ResolvePermissionResource(_ context.Context, scope sharedkernel.Scope, typ, id string) (PermissionResource, error) {
	if typ != "agent_installation" && id != typ+"-fixture" || typ == "agent_installation" && id != scope.InstallationID {
		return PermissionResource{}, ErrInvalidResource
	}
	return PermissionResource{Type: typ, ID: id, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, InstallationID: scope.InstallationID, AgentID: "requested-agent", AgentVersionID: r.version}, nil
}

func (r *completeAgentRequirementsFixture) ResolveAgentUseRequirements(_ context.Context, scope sharedkernel.Scope) (AgentUseRequirements, error) {
	if r.requirementsError != nil {
		return AgentUseRequirements{}, r.requirementsError
	}
	value := AgentUseRequirements{InstallationID: scope.InstallationID, AgentID: "requested-agent", AgentVersionID: r.version, DisplayName: "Fixture Agent", PolicyHash: strings.Repeat("a", 64)}
	for _, item := range []struct{ typ, action, data string }{
		{"model", "model.generate", "approved_organization"}, {"model", "model.embed", "approved_organization"},
		{"tool", "tool.invoke", "approved_organization"}, {"knowledge", "knowledge.search", "approved_organization"},
		{"memory", "memory.read", "owner"}, {"memory", "memory.write", "owner"}, {"skill", "skill.load", "approved_organization"},
		{"agent_installation", "agent.delegate", "approved_organization"},
	} {
		id := item.typ + "-fixture"
		if item.typ == "agent_installation" {
			id = scope.InstallationID
		}
		value.Requirements = append(value.Requirements, AgentUseRequirement{ResourceType: item.typ, ResourceID: id, Action: item.action, DataScope: DataScope{Type: item.data}, RequiresConfirmation: item.typ == "tool"})
	}
	err := value.Seal()
	return value, err
}

func TestSQLDepartmentAgentPackageUnavailableInspectionAndSuspension(t *testing.T) {
	f, resolver, manager, use := newCompleteAgentFixture(t)
	c := completeApprovalFixtureCommand(t, f, *use.AgentSelection, "active", "approve-before-retirement", Validity{})
	if _, err := f.store.CommitAgentPackageApproval(f.ctx, f.actors[0], c); err != nil {
		t.Fatal(err)
	}
	resolver.requirementsError = ErrInvalidResource
	resolver.availabilityReason = "RESOURCE_UNAVAILABLE"
	inspection, err := f.store.InspectDepartmentAgentPackages(f.ctx, manager, *use.AgentSelection)
	if err != nil || len(inspection.Entries) != 1 || inspection.Entries[0].Approved || inspection.Entries[0].AvailabilityReason != "RESOURCE_UNAVAILABLE" || inspection.Entries[0].Approval == nil {
		t.Fatal("exact-owned unavailable Agent cannot be inspected safely", inspection, err)
	}
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, manager, use); !errors.Is(err, ErrAgentPackageStale) {
		t.Fatal("stored approval permitted new unavailable Agent assignment", err)
	}
	resolver.availabilityError = ErrInvalidResource
	if _, err := f.store.InspectDepartmentAgentPackages(f.ctx, manager, *use.AgentSelection); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("ownership mismatch exposed stored requirements", err)
	}
	resolver.availabilityError, resolver.availabilityReason = nil, ""
	if _, err := f.store.InspectDepartmentAgentPackages(f.ctx, manager, *use.AgentSelection); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("unknown provider failure fell back to stored approval", err)
	}
	resolver.availabilityReason = "RESOURCE_UNAVAILABLE"
	pause := completeApprovalFixtureCommand(t, f, *use.AgentSelection, "suspended", "pause-retired-agent", Validity{})
	if _, err := f.store.CommitAgentPackageApproval(f.ctx, f.actors[0], pause); err != nil {
		t.Fatal("retired Agent approval cannot be suspended", err)
	}
}

func newCompleteAgentFixture(t *testing.T) (administratorFixture, *completeAgentRequirementsFixture, sharedkernel.Scope, AuthorizationChangeCommand) {
	t.Helper()
	f := newAdministratorFixture(t)
	r := &completeAgentRequirementsFixture{version: "fixture-version-1"}
	f.store.SetPermissionResourceResolver(r)
	f.store.SetCapabilityResourceResolver(r)
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	manager := f.actors[2]
	department := ManagementScope{Type: "department", TenantID: manager.TenantID, DepartmentID: manager.DepartmentID}
	appoint := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: manager.PrincipalID, ExpectedRevision: 1, IdempotencyKey: "package-manager", Reason: "scoped member and Agent management",
		Memberships: []MembershipMutation{{ID: "package-manager-member", Scope: department, Status: "active"}}, Preset: &PresetSelection{Code: "department_admin", Version: 3, Scope: department}}
	commitCompleteFixtureChange(t, f, f.actors[0], appoint)
	creation := previewCreation(t, f, creationFixtureCommand(f, "package.member.user"))
	created, err := f.store.CreatePermissionPrincipal(f.ctx, f.actors[0], creation)
	if err != nil {
		t.Fatal(err)
	}
	command := AuthorizationChangeCommand{Purpose: departmentAgentAccessPurpose, SubjectType: PrincipalUser, SubjectID: creation.Username, ExpectedRevision: created.Revision, Reason: "complete selected Agent use", IdempotencyKey: "package-user-use",
		AgentSelection: &DepartmentAgentSelection{Scope: department, IncludeDependencies: true, Targets: []DepartmentAgentTarget{{ApplicationID: manager.ApplicationID, InstallationIDs: []string{"fixture-installation"}}}}}
	return f, r, manager, command
}

func commitCompleteFixtureChange(t *testing.T, f administratorFixture, actor sharedkernel.Scope, c AuthorizationChangeCommand) AuthorizationChangeReceipt {
	t.Helper()
	p, err := f.store.PreviewAuthorizationChange(f.ctx, actor, c)
	if err != nil {
		t.Fatal(err)
	}
	c.PlanDigest, c.PlanExpiresAt = p.Digest, p.ExpiresAt
	receipt, err := f.store.CommitAuthorizationChange(f.ctx, actor, c)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func completeApprovalFixtureCommand(t *testing.T, f administratorFixture, selection DepartmentAgentSelection, status, key string, validity Validity) AgentPackageApprovalCommand {
	t.Helper()
	inspection, err := f.store.InspectDepartmentAgentPackages(f.ctx, f.actors[0], selection)
	if err != nil || !inspection.CanApprove {
		t.Fatal("root requirements inspection", err)
	}
	c := AgentPackageApprovalCommand{Scope: selection.Scope, Status: status, Reason: "approved scoped Agent dependencies", IdempotencyKey: key, Validity: validity}
	for _, entry := range inspection.Entries {
		revision := uint64(0)
		if entry.Approval != nil {
			revision = entry.Approval.Revision
		}
		c.Items = append(c.Items, AgentPackageApprovalItem{ApplicationID: entry.ApplicationID, InstallationID: entry.Requirements.InstallationID, RequirementsDigest: entry.Requirements.Digest, ExpectedRevision: revision})
	}
	p, err := f.store.PreviewAgentPackageApproval(f.ctx, f.actors[0], c)
	if err != nil {
		t.Fatal(err)
	}
	c.PlanDigest, c.PlanExpiresAt = p.Digest, p.ExpiresAt
	proof, err := f.store.CreateLocalStepUp(f.ctx, f.actors[0], StepUpRequest{Action: p.StepUpAction, RequestDigest: p.RequestDigest, CurrentPassword: "fixture-administrator-password"}) // secret-scan: allow existing deterministic disposable fixture credential
	if err != nil {
		t.Fatal(err)
	}
	c.StepUpToken = proof.Token
	return c
}

func TestSQLDepartmentAgentPackageApprovalAtomicityAndHTTP(t *testing.T) {
	f, _, manager, use := newCompleteAgentFixture(t)
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, manager, use); !errors.Is(err, ErrAgentPackageApprovalRequired) {
		t.Fatal("unapproved dependencies accepted", err)
	}
	c := completeApprovalFixtureCommand(t, f, *use.AgentSelection, "active", "approve-package", Validity{})
	if _, err := f.store.PreviewAgentPackageApproval(f.ctx, manager, c); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("department manager became company approver", err)
	}
	withoutProof := c
	withoutProof.StepUpToken = ""
	if _, err := f.store.CommitAgentPackageApproval(f.ctx, f.actors[0], withoutProof); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal("approval did not require fresh authentication", err)
	}
	fault := errors.New("approval audit unavailable")
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return fault })
	if _, err := f.store.CommitAgentPackageApproval(f.ctx, f.actors[0], c); !errors.Is(err, fault) {
		t.Fatal("approval audit was not atomic", err)
	}
	var count int
	if err := f.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM platform_identity_department_agent_package`).Scan(&count); err != nil || count != 0 {
		t.Fatal("approval partially persisted after audit failure", count, err)
	}
	f.store.SetAdministrativeRecorder(func(_ context.Context, _ *sql.Tx, _ sharedkernel.Scope, event AdministrativeEvent) error {
		if event.SubjectType != "" || event.DetailsDigest == "" {
			t.Fatal("department approval fabricated principal invalidation or omitted details")
		}
		return nil
	})
	receipt, err := f.store.CommitAgentPackageApproval(f.ctx, f.actors[0], c)
	if err != nil || len(receipt.Entries) != 1 || receipt.Command.StepUpToken != "" {
		t.Fatal("approval commit/proof rollback", err)
	}
	replay := c
	replay.StepUpToken, replay.PlanDigest = "", ""
	replay.PlanExpiresAt = time.Time{}
	retried, err := f.store.CommitAgentPackageApproval(f.ctx, f.actors[0], replay)
	if err != nil || retried.ID != receipt.ID {
		t.Fatal("original approval receipt not replayable", err)
	}
	replay.Reason = "different approved effect"
	if _, err := f.store.CommitAgentPackageApproval(f.ctx, f.actors[0], replay); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("idempotency key reused for another approval", err)
	}
	for _, actor := range f.actors {
		snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, actor.PrincipalID)
		if err != nil || len(snapshot.Grants) != 0 {
			t.Fatal("approval implicitly granted business use", err)
		}
	}
	handler := NewModule(f.store, "private-fixture-token").Handler()
	call := func(actor sharedkernel.Scope, method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
		principal, err := f.store.GetPrincipal(f.ctx, PrincipalUser, actor.PrincipalID)
		if err != nil {
			t.Fatal(err)
		}
		setBrowserIdentityHeaders(r, principal, actor.DepartmentID, actor.ApplicationID)
		r.Header.Set("Authorization", "Bearer private-fixture-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	w := call(manager, http.MethodPost, "/department-agent-packages:inspect", use.AgentSelection)
	var inspection DepartmentAgentPackageInspection
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &inspection) != nil || len(inspection.Entries) != 1 || inspection.CanApprove || !inspection.Entries[0].Approved {
		t.Fatal("department inspection contract", w.Code, w.Body.String())
	}
	for _, path := range []string{"/department-agent-packages:preview", "/department-agent-packages:commit"} {
		if denied := call(manager, http.MethodPost, path, c); denied.Code != 403 {
			t.Fatal("department approval HTTP bypass", path, denied.Code)
		}
	}
	foreign := *use.AgentSelection
	foreign.Scope.DepartmentID += "-other"
	if denied := call(manager, http.MethodPost, "/department-agent-packages:inspect", foreign); denied.Code != 403 {
		t.Fatal("cross department requirements disclosed", denied.Code)
	}
	if wrongMethod := call(f.actors[0], http.MethodGet, "/department-agent-packages:commit", nil); wrongMethod.Code != 405 {
		t.Fatal("approval accepts wrong method", wrongMethod.Code)
	}
}

func TestSQLDepartmentCompleteAgentUseReapprovalAndPreservingRevocation(t *testing.T) {
	f, resolver, manager, command := newCompleteAgentFixture(t)
	c := completeApprovalFixtureCommand(t, f, *command.AgentSelection, "active", "first-package", Validity{})
	if _, err := f.store.CommitAgentPackageApproval(f.ctx, f.actors[0], c); err != nil {
		t.Fatal(err)
	}
	oldPlan, err := f.store.PreviewAuthorizationChange(f.ctx, manager, command)
	if err != nil {
		t.Fatal(err)
	}
	resolver.version = "fixture-version-2"
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, manager, command); !errors.Is(err, ErrAgentPackageStale) {
		t.Fatal("changed publication used old company approval", err)
	}
	c = completeApprovalFixtureCommand(t, f, *command.AgentSelection, "active", "new-package-version", Validity{})
	if _, err := f.store.CommitAgentPackageApproval(f.ctx, f.actors[0], c); err != nil {
		t.Fatal(err)
	}
	command.PlanDigest, command.PlanExpiresAt = oldPlan.Digest, oldPlan.ExpiresAt
	if _, err := f.store.CommitAuthorizationChange(f.ctx, manager, command); !errors.Is(err, ErrPermissionPlanStale) {
		t.Fatal("stale user authorization committed after reapproval", err)
	}
	useReceipt := commitCompleteFixtureChange(t, f, manager, command)
	app := ManagementScope{Type: "application", TenantID: manager.TenantID, DepartmentID: manager.DepartmentID, ApplicationID: manager.ApplicationID}
	installation := app
	installation.Type, installation.ResourceID = "agent_installation", "fixture-installation"
	requirements, _ := resolver.ResolveAgentUseRequirements(f.ctx, sharedkernel.Scope{InstallationID: installation.ResourceID})
	queries := []PermissionQuery{{Action: "run", Scope: installation, ResourceType: "agent_installation", ResourceID: installation.ResourceID}}
	for _, item := range requirements.Requirements {
		queries = append(queries, PermissionQuery{Action: item.Action, Scope: installation, ResourceType: item.ResourceType, ResourceID: item.ResourceID})
	}
	for _, q := range queries {
		decision, err := f.store.ResolvePermission(f.ctx, PrincipalUser, command.SubjectID, q)
		if err != nil || !decision.Allowed {
			t.Fatal("complete resource qualification missing", q.Action, decision, err)
		}
	}
	for _, action := range []string{"history.export", "history.share", "business.review", "audit.content.read"} {
		q := queries[0]
		q.Action = action
		decision, err := f.store.ResolvePermission(f.ctx, PrincipalUser, command.SubjectID, q)
		if err != nil || decision.Allowed {
			t.Fatal("complete Agent use widened sensitive actions", action, decision, err)
		}
	}
	resolver.version = "unapproved-next-version"
	decision, err := f.store.ResolvePermission(f.ctx, PrincipalUser, command.SubjectID, queries[0])
	if err != nil || decision.Allowed || decision.Reason != "AGENT_PACKAGE_STALE" {
		t.Fatal("permission directory silently followed unapproved publication", decision, err)
	}
	explanation, err := f.store.ExplainPermission(f.ctx, manager, PrincipalUser, command.SubjectID, queries[0])
	if err != nil || explanation.Allowed || explanation.Reason != "AGENT_PACKAGE_STALE" || len(explanation.Grants) != 0 {
		t.Fatal("stale publication explanation incorrectly reported runnable", err)
	}
	resolver.version = "fixture-version-2"
	copyGrant := useReceipt.Change.Grants[0]
	copyGrant.ID, copyGrant.SourceID, copyGrant.PresetCode, copyGrant.PresetVersion = "forged-stamp", "arbitrary-source", "", 0
	manual := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: command.SubjectID, ExpectedRevision: useReceipt.Revision, IdempotencyKey: "manual-preserved", Reason: "independent model use and review", Grants: []Grant{copyGrant}}
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, f.actors[0], manual); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("raw command forged company stamp", err)
	}
	manual.Grants = []Grant{}
	for _, item := range []struct{ id, typ, resource, action, effect string }{
		{"manual-model", "model", "model-fixture", "model.generate", "allow"}, {"manual-deny", "tool", "tool-fixture", "tool.invoke", "deny"}, {"manual-review", "agent_installation", "fixture-installation", "business.review", "allow"},
	} {
		manual.Grants = append(manual.Grants, Grant{ID: item.id, SourceID: "manual", SubjectType: PrincipalUser, SubjectID: command.SubjectID, TenantID: app.TenantID, DepartmentID: app.DepartmentID, ApplicationID: app.ApplicationID,
			AgentInstanceID: "fixture-installation", ResourceType: item.typ, ResourceID: item.resource, Action: item.action, Effect: item.effect, Status: "active", Revision: 1, DataScope: DataScope{Type: "approved_organization"}})
	}
	manual.Bindings = []RoleBinding{{ID: "manual-review-role", SubjectID: command.SubjectID, SourceID: "manual", Scope: app, RoleCode: "reviewer", RoleVersion: 1, Status: "active", Revision: 1}}
	manualReceipt := commitCompleteFixtureChange(t, f, f.actors[0], manual)
	for _, id := range []string{"manual-model", "manual-deny", "manual-review"} {
		attempt := AuthorizationChangeCommand{Purpose: departmentAgentAccessPurpose, RevokePackageUse: true, SubjectType: PrincipalUser, SubjectID: command.SubjectID, ExpectedRevision: manualReceipt.Revision, IdempotencyKey: "forbidden-" + id, Reason: "attempt to remove independent permission", RevokeGrantIDs: []string{id}}
		if _, err := f.store.PreviewAuthorizationChange(f.ctx, manager, attempt); !errors.Is(err, ErrPermissionDenied) {
			t.Fatal("department manager removed independent/sensitive/deny grant", id, err)
		}
	}
	c = completeApprovalFixtureCommand(t, f, *command.AgentSelection, "suspended", "suspend-package", Validity{})
	if _, err := f.store.CommitAgentPackageApproval(f.ctx, f.actors[0], c); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		action, typ, id string
		allowed         bool
	}{{"run", "agent_installation", "fixture-installation", false}, {"memory.read", "memory", "memory-fixture", false}, {"model.generate", "model", "model-fixture", true}} {
		q := PermissionQuery{Action: tc.action, Scope: installation, ResourceType: tc.typ, ResourceID: tc.id}
		decision, err := f.store.ResolvePermission(f.ctx, PrincipalUser, command.SubjectID, q)
		if err != nil || decision.Allowed != tc.allowed {
			t.Fatal("suspension did not respect company package vs independent rights", tc.action, decision, err)
		}
	}
	revoke := AuthorizationChangeCommand{Purpose: departmentAgentAccessPurpose, RevokePackageUse: true, SubjectType: PrincipalUser, SubjectID: command.SubjectID, ExpectedRevision: manualReceipt.Revision, IdempotencyKey: "remove-package-use", Reason: "remove complete selected Agent use"}
	for _, grant := range useReceipt.Change.Grants {
		revoke.RevokeGrantIDs = append(revoke.RevokeGrantIDs, grant.ID)
	}
	commitCompleteFixtureChange(t, f, manager, revoke)
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, command.SubjectID)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"manual-model", "manual-deny", "manual-review"} {
		if !slices.ContainsFunc(snapshot.Grants, func(g Grant) bool { return g.ID == id && g.Status == "active" }) {
			t.Fatal("independent authorization lost on complete revocation", id)
		}
	}
}

func TestSQLDepartmentAgentPackagesForeignCompanyTargetAndAudit(t *testing.T) {
	f, _, manager, _ := newCompleteAgentFixture(t)
	company, department, app := "package-company-beta", "package-department-beta", "package-entry-beta"
	for _, err := range []error{
		f.store.CreateTenant(f.ctx, Tenant{ID: company, Code: company, Name: "Beta company", Status: "active", Revision: 1}),
		f.store.CreateDepartment(f.ctx, Department{ID: department, TenantID: company, Code: department, Name: "Beta department", Status: "active", Revision: 1}),
		f.store.CreateApplication(f.ctx, Application{ID: app, TenantID: company, DepartmentID: department, Code: app, Name: "Beta entry", Status: "active", Revision: 1}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	selection := DepartmentAgentSelection{Scope: ManagementScope{Type: "department", TenantID: company, DepartmentID: department}, Targets: []DepartmentAgentTarget{{ApplicationID: app, InstallationIDs: []string{"fixture-installation-beta"}}}}
	if _, err := f.store.InspectDepartmentAgentPackages(f.ctx, manager, selection); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("foreign company requirements disclosed to department manager", err)
	}
	c := completeApprovalFixtureCommand(t, f, selection, "active", "approve-company-beta", Validity{})
	recorded := false
	f.store.SetAdministrativeRecorder(func(_ context.Context, _ *sql.Tx, scope sharedkernel.Scope, event AdministrativeEvent) error {
		if scope.TenantID != company || scope.DepartmentID != department || scope.ApplicationID != app || scope.PrincipalID != f.actors[0].PrincipalID || event.SubjectType != "" {
			t.Fatal("foreign company approval audit mixed actor workspace with target")
		}
		recorded = true
		return nil
	})
	if _, err := f.store.CommitAgentPackageApproval(f.ctx, f.actors[0], c); err != nil || !recorded {
		t.Fatal("root foreign approval", err)
	}
	root, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, f.actors[0].PrincipalID)
	if err != nil || root.Principal.TenantID != f.actors[0].TenantID || len(root.Grants) != 0 || slices.ContainsFunc(root.Memberships, func(m Membership) bool { return m.Scope.TenantID == company }) {
		t.Fatal("company target approval changed root business identity", err)
	}
}

func TestSQLDepartmentCompleteAgentUseBatchBoundsExpiryAndAdmissionVersion(t *testing.T) {
	f, resolver, manager, command := newCompleteAgentFixture(t)
	command.AgentSelection.Targets[0].InstallationIDs = nil
	for i := 0; i < 16; i++ {
		command.AgentSelection.Targets[0].InstallationIDs = append(command.AgentSelection.Targets[0].InstallationIDs, fmt.Sprintf("fixture-installation-%02d", i))
	}
	expiry := f.now.Add(2 * time.Hour)
	c := completeApprovalFixtureCommand(t, f, *command.AgentSelection, "active", "approve-sixteen", Validity{ExpiresAt: &expiry})
	if _, err := f.store.CommitAgentPackageApproval(f.ctx, f.actors[0], c); err != nil {
		t.Fatal(err)
	}
	requestedEnd := f.now.Add(10 * time.Hour)
	command.AgentSelection.ExpiresAt = &requestedEnd
	plan, err := f.store.PreviewAuthorizationChange(f.ctx, manager, command)
	if err != nil || len(plan.ExpandedGrants) <= 128 {
		t.Fatal("bounded typed batch incorrectly limited to generic raw grants", err)
	}
	for _, grant := range plan.ExpandedGrants {
		if grant.ExpiresAt == nil || !grant.ExpiresAt.Equal(expiry) || !validAgentPackageStamp(grant) {
			t.Fatal("user grant outlives company approval or lacks source stamp")
		}
	}
	tooMany := *command.AgentSelection
	tooMany.Targets = []DepartmentAgentTarget{{ApplicationID: manager.ApplicationID, InstallationIDs: append(append([]string(nil), tooMany.Targets[0].InstallationIDs...), "fixture-installation-extra")}}
	if _, err := f.store.InspectDepartmentAgentPackages(f.ctx, f.actors[0], tooMany); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("unbounded selection accepted", err)
	}
	commitCompleteFixtureChange(t, f, manager, command)
	scope := manager
	scope.PrincipalID, scope.InstallationID, scope.AgentInstanceID, scope.AgentID, scope.AgentVersionID = command.SubjectID, command.AgentSelection.Targets[0].InstallationIDs[0], command.AgentSelection.Targets[0].InstallationIDs[0], "requested-agent", resolver.version
	if _, err := f.store.CurrentAuthorizationEpoch(f.ctx, scope, "run"); err != nil {
		t.Fatal("approved exact version cannot be admitted", err)
	}
	scope.AgentVersionID = "unapproved-next-version"
	if _, err := f.store.CurrentAuthorizationEpoch(f.ctx, scope, "run"); err == nil {
		t.Fatal("company approval silently followed a new published version")
	}
	f.store.clock = func() time.Time { return expiry }
	app := ManagementScope{Type: "application", TenantID: manager.TenantID, DepartmentID: manager.DepartmentID, ApplicationID: manager.ApplicationID}
	decision, err := f.store.ResolvePermission(f.ctx, PrincipalUser, command.SubjectID, PermissionQuery{Action: "run", Scope: app, ResourceType: "agent_installation", ResourceID: scope.InstallationID})
	if err != nil || decision.Allowed {
		t.Fatal("expired package still allowed Agent use", decision, err)
	}
}
