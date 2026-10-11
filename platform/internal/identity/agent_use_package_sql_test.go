package identity

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func agentUseFixtureBatch(t *testing.T, f administratorFixture, resolver *agentUseFixtureResolver, key string, users ...string) PermissionBatchCommand {
	t.Helper()
	f.store.SetCapabilityResourceResolver(resolver)
	actor := f.actors[1]
	scope := ManagementScope{Type: "agent_installation", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, ResourceID: "fixture-installation"}
	pack, err := f.store.AgentUsePackage(f.ctx, actor, scope)
	if err != nil {
		t.Fatal("read actual use package", err)
	}
	command := PermissionBatchCommand{Kind: "authorization", Scope: ManagementScope{Type: "department", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID}, IdempotencyKey: key, Reason: "review published Agent use and dependencies for selected users"}
	for _, id := range users {
		departmentAgentFixtureUser(t, f, id)
		command.Items = append(command.Items, PermissionBatchItemCommand{Authorization: &AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: id, ExpectedRevision: 1,
			Memberships: []MembershipMutation{{ID: id + "-member", Scope: command.Scope, Status: "active"}},
			AgentUse:    &AgentUseSelection{Scope: scope, AgentVersionID: pack.AgentVersionID, PackageDigest: pack.Digest}}})
	}
	return command
}

func agentUseFixtureCeiling(t *testing.T, f administratorFixture, revision uint64, key string, remove string) DepartmentAgentChangeReceipt {
	t.Helper()
	command := departmentAgentFixtureCommand(f, revision, key)
	command.Entries[0].Actions = nil
	for _, resource := range agentUseFixtureResources() {
		if resource.Action != remove {
			command.Entries[0].Actions = append(command.Entries[0].Actions, resource.Action)
		}
	}
	return departmentAgentFixtureCommit(t, f, command)
}

func TestSQLAgentUsePackageBatchActualDependenciesAndCeiling(t *testing.T) {
	f := newDepartmentAgentFixture(t)
	departmentAgentFixtureManager(t, f)
	resolver := &agentUseFixtureResolver{}
	command := agentUseFixtureBatch(t, f, resolver, "complete-agent-use-batch", "agent-use-a", "agent-use-b")
	agentUseFixtureCeiling(t, f, 0, "approve-package-ceiling", "")
	actor := f.actors[2]
	prepared := createPermissionBatchFixture(t, f, actor, command)
	for _, item := range prepared.Items {
		if item.Status != "pending" || item.Impact.AddedRoles != 2 || item.Impact.AddedResourceGrants != len(agentUseFixtureResources()) || item.Impact.ResourceCounts["model"] != 1 || item.Impact.ResourceCounts["skill"] != 1 {
			t.Fatal("package preview omitted actual dependency grants or Skill identity", item)
		}
	}
	for range command.Items {
		if _, err := f.store.ContinuePermissionBatch(f.ctx, actor, command.IdempotencyKey); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range prepared.Items {
		snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, item.SubjectID)
		if err != nil || len(snapshot.Grants) != 12 || len(snapshot.Bindings) != 2 || len(snapshot.Memberships) != 1 {
			t.Fatal("complete package did not produce actual role, membership and dependency facts", err)
		}
		for _, grant := range snapshot.Grants {
			decision, err := EvaluatePermission(snapshot, PermissionQuery{Action: grant.Action, Scope: grantAuthorizationScope(grant), ResourceType: grant.ResourceType, ResourceID: grant.ResourceID, Now: f.now})
			if err != nil || !decision.Allowed || grant.DataScope.Type != "owner" || grant.DepartmentAgentActionVersion == 0 {
				t.Fatal("package dependency is unusable or bypassed managed source metadata", grant.Action, decision, err)
			}
		}
		for _, action := range []string{"history.export", "history.share", "agent.develop", "administrator.appoint"} {
			decision, err := EvaluatePermission(snapshot, PermissionQuery{Action: action, Scope: command.Items[0].Authorization.AgentUse.Scope, ResourceType: "agent_installation", ResourceID: "fixture-installation", Now: f.now})
			if err != nil || decision.Allowed {
				t.Fatal("ordinary use package acquired sensitive or administrative authority", action, err)
			}
		}
	}
	agentUseFixtureCeiling(t, f, 1, "withdraw-model-from-package", "model.generate")
	agentUseFixtureCeiling(t, f, 2, "restore-model-after-review", "")
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, "agent-use-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range snapshot.Grants {
		decision, err := EvaluatePermission(snapshot, PermissionQuery{Action: grant.Action, Scope: grantAuthorizationScope(grant), ResourceType: grant.ResourceType, ResourceID: grant.ResourceID, Now: f.now})
		if err != nil || decision.Allowed == (grant.Action == "model.generate") {
			t.Fatal("restoring a ceiling resurrected old dependency source or revoked unrelated use", grant.Action, decision, err)
		}
	}
}

func TestSQLAgentUsePackageCatalogUpgradePreservesPublishedV1AndFacts(t *testing.T) {
	f := newDepartmentAgentFixture(t)
	departmentAgentFixtureUser(t, f, "catalog-upgrade-user")
	departmentAgentFixtureAuthorize(t, f, f.actors[1], AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: "catalog-upgrade-user", ExpectedRevision: 1, IdempotencyKey: "catalog-upgrade-existing-facts", Reason: "Preserve previously approved ordinary v1 business facts",
		Memberships: []MembershipMutation{{ID: "catalog-upgrade-member", Scope: ManagementScope{Type: "department", TenantID: f.actors[1].TenantID, DepartmentID: f.actors[1].DepartmentID}, Status: "active"}},
		Preset:      &PresetSelection{Code: "operator", Version: 1, Scope: ManagementScope{Type: "application", TenantID: f.actors[1].TenantID, DepartmentID: f.actors[1].DepartmentID, ApplicationID: f.actors[1].ApplicationID}, ResourceIDs: []string{"fixture-installation"}}})
	var roleHash, presetHash string
	if err := f.store.db.QueryRowContext(f.ctx, `SELECT content_hash FROM platform_identity_role_definition WHERE role_code='operator' AND role_version=1`).Scan(&roleHash); err != nil {
		t.Fatal(err)
	}
	if err := f.store.db.QueryRowContext(f.ctx, `SELECT content_hash FROM platform_identity_preset_definition WHERE preset_code='operator' AND preset_version=1`).Scan(&presetHash); err != nil {
		t.Fatal(err)
	}
	// Emulate the previous catalog in this owned fixture; no existing user is
	// bound to the new version. The real migrate command always runs EnsureSchema.
	if _, err := f.store.db.ExecContext(f.ctx, `DELETE FROM platform_identity_role_definition WHERE role_code='operator' AND role_version=2`); err != nil {
		t.Fatal(err)
	}
	before, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, "catalog-upgrade-user")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := f.store.EnsureSchema(f.ctx); err != nil {
			t.Fatal("catalog migration replay", err)
		}
	}
	for _, item := range []struct{ query, want string }{{`SELECT content_hash FROM platform_identity_role_definition WHERE role_code='operator' AND role_version=1`, roleHash}, {`SELECT content_hash FROM platform_identity_preset_definition WHERE preset_code='operator' AND preset_version=1`, presetHash}} {
		var got string
		if err := f.store.db.QueryRowContext(f.ctx, item.query).Scan(&got); err != nil || got != item.want {
			t.Fatal("new ordinary role replaced an immutable published v1 catalog entry", err)
		}
	}
	var count int
	if err := f.store.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_role_definition WHERE role_code=? AND role_version=?`), "operator", 2).Scan(&count); err != nil || count != 1 {
		t.Fatal("new ordinary role absent or duplicated after migration replay", err)
	}
	after, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, "catalog-upgrade-user")
	if err != nil || after.Principal.Revision != before.Principal.Revision || !reflect.DeepEqual(after.Bindings, before.Bindings) || !reflect.DeepEqual(after.Grants, before.Grants) || !reflect.DeepEqual(after.Memberships, before.Memberships) || len(after.Bindings) != 1 || len(after.Grants) != 5 {
		t.Fatal("catalog upgrade implicitly changed user rights", err)
	}
}

func TestSQLAgentUsePackagePinsReviewAndRollsBackUnknownAuditResult(t *testing.T) {
	f := newDepartmentAgentFixture(t)
	resolver := &agentUseFixtureResolver{}
	command := agentUseFixtureBatch(t, f, resolver, "package-pinned-review", "pinned-agent-user")
	plan, err := f.store.PreviewPermissionBatch(f.ctx, f.actors[1], command)
	if err != nil || plan.Items[0].Status != "pending" {
		t.Fatal(err)
	}
	resolver.version = "fixture-version-changed"
	if _, err := f.store.CreatePermissionBatch(f.ctx, f.actors[1], plan.Change); !errors.Is(err, ErrPermissionPlanStale) {
		t.Fatal("changed Agent version registered an old review", err)
	}
	resolver.version = ""
	batch, err := f.store.CreatePermissionBatch(f.ctx, f.actors[1], plan.Change)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("owned failure after package authorization audit")
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return failure })
	if _, err := f.store.ContinuePermissionBatch(f.ctx, f.actors[1], batch.Command.IdempotencyKey); !errors.Is(err, failure) {
		t.Fatal("unknown audit result was disguised as a business refusal", err)
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, "pinned-agent-user")
	if err != nil || snapshot.Principal.Revision != 1 || len(snapshot.Grants) != 0 || len(snapshot.Bindings) != 0 || len(snapshot.Memberships) != 0 {
		t.Fatal("failed package left partial permission facts", err)
	}
	reopened, err := f.store.GetPermissionBatch(f.ctx, f.actors[1], batch.Command.IdempotencyKey)
	if err != nil || reopened.Items[0].Status != "pending" {
		t.Fatal("unknown package item cannot be recovered under the original batch", err)
	}
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	resolver.policyDigest = strings.Repeat("b", 64)
	finished, err := f.store.ContinuePermissionBatch(f.ctx, f.actors[1], batch.Command.IdempotencyKey)
	if err != nil || finished.Items[0].Status != "failed" || finished.Items[0].FailureCode != "CONFLICT_REVIEW_REQUIRED" {
		t.Fatal("changed published policy continued an old package review", err)
	}
	snapshot, err = f.store.PermissionSnapshot(f.ctx, PrincipalUser, "pinned-agent-user")
	if err != nil || len(snapshot.Grants) != 0 || len(snapshot.Bindings) != 0 {
		t.Fatal("policy conflict committed package facts", err)
	}
}

func TestSQLAgentUsePackageRejectsUnauthorizedMixedAndIncompleteCeiling(t *testing.T) {
	f := newDepartmentAgentFixture(t)
	resolver := &agentUseFixtureResolver{}
	command := agentUseFixtureBatch(t, f, resolver, "blocked-package", "blocked-agent-user")
	scope := command.Items[0].Authorization.AgentUse.Scope
	unprivileged := departmentAgentFixtureUser(t, f, "unprivileged-package-reader")
	before := resolver.calls
	if _, err := f.store.AgentUsePackage(f.ctx, unprivileged, scope); !errors.Is(err, ErrPermissionDenied) || resolver.calls != before {
		t.Fatal("unprivileged package metadata read reached published resources", err)
	}
	otherCompany := scope
	otherCompany.TenantID = "other-company"
	if _, err := f.store.AgentUsePackage(f.ctx, f.actors[1], otherCompany); !errors.Is(err, ErrPermissionDenied) || resolver.calls != before {
		t.Fatal("package read crossed the actor's company", err)
	}
	change := *command.Items[0].Authorization
	change.IdempotencyKey, change.Reason = "mixed-package-review", "reject mixed direct grants"
	change.Grants = []Grant{{ID: "unreviewed-extra-grant"}}
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, f.actors[1], change); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("package accepted extra caller-supplied grants", err)
	}
	change.Grants = nil
	change.SubjectID = f.actors[1].PrincipalID
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, f.actors[1], change); err == nil {
		t.Fatal("administrator could open business use for self")
	}
	agentUseFixtureCeiling(t, f, 0, "incomplete-package-ceiling", "tool.invoke")
	plan, err := f.store.PreviewPermissionBatch(f.ctx, f.actors[1], command)
	if err != nil || plan.Items[0].Status != "blocked" || plan.Items[0].FailureCode != "PERMISSION_DENIED" {
		t.Fatal("package silently omitted an unapproved required dependency", err)
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, "blocked-agent-user")
	if err != nil || len(snapshot.Grants) != 0 || len(snapshot.Memberships) != 0 {
		t.Fatal("blocked package preview created partial facts", err)
	}
}
