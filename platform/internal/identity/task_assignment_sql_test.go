package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"testing"
	"time"
)

type assignmentResolverFixture struct {
	object DataObject
	err    error
}

func TestSQLTaskAssignmentNaturalValidityPersistsEpoch(t *testing.T) {
	f := newAdministratorFixture(t)
	actor := f.actors[2]
	app := ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	resource := app
	resource.Type, resource.ResourceID = "agent_installation", "installation-test"
	starts, expires := f.now.Add(time.Minute), f.now.Add(2*time.Minute)
	object := DataObject{ID: "temporal-task", OwnerID: "other-owner", Scope: resource}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := insertRoleBinding(f.ctx, tx, RoleBinding{ID: "temporal-operator", SubjectID: actor.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := insertPermissionGrant(f.ctx, tx, Grant{ID: "temporal-run", SubjectType: PrincipalUser, SubjectID: actor.PrincipalID, TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, AgentInstanceID: resource.ResourceID, ResourceType: "agent_installation", ResourceID: resource.ResourceID, Action: "run", Effect: "allow", Status: "active", Revision: 1, SourceID: "fixture", DataScope: DataScope{Type: "owner"}}, f.now); err != nil {
		t.Fatal(err)
	}
	if err := insertTaskAssignment(f.ctx, tx, TaskAssignment{ID: "temporal-assignment", SubjectID: actor.PrincipalID, TaskID: object.ID, Action: "history.read", Scope: resource, Status: "active", Revision: 1, SourceID: "fixture", TaskObject: &object, Validity: Validity{StartsAt: &starts, ExpiresAt: &expires}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	cursor := f.now
	f.store.clock = func() time.Time { return cursor }
	actor.AgentInstanceID = resource.ResourceID
	for index, at := range []time.Time{f.now, starts, expires} {
		cursor = at
		epoch, err := f.store.CurrentAuthorizationEpoch(f.ctx, actor, "run")
		if err != nil || epoch != uint64(index+1) {
			t.Fatal("assignment natural state did not advance live epoch", epoch, err)
		}
	}
	var revision uint64
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_policy_migration WHERE principal_type='user' AND subject_id=?`), actor.PrincipalID).Scan(&revision); err != nil || revision != 1 {
		t.Fatal("natural assignment boundary rewrote permission revision", revision, err)
	}
	restarted := NewSQLStore(f.db)
	restarted.clock = func() time.Time { return cursor }
	epoch, err := restarted.CurrentAuthorizationEpoch(f.ctx, actor, "run")
	if err != nil || epoch != 3 {
		t.Fatal("assignment epoch lost on store restart", epoch, err)
	}
}

func (r *assignmentResolverFixture) ResolvePermissionTask(context.Context, sharedkernel.Scope, ManagementScope, string) (DataObject, error) {
	return r.object, r.err
}

func TestSQLTaskAssignmentAtomicCASIdempotencyAndRevocation(t *testing.T) {
	f := newAdministratorFixture(t)
	actor, target := f.actors[0], f.actors[2]
	app := ManagementScope{Type: "application", TenantID: target.TenantID, DepartmentID: target.DepartmentID, ApplicationID: target.ApplicationID}
	resource := app
	resource.Type, resource.ResourceID = "agent_installation", "installation-test"
	resolver := &assignmentResolverFixture{object: DataObject{ID: "actual-task", OwnerID: "actual-other-owner", ActorID: "actual-other-owner", Scope: resource}}
	f.store.SetPermissionTaskResolver(resolver)
	f.store.SetPermissionResourceResolver(permissionTestResourceResolver{})
	notifications := notification.NewSQLStore(f.db)
	if err := notifications.EnsureSchema(f.ctx); err != nil {
		t.Fatal(err)
	}
	audits := audit.NewSQLStoreWithOutbox(f.db, notifications)
	if err := audits.EnsureSchema(f.ctx); err != nil {
		t.Fatal(err)
	}
	record := func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, r AuthorizationChangeReceipt) error {
		return audits.RecordTx(tx, audit.Event{ID: r.ID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: "user", ActorID: r.ActorID, AggregateType: "identity_authorization_change", AggregateID: r.SubjectID, Action: "authorization.changed", Outcome: "success", Summary: r.Reason, CreatedAt: r.OccurredAt})
	}
	command := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: target.PrincipalID, ExpectedRevision: 1, IdempotencyKey: "assign-original", Reason: "assign an actual scoped task", Assignments: []TaskAssignment{{ID: "assignment", SubjectID: target.PrincipalID, TaskID: "actual-task", Action: "business.content.read", Scope: resource, Status: "active", Revision: 1, SourceID: "first-source"}}}
	plan, err := f.store.PreviewAuthorizationChange(f.ctx, actor, command)
	if err != nil || len(plan.ExpandedAssignments) != 1 || plan.ExpandedAssignments[0].TaskObject.OwnerID != resolver.object.OwnerID || command.Assignments[0].TaskObject != nil || plan.Command.Assignments[0].TaskObject != nil {
		t.Fatal("invalid preview or mutated original request", plan, err)
	}
	command.PlanDigest, command.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	f.store.SetAuthorizationChangeRecorder(func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, r AuthorizationChangeReceipt) error {
		if err := record(ctx, tx, scope, r); err != nil {
			return err
		}
		return errors.New("injected outbox failure")
	})
	if _, err := f.store.CommitAuthorizationChange(f.ctx, actor, command); err == nil {
		t.Fatal("audit failure ignored")
	}
	for _, query := range []string{`SELECT COUNT(*) FROM platform_identity_task_assignment`, `SELECT COUNT(*) FROM platform_audit_event`, `SELECT COUNT(*) FROM platform_notification_outbox`, `SELECT COUNT(*) FROM platform_identity_authorization_change`} {
		var count int
		if err := f.db.QueryRowContext(f.ctx, query).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed transaction leaked", query, count, err)
		}
	}
	f.store.SetAuthorizationChangeRecorder(record)
	resolver.object.OwnerID = "changed-owner"
	if _, err := f.store.CommitAuthorizationChange(f.ctx, actor, command); !errors.Is(err, ErrPermissionPlanStale) {
		t.Fatal("changed task metadata did not invalidate preview", err)
	}
	resolver.object.OwnerID = "actual-other-owner"
	receipt, err := f.store.CommitAuthorizationChange(f.ctx, actor, command)
	if err != nil || receipt.Revision != 2 || len(receipt.Change.Assignments) != 1 {
		t.Fatal(receipt, err)
	}
	replay, err := f.store.CommitAuthorizationChange(f.ctx, actor, command)
	if err != nil || replay.ID != receipt.ID {
		t.Fatal("retry failed", replay, err)
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, target.PrincipalID)
	if err != nil || len(snapshot.Assignments) != 1 || len(snapshot.Bindings) != 0 || len(snapshot.Grants) != 0 {
		t.Fatal("assignment supplied business permissions", snapshot, err)
	}
	// Same task can retain a different source when the first assignment is revoked.
	second := command
	second.ExpectedRevision, second.IdempotencyKey = 2, "assign-second"
	second.Assignments = append([]TaskAssignment(nil), command.Assignments...)
	second.Assignments[0].ID, second.Assignments[0].SourceID = "assignment-second", "second-source"
	plan, err = f.store.PreviewAuthorizationChange(f.ctx, actor, second)
	if err != nil {
		t.Fatal(err)
	}
	second.PlanDigest, second.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	if _, err = f.store.CommitAuthorizationChange(f.ctx, actor, second); err != nil {
		t.Fatal(err)
	}
	revoke := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: target.PrincipalID, ExpectedRevision: 3, IdempotencyKey: "revoke-first", Reason: "revoke one assignment source", RevokeAssignmentIDs: []string{"assignment"}}
	plan, err = f.store.PreviewAuthorizationChange(f.ctx, actor, revoke)
	if err != nil {
		t.Fatal(err)
	}
	revoke.PlanDigest, revoke.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	if _, err = f.store.CommitAuthorizationChange(f.ctx, actor, revoke); err != nil {
		t.Fatal(err)
	}
	snapshot, err = f.store.PermissionSnapshot(f.ctx, PrincipalUser, target.PrincipalID)
	if err != nil || snapshot.Assignments[0].Status != "revoked" || snapshot.Assignments[1].Status != "active" {
		t.Fatal(snapshot.Assignments, err)
	}
	// Removing the member retires all remaining task facts, so rejoining does not revive them.
	remove := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: target.PrincipalID, ExpectedRevision: 4, IdempotencyKey: "remove-assigned-member", Reason: "remove assigned member", Memberships: []MembershipMutation{{ID: target.PrincipalID + "-member", ExpectedRevision: 1, Scope: app, Status: "revoked"}}}
	plan, err = f.store.PreviewAuthorizationChange(f.ctx, actor, remove)
	if err != nil || len(plan.AutomaticRevokeAssignmentIDs) != 1 {
		t.Fatal(plan, err)
	}
	remove.PlanDigest, remove.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	if _, err = f.store.CommitAuthorizationChange(f.ctx, actor, remove); err != nil {
		t.Fatal(err)
	}
	snapshot, err = f.store.PermissionSnapshot(f.ctx, PrincipalUser, target.PrincipalID)
	if err != nil || snapshot.Assignments[1].Status != "revoked" {
		t.Fatal(snapshot.Assignments, err)
	}
}

func TestSQLTaskAssignmentDelegationAndInputBoundary(t *testing.T) {
	f := newAdministratorFixture(t)
	actor, target := f.actors[0], f.actors[2]
	app := ManagementScope{Type: "application", TenantID: target.TenantID, DepartmentID: target.DepartmentID, ApplicationID: target.ApplicationID}
	resource := app
	resource.Type, resource.ResourceID = "agent_installation", "installation-test"
	resolver := &assignmentResolverFixture{object: DataObject{ID: "known-task", OwnerID: "other-owner", Scope: resource}}
	f.store.SetPermissionTaskResolver(resolver)
	end := f.now.Add(time.Hour)
	command := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: target.PrincipalID, ExpectedRevision: 1, IdempotencyKey: "bounded-assignment", Reason: "task assignment delegation test", Assignments: []TaskAssignment{{ID: "bounded", SubjectID: target.PrincipalID, TaskID: "known-task", Action: "business.review", Scope: resource, Status: "active", Revision: 1, SourceID: "bounded-source", Validity: Validity{ExpiresAt: &end}}}}
	for _, name := range []string{"browser-metadata", "unknown-task", "wrong-installation", "machine-target"} {
		t.Run(name, func(t *testing.T) {
			c := command
			c.Assignments = append([]TaskAssignment(nil), command.Assignments...)
			resolver.object.ID, resolver.object.Scope = "known-task", resource
			switch name {
			case "browser-metadata":
				c.Assignments[0].TaskObject = &resolver.object
			case "unknown-task":
				resolver.object.ID = "other-task"
			case "wrong-installation":
				resolver.object.Scope.ResourceID = "other-installation"
			case "machine-target":
				c.SubjectType = PrincipalServicePrincipal
			}
			if _, err := f.store.PreviewAuthorizationChange(f.ctx, actor, c); err == nil {
				t.Fatal("invalid assignment accepted")
			}
		})
	}
	resolver.object.ID, resolver.object.Scope = "known-task", resource
	// Demote the fixture caller to a permission administrator; the other super administrator remains.
	b := RoleBinding{ID: f.bindings[0], SubjectID: actor.PrincipalID, RoleCode: "permission_admin", RoleVersion: 1, Scope: app, Status: "active", Revision: 2, SourceID: "fixture"}
	raw, _ := json.Marshal(b)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_role_binding SET role_code='permission_admin',revision=2,payload=? WHERE id=?`), string(raw), b.ID); err != nil {
		t.Fatal(err)
	}
	d := Delegation{ID: "task-delegation", SubjectID: actor.PrincipalID, Scope: app, ManagementActions: []string{"authorization.change"}, Actions: []string{"business.review"}, Resources: []string{"installation-test"}, DataScopeTypes: []string{"explicit_set"}, DataIDs: []string{"known-task"}, MaxDurationSeconds: 3600, Status: "active", Revision: 1, Validity: Validity{ExpiresAt: &end}}
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, actor, command); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("undelegated assignment accepted", err)
	}
	raw, _ = json.Marshal(d)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_delegation(id,subject_id,tenant_id,department_id,application_id,status,revision,payload) VALUES(?,?,?,?,?,'active',1,?)`), d.ID, d.SubjectID, app.TenantID, app.DepartmentID, app.ApplicationID, string(raw)); err != nil {
		t.Fatal(err)
	}
	plan, err := f.store.PreviewAuthorizationChange(f.ctx, actor, command)
	if err != nil || plan.ExpandedAssignments[0].DelegationID != d.ID {
		t.Fatal(plan, err)
	}
	c := command
	c.Assignments = append([]TaskAssignment(nil), command.Assignments...)
	c.Assignments[0].Action = "history.read"
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, actor, c); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("assignment action escaped delegation", err)
	}
	c.Assignments[0].Action = "business.review"
	later := end.Add(time.Second)
	c.Assignments[0].ExpiresAt = &later
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, actor, c); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("assignment lifetime escaped delegation", err)
	}
	c.Assignments[0].ExpiresAt = &end
	c.Assignments[0].TaskID = "other-task"
	resolver.object.ID = "other-task"
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, actor, c); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("assignment task escaped delegation", err)
	}
}
