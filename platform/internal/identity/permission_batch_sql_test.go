package identity

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func permissionBatchFixtureCommand(t *testing.T, f administratorFixture, key string, ids ...string) PermissionBatchCommand {
	t.Helper()
	actor := f.actors[1]
	department := ManagementScope{Type: "department", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID}
	app := ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	command := PermissionBatchCommand{Scope: department, Kind: "authorization", IdempotencyKey: key, Reason: "Department grants selected users approved Agent use"}
	for _, id := range ids {
		departmentAgentFixtureUser(t, f, id)
		command.Items = append(command.Items, PermissionBatchItemCommand{Authorization: &AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: id, ExpectedRevision: 1, Memberships: []MembershipMutation{{ID: id + "-member", Scope: department, Status: "active"}}, Preset: &PresetSelection{Code: "operator", Version: 1, Scope: app, ResourceIDs: []string{"fixture-installation"}}}})
	}
	return command
}

func createPermissionBatchFixture(t *testing.T, f administratorFixture, actor sharedkernel.Scope, command PermissionBatchCommand) PermissionBatch {
	t.Helper()
	plan, err := f.store.PreviewPermissionBatch(f.ctx, actor, command)
	if err != nil {
		t.Fatal("preview persistent batch", err)
	}
	batch, err := f.store.CreatePermissionBatch(f.ctx, actor, plan.Change)
	if err != nil {
		t.Fatal("prepare persistent batch", err)
	}
	return batch
}

func TestSQLPermissionBatchDepartmentRolesAndAutomaticRevocationImpact(t *testing.T) {
	f := newDepartmentAgentFixture(t)
	company := f.actors[1]
	department := ManagementScope{Type: "department", TenantID: company.TenantID, DepartmentID: company.DepartmentID}
	command := PermissionBatchCommand{Scope: department, Kind: "authorization", IdempotencyKey: "department-role-batch", Reason: "Company assigns two departmental administrators"}
	for _, id := range []string{"department-batch-admin-a", "department-batch-admin-b"} {
		departmentAgentFixtureUser(t, f, id)
		command.Items = append(command.Items, PermissionBatchItemCommand{Authorization: &AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: id, ExpectedRevision: 1,
			Memberships: []MembershipMutation{{ID: id + "-member", Scope: department, Status: "active"}}, Preset: &PresetSelection{Code: "department_admin", Version: 2, Scope: department}}})
	}
	batch := createPermissionBatchFixture(t, f, company, command)
	for _, item := range batch.Items {
		if item.Status != "pending" || item.Impact == nil || item.Impact.AddedRoles != 1 || item.Impact.ChangedMemberships != 1 || item.Impact.AddedResourceGrants != 0 {
			t.Fatal("company department role preview misrepresented the effects", item)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := f.store.ContinuePermissionBatch(f.ctx, company, command.IdempotencyKey); err != nil {
			t.Fatal(err)
		}
	}
	for index, id := range []string{"department-batch-admin-a", "department-batch-admin-b"} {
		snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, id)
		if err != nil || administrationKind(snapshot, f.now) != "department" || len(snapshot.Memberships) != 1 || len(snapshot.Grants) != 0 {
			t.Fatal("batch did not assign actual department administration without business grants", id, err)
		}
		if allowed, err := managementCapabilityAvailable(snapshot, PermissionQuery{Action: "membership.manage", Scope: department, Now: f.now}); err != nil || !allowed {
			t.Fatal("new department administrator cannot manage departmental members", err)
		}
		change := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: id, ExpectedRevision: snapshot.Principal.Revision,
			Memberships: []MembershipMutation{{ID: id + "-member", ExpectedRevision: snapshot.Memberships[0].Revision, Scope: department, Status: "active"}}}
		if index == 0 {
			change.RevokeBindingIDs = []string{snapshot.Bindings[0].ID}
		} else {
			change.Memberships[0].Status = "revoked"
		}
		operation := PermissionBatchCommand{Scope: department, Kind: "authorization", IdempotencyKey: id + "-remove-admin", Reason: "Company reviews explicit and automatic department role removal", Items: []PermissionBatchItemCommand{{Authorization: &change}}}
		prepared := createPermissionBatchFixture(t, f, company, operation)
		if prepared.Items[0].Impact == nil || len(prepared.Items[0].Impact.RevokedBindingIDs) != 1 || prepared.Items[0].Impact.RevokedBindingIDs[0] != snapshot.Bindings[0].ID {
			t.Fatal("preview omitted an explicit or automatic administrator role revocation", prepared.Items[0].Impact)
		}
		finished, err := f.store.ContinuePermissionBatch(f.ctx, company, operation.IdempotencyKey)
		if err != nil || finished.Items[0].Status != "succeeded" {
			t.Fatal("department role removal did not complete", err)
		}
		after, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, id)
		if err != nil || administrationKind(after, f.now) != "" {
			t.Fatal("removed department role remains effective", err)
		}
		if index == 0 && after.Memberships[0].Status != "active" || index == 1 && after.Memberships[0].Status != "revoked" {
			t.Fatal("batch applied the wrong membership outcome", after.Memberships)
		}
		if allowed, err := managementCapabilityAvailable(after, PermissionQuery{Action: "membership.manage", Scope: department, Now: f.now}); err != nil || allowed {
			t.Fatal("removed departmental administrator retained member management", err)
		}
	}
}

func TestSQLPermissionBatchPartialConflictRecoveryAndConcurrentProgress(t *testing.T) {
	f := newDepartmentAgentFixture(t)
	departmentAgentFixtureManager(t, f)
	departmentAgentFixtureCommit(t, f, departmentAgentFixtureCommand(f, 0, "batch-managed-department"))
	command := permissionBatchFixtureCommand(t, f, "partial-batch", "batch-user-a", "batch-user-b", "batch-user-c", "batch-user-removed")
	actor := f.actors[2]
	plan, err := f.store.PreviewPermissionBatch(f.ctx, actor, command)
	if err != nil || len(plan.Items) != 4 {
		t.Fatal("preview all selected members", err)
	}
	if plan.Items[0].Impact == nil || plan.Items[0].Impact.AddedRoles != 1 || plan.Items[0].Impact.AddedResourceGrants != 5 || plan.Items[0].Impact.ChangedMemberships != 1 {
		t.Fatal("batch preview omitted actual role, Agent grant or membership impact", plan.Items[0].Impact)
	}
	var batches int
	if err := f.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM platform_identity_permission_batch`).Scan(&batches); err != nil || batches != 0 {
		t.Fatal("preview persisted a batch", err)
	}
	batch, err := f.store.CreatePermissionBatch(f.ctx, actor, plan.Change)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"batch-user-a", "batch-user-b", "batch-user-c"} {
		principal, err := f.store.GetPrincipal(f.ctx, PrincipalUser, id)
		if err != nil || principal.Revision != 1 {
			t.Fatal("preparing batch granted authority", err)
		}
	}
	if replay, err := f.store.CreatePermissionBatch(f.ctx, actor, plan.Change); err != nil || replay.ID != batch.ID {
		t.Fatal("same preparation did not return original batch", err)
	}
	changed := plan.Change
	changed.Reason += " changed"
	if _, err := f.store.CreatePermissionBatch(f.ctx, actor, changed); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("same key accepted changed command", err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET revision=revision+1 WHERE principal_type='user' AND id=?`), "batch-user-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, `DELETE FROM platform_identity_principal WHERE principal_type='user' AND id='batch-user-removed'`); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := f.store.ContinuePermissionBatch(f.ctx, actor, command.IdempotencyKey)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("concurrent progress", err)
		}
	}
	reopened := NewSQLStore(f.db)
	reopened.clock = f.store.clock
	finished, err := reopened.GetPermissionBatch(f.ctx, actor, command.IdempotencyKey)
	if err != nil || finished.Items[0].Status != "succeeded" || finished.Items[1].Status != "failed" || finished.Items[1].FailureCode != "CONFLICT_REVIEW_REQUIRED" || finished.Items[2].Status != "succeeded" || finished.Items[3].Status != "failed" || finished.Items[3].FailureCode != "INVALID_OR_UNAVAILABLE" {
		t.Fatal("partial results did not survive repository reopen", err)
	}
	var receipts int
	if err := f.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM platform_identity_authorization_change WHERE subject_id IN ('batch-user-a','batch-user-b','batch-user-c')`).Scan(&receipts); err != nil || receipts != 2 {
		t.Fatal("concurrent batch duplicated or lost per-user receipts", receipts, err)
	}
	for index, item := range finished.Items {
		if index == 3 {
			continue // The isolated recipient was physically removed above.
		}
		user := actor
		user.PrincipalID = item.SubjectID
		departmentAgentFixtureDecision(t, f, user, "run", index != 1)
	}
	if _, err := f.store.GetPermissionBatch(f.ctx, f.actors[1], command.IdempotencyKey); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("another actor could query the batch by the original key", err)
	}
}

func TestSQLPermissionBatchAuditFaultCancellationAndLostAuthority(t *testing.T) {
	f := newDepartmentAgentFixture(t)
	departmentAgentFixtureManager(t, f)
	departmentAgentFixtureCommit(t, f, departmentAgentFixtureCommand(f, 0, "batch-fault-department"))
	command := permissionBatchFixtureCommand(t, f, "fault-batch", "fault-batch-user-a", "fault-batch-user-b")
	actor := f.actors[2]
	createPermissionBatchFixture(t, f, actor, command)
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error {
		return errors.New("owned batch audit failure")
	})
	if _, err := f.store.ContinuePermissionBatch(f.ctx, actor, command.IdempotencyKey); err == nil {
		t.Fatal("audit outage was accepted")
	}
	pending, err := f.store.GetPermissionBatch(f.ctx, actor, command.IdempotencyKey)
	if err != nil || pending.Items[0].Status != "pending" {
		t.Fatal("audit fault was recorded as a confirmed result", err)
	}
	principal, err := f.store.GetPrincipal(f.ctx, PrincipalUser, "fault-batch-user-a")
	if err != nil || principal.Revision != 1 {
		t.Fatal("audit failure did not roll back personal authorization", err)
	}
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	if _, err := f.store.ContinuePermissionBatch(f.ctx, actor, command.IdempotencyKey); err != nil {
		t.Fatal(err)
	}
	cancelled, err := f.store.CancelPermissionBatch(f.ctx, actor, command.IdempotencyKey)
	if err != nil || cancelled.Items[0].Status != "succeeded" || cancelled.Items[1].Status != "cancelled" {
		t.Fatal("cancel did not preserve completed authority", err)
	}
	if _, err := f.store.ContinuePermissionBatch(f.ctx, actor, command.IdempotencyKey); err != nil {
		t.Fatal("completed batch continuation was not a no-op", err)
	}
	user := actor
	user.PrincipalID = "fault-batch-user-a"
	departmentAgentFixtureDecision(t, f, user, "run", true)
	user.PrincipalID = "fault-batch-user-b"
	departmentAgentFixtureDecision(t, f, user, "run", false)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_role_binding SET status='revoked',revision=revision+1,payload=jsonb_set(payload::jsonb,'{status}','"revoked"'::jsonb)::json WHERE subject_id=? AND role_code='department_admin'`), actor.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.GetPermissionBatch(f.ctx, actor, command.IdempotencyKey); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("lost management authority could read old batch details", err)
	}
	if _, err := f.store.ContinuePermissionBatch(f.ctx, actor, command.IdempotencyKey); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("lost management authority could continue", err)
	}
}

func TestSQLPermissionBatchApprovalsAreAtomicAndRespectWithdrawal(t *testing.T) {
	f := newDepartmentAgentFixture(t)
	f.store.SetPermissionResourceResolver(enrollmentFixtureResolver{})
	actor := f.actors[1]
	app := ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	command := PermissionBatchCommand{Scope: app, Kind: "decision", IdempotencyKey: "decision-batch", Reason: "Approve selected basic requested roles"}
	requests := []PermissionRequest{}
	for _, id := range []string{"approval-batch-user-a", "approval-batch-user-b"} {
		user := departmentAgentFixtureUser(t, f, id)
		admission := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: id, ExpectedRevision: 1, IdempotencyKey: id + "-admit", Reason: "admit batch applicant", Memberships: []MembershipMutation{{ID: id + "-member", Scope: app, Status: "active"}}}
		departmentAgentFixtureAuthorize(t, f, actor, admission)
		request, err := f.store.CreatePermissionRequest(f.ctx, user, PermissionRequestCreate{Scope: app, IdempotencyKey: id + "-apply", Reason: "Request business operator and export", Items: []PermissionRequestItem{{ID: "operator", Kind: "role", RoleCode: "operator", RoleVersion: 1, Scope: app}, {ID: "export", Kind: "resource", ResourceID: "fixture-installation", Action: "history.export", Scope: app, DataScope: DataScope{Type: "owner"}}}})
		if err != nil {
			t.Fatal(err)
		}
		requests = append(requests, request)
		command.Items = append(command.Items, PermissionBatchItemCommand{Decision: &PermissionRequestDecision{RequestID: request.ID, ExpectedRevision: request.Revision, ExpectedSubjectRevision: 2, Decision: "approved", ApprovedItemIDs: []string{"operator"}}})
	}
	prepared := createPermissionBatchFixture(t, f, actor, command)
	if prepared.Items[0].Impact == nil || prepared.Items[0].Impact.ApprovedItems != 1 || prepared.Items[0].Impact.RejectedItems != 1 {
		t.Fatal("approval impact omitted the requested export rejection", prepared.Items[0].Impact)
	}
	if _, err := f.store.WithdrawPermissionRequest(f.ctx, sharedkernel.Scope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, PrincipalID: requests[1].SubjectID, PrincipalType: "user"}, PermissionRequestWithdrawal{RequestID: requests[1].ID, ExpectedRevision: requests[1].Revision, IdempotencyKey: "batch-user-withdraws", Reason: "Applicant withdraws"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := f.store.ContinuePermissionBatch(f.ctx, actor, command.IdempotencyKey); err != nil {
			t.Fatal(err)
		}
	}
	finished, err := f.store.GetPermissionBatch(f.ctx, actor, command.IdempotencyKey)
	if err != nil || finished.Items[0].Status != "succeeded" || finished.Items[1].Status != "failed" || finished.Items[0].Decision == nil || finished.Items[0].Decision.Request.Status != "approved" {
		t.Fatal("batch decision results incorrect", err)
	}
	if finished.Items[0].Decision.Request.Items[1].Outcome == "approved" {
		t.Fatal("unselected export was approved by the batch")
	}
	request, err := f.store.GetPermissionRequest(f.ctx, actor, requests[1].ID)
	if err != nil || request.Status != "withdrawn" {
		t.Fatal("batch overwrote applicant withdrawal", err)
	}
}

func TestSQLPermissionBatchPendingCeilingExpiryAndCorruption(t *testing.T) {
	f := newDepartmentAgentFixture(t)
	departmentAgentFixtureManager(t, f)
	departmentAgentFixtureCommit(t, f, departmentAgentFixtureCommand(f, 0, "batch-pending-ceiling"))
	actor := f.actors[2]
	command := permissionBatchFixtureCommand(t, f, "ceiling-pending-batch", "pending-batch-user-a", "pending-batch-user-b")
	createPermissionBatchFixture(t, f, actor, command)
	if _, err := f.store.ContinuePermissionBatch(f.ctx, actor, command.IdempotencyKey); err != nil {
		t.Fatal(err)
	}
	withdrawal := departmentAgentFixtureCommand(f, 1, "batch-ceiling-withdrawn")
	withdrawal.Entries = nil
	departmentAgentFixtureCommit(t, f, withdrawal)
	batch, err := f.store.ContinuePermissionBatch(f.ctx, actor, command.IdempotencyKey)
	if err != nil || batch.Items[0].Status != "succeeded" || batch.Items[1].Status != "failed" || batch.Items[1].FailureCode != "PERMISSION_DENIED" {
		t.Fatal("pending batch ignored withdrawn company Agent ceiling", err)
	}
	for _, id := range []string{"pending-batch-user-a", "pending-batch-user-b"} {
		user := actor
		user.PrincipalID = id
		departmentAgentFixtureDecision(t, f, user, "run", false)
	}
	departmentAgentFixtureCommit(t, f, departmentAgentFixtureCommand(f, 2, "batch-ceiling-restored"))
	user := actor
	user.PrincipalID = "pending-batch-user-a"
	departmentAgentFixtureDecision(t, f, user, "run", false)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_permission_batch SET payload=jsonb_set(payload,'{items,1,command,authorization,subject_id}','"tampered-recipient"'::jsonb) WHERE id=?`), batch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.GetPermissionBatch(f.ctx, actor, command.IdempotencyKey); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("corrupt persisted command was displayed as valid", err)
	}
	if _, err := f.store.ContinuePermissionBatch(f.ctx, actor, command.IdempotencyKey); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("corrupt persisted command could be continued", err)
	}
	expiring := permissionBatchFixtureCommand(t, f, "expired-pending-batch", "expired-batch-user")
	createPermissionBatchFixture(t, f, actor, expiring)
	f.store.clock = func() time.Time { return f.now.Add(6 * time.Minute) }
	expired, err := f.store.ContinuePermissionBatch(f.ctx, actor, expiring.IdempotencyKey)
	if err != nil || expired.Items[0].Status != "failed" || expired.Items[0].FailureCode != "CONFLICT_REVIEW_REQUIRED" {
		t.Fatal("expired batch preview still produced permission", err)
	}
}
