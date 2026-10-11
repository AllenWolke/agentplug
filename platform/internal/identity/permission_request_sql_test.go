package identity

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"sync"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func permissionApplicationCommand(f administratorFixture, key string) PermissionRequestCreate {
	a := f.actors[2]
	scope := ManagementScope{Type: "application", TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID}
	return PermissionRequestCreate{Scope: scope, IdempotencyKey: key, Reason: "request an operator identity and selected operations", Items: []PermissionRequestItem{
		{ID: "operator", Kind: "role", Scope: scope, RoleCode: "operator", RoleVersion: 1},
		{ID: "run", Kind: "resource", Scope: scope, ResourceID: "fixture-installation", Action: "run", DataScope: DataScope{Type: "owner"}},
		{ID: "export", Kind: "resource", Scope: scope, ResourceID: "fixture-installation", Action: "history.export", DataScope: DataScope{Type: "owner"}},
	}}
}

func applicationDecision(f administratorFixture, r PermissionRequest, key string) PermissionRequestDecision {
	return PermissionRequestDecision{RequestID: r.ID, ExpectedRevision: r.Revision, ExpectedSubjectRevision: 1, IdempotencyKey: key, Decision: "approved", ApprovedItemIDs: []string{"operator", "run"}, Reason: "grant identity and run only"}
}

func previewApplicationDecision(t *testing.T, f administratorFixture, c PermissionRequestDecision) PermissionRequestDecision {
	t.Helper()
	p, err := f.store.PreviewPermissionRequestDecision(f.ctx, f.actors[0], c)
	if err != nil {
		t.Fatal(err)
	}
	c.PlanDigest, c.PlanExpiresAt = p.Digest, p.ExpiresAt
	return c
}

func TestSQLPermissionRequestsSubsetAndAtomicAudit(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetPermissionResourceResolver(enrollmentFixtureResolver{})
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	c := permissionApplicationCommand(f, "subset")
	r, err := f.store.CreatePermissionRequest(f.ctx, f.actors[2], c)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range c.Items {
		if item.Outcome != "" {
			t.Fatal("request submission mutated caller data")
		}
	}
	prior, err := f.store.CreatePermissionRequest(f.ctx, f.actors[2], c)
	if err != nil || prior.ID != r.ID {
		t.Fatal("creation not idempotent", prior, err)
	}
	if _, err := f.store.PreviewPermissionRequestDecision(f.ctx, f.actors[2], applicationDecision(f, r, "self")); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("self approval allowed", err)
	}
	if _, _, err := f.store.ListPermissionRequests(f.ctx, f.actors[2], r.Scope, true, "", 1, 20); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("ordinary user read management queue", err)
	}
	decision := previewApplicationDecision(t, f, applicationDecision(f, r, "decide-subset"))
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error {
		return errors.New("request audit failure")
	})
	if _, err := f.store.DecidePermissionRequest(f.ctx, f.actors[0], decision); err == nil {
		t.Fatal("audit failure committed grants")
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, r.SubjectID)
	if err != nil || snapshot.Principal.Revision != 1 || len(snapshot.Bindings) != 0 || len(snapshot.Grants) != 0 {
		t.Fatal("partial authorization survived rollback", snapshot, err)
	}
	current, err := f.store.GetPermissionRequest(f.ctx, f.actors[2], r.ID)
	if err != nil || current.Status != "pending" || current.Revision != 1 {
		t.Fatal("request advanced despite rollback", current, err)
	}
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return nil })
	receipt, err := f.store.DecidePermissionRequest(f.ctx, f.actors[0], decision)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Authorization == nil || len(receipt.Authorization.Change.Grants) != 1 || len(receipt.Authorization.Change.Bindings) != 1 || receipt.Request.Items[2].Outcome != "rejected" || receipt.Request.Items[0].Outcome != "approved" {
		t.Fatal("subset outcomes or facts incorrect", receipt)
	}
	retry, err := f.store.DecidePermissionRequest(f.ctx, f.actors[0], decision)
	if err != nil || retry.Authorization.ID != receipt.Authorization.ID {
		t.Fatal("decision retry failed", retry, err)
	}
	owned, total, err := f.store.ListPermissionRequests(f.ctx, f.actors[2], r.Scope, false, "approved", 1, 20)
	if err != nil || total != 1 || len(owned) != 1 || owned[0].Items[2].Outcome != "rejected" {
		t.Fatal("owner cannot see per-item result", owned, total, err)
	}
	snapshot, err = f.store.PermissionSnapshot(f.ctx, PrincipalUser, r.SubjectID)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"run", "history.export"} {
		actual, err := EvaluatePermission(snapshot, PermissionQuery{Action: action, Scope: r.Scope, ResourceType: "agent_installation", ResourceID: "fixture-installation", Now: f.now})
		if err != nil || actual.Allowed != (action == "run") {
			t.Fatal("unapproved action granted or approved action denied", action, actual, err)
		}
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE principal_type='user' AND id=?`), f.actors[0].PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DecidePermissionRequest(f.ctx, f.actors[0], decision); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("disabled reviewer recovered receipt", err)
	}
}

func TestSQLPermissionRequestWithdrawalAndDecisionRace(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetPermissionResourceResolver(enrollmentFixtureResolver{})
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	r, err := f.store.CreatePermissionRequest(f.ctx, f.actors[2], permissionApplicationCommand(f, "race"))
	if err != nil {
		t.Fatal(err)
	}
	c := previewApplicationDecision(t, f, applicationDecision(f, r, "race-decision"))
	withdrawal := PermissionRequestWithdrawal{RequestID: r.ID, ExpectedRevision: 1, IdempotencyKey: "withdraw-race", Reason: "request no longer needed"}
	if _, err := f.store.WithdrawPermissionRequest(f.ctx, f.actors[0], withdrawal); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("another person withdrew request", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, err := f.store.WithdrawPermissionRequest(f.ctx, f.actors[2], withdrawal)
		results <- err
	}()
	go func() {
		defer wg.Done()
		<-start
		_, err := f.store.DecidePermissionRequest(f.ctx, f.actors[0], c)
		results <- err
	}()
	close(start)
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrIdentityConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("withdraw and approval both succeeded", success, conflict)
	}
	current, err := f.store.GetPermissionRequest(f.ctx, f.actors[2], r.ID)
	if err != nil || current.Revision != 2 {
		t.Fatal(current, err)
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, r.SubjectID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status == "withdrawn" && len(snapshot.Grants) != 0 || current.Status == "approved" && len(snapshot.Grants) != 1 {
		t.Fatal("status and permissions disagree", current, snapshot)
	}
}

func TestSQLPermissionRequestsBoundaryAndRejection(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetPermissionResourceResolver(enrollmentFixtureResolver{})
	c := permissionApplicationCommand(f, "boundaries")
	c.Items[0].RoleCode = "super_admin"
	if _, err := f.store.CreatePermissionRequest(f.ctx, f.actors[2], c); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("protected role accepted in ordinary request", err)
	}
	c = permissionApplicationCommand(f, "rejection")
	r, err := f.store.CreatePermissionRequest(f.ctx, f.actors[2], c)
	if err != nil {
		t.Fatal(err)
	}
	decision := applicationDecision(f, r, "reject-all")
	decision.Decision, decision.ApprovedItemIDs = "rejected", nil
	decision = previewApplicationDecision(t, f, decision)
	receipt, err := f.store.DecidePermissionRequest(f.ctx, f.actors[0], decision)
	if err != nil || receipt.Authorization != nil || receipt.Request.Status != "rejected" {
		t.Fatal(receipt, err)
	}
	for _, item := range receipt.Request.Items {
		if item.Outcome != "rejected" {
			t.Fatal("item result missing", item)
		}
	}
	other := permissionApplicationCommand(f, "self-admin")
	if _, err := f.store.CreatePermissionRequest(f.ctx, f.actors[0], other); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("administrator submitted a personal permission request", err)
	}
	// A request submitted before appointment remains historical data. Promotion
	// must neither enable self-review nor permit another personal request.
	r, err = f.store.CreatePermissionRequest(f.ctx, f.actors[2], other)
	if err != nil {
		t.Fatal(err)
	}
	appointment := f.command(2, "appoint-pending-request-owner")
	appointment.RoleCode, appointment.Scope = "super_admin", ManagementScope{Type: "global"}
	appointment = f.authenticate(t, 1, appointment)
	if _, err := f.store.AppointAdministrator(f.ctx, f.actors[1], appointment); err != nil {
		t.Fatal(err)
	}
	selfDecision := applicationDecision(f, r, "self-admin-review")
	selfDecision.ExpectedSubjectRevision = 2
	if _, err := f.store.PreviewPermissionRequestDecision(f.ctx, f.actors[2], selfDecision); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("super admin approved own request", err)
	}
	other.IdempotencyKey = "self-admin-after-appointment"
	if _, err := f.store.CreatePermissionRequest(f.ctx, f.actors[2], other); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("new administrator submitted a personal permission request", err)
	}
}
