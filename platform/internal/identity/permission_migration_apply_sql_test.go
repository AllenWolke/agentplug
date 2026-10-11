package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLMigrationMappingCommitPreservesSourceAndRollsBack(t *testing.T) {
	db := newEmptyMigrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s := NewSQLStore(db)
	outbox := notification.NewSQLStore(db)
	a := audit.NewSQLStoreWithOutbox(db, outbox)
	for _, ensure := range []func(context.Context) error{s.EnsureSchema, outbox.EnsureSchema, a.EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	scope := ManagementScope{Type: "application", TenantID: "migration-tenant", DepartmentID: "migration-department", ApplicationID: "migration-application"}
	for _, err := range []error{
		s.CreateTenant(ctx, Tenant{ID: scope.TenantID, Code: "migration", Name: "fixture", Status: "active", Revision: 1}),
		s.CreateDepartment(ctx, Department{ID: scope.DepartmentID, TenantID: scope.TenantID, Code: "migration", Name: "fixture", Status: "active", Revision: 1}),
		s.CreateApplication(ctx, Application{ID: scope.ApplicationID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, Code: "migration", Name: "fixture", Status: "active", Revision: 1}),
		s.CreatePrincipal(ctx, Principal{Type: PrincipalUser, ID: "migration-admin", TenantID: scope.TenantID, IsActive: true}),
		s.CreatePrincipal(ctx, Principal{Type: PrincipalUser, ID: "migration-user", TenantID: scope.TenantID, IsActive: true, Roles: []string{"operator"}}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES ('user','migration-admin','v2',1,1)`)); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertRoleBinding(ctx, tx, RoleBinding{ID: "migration-super", SubjectID: "migration-admin", RoleCode: "super_admin", RoleVersion: 1, Scope: ManagementScope{Type: "global"}, Status: "active", Revision: 1, SourceID: "fixture"}); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, g := range []Grant{
		{ID: "migration-allow", Action: "run", Effect: "allow", Status: "active"},
		{ID: "migration-deny", Action: "cancel", Effect: "deny", Status: "active"},
		{ID: "migration-revoked", Action: "events", Effect: "allow", Status: "revoked"},
	} {
		g.TenantID, g.DepartmentID, g.ApplicationID = scope.TenantID, scope.DepartmentID, scope.ApplicationID
		g.AgentInstanceID = "installation-test"
		g.SubjectType = PrincipalUser
		g.SubjectID = "migration-user"
		g.Revision = 1
		if err := s.CreateGrant(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE id='migration-user' AND principal_type='user'`)); err != nil {
		t.Fatal(err)
	}
	// Retain an actual persisted authentication row without logging its contents.
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_local_credential(principal_id,tenant_id,department_id,application_id,display_name,password_hash,auth_revision,active,created_at,updated_at) VALUES ('migration-user',?,?,?,'fixture','fixture-hash-not-a-login',7,FALSE,clock_timestamp(),clock_timestamp())`), scope.TenantID, scope.DepartmentID, scope.ApplicationID); err != nil {
		t.Fatal(err)
	}
	s.SetPermissionResourceResolver(permissionTestResourceResolver{})
	actor := sharedkernel.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, PrincipalType: "user", PrincipalID: "migration-admin"}
	batch, err := s.InspectMigrationSources(ctx, scope.TenantID, []MigrationSubject{{Type: PrincipalUser, ID: "migration-user"}})
	if err != nil {
		t.Fatal(err)
	}
	source := batch.Sources[0]
	raw, _ := json.Marshal(source.Snapshot)
	var target PermissionSnapshot
	if err := json.Unmarshal(raw, &target); err != nil {
		t.Fatal(err)
	}
	target.Mode = "v2"
	target.Memberships = []Membership{{ID: "migration-member", SubjectID: "migration-user", Scope: scope, Status: "active", Revision: 1}}
	target.Bindings = []RoleBinding{{ID: "migration-operator", SubjectID: "migration-user", RoleCode: "operator", RoleVersion: 1, Scope: scope, Status: "active", Revision: 1, SourceID: "reviewed-job"}}
	for i := range target.Grants {
		g := &target.Grants[i]
		if g.Status != "active" {
			continue
		}
		g.ResourceType = "agent_installation"
		g.ResourceID = "installation-test"
		if g.Effect == "deny" {
			g.DataScope = DataScope{Type: "approved_organization"}
		} else {
			g.DataScope = DataScope{Type: "owner"}
			g.Revision++
		}
	}
	mapping := MigrationMapping{ExpectedSourceDigest: source.SourceDigest, Basis: "reviewed source conversion, preserve disabled user and all deny/revoked facts", Target: target}
	fail := true
	s.SetAuthorizationChangeRecorder(func(_ context.Context, tx *sql.Tx, scope sharedkernel.Scope, r AuthorizationChangeReceipt) error {
		if err := a.RecordTx(tx, audit.Event{ID: r.ID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorID: r.ActorID, ActorType: "user", AggregateType: "identity_authorization_change", AggregateID: r.SubjectID, Action: "authorization.changed", Outcome: "success", Summary: r.Reason, CreatedAt: r.OccurredAt}); err != nil {
			return err
		}
		if fail {
			return errors.New("injected failure after actual audit and outbox")
		}
		return nil
	})
	if _, err := s.CommitMigrationMapping(ctx, actor, "migration-batch", mapping); err == nil {
		t.Fatal("migration ignored audit/outbox failure")
	}
	rolledBack, err := s.InspectMigrationSources(ctx, scope.TenantID, []MigrationSubject{{Type: PrincipalUser, ID: "migration-user"}})
	if err != nil || rolledBack.Sources[0].SourceDigest != source.SourceDigest {
		t.Fatal("source escaped rollback", err)
	}
	for _, query := range []string{`SELECT COUNT(*) FROM platform_identity_authorization_change`, `SELECT COUNT(*) FROM platform_audit_event`, `SELECT COUNT(*) FROM platform_notification_outbox`} {
		var n int
		if err := db.QueryRowContext(ctx, query).Scan(&n); err != nil || n != 0 {
			t.Fatal("receipt/audit/outbox escaped rollback", n, err)
		}
	}
	stale := mapping
	stale.ExpectedSourceDigest = permissionHash([]byte("stale"))
	if _, err := s.CommitMigrationMapping(ctx, actor, "stale-batch", stale); !errors.Is(err, ErrPermissionPlanStale) {
		t.Fatal("stale source accepted", err)
	}
	fail = false
	var wg sync.WaitGroup
	results := make(chan AuthorizationChangeReceipt, 6)
	failures := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := s.CommitMigrationMapping(ctx, actor, "migration-batch", mapping)
			if err != nil {
				failures <- err
			} else {
				results <- r
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	var receiptID string
	count := 0
	for r := range results {
		count++
		if receiptID != "" && receiptID != r.ID {
			t.Fatal("retry produced distinct receipts")
		}
		receiptID = r.ID
	}
	if count != 6 {
		t.Fatal("concurrent commits did not all resolve", count)
	}
	after, err := s.InspectMigrationSources(ctx, scope.TenantID, []MigrationSubject{{Type: PrincipalUser, ID: "migration-user"}})
	if err != nil {
		t.Fatal(err)
	}
	next := after.Sources[0]
	if next.Snapshot.Mode != "v2" || next.Snapshot.Principal.IsActive || next.Snapshot.Principal.ID != source.Snapshot.Principal.ID || !migrationEqual(next.Snapshot.Principal.Roles, source.Snapshot.Principal.Roles) || next.AuthenticationDigest != source.AuthenticationDigest || next.PermissionEpoch != source.PermissionEpoch+1 || len(next.Snapshot.Grants) != 3 || len(next.Snapshot.Bindings) != 1 || len(next.Snapshot.Memberships) != 1 {
		t.Fatal("migration lost preserved facts or epoch")
	}
	for _, g := range next.Snapshot.Grants {
		if g.ID == "migration-deny" && (g.Effect != "deny" || g.DataScope.Type != "approved_organization" || g.Revision != 1) {
			t.Fatal("legacy deny changed")
		}
		if g.ID == "migration-revoked" && g.Status != "revoked" {
			t.Fatal("revoked source revived")
		}
	}
	for _, query := range []string{`SELECT COUNT(*) FROM platform_identity_authorization_change`, `SELECT COUNT(*) FROM platform_audit_event`, `SELECT COUNT(*) FROM platform_notification_outbox`} {
		var n int
		if err := db.QueryRowContext(ctx, query).Scan(&n); err != nil || n != 1 {
			t.Fatal("retry duplicated receipt/audit/outbox", n, err)
		}
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_role_binding SET payload=jsonb_set(payload::jsonb,'{status}','"revoked"'::jsonb)::json,status='revoked' WHERE id='migration-super'`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitMigrationMapping(ctx, actor, "migration-batch", mapping); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("revoked administrator replay", err)
	}
}
