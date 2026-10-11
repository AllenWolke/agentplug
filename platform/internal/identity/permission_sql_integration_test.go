package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type permissionTestResourceResolver struct{}

func (permissionTestResourceResolver) ResolveAgentInstallation(_ context.Context, scope sharedkernel.Scope, id string) (AgentInstallation, error) {
	if id != "installation-test" || scope.ApplicationID == "" {
		return AgentInstallation{}, ErrAgentInstallationNotFound
	}
	return AgentInstallation{AgentID: "fixture"}, nil
}

func TestSQLPermissionChangeAtomicRetryAndStalePlan(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s := NewSQLStore(db)
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsurePermissionSchema(ctx); err != nil {
		t.Fatal("migration replay", err)
	}
	outbox := notification.NewSQLStore(db)
	if err := outbox.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	auditStore := audit.NewSQLStoreWithOutbox(db, outbox)
	if err := auditStore.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("pv2-%d", time.Now().UnixNano())
	scope := ManagementScope{Type: "application", TenantID: prefix, DepartmentID: prefix + "-d", ApplicationID: prefix + "-a"}
	actorID, targetID := prefix+"-admin", prefix+"-user"
	for _, err := range []error{
		s.CreateTenant(ctx, Tenant{ID: scope.TenantID, Code: prefix, Name: "isolated", Status: "active", Revision: 1}),
		s.CreateDepartment(ctx, Department{ID: scope.DepartmentID, TenantID: scope.TenantID, Code: prefix, Name: "isolated", Status: "active", Revision: 1}),
		s.CreateApplication(ctx, Application{ID: scope.ApplicationID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, Code: prefix, Name: "isolated", Status: "active", Revision: 1}),
		s.CreatePrincipal(ctx, Principal{Type: PrincipalUser, ID: actorID, TenantID: scope.TenantID, IsActive: true}),
		s.CreatePrincipal(ctx, Principal{Type: PrincipalUser, ID: targetID, TenantID: scope.TenantID, IsActive: true}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{actorID, targetID} {
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',?,'v2',1,1)`), id); err != nil {
			t.Fatal(err)
		}
	}
	member := Membership{ID: prefix + "-membership", SubjectID: targetID, Scope: scope, Status: "active", Revision: 1}
	raw, _ := json.Marshal(member)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES(?,?,?,?,?,'active',1,?,?)`), member.ID, targetID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, string(raw), permissionHash(raw)); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = insertRoleBinding(ctx, tx, RoleBinding{ID: prefix + "-admin-binding", SubjectID: actorID, RoleCode: "super_admin", RoleVersion: 1, Scope: ManagementScope{Type: "global"}, Status: "active", Revision: 1, SourceID: "test-fixture"})
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	s.SetPermissionResourceResolver(permissionTestResourceResolver{})
	actor := sharedkernel.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, PrincipalType: "user", PrincipalID: actorID, TraceID: prefix}
	command := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: targetID, ExpectedRevision: 1, IdempotencyKey: prefix, Reason: "isolated transaction test", Bindings: []RoleBinding{{ID: prefix + "-operator", SubjectID: targetID, RoleCode: "operator", RoleVersion: 1, Scope: scope, Status: "active", Revision: 1, SourceID: prefix}}, Grants: []Grant{{ID: prefix + "-grant", SubjectType: PrincipalUser, SubjectID: targetID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: "installation-test", ResourceType: "agent_installation", ResourceID: "installation-test", Action: "run", Effect: "allow", Status: "active", Revision: 1, SourceID: prefix, DataScope: DataScope{Type: "owner"}}}}
	// Identical action/resource/data scope from independent sources must coexist.
	alternative := command.Grants[0]
	alternative.ID, alternative.SourceID = prefix+"-alternative", prefix+"-other-source"
	command.Grants = append(command.Grants, alternative)
	plan, err := s.PreviewAuthorizationChange(ctx, actor, command)
	if err != nil {
		t.Fatal(err)
	}
	command.PlanDigest, command.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	if _, err := s.CommitAuthorizationChange(ctx, actor, command); !errors.Is(err, ErrPermissionRecorderUnavailable) {
		t.Fatal("missing recorder accepted", err)
	}
	recorder := func(_ context.Context, tx *sql.Tx, scope sharedkernel.Scope, r AuthorizationChangeReceipt) error {
		return auditStore.RecordTx(tx, audit.Event{ID: r.ID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: "user", ActorID: r.ActorID, AggregateType: "identity_authorization_change", AggregateID: r.SubjectID, Action: "authorization.changed", Outcome: "success", Summary: r.Reason, CreatedAt: r.OccurredAt})
	}
	s.SetAuthorizationChangeRecorder(func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, r AuthorizationChangeReceipt) error {
		if err := recorder(ctx, tx, scope, r); err != nil {
			return err
		}
		return errors.New("injected failure after audit and outbox")
	})
	if _, err := s.CommitAuthorizationChange(ctx, actor, command); err == nil {
		t.Fatal("injected failure ignored")
	}
	for _, query := range []string{`SELECT COUNT(*) FROM platform_identity_role_binding WHERE subject_id=? AND role_code='operator'`, `SELECT COUNT(*) FROM platform_identity_grant WHERE subject_id=?`, `SELECT COUNT(*) FROM platform_identity_authorization_change WHERE subject_id=?`, `SELECT COUNT(*) FROM platform_audit_event WHERE aggregate_id=?`} {
		var count int
		if err := db.QueryRowContext(ctx, sqlutil.Bind(query), targetID).Scan(&count); err != nil || count != 0 {
			t.Fatal("transaction leaked rows", count, err)
		}
	}
	var notifications int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_notification_outbox WHERE tenant_id=?`), scope.TenantID).Scan(&notifications); err != nil || notifications != 0 {
		t.Fatal("outbox escaped rollback", notifications, err)
	}
	s.SetAuthorizationChangeRecorder(recorder)
	var wg sync.WaitGroup
	receipts := make(chan AuthorizationChangeReceipt, 6)
	failures := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := s.CommitAuthorizationChange(ctx, actor, command)
			if err != nil {
				failures <- err
			} else {
				receipts <- r
			}
		}()
	}
	wg.Wait()
	close(failures)
	close(receipts)
	for err := range failures {
		t.Error(err)
	}
	var receipt AuthorizationChangeReceipt
	for r := range receipts {
		if receipt.ID != "" && receipt.ID != r.ID {
			t.Error("retry produced multiple receipts")
		}
		receipt = r
	}
	if receipt.ID == "" {
		t.Fatal("no successful receipt")
	}
	var count int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_authorization_change WHERE subject_id=?`), targetID).Scan(&count); err != nil || count != 1 {
		t.Fatal("not idempotent", count, err)
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_notification_outbox WHERE tenant_id=?`), scope.TenantID).Scan(&count); err != nil || count != 1 {
		t.Fatal("outbox not atomic", count, err)
	}
	query := PermissionQuery{Action: "run", Scope: scope, ResourceType: "agent_installation", ResourceID: "installation-test"}
	decision, err := s.ResolvePermission(ctx, PrincipalUser, targetID, query)
	if err != nil || !decision.Allowed {
		t.Fatal("committed grant unusable", decision, err)
	}
	snapshot, err := s.PermissionSnapshot(ctx, PrincipalUser, targetID)
	if err != nil || len(snapshot.Grants) != 2 || snapshot.Grants[0].SourceID == snapshot.Grants[1].SourceID {
		t.Fatal("independent grant sources were collapsed", snapshot.Grants, err)
	}
	for _, grant := range snapshot.Grants {
		if grant.ResourceType != "agent_installation" || grant.ResourceID != "installation-test" || grant.DataScope.Type != "owner" {
			t.Fatal("grant permission payload was lost", grant)
		}
	}
	duplicate := alternative
	duplicate.ID = prefix + "-duplicate-source"
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	duplicateErr := insertPermissionGrant(ctx, tx, duplicate, time.Now())
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(duplicateErr, ErrIdentityConflict) {
		t.Fatal("same grant source bypassed database unique key", duplicateErr)
	}
	altered := command
	altered.Reason = "different payload"
	if _, err := s.CommitAuthorizationChange(ctx, actor, altered); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("idempotency digest conflict ignored", err)
	}
	revoke := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: targetID, ExpectedRevision: 2, IdempotencyKey: prefix + "-revoke", Reason: "revoke source", RevokeGrantIDs: []string{prefix + "-grant"}}
	preview, err := s.PreviewAuthorizationChange(ctx, actor, revoke)
	if err != nil {
		t.Fatal(err)
	}
	revoke.PlanDigest, revoke.PlanExpiresAt = preview.Digest, preview.ExpiresAt
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET revision=revision+1 WHERE id=?`), targetID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitAuthorizationChange(ctx, actor, revoke); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("stale baseline accepted", err)
	}
	revoke.ExpectedRevision = 3
	preview, err = s.PreviewAuthorizationChange(ctx, actor, revoke)
	if err != nil {
		t.Fatal(err)
	}
	revoke.PlanDigest, revoke.PlanExpiresAt = preview.Digest, preview.ExpiresAt
	if _, err := s.CommitAuthorizationChange(ctx, actor, revoke); err != nil {
		t.Fatal(err)
	}
	decision, err = s.ResolvePermission(ctx, PrincipalUser, targetID, query)
	if err != nil || !decision.Allowed {
		t.Fatal("revoking one source removed independent authorization", decision, err)
	}
	revoke.ExpectedRevision = 4
	revoke.IdempotencyKey = prefix + "-revoke-alternative"
	revoke.RevokeGrantIDs = []string{alternative.ID}
	preview, err = s.PreviewAuthorizationChange(ctx, actor, revoke)
	if err != nil {
		t.Fatal(err)
	}
	revoke.PlanDigest, revoke.PlanExpiresAt = preview.Digest, preview.ExpiresAt
	if _, err := s.CommitAuthorizationChange(ctx, actor, revoke); err != nil {
		t.Fatal(err)
	}
	decision, err = s.ResolvePermission(ctx, PrincipalUser, targetID, query)
	if err != nil || decision.Allowed {
		t.Fatal("all revoked sources accepted", decision, err)
	}
}
