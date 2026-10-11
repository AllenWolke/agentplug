package identity

import (
	"context"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Independent PostgreSQL only: verify actual grant/identity generations survive
// connection changes and reject revoked grants, not just in-memory stubs.
// 仅使用独立 PostgreSQL，验证真实授权/身份版本与撤权拒绝，不以假仓储代替持久化。
func TestSQLAuthorizationEpochTracksIAMAndRejectsRevocation(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal("open isolated IAM fixture failed")
	}
	defer db.Close()
	store := NewSQLStore(db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	id := "iam-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	scope := sharedkernel.Scope{TenantID: id, DepartmentID: id + "-d", ApplicationID: id + "-a", AgentInstanceID: id + "-i", InstallationID: id + "-i", AgentID: "example-agent", AgentVersionID: "v1", PrincipalType: "user", PrincipalID: id + "-u"}
	for _, err := range []error{
		store.CreateTenant(ctx, Tenant{ID: scope.TenantID, Code: id, Name: "isolated", Status: "active", Revision: 1}),
		store.CreateDepartment(ctx, Department{ID: scope.DepartmentID, TenantID: scope.TenantID, Code: "department", Name: "isolated", Status: "active", Revision: 1}),
		store.CreateApplication(ctx, Application{ID: scope.ApplicationID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, Code: "app", Name: "isolated", Status: "active", Revision: 1}),
		store.CreatePrincipal(ctx, Principal{ID: scope.PrincipalID, Type: PrincipalUser, TenantID: scope.TenantID, Roles: []string{"operator"}, IsActive: true, Revision: 1}),
		store.CreateGrant(ctx, Grant{ID: id + "-grant", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: scope.AgentInstanceID, SubjectType: PrincipalUser, SubjectID: scope.PrincipalID, Action: "run", Effect: "allow", Status: GrantActive, Revision: 1}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	epoch, err := store.CurrentAuthorizationEpoch(ctx, scope, "run")
	if err != nil || epoch != 1 {
		t.Fatalf("first IAM epoch: %d %v", epoch, err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			got, err := store.CurrentAuthorizationEpoch(ctx, scope, "run")
			if err != nil || got != epoch {
				t.Errorf("concurrent IAM version: %d %v", got, err)
			}
		}()
	}
	workers.Wait()
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET revision=revision+1 WHERE id=? AND principal_type='user'`), scope.PrincipalID); err != nil {
		t.Fatal(err)
	}
	newEpoch, err := store.CurrentAuthorizationEpoch(ctx, scope, "run")
	if err != nil || newEpoch != epoch+1 {
		t.Fatalf("principal change did not advance epoch: %d %v", newEpoch, err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_application SET revision=revision+1 WHERE id=? AND tenant_id=?`), scope.ApplicationID, scope.TenantID); err != nil {
		t.Fatal(err)
	}
	newEpoch, err = NewSQLStore(db).CurrentAuthorizationEpoch(ctx, scope, "run")
	if err != nil || newEpoch != epoch+2 {
		t.Fatalf("application change did not persist epoch: %d %v", newEpoch, err)
	}
	forged := scope
	forged.ApplicationID = "other-application"
	if got, err := store.CurrentAuthorizationEpoch(ctx, forged, "run"); err == nil || got != 0 {
		t.Fatal("forged scope accepted")
	}
	if err := store.RevokeGrant(ctx, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentInstanceID, id+"-grant", 1); err != nil {
		t.Fatal(err)
	}
	if got, err := store.CurrentAuthorizationEpoch(ctx, scope, "run"); err == nil || got != 0 {
		t.Fatal("revoked authority returned a usable epoch")
	}
}
