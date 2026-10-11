package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLPermissionWorkloadCreationAtomicUnprivilegedAndRetry(t *testing.T) {
	f := newAdministratorFixture(t)
	a := f.actors[0]
	c := WorkloadCreationCommand{PrincipalID: "versioned-worker", Scope: ManagementScope{Type: "application", TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID}, NetworkCIDRs: []string{"127.0.0.1/32"}, ClientSecret: strings.Repeat("s", 43), IdempotencyKey: "create-worker", Reason: "explicit unprivileged executor"}
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return nil })
	if _, err := f.store.CreatePermissionWorkload(f.ctx, f.actors[2], c); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("ordinary user created machine", err)
	}
	failure := errors.New("recorder unavailable")
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return failure })
	if _, err := f.store.CreatePermissionWorkload(f.ctx, a, c); !errors.Is(err, failure) {
		t.Fatal("audit failure ignored", err)
	}
	var count int
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_principal WHERE principal_type='service_principal' AND id=?`), c.PrincipalID).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial machine survived rollback", count, err)
	}
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return nil })
	event, err := f.store.CreatePermissionWorkload(f.ctx, a, c)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.store.CreatePermissionWorkload(f.ctx, a, c)
	if err != nil || retry.ID != event.ID {
		t.Fatal("retry changed event", retry, err)
	}
	raw, _ := json.Marshal(c)
	if strings.Contains(string(raw), c.ClientSecret) {
		t.Fatal("secret included in command projection")
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalServicePrincipal, c.PrincipalID)
	if err != nil || snapshot.Mode != "v2" || snapshot.Principal.Revision != 1 || len(snapshot.Bindings) != 0 || len(snapshot.Grants) != 0 || len(snapshot.Principal.Roles) != 0 {
		t.Fatal("machine implicitly privileged", snapshot, err)
	}
	credential, err := f.store.GetMachineCredential(f.ctx, a.TenantID, c.PrincipalID)
	if err != nil || credential.Revision != 1 || credential.SecretHash != digestMachineValue(c.ClientSecret) {
		t.Fatal("credential missing", err)
	}
	c.ClientSecret = strings.Repeat("x", 43)
	if _, err := f.store.CreatePermissionWorkload(f.ctx, a, c); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("retry replaced secret", err)
	}
}
