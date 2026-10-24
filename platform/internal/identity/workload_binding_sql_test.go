package identity

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"reflect"
	"strings"
	"testing"
)

type workloadTargetFixture struct{}

func (workloadTargetFixture) ResolvePermissionResource(_ context.Context, s sharedkernel.Scope, typ, id string) (PermissionResource, error) {
	return PermissionResource{Type: typ, ID: id, TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, InstallationID: s.InstallationID, AgentID: "fixture-agent", AgentVersionID: "fixture-version"}, nil
}
func TestSQLWorkloadBindingCASAuditRetryAndRevocation(t *testing.T) {
	f := newAdministratorFixture(t)
	a := f.actors[0]
	subject := "workload-executor"
	if err := f.store.CreatePrincipal(f.ctx, Principal{Type: PrincipalServicePrincipal, ID: subject, TenantID: a.TenantID, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('service_principal',?,'v2',1,1)`), subject); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateMachineCredential(f.ctx, MachineCredential{TenantID: a.TenantID, PrincipalID: subject, SecretHash: strings.Repeat("a", 64), NetworkCIDRs: []string{"127.0.0.1/32"}, Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	f.store.SetCapabilityResourceResolver(workloadTargetFixture{})
	c := WorkloadBindingCommand{Binding: WorkloadBinding{TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID, InstallationID: "fixture-installation", AgentID: "fixture-agent", AgentVersionID: "fixture-version", PrincipalID: subject}, IdempotencyKey: "bind", Reason: "explicit workload identity"}
	if _, err := f.store.ChangeWorkloadBinding(f.ctx, f.actors[2], c); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("ordinary user bound executor", err)
	}
	failure := errors.New("audit unavailable")
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return failure })
	if _, err := f.store.ChangeWorkloadBinding(f.ctx, a, c); !errors.Is(err, failure) {
		t.Fatal("audit failure ignored", err)
	}
	var count int
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_workload_binding`)).Scan(&count); err != nil || count != 0 {
		t.Fatal("binding survived rollback", count, err)
	}
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return nil })
	receipt, err := f.store.ChangeWorkloadBinding(f.ctx, a, c)
	if err != nil || receipt.Binding.Revision != 1 {
		t.Fatal(receipt, err)
	}
	applicationScope := ManagementScope{Type: "application", TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID}
	listed, err := f.store.ListWorkloadBindings(f.ctx, a, applicationScope)
	if err != nil || len(listed) != 1 || !reflect.DeepEqual(listed[0], receipt.Binding) {
		t.Fatal("scoped binding directory lost metadata", listed, err)
	}
	if _, err := f.store.ListWorkloadBindings(f.ctx, f.actors[2], applicationScope); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("ordinary user read bindings", err)
	}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := insertRoleBinding(f.ctx, tx, RoleBinding{ID: "fixture-integration-role", SubjectID: f.actors[2].PrincipalID, RoleCode: "integration_admin", RoleVersion: 1, Scope: applicationScope, Status: "active", Revision: 1, SourceID: "binding-directory-fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if listed, err := f.store.ListWorkloadBindings(f.ctx, f.actors[2], applicationScope); err != nil || len(listed) != 1 {
		t.Fatal("integration administrator cannot read own application bindings", listed, err)
	}
	outside := applicationScope
	outside.ApplicationID += "-outside"
	if err := f.store.CreateApplication(f.ctx, Application{ID: outside.ApplicationID, TenantID: outside.TenantID, DepartmentID: outside.DepartmentID, Code: outside.ApplicationID, Name: "outside fixture", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ListWorkloadBindings(f.ctx, f.actors[2], outside); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("integration administrator read outside application", err)
	}
	retry, err := f.store.ChangeWorkloadBinding(f.ctx, a, c)
	if err != nil || retry.ID != receipt.ID {
		t.Fatal("retry changed receipt", retry, err)
	}
	scope := sharedkernel.Scope{TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID, InstallationID: c.Binding.InstallationID, AgentInstanceID: c.Binding.InstallationID, AgentID: c.Binding.AgentID, AgentVersionID: c.Binding.AgentVersionID, PrincipalType: "user", PrincipalID: a.PrincipalID, SessionID: "session", RunID: "run", TraceID: "trace", AuthorizationEpoch: 1}
	b, err := f.store.ResolveWorkloadIdentity(f.ctx, scope)
	if err != nil || b.PrincipalID != subject {
		t.Fatal(b, err)
	}
	scope.AgentVersionID = "other"
	if _, err := f.store.ResolveWorkloadIdentity(f.ctx, scope); err == nil {
		t.Fatal("wrong version admitted")
	}
	scope.AgentVersionID = c.Binding.AgentVersionID
	stale := c
	stale.IdempotencyKey = "stale"
	if _, err := f.store.ChangeWorkloadBinding(f.ctx, a, stale); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("stale binding accepted", err)
	}
	overwrite := c
	overwrite.ExpectedRevision = 1
	overwrite.IdempotencyKey = "overwrite"
	overwrite.Binding.PrincipalID = "replacement-executor"
	if _, err := f.store.ChangeWorkloadBinding(f.ctx, a, overwrite); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("active identity replaced", err)
	}
	revoke := c
	revoke.IdempotencyKey = "revoke"
	revoke.ExpectedRevision = 1
	revoke.Revoke = true
	if _, err := f.store.ChangeWorkloadBinding(f.ctx, a, revoke); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ResolveWorkloadIdentity(f.ctx, scope); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("revoked binding resolved", err)
	}
	listed, err = f.store.ListWorkloadBindings(f.ctx, a, applicationScope)
	if err != nil || len(listed) != 1 || listed[0].Status != "revoked" || listed[0].Revision != 2 {
		t.Fatal("directory hid revoked CAS revision", listed, err)
	}
	machine, err := f.store.PermissionSnapshot(f.ctx, PrincipalServicePrincipal, subject)
	if err != nil || len(machine.Grants) != 0 || machine.Principal.Revision != 3 {
		t.Fatal("binding granted capability or retried mutation", machine, err)
	}
	replacement := "replacement-executor"
	if err := f.store.CreatePrincipal(f.ctx, Principal{Type: PrincipalServicePrincipal, ID: replacement, TenantID: a.TenantID, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('service_principal',?,'v2',1,1)`), replacement); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateMachineCredential(f.ctx, MachineCredential{TenantID: a.TenantID, PrincipalID: replacement, SecretHash: strings.Repeat("b", 64), NetworkCIDRs: []string{"127.0.0.1/32"}}); err != nil {
		t.Fatal(err)
	}
	swap := c
	swap.ExpectedRevision = 2
	swap.IdempotencyKey = "explicit-replacement"
	swap.Binding.PrincipalID = replacement
	if _, err := f.store.ChangeWorkloadBinding(f.ctx, a, swap); err != nil {
		t.Fatal("revoked binding replacement denied", err)
	}
	bound, err := f.store.ResolveWorkloadIdentity(f.ctx, scope)
	if err != nil || bound.PrincipalID != replacement || bound.Revision != 3 {
		t.Fatal(bound, err)
	}
	var indexedPrincipal string
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT principal_id FROM platform_identity_workload_binding WHERE scope_hash=?`), workloadScopeHash(c.Binding)).Scan(&indexedPrincipal); err != nil || indexedPrincipal != replacement {
		t.Fatal("replacement projection stale", indexedPrincipal, err)
	}

}
