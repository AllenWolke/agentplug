package identity

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLScopedMachineCredentialLifecycle(t *testing.T) {
	f := newAdministratorFixture(t)
	root, manager := f.actors[0], f.actors[2]
	appScope := ManagementScope{Type: "application", TenantID: root.TenantID, DepartmentID: root.DepartmentID, ApplicationID: root.ApplicationID}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = insertRoleBinding(f.ctx, tx, RoleBinding{ID: "fixture-integration-manager", SubjectID: manager.PrincipalID, RoleCode: "integration_admin", RoleVersion: 1, Scope: appScope, Status: "active", Revision: 1, SourceID: "fixture"})
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	otherScope := appScope
	otherScope.ApplicationID += "-other"
	if err := f.store.CreateApplication(f.ctx, Application{ID: otherScope.ApplicationID, TenantID: root.TenantID, DepartmentID: root.DepartmentID, Code: otherScope.ApplicationID, Name: "other application", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	f.store.SetCapabilityResourceResolver(workloadTargetFixture{})
	bind := func(principal, installation string, scope ManagementScope) {
		t.Helper()
		_, err := f.store.ChangeWorkloadBinding(f.ctx, root, WorkloadBindingCommand{Binding: WorkloadBinding{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, InstallationID: installation, AgentID: "fixture-agent", AgentVersionID: "fixture-version", PrincipalID: principal}, IdempotencyKey: installation, Reason: "explicit fixture installation"})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"own-executor", "other-executor", "unbound-executor"} {
		_, err := f.store.CreatePermissionWorkload(f.ctx, root, WorkloadCreationCommand{PrincipalID: id, Scope: appScope, NetworkCIDRs: []string{"127.0.0.1/32"}, ClientSecret: strings.Repeat("s", 43), IdempotencyKey: id, Reason: "explicit fixture executor"})
		if err != nil {
			t.Fatal(err)
		}
	}
	bind("own-executor", "own-installation", appScope)
	bind("other-executor", "other-installation", otherScope)
	items, err := f.store.ListPermissionMachineCredentials(f.ctx, manager)
	if err != nil || len(items) != 1 || items[0].PrincipalID != "own-executor" || items[0].SecretHash != "" {
		t.Fatal("application list leaked other/unbound credentials or secret", items, err)
	}
	directory, err := f.store.PagePermissionMachines(f.ctx, manager, "", 1, 20)
	if err != nil || directory.Total != 1 || len(directory.Items) != 1 || directory.Items[0].ID != "own-executor" || len(directory.Items[0].Roles)+len(directory.Items[0].Groups) != 0 {
		t.Fatal("machine directory leaked unrelated identity or cached roles", directory, err)
	}
	rootPage, err := f.store.PagePermissionMachines(f.ctx, root, "", 1, 2)
	if err != nil || rootPage.Total != 3 || len(rootPage.Items) != 2 {
		t.Fatal("tenant machine metadata pagination failed", rootPage, err)
	}
	rootPage, err = f.store.PagePermissionMachines(f.ctx, root, "", 2, 2)
	if err != nil || rootPage.Total != 3 || len(rootPage.Items) != 1 {
		t.Fatal("tenant machine metadata second page failed", rootPage, err)
	}
	filtered, err := f.store.PagePermissionMachines(f.ctx, manager, "other-executor", 1, 20)
	if err != nil || filtered.Total != 0 || len(filtered.Items) != 0 {
		t.Fatal("explicit ID bypassed machine directory scope", filtered, err)
	}
	for _, id := range []string{"other-executor", "unbound-executor"} {
		if _, err := f.store.ChangePermissionMachineCredential(f.ctx, manager, id, 1, strings.Repeat("a", 64), []string{"127.0.0.1/32"}, false); !errors.Is(err, ErrPermissionDenied) {
			t.Fatal("application administrator changed unrelated machine", id, err)
		}
	}
	// 同一凭证影响所有安装实例，只管理其中一个应用不能操作共享机器。
	bind("own-executor", "shared-other-installation", otherScope)
	if _, err := f.store.ChangePermissionMachineCredential(f.ctx, manager, "own-executor", 1, "", nil, true); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("shared machine crossed application boundary", err)
	}
	items, err = f.store.ListPermissionMachineCredentials(f.ctx, manager)
	if err != nil || len(items) != 0 {
		t.Fatal("shared machine visible to partial-scope administrator", items, err)
	}
	directory, err = f.store.PagePermissionMachines(f.ctx, manager, "", 1, 20)
	if err != nil || directory.Total != 0 || len(directory.Items) != 0 {
		t.Fatal("shared machine metadata escaped all-binding boundary", directory, err)
	}
	_, err = f.store.ChangeWorkloadBinding(f.ctx, root, WorkloadBindingCommand{Binding: WorkloadBinding{TenantID: otherScope.TenantID, DepartmentID: otherScope.DepartmentID, ApplicationID: otherScope.ApplicationID, InstallationID: "shared-other-installation", AgentID: "fixture-agent", AgentVersionID: "fixture-version", PrincipalID: "own-executor"}, ExpectedRevision: 1, Revoke: true, IdempotencyKey: "revoke-shared-fixture", Reason: "return to sole application fixture"})
	if err != nil {
		t.Fatal(err)
	}
	epoch := func() uint64 {
		t.Helper()
		var value uint64
		if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT epoch FROM platform_identity_policy_migration WHERE principal_type='service_principal' AND subject_id='own-executor'`)).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	beforeEpoch := epoch()
	before, err := f.store.GetMachineCredential(f.ctx, root.TenantID, "own-executor")
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("audit/outbox unavailable")
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return failure })
	if _, err := f.store.ChangePermissionMachineCredential(f.ctx, manager, "own-executor", 1, strings.Repeat("a", 64), []string{"127.0.0.1/32"}, false); !errors.Is(err, failure) {
		t.Fatal("audit failure did not reject mutation", err)
	}
	current, err := f.store.GetMachineCredential(f.ctx, root.TenantID, "own-executor")
	if err != nil || current.SecretHash != before.SecretHash || current.Revision != 1 || epoch() != beforeEpoch {
		t.Fatal("credential or epoch survived failed transaction", err)
	}
	var events []AdministrativeEvent
	f.store.SetAdministrativeRecorder(func(_ context.Context, _ *sql.Tx, actor sharedkernel.Scope, event AdministrativeEvent) error {
		if actor.PrincipalID != manager.PrincipalID || event.SubjectID != "own-executor" || event.Action != "machine.manage" {
			return errors.New("wrong audit attribution")
		}
		events = append(events, event)
		return nil
	})
	if revision, err := f.store.ChangePermissionMachineCredential(f.ctx, manager, "own-executor", 1, strings.Repeat("a", 64), []string{"127.0.0.1/32"}, false); err != nil || revision != 2 || epoch() != beforeEpoch+1 || len(events) != 1 {
		t.Fatal("rotation not committed with epoch and recorder", revision, err)
	}
	principal, err := f.store.GetPrincipal(f.ctx, PrincipalUser, manager.PrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	module := NewModule(f.store, "private-token")
	r := httptest.NewRequest(http.MethodPost, "/machine-credentials/own-executor/rotate", strings.NewReader(`{"expected_revision":1,"network_cidrs":["127.0.0.1/32"]}`))
	setBrowserIdentityHeaders(r, principal, manager.DepartmentID, manager.ApplicationID)
	r.Header.Set("Authorization", "Bearer private-token")
	r.Header.Set("X-Internal-Token", "private-token")
	w := httptest.NewRecorder()
	module.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "REVISION_CONFLICT") {
		t.Fatal("HTTP stale credential CAS incorrectly mapped", w.Code, w.Body.String())
	}
	if revision, err := f.store.ChangePermissionMachineCredential(f.ctx, manager, "own-executor", 2, "", nil, true); err != nil || revision != 3 || epoch() != beforeEpoch+2 || len(events) != 2 {
		t.Fatal("disable not committed", revision, err)
	}
	current, err = f.store.GetMachineCredential(f.ctx, root.TenantID, "own-executor")
	if err != nil || current.Status != "disabled" || current.Revision != 3 {
		t.Fatal("machine remained active", err)
	}
	if _, err := f.store.ChangePermissionMachineCredential(f.ctx, manager, "own-executor", 3, strings.Repeat("b", 64), []string{"127.0.0.1/32"}, false); !errors.Is(err, ErrMachineCredentialConflict) {
		t.Fatal("rotation reactivated disabled credential", err)
	}
}
