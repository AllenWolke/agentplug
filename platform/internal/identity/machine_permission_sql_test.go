package identity

import (
	"github.com/lexagent/platform/internal/sqlutil"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLMachineProtocolVersionedActionsAndLiveObjectScope(t *testing.T) {
	f := newAdministratorFixture(t)
	a := f.actors[0]
	subject := "protocol-machine"
	if err := f.store.CreatePrincipal(f.ctx, Principal{Type: PrincipalServicePrincipal, ID: subject, TenantID: a.TenantID, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('service_principal',?,'v2',1,1)`), subject); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateMachineCredential(f.ctx, MachineCredential{TenantID: a.TenantID, PrincipalID: subject, SecretHash: digestMachineValue("sql-fixture-secret"), NetworkCIDRs: []string{"127.0.0.1/32"}, Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, action := range []string{"run", "history.read", "cancel", "history.continue"} {
		if err := insertPermissionGrant(f.ctx, tx, Grant{ID: "machine-" + action, SubjectType: PrincipalServicePrincipal, SubjectID: subject, TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID,
			AgentInstanceID: "installation-test", ResourceType: "agent_installation", ResourceID: "installation-test", Action: action, Effect: "allow", Status: "active", Revision: 1, SourceID: "machine-protocol-fixture", DataScope: DataScope{Type: "owner"}}, f.now); err != nil {
			t.Fatal(err)
		}
	}
	if err := insertPermissionGrant(f.ctx, tx, Grant{ID: "machine-object-deny", SubjectType: PrincipalServicePrincipal, SubjectID: subject, TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID,
		AgentInstanceID: "installation-test", ResourceType: "agent_installation", ResourceID: "installation-test", Action: "history.read", Effect: "deny", Status: "active", Revision: 1, SourceID: "machine-protocol-fixture", DataScope: DataScope{Type: "explicit_set", IDs: []string{"denied-run"}}}, f.now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	m := NewModule(f.store, "internal")
	request := MachineTokenIssueRequest{GrantType: "client_credentials", TenantID: a.TenantID, ClientID: subject, ClientSecret: "sql-fixture-secret",
		Scope: MachineGrantScope{TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID, AgentInstanceID: "installation-test", Actions: []string{"run", "read", "events", "cancel", "resume"}}}
	token, err := m.ExchangeMachineToken(f.ctx, request, "127.0.0.1:1234")
	if err != nil {
		t.Fatal("actual SQL machine token exchange failed", err)
	}
	run := sharedkernel.Scope{TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID, AgentInstanceID: "installation-test", PrincipalType: "service_principal", PrincipalID: subject, RunID: "allowed-run"}
	for _, action := range []string{"read", "events", "cancel", "resume"} {
		if err := m.AuthorizeMachineRunToken(f.ctx, token.AccessToken, "127.0.0.1:1234", action, run, run.RunID); err != nil {
			t.Fatal("SQL owner action failed", action, err)
		}
	}
	denied := run
	denied.RunID = "denied-run"
	if m.AuthorizeMachineRunToken(f.ctx, token.AccessToken, "127.0.0.1:1234", "events", denied, denied.RunID) == nil {
		t.Fatal("SQL object-specific deny failed")
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id='machine-history.read'`)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AuthenticateMachineToken(f.ctx, token.AccessToken, "127.0.0.1:1234", "read"); err == nil {
		t.Fatal("old token survived SQL permission revoke")
	}
	if err := m.AuthorizeMachineRunToken(f.ctx, token.AccessToken, "127.0.0.1:1234", "cancel", run, run.RunID); err != nil {
		t.Fatal("read revoke removed independent cancel grant", err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_application SET status='disabled' WHERE id=?`), a.ApplicationID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AuthenticateMachineToken(f.ctx, token.AccessToken, "127.0.0.1:1234", "run"); err == nil {
		t.Fatal("old token ignored disabled application")
	}
	request.Scope.Actions = []string{"run"}
	if _, err := m.ExchangeMachineToken(f.ctx, request, "127.0.0.1:1234"); err == nil {
		t.Fatal("disabled application issued new machine token")
	}
}
