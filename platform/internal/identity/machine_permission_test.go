package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestMachineProtocolActionsUseCurrentVersionedGrantsAndRunDataScope(t *testing.T) {
	snapshot, _ := permissionFixture()
	snapshot.Principal.Type = PrincipalServicePrincipal
	snapshot.Bindings, snapshot.Memberships, snapshot.Principal.Roles = nil, nil, nil
	base := snapshot.Grants[0]
	base.SubjectType = PrincipalServicePrincipal
	snapshot.Grants = nil
	for _, action := range []string{"run", "history.read", "cancel", "history.continue"} {
		grant := base
		grant.ID, grant.Action = action, action
		snapshot.Grants = append(snapshot.Grants, grant)
	}
	store := &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal,
		machineCredentials: map[string]MachineCredential{machineStoreKey("t", "u"): {TenantID: "t", PrincipalID: "u", SecretHash: digestMachineValue("fixture-secret"), Status: "active", Revision: 1, NetworkCIDRs: []string{"127.0.0.1/32"}}}}, snapshot: snapshot}
	m := NewModule(store, "internal")
	ctx := context.Background()
	request := MachineTokenIssueRequest{GrantType: "client_credentials", TenantID: "t", ClientID: "u", ClientSecret: "fixture-secret",
		Scope: MachineGrantScope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "i", Actions: []string{"run", "read", "events", "cancel", "resume"}}}
	token, err := m.ExchangeMachineToken(ctx, request, "127.0.0.1:1234")
	if err != nil {
		t.Fatal("v2 machine protocol could not exchange current grants", err)
	}
	run := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "i", PrincipalType: "service_principal", PrincipalID: "u", RunID: "owned-run"}
	for _, action := range []string{"read", "events", "cancel", "resume"} {
		if err := m.AuthorizeMachineRunToken(ctx, token.AccessToken, "127.0.0.1:1234", action, run, run.RunID); err != nil {
			t.Fatal("owner-scoped action failed", action, err)
		}
	}
	foreign := run
	foreign.PrincipalID = "other"
	if m.AuthorizeMachineRunToken(ctx, token.AccessToken, "127.0.0.1:1234", "read", foreign, foreign.RunID) == nil {
		t.Fatal("another machine's run was disclosed")
	}
	deny := store.snapshot.Grants[1]
	deny.ID, deny.Effect, deny.DataScope = "one-run-deny", "deny", DataScope{Type: "explicit_set", IDs: []string{"denied-run"}}
	store.snapshot.Grants = append(store.snapshot.Grants, deny)
	if m.AuthorizeMachineRunToken(ctx, token.AccessToken, "127.0.0.1:1234", "read", run, run.RunID) != nil {
		t.Fatal("one-object deny incorrectly denied another run")
	}
	denied := run
	denied.RunID = "denied-run"
	if m.AuthorizeMachineRunToken(ctx, token.AccessToken, "127.0.0.1:1234", "events", denied, denied.RunID) == nil {
		t.Fatal("object deny did not stop event disclosure")
	}
	store.snapshot.Grants = store.snapshot.Grants[:4]
	store.snapshot.Grants[1].DataScope = DataScope{Type: "explicit_set", IDs: []string{"another-run"}}
	if m.AuthorizeMachineRunToken(ctx, token.AccessToken, "127.0.0.1:1234", "read", run, run.RunID) == nil {
		t.Fatal("explicit-set grant escaped its data scope")
	}
	store.snapshot.Grants[1].DataScope = DataScope{Type: "owner"}
	expired := time.Now().UTC().Add(-time.Second)
	store.snapshot.Grants[1].ExpiresAt = &expired
	if _, err := m.AuthenticateMachineToken(ctx, token.AccessToken, "127.0.0.1:1234", "read"); err == nil {
		t.Fatal("old issued token survived grant expiration")
	}
	store.snapshot.Grants[1].ExpiresAt = nil
	store.snapshot.Grants[1].Status = "revoked"
	if _, err := m.AuthenticateMachineToken(ctx, token.AccessToken, "127.0.0.1:1234", "events"); err == nil {
		t.Fatal("old issued token survived grant revocation")
	}
	store.snapshot.Grants[1].Status = "active"
	store.failure = errors.New("IAM unavailable")
	if _, err := m.AuthenticateMachineToken(ctx, token.AccessToken, "127.0.0.1:1234", "read"); err == nil {
		t.Fatal("IAM failure fell back to legacy access")
	}
	store.failure = nil
	request.Scope.Actions = []string{"run"}
	runOnly, err := m.ExchangeMachineToken(ctx, request, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AuthenticateMachineToken(ctx, runOnly.AccessToken, "127.0.0.1:1234", "read"); err == nil {
		t.Fatal("IAM grant expanded the issued token's action restrictions")
	}
}
