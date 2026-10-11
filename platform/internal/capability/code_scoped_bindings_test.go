package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	protocol "github.com/lexagent/code-runtime-contract"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func scopedCodeFixture(t *testing.T) (*protocol.Signer, CodeBinding) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := protocol.NewSigner(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer, CodeBinding{ToolName: "code.python", ControllerID: "controller-a", ProfileID: "profile-a", Endpoint: "https://example.com", Language: "python", TenantID: "tenant", ApplicationID: "app", AgentIDs: []string{"agent"}, Limits: protocol.Limits{MemoryBytes: 128 << 20, CPUMilli: 500, CPUSeconds: 5, PIDs: 16, DiskBytes: 8 << 20, TimeoutSeconds: 15, OutputBytes: 64 << 10}}
}

func scopedCodeApproval(scope sharedkernel.Scope, fp string) context.Context {
	return context.WithValue(context.Background(), runtimeExecutionAuthorizationKey{}, runtimeExecutionAuthorization{
		PolicyHash: strings.Repeat("a", 64), Approval: ToolConfirmationClaims{ScopeHash: ToolReceiptScopeHash(scope), ApprovalID: "approval", ToolName: "code.python", CallID: "call", Fingerprint: fp, PolicyHash: strings.Repeat("a", 64), AuthorizationEpoch: scope.AuthorizationEpoch, ActorID: scope.PrincipalID, ExpiresAt: time.Now().Add(time.Minute).Unix()},
	})
}

func TestCodeProviderExactScopedBindingsAndPermitIsolation(t *testing.T) {
	signer, first := scopedCodeFixture(t)
	second := first
	second.ApplicationID = "app-second"
	second.ProfileID = "profile-second"
	second.ControllerID = "controller-second"
	second.Endpoint = "https://example.org"
	second.Limits.CPUMilli = 250
	third := second
	third.TenantID = "tenant-third"
	third.ProfileID = "profile-third"
	sibling := first
	sibling.AgentIDs = []string{"sibling"}
	sibling.ProfileID = "profile-sibling"
	p, err := NewCodeToolProvider([]CodeBinding{first, second, third, sibling}, signer, false, modelgateway.NewGuardedEndpointClient)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.RegisteredTools()) != 1 || !p.Supports("code.python") || p.Supports("code.shell") {
		t.Fatal("logical registry duplicated or gained a tool")
	}
	descriptor, ok := p.DescribeTool("code.python")
	if !ok || descriptor.Risk != "high" || descriptor.ExecutionType != "code" {
		t.Fatal("registration risk changed")
	}
	base := mcpTestScope()
	scopes := []sharedkernel.Scope{base, base, base, base}
	scopes[1].ApplicationID = second.ApplicationID
	scopes[2].ApplicationID = third.ApplicationID
	scopes[2].TenantID = third.TenantID
	scopes[3].AgentID = "sibling"
	expected := []CodeBinding{first, second, third, sibling}
	fp := strings.Repeat("b", 64)
	for i, scope := range scopes {
		if err = p.ValidateToolCommand(ToolCommand{Scope: scope, Name: "code.python", CallID: "call", Payload: map[string]any{"code": "print(20)"}}); err != nil {
			t.Fatal(i, err)
		}
		bound, permit, err := p.permit(scopedCodeApproval(scope, fp), scope, "code.python", "call", fp, "receipt", "")
		if err != nil {
			t.Fatal(i, err)
		}
		if bound.binding.Endpoint != expected[i].Endpoint || permit.ControllerID != expected[i].ControllerID || permit.ProfileID != expected[i].ProfileID || permit.Limits != expected[i].Limits {
			t.Fatal("another scope supplied controller/profile/limits", i)
		}
		if i > 0 {
			if _, _, err = p.permit(scopedCodeApproval(base, fp), scope, "code.python", "call", fp, "receipt", ""); err == nil {
				t.Fatal("approval crossed scope", i)
			}
		}
	}
	for _, field := range []string{"tenant", "application", "agent"} {
		wrong := base
		switch field {
		case "tenant":
			wrong.TenantID = "unbound"
		case "application":
			wrong.ApplicationID = "unbound"
		case "agent":
			wrong.AgentID = "unbound"
		}
		if err = p.ValidateToolCommand(ToolCommand{Scope: wrong, Name: "code.python", CallID: "call", Payload: map[string]any{"code": "print(20)"}}); err == nil {
			t.Fatal("unbound scope fell back", field)
		}
		if _, _, err = p.permit(scopedCodeApproval(wrong, fp), wrong, "code.python", "call", fp, "receipt", ""); err == nil {
			t.Fatal("unbound scope gained permit", field)
		}
	}
	if _, _, err = p.permit(context.Background(), base, "code.python", "call", fp, "receipt", ""); err == nil {
		t.Fatal("binding granted execution without approval")
	}
	if err = p.ValidateToolCommand(ToolCommand{Scope: base, Name: "code.python", CallID: "call", Payload: map[string]any{"code": "print(20)", "profile_id": "profile-second"}}); err == nil {
		t.Fatal("caller selected sandbox profile")
	}
	first.AgentIDs[0] = "mutated"
	if err = p.ValidateToolCommand(ToolCommand{Scope: base, Name: "code.python", CallID: "call", Payload: map[string]any{"code": "print(20)"}}); err != nil {
		t.Fatal("operator slice mutation changed frozen binding", err)
	}
}

func TestCodeProviderRejectsAmbiguousScopeAndLanguage(t *testing.T) {
	signer, first := scopedCodeFixture(t)
	for _, kind := range []string{"same_agent", "overlap", "different_language"} {
		second := first
		second.ProfileID = "another-profile"
		switch kind {
		case "overlap":
			second.AgentIDs = []string{"new-agent", "agent"}
		case "different_language":
			second.ApplicationID = "other-app"
			second.Language = "shell"
		}
		if _, err := NewCodeToolProvider([]CodeBinding{first, second}, signer, false, modelgateway.NewGuardedEndpointClient); err == nil {
			t.Fatal("ambiguous binding accepted", kind)
		}
	}
}
