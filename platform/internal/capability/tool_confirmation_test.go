package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func confirmationTestToken(t *testing.T, key ed25519.PrivateKey, claims ToolConfirmationClaims) string {
	t.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte(toolConfirmationDomain), body...)))
}
func confirmationTestClaims(scope sharedkernel.Scope, policy, name, call, fingerprint string, now time.Time) ToolConfirmationClaims {
	return ToolConfirmationClaims{Version: "tool-confirmation/v1", ApprovalID: "human-approved-operation", ActorID: scope.PrincipalID, ScopeHash: ToolReceiptScopeHash(scope), AuthorizationEpoch: scope.AuthorizationEpoch, PolicyHash: policy, ToolName: name, CallID: call, Fingerprint: fingerprint, IssuedAt: now.Unix(), ExpiresAt: now.Unix() + 60}
}

// Ledger/outbox tests use a cryptographically bound approval fixture. This is
// deliberately explicit at the call site; requests are never auto-approved.
func approveNotificationFixture(t *testing.T, module *Module, c harnessContext, input map[string]any) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewToolConfirmationVerifier(public)
	if err != nil {
		t.Fatal(err)
	}
	module.SetToolConfirmationVerifier(verifier)
	module.SetToolConfirmationAuthority(confirmationAuthorityFixture{check: func(ToolConfirmationClaims) error { return nil }})
	fingerprint, err := ToolCommandFingerprint("send_notification", input["payload"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	input["confirmation_token"] = confirmationTestToken(t, private, confirmationTestClaims(scopeFromHarness(c), notificationPolicyResolver().snapshot.Hash, "send_notification", input["call_id"].(string), fingerprint, time.Now()))
}

func TestToolConfirmationBindsApprovalToExactOperation(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier, _ := NewToolConfirmationVerifier(public)
	now := time.Now()
	scope := scopeFromHarness(capabilityContext())
	fingerprint, _ := ToolCommandFingerprint("fixture.read", map[string]any{"value": "one"})
	policy := strings.Repeat("a", 64)
	claims := confirmationTestClaims(scope, policy, "fixture.read", "call", fingerprint, now)
	if verifier.Verify(confirmationTestToken(t, private, claims), scope, policy, "fixture.read", "call", fingerprint, now) != nil {
		t.Fatal("valid operation approval rejected")
	}
	for _, mutate := range []func(*ToolConfirmationClaims){func(c *ToolConfirmationClaims) { c.Version = "other" }, func(c *ToolConfirmationClaims) { c.ActorID = "other-user" }, func(c *ToolConfirmationClaims) { c.ScopeHash = "other-scope" }, func(c *ToolConfirmationClaims) { c.AuthorizationEpoch++ }, func(c *ToolConfirmationClaims) { c.PolicyHash = "other-policy" }, func(c *ToolConfirmationClaims) { c.ToolName = "other-tool" }, func(c *ToolConfirmationClaims) { c.CallID = "other-call" }, func(c *ToolConfirmationClaims) { c.Fingerprint = "other-input" }, func(c *ToolConfirmationClaims) { c.ApprovalID = "" }, func(c *ToolConfirmationClaims) { c.IssuedAt = now.Unix() + 10 }, func(c *ToolConfirmationClaims) { c.ExpiresAt = now.Unix() }, func(c *ToolConfirmationClaims) { c.ExpiresAt = c.IssuedAt + 301 }} {
		changed := claims
		mutate(&changed)
		if verifier.Verify(confirmationTestToken(t, private, changed), scope, policy, "fixture.read", "call", fingerprint, now) == nil {
			t.Fatal("mutated approval accepted")
		}
	}
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	for _, token := range []string{"", "true", "malformed", confirmationTestToken(t, foreign, claims), strings.Repeat("x", 8193)} {
		if verifier.Verify(token, scope, policy, "fixture.read", "call", fingerprint, now) == nil {
			t.Fatal("untrusted confirmation accepted")
		}
	}
	scope.RunID = "another-run"
	if verifier.Verify(confirmationTestToken(t, private, claims), scope, policy, "fixture.read", "call", fingerprint, now) == nil {
		t.Fatal("cross-run confirmation accepted")
	}
}

func TestSignedToolGatewayRequiresConfirmationAndStillRechecksIAM(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	approvalPublic, approvalPrivate, _ := ed25519.GenerateKey(rand.Reader)
	policy := governedInvocationResolver()
	policy.snapshot.Hash = strings.Repeat("b", 64)
	policy.snapshot.Tool.AllowedTools = []string{"fixture.read"}
	policy.snapshot.Tool.RequireConfirmation = []string{"fixture.read"}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, policy)
	provider := &observationFixtureProvider{output: map[string]any{"answer": "approved-result"}}
	module.SetToolProvider(provider)
	denied := false
	module.SetLiveExecutionAuthority(contextPreparationAuthority{testLiveAuthorityFunc: func(context.Context, sharedkernel.Scope, string, string, string) error { return nil }, resource: func(CapabilityResourceAccess) error {
		if denied {
			return errors.New("resource revoked")
		}
		return nil
	}})
	ctx := capabilityContext()
	ctx.PlatformContextToken = signedContextToken(t, private, ctx, time.Now().Unix()-1, time.Now().Unix()+120)
	payload := map[string]any{"value": "one"}
	input := map[string]any{"name": "fixture.read", "call_id": "approval-call", "payload": payload, "confirmed": true}
	response := capabilityRequest(t, module, "/internal/tool/invoke", ctx, input)
	if response.Code != 403 || provider.calls != 0 || !strings.Contains(response.Body.String(), "TOOL_CONFIRMATION_REQUIRED") {
		t.Fatalf("boolean confirmation denial status=%d calls=%d body=%s", response.Code, provider.calls, response.Body.String())
	}
	verifier, _ := NewToolConfirmationVerifier(approvalPublic)
	module.SetToolConfirmationVerifier(verifier)
	module.SetToolConfirmationAuthority(confirmationAuthorityFixture{check: func(ToolConfirmationClaims) error { return nil }})
	fingerprint, _ := ToolCommandFingerprint("fixture.read", payload)
	claims := confirmationTestClaims(scopeFromHarness(ctx), policy.snapshot.Hash, "fixture.read", "approval-call", fingerprint, time.Now())
	input["confirmation_token"] = confirmationTestToken(t, approvalPrivate, claims)
	first := capabilityRequest(t, module, "/internal/tool/invoke", ctx, input)
	second := capabilityRequest(t, module, "/internal/tool/invoke", ctx, input)
	if first.Code != 200 || second.Code != 200 || provider.calls != 1 || first.Body.String() != second.Body.String() {
		t.Fatal("approved operation/replay failed")
	}
	input["payload"] = map[string]any{"value": "changed"}
	if capabilityRequest(t, module, "/internal/tool/invoke", ctx, input).Code != 403 || provider.calls != 1 {
		t.Fatal("confirmation reused with changed arguments")
	}
	input["payload"] = payload
	denied = true
	response = capabilityRequest(t, module, "/internal/tool/invoke", ctx, input)
	if response.Code != 403 || strings.Contains(response.Body.String(), "approved-result") || provider.calls != 1 {
		t.Fatal("confirmation overrode revoked IAM")
	}
	denied = false
	checks := 0
	module.SetToolConfirmationAuthority(confirmationAuthorityFixture{check: func(ToolConfirmationClaims) error {
		checks++
		if checks >= 2 {
			return ErrToolApprovalDenied
		}
		return nil
	}})
	response = capabilityRequest(t, module, "/internal/tool/invoke", ctx, input)
	if response.Code != 403 || checks != 2 || provider.calls != 1 || strings.Contains(response.Body.String(), "approved-result") {
		t.Fatal("approval revoked after first check disclosed replay")
	}
}

type confirmationAuthorityFixture struct {
	check func(ToolConfirmationClaims) error
}

func (f confirmationAuthorityFixture) CheckApproval(_ context.Context, c ToolConfirmationClaims) error {
	return f.check(c)
}
