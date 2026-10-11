package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type testLiveAuthorityFunc func(context.Context, sharedkernel.Scope, string, string, string) error

func (f testLiveAuthorityFunc) AuthorizeCapability(ctx context.Context, s sharedkernel.Scope, op, body, policy string) error {
	return f(ctx, s, op, body, policy)
}

func TestCapabilitySignedTokenRequiresLiveAuthority(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := newTestModule("internal-token", "signing-secret", public, "platform", "agent-runtime")
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	if err := m.Start(context.Background()); err == nil {
		t.Fatal("signed deployment started without live authority")
	}
	result := capabilityRequest(t, m, "/internal/model/embed", c, map[string]any{"texts": []string{"scope-bound"}})
	if result.Code != http.StatusForbidden {
		t.Fatal("token without trusted Run admitted")
	}
	calls := 0
	m.SetLiveExecutionAuthority(testLiveAuthorityFunc(func(_ context.Context, scope sharedkernel.Scope, operation, body, policy string) error {
		calls++
		if scope.RunID != c.TaskID || scope.InstallationID != c.InstallationID || scope.AuthorizationEpoch != c.AuthorizationEpoch || operation != "invoke" || len(body) != 64 || len(policy) != 64 {
			t.Fatal("live authority lost signed binding")
		}
		return errors.New("trusted Run cancelled or authorization revoked")
	}))
	result = capabilityRequest(t, m, "/internal/model/embed", c, map[string]any{"texts": []string{"scope-bound"}})
	if result.Code != http.StatusForbidden || calls != 1 {
		t.Fatal("current live authority denial bypassed")
	}
}

func TestMachineCapabilityRechecksLiveAuthorizationEpochBeforeEffect(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := newTestModule("internal-token", "signing-secret", public, "platform", "agent-runtime")
	c := capabilityContext()
	c.PrincipalType = "service_principal"
	c.ActorID = "external-client"
	c.AuthorizationEpoch = 9
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	allow, checks := true, 0
	m.SetLiveExecutionAuthority(testLiveAuthorityFunc(func(_ context.Context, scope sharedkernel.Scope, operation, _, _ string) error {
		if scope.AuthorizationEpoch != 9 || scope.PrincipalType != "service_principal" || scope.PrincipalID != "external-client" || operation != "invoke" {
			return errors.New("unexpected trusted scope")
		}
		if !allow {
			return errors.New("authorization revoked")
		}
		checks++
		return nil
	}))
	if got := capabilityRequest(t, m, "/internal/model/embed", c, map[string]any{"texts": []string{"abc"}}); got.Code != http.StatusOK || checks != 2 {
		t.Fatalf("authorized machine request: status=%d checks=%d body=%s", got.Code, checks, got.Body.String())
	}
	allow = false
	if got := capabilityRequest(t, m, "/internal/model/embed", c, map[string]any{"texts": []string{"abc"}}); got.Code != http.StatusForbidden || checks != 2 {
		t.Fatalf("revoked machine request: status=%d checks=%d", got.Code, checks)
	}
}

// Live-authority fixtures isolate run/lease checks; resource denial has its
// own fixtures and tests rather than relying on missing production wiring.
func (f testLiveAuthorityFunc) AuthorizeCapabilityResource(context.Context, sharedkernel.Scope, CapabilityResourceAccess) error {
	return nil
}

func (f testLiveAuthorityFunc) AuthenticateWorkload(context.Context, sharedkernel.Scope, string, string, string) error {
	return nil
}
