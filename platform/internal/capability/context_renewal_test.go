package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type testTokenRenewer struct {
	authorize testLiveAuthorityFunc
	token     string
	calls     int
}

func (a *testTokenRenewer) AuthorizeCapability(ctx context.Context, s sharedkernel.Scope, op, body, policy string) error {
	return a.authorize(ctx, s, op, body, policy)
}
func (a *testTokenRenewer) RenewCapability(ctx context.Context, _ sharedkernel.Scope, _, _, _ string) (string, error) {
	if _, ok := sharedkernel.ExecutionLeaseFromContext(ctx); !ok {
		return "", errors.New("missing proof")
	}
	a.calls++
	return a.token, nil
}

func TestExpiredCapabilityOnlyRenewsAfterLiveAuthority(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := newTestModule("internal", "signing", public, "platform", "agent-runtime")
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-400, time.Now().Unix()-280)
	renewer := &testTokenRenewer{token: signedContextToken(t, private, c, time.Now().Unix(), time.Now().Unix()+120)}
	renewer.authorize = func(ctx context.Context, _ sharedkernel.Scope, _, _, _ string) error {
		binding, ok := sharedkernel.ExecutionLeaseFromContext(ctx)
		if !ok || binding.Revision != 3 {
			return errors.New("lease proof denied")
		}
		return nil
	}
	m.SetLiveExecutionAuthority(renewer)
	response := capabilityRequest(t, m, "/internal/model/embed", c, map[string]any{"texts": []string{"test"}})
	if response.Code != http.StatusForbidden {
		t.Fatal("expired token invoked capability")
	}
	response = capabilityRequest(t, m, "/internal/context/renew", c, map[string]any{})
	if response.Code != 200 || renewer.calls != 1 {
		t.Fatalf("renewal failed %d %s", response.Code, response.Body.String())
	}
	var result struct {
		Data struct {
			Token string `json:"context_token"`
		} `json:"data"`
	}
	if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Data.Token != renewer.token {
		t.Fatal("renewed token missing")
	}
	renewer.authorize = func(context.Context, sharedkernel.Scope, string, string, string) error { return errors.New("revoked") }
	response = capabilityRequest(t, m, "/internal/context/renew", c, map[string]any{})
	if response.Code != 403 || renewer.calls != 1 {
		t.Fatal("revoked identity renewed")
	}
}

func (a *testTokenRenewer) AuthorizeCapabilityResource(context.Context, sharedkernel.Scope, CapabilityResourceAccess) error {
	return nil
}

func (f *testTokenRenewer) AuthenticateWorkload(context.Context, sharedkernel.Scope, string, string, string) error {
	return nil
}
