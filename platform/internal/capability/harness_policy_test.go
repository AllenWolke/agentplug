package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestHarnessPolicyDisclosureIsPinnedAndRechecksCurrentAuthority(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := governedInvocationResolver()
	resolver.snapshot.Hash = strings.Repeat("b", 64)
	resolver.snapshot.Runtime.Harness = &policyasset.HarnessPolicy{MaxRounds: 3, MaxToolCalls: 5, MaxRepeatedCalls: 1, MaxElapsedSeconds: 60, LimitBehavior: "incomplete"}
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
	checks, revoke := 0, false
	m.SetLiveExecutionAuthority(contextPreparationAuthority{
		testLiveAuthorityFunc: func(context.Context, sharedkernel.Scope, string, string, string) error { return nil },
		resource: func(a CapabilityResourceAccess) error {
			if a.Action != "model.generate" || a.ResourceType != "model" || a.ResourceID != "model-a" {
				t.Fatalf("wrong resource boundary: %+v", a)
			}
			checks++
			if revoke && checks%2 == 0 {
				return errors.New("revoked before disclosure")
			}
			return nil
		},
	})
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	var previousHash string
	for i := 0; i < 2; i++ {
		r := capabilityRequest(t, m, "/internal/runtime/harness-policy", c, map[string]any{})
		if r.Code != http.StatusOK {
			t.Fatalf("policy disclosure failed: %d", r.Code)
		}
		var body struct {
			Result struct {
				Version string                    `json:"version"`
				Hash    string                    `json:"policy_hash"`
				Time    int64                     `json:"server_time_ms"`
				Limits  policyasset.HarnessPolicy `json:"limits"`
			} `json:"data"`
		}
		if json.Unmarshal(r.Body.Bytes(), &body) != nil || body.Result.Version != "harness-policy/v1" || len(body.Result.Hash) != 64 || body.Result.Time <= 0 || body.Result.Limits != *resolver.snapshot.Runtime.Harness {
			t.Fatal("unbound policy response")
		}
		if previousHash != "" && previousHash != body.Result.Hash {
			t.Fatal("clock changed immutable policy hash")
		}
		previousHash = body.Result.Hash
	}
	if r := capabilityRequest(t, m, "/internal/runtime/harness-policy", c, map[string]any{"max_rounds": 8}); r.Code != http.StatusBadRequest {
		t.Fatal("caller selected limits")
	}
	revoke = true
	checks = 0
	if r := capabilityRequest(t, m, "/internal/runtime/harness-policy", c, map[string]any{}); r.Code != http.StatusForbidden || strings.Contains(r.Body.String(), "max_rounds") {
		t.Fatal("revoked limits disclosed")
	}
}
