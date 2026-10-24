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

type windowAuthorityFixture struct {
	contextPreparationAuthority
	start time.Time
}

func (a windowAuthorityFixture) PublishedExecutionWindow(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string, seconds int) (time.Time, time.Time, error) {
	if _, ok := sharedkernel.ExecutionLeaseFromContext(ctx); !ok || scope.ValidateTrusted() != nil || operation == "" || bodyHash == "" || policyHash == "" || seconds != 1800 {
		return time.Time{}, time.Time{}, errors.New("window not bound to live execution")
	}
	return a.start, a.start.Add(time.Duration(seconds) * time.Second), nil
}

func TestBatchDisclosureIsOptInAndRequiresAnOriginalExecutionWindow(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := governedInvocationResolver()
	resolver.snapshot.Hash = strings.Repeat("b", 64)
	resolver.snapshot.Runtime.TaskTimeoutSeconds = 1800
	resolver.snapshot.Runtime.Batch = &policyasset.BatchPolicy{MaxItems: 1000, ItemTimeoutSeconds: 30, ElapsedSeconds: 1800}
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
	authority := contextPreparationAuthority{
		testLiveAuthorityFunc: func(context.Context, sharedkernel.Scope, string, string, string) error { return nil },
		resource:              func(CapabilityResourceAccess) error { return nil },
	}
	m.SetLiveExecutionAuthority(authority)
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	if r := capabilityRequest(t, m, "/internal/runtime/harness-policy", c, map[string]any{"include_batch": true}); r.Code != http.StatusServiceUnavailable {
		t.Fatal("missing original window replaced by a fresh clock", r.Code)
	}
	start := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	m.SetLiveExecutionAuthority(windowAuthorityFixture{authority, start})
	for _, include := range []bool{false, true} {
		input := map[string]any{}
		if include {
			input["include_batch"] = true
		}
		r := capabilityRequest(t, m, "/internal/runtime/harness-policy", c, input)
		var body struct {
			Data map[string]json.RawMessage `json:"data"`
		}
		if r.Code != http.StatusOK || json.Unmarshal(r.Body.Bytes(), &body) != nil {
			t.Fatal("policy read failed", r.Code)
		}
		if !include {
			if len(body.Data) != 4 || string(body.Data["version"]) != `"harness-policy/v1"` {
				t.Fatal("v1 contract changed")
			}
			continue
		}
		var execution struct {
			Batch  policyasset.BatchPolicy `json:"batch"`
			Window struct {
				Start    int64 `json:"started_ms"`
				Deadline int64 `json:"deadline_ms"`
			} `json:"window"`
		}
		if json.Unmarshal(body.Data["execution"], &execution) != nil || execution.Batch != *resolver.snapshot.Runtime.Batch || execution.Window.Start != start.UnixMilli() || execution.Window.Deadline != start.Add(30*time.Minute).UnixMilli() {
			t.Fatal("disclosed profile or original deadline changed")
		}
	}
}
