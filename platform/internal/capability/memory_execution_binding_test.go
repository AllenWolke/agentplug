package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type boundMemorySink struct {
	MemoryStore
	t      *testing.T
	writes int
}

func (s *boundMemorySink) SaveAuthorized(ctx context.Context, key string, entry memoryEntry, max int, check func(context.Context) error) error {
	lease, found := sharedkernel.ExecutionLeaseFromContext(ctx)
	if !found || lease.Revision != 3 || lease.TokenHash != strings.Repeat("c", 64) {
		s.t.Fatal("verified execution lease was lost before the memory transaction")
	}
	mutation, ok := ctx.Value(memoryMutationKey{}).(memoryMutation)
	if !ok || mutation.Scope.RunID != "run-a" || mutation.CallID != "request-a" || len(mutation.Fingerprint) != 64 {
		s.t.Fatal("memory mutation lost its original request binding")
	}
	bound, ok := ctx.Value(runtimeBudgetContextKey{}).(skillRuntimeContext)
	if !ok || bound.Scope != mutation.Scope || bound.Lease != lease || bound.Check == nil {
		s.t.Fatal("current-authority callback lost its private binding")
	}
	if err := check(ctx); err != nil {
		return err
	}
	s.writes++
	return nil
}

func TestMemoryExecutionBindingSurvivesSignedGatewayAndRejectsForgery(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := policyasset.Snapshot{ModelProfileID: "model-a", PromptVersionID: "prompt-a", ToolPolicyID: "tool-a", MemoryPolicyID: "memory-a", KnowledgePolicyID: "knowledge-a", RuntimePolicyID: "runtime-a", Revision: 1, Hash: strings.Repeat("b", 64), Memory: policyasset.MemoryPolicy{WorkingTTLSeconds: 30, MaxEntries: 10}}
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, fixedPolicyResolver{snapshot: policy})
	m.SetLiveExecutionAuthority(testLiveAuthorityFunc(func(context.Context, sharedkernel.Scope, string, string, string) error { return nil }))
	sink := &boundMemorySink{MemoryStore: m.memoryStore, t: t}
	m.memoryStore = sink
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	input := map[string]any{"operation": "save", "namespace": "working", "key": "progress", "value": map[string]any{"step": 1}}
	if response := capabilityRequest(t, m, "/internal/memory/access", c, input); response.Code != http.StatusOK || sink.writes != 1 {
		t.Fatalf("signed memory transaction failed: status=%d body=%s", response.Code, response.Body.String())
	}
	c.TaskID = "forged-run"
	if response := capabilityRequest(t, m, "/internal/memory/access", c, input); response.Code != http.StatusForbidden || sink.writes != 1 {
		t.Fatal("forged Run reached the memory writer")
	}
}
