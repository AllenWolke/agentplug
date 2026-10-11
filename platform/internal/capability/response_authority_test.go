package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type responseKnowledgeFixture struct{ after func() }

func (f responseKnowledgeFixture) Search(context.Context, harnessContext, knowledgeQuery) (map[string]any, error) {
	f.after()
	return map[string]any{"references": []map[string]any{{"doc_id": "private-response-document", "content": "private-response-body"}}}, nil
}

type responseMemoryFixture struct {
	after func()
	saved bool
}

func (f *responseMemoryFixture) Load(context.Context, string) (memoryEntry, bool, error) {
	f.after()
	return memoryEntry{Value: map[string]any{"text": "private-response-body"}, ExpiresAt: time.Now().Add(time.Minute)}, true, nil
}
func (f *responseMemoryFixture) Save(context.Context, string, memoryEntry, int) error {
	f.saved = true
	return nil
}

func (f *responseMemoryFixture) SaveAuthorized(ctx context.Context, key string, entry memoryEntry, maxEntries int, check func(context.Context) error) error {
	if err := check(ctx); err != nil {
		return errMemoryWriteDenied
	}
	return f.Save(ctx, key, entry, maxEntries)
}

type responseModelFixture struct {
	ModelInvocationStore
	after func()
}

type replayResponseFixture struct {
	ModelInvocationStore
	afterReplay func()
}

func (f replayResponseFixture) Reserve(ctx context.Context, scope, key, fingerprint string, budget, estimate int64) (ModelInvocation, bool, error) {
	result, replay, err := f.ModelInvocationStore.Reserve(ctx, scope, key, fingerprint, budget, estimate)
	if err == nil && replay {
		f.afterReplay()
	}
	return result, replay, err
}

type revokeAfterWorkloadFixture struct{ *resourceAuthorityFixture }

func (f revokeAfterWorkloadFixture) AuthenticateWorkload(context.Context, sharedkernel.Scope, string, string, string) error {
	f.denied = true
	return nil
}

func (f responseModelFixture) Complete(ctx context.Context, scope, key, fingerprint string, result map[string]any, cost int64) error {
	if err := f.ModelInvocationStore.Complete(ctx, scope, key, fingerprint, result, cost); err != nil {
		return err
	}
	f.after()
	return nil
}

func TestSignedCapabilityRechecksBeforeDisclosingProviderResults(t *testing.T) {
	for _, route := range []string{"/internal/knowledge/search", "/internal/memory/access", "/internal/model/generate"} {
		t.Run(route, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			resolver := governedModelResolver("local", false, 0)
			resolver.snapshot.Hash = strings.Repeat("b", 64)
			f := &resourceAuthorityFixture{}
			revoke := func() { f.denied = true }
			store := newMemoryModelInvocationStore()
			m := NewModuleWithGovernance("internal-token", "signing-secret", public, "platform", "agent-runtime",
				responseKnowledgeFixture{revoke}, resolver, &responseMemoryFixture{after: revoke}, responseModelFixture{store, revoke})
			m.SetLiveExecutionAuthority(f)
			c := capabilityContext()
			c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
			input := map[string]any{"query": "question", "knowledge_scope": "platform-knowledge"}
			if route == "/internal/memory/access" {
				input = map[string]any{"operation": "load", "namespace": "working", "key": "answer"}
			}
			if route == "/internal/model/generate" {
				input = map[string]any{"idempotency_key": "response-revocation", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "question"}}}
			}
			got := capabilityRequest(t, m, route, c, input)
			wantChecks := 2
			if route == "/internal/model/generate" {
				// Admission, the final pre-send check, and post-receipt disclosure.
				wantChecks = 3
			}
			if got.Code != http.StatusForbidden || strings.Contains(got.Body.String(), "private-response") || !f.denied || f.calls != wantChecks {
				t.Fatalf("provider result escaped current authority check: status=%d body=%s checks=%d", got.Code, got.Body.String(), f.calls)
			}
			if route == "/internal/model/generate" {
				if len(store.records) != 1 {
					t.Fatal("billable invocation was discarded")
				}
				for _, record := range store.records {
					if record.Status != "completed" || record.CostCents <= 0 || record.Response == nil {
						t.Fatal("recorded model result and cost must survive response denial")
					}
				}
			}
		})
	}
}

func TestSignedCapabilityRechecksModelReplayAndMemoryWriteAdmission(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := governedModelResolver("local", false, 0)
	resolver.snapshot.Hash = strings.Repeat("b", 64)
	f := &resourceAuthorityFixture{}
	store := newMemoryModelInvocationStore()
	memory := &responseMemoryFixture{}
	m := NewModuleWithGovernance("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver, memory,
		replayResponseFixture{store, func() { f.denied = true }})
	m.SetLiveExecutionAuthority(f)
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	input := map[string]any{"idempotency_key": "replay-revocation", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "question"}}}
	if got := capabilityRequest(t, m, "/internal/model/generate", c, input); got.Code != http.StatusOK {
		t.Fatal(got.Code, got.Body.String())
	}
	if got := capabilityRequest(t, m, "/internal/model/generate", c, input); got.Code != http.StatusForbidden || len(store.records) != 1 {
		t.Fatal("replay disclosed after revocation", got.Code, got.Body.String())
	}
	f.denied = false
	m.SetLiveExecutionAuthority(revokeAfterWorkloadFixture{f})
	got := capabilityRequest(t, m, "/internal/memory/access", c, map[string]any{"operation": "save", "namespace": "working", "key": "answer", "value": map[string]any{"text": "private-response-body"}})
	if got.Code != http.StatusForbidden || memory.saved {
		t.Fatal("memory write admitted with revoked permission", got.Code, got.Body.String())
	}
}
