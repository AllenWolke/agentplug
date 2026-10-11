package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestModelSignedReceiptRechecksResourceBeforeDisclosure(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := governedInvocationResolver()
	policy.snapshot.Hash = strings.Repeat("b", 64)
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, policy)
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	messages := []modelgateway.Message{{Role: "user", Content: "hello"}}
	fingerprint, err := modelCommandFingerprint(messages, 0, policy.snapshot.Model.MaxTokens, "prompt-hash", policy.snapshot.Model, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	store := m.modelStore.(*memoryModelInvocationStore)
	if _, _, err = store.Reserve(context.Background(), capabilityScopeHash(c), "signed-model-read", fingerprint, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err = store.Complete(context.Background(), capabilityScopeHash(c), "signed-model-read", fingerprint, map[string]any{"text": "protected-model-answer"}, 0); err != nil {
		t.Fatal(err)
	}
	checks, denyAt := 0, 0
	m.SetLiveExecutionAuthority(contextPreparationAuthority{testLiveAuthorityFunc: func(context.Context, sharedkernel.Scope, string, string, string) error { return nil }, resource: func(access CapabilityResourceAccess) error {
		if access.Action != "model.generate" || access.ResourceType != "model" || access.ResourceID != "model-a" {
			t.Fatal("receipt bypassed model permission")
		}
		checks++
		if checks == denyAt {
			return errors.New("revoked")
		}
		return nil
	}})
	input := map[string]any{"messages": messages, "prompt_template_hash": "prompt-hash", "idempotency_key": "signed-model-read"}
	if result := capabilityRequest(t, m, "/internal/model/receipt", c, input); result.Code != 200 || !strings.Contains(result.Body.String(), "protected-model-answer") {
		t.Fatal("authorized receipt failed")
	}
	denyAt = checks + 2
	if result := capabilityRequest(t, m, "/internal/model/receipt", c, input); result.Code != 403 || strings.Contains(result.Body.String(), "protected-model-answer") {
		t.Fatal("revoked receipt disclosed answer")
	}
}

func TestModelReadOnlyReceiptDoesNotCreateInvocationOrChangeSpend(t *testing.T) {
	m := newTestModule("internal-token", "signing-secret", nil, "platform", "agent-runtime")
	c := capabilityContext()
	input := map[string]any{"messages": []map[string]string{{"role": "user", "content": "hello"}}, "idempotency_key": "model-receipt"}
	store := m.modelStore.(*memoryModelInvocationStore)
	if result := capabilityRequest(t, m, "/internal/model/receipt", c, input); result.Code != 200 || !strings.Contains(result.Body.String(), `"status":"not_found"`) || len(store.records) != 0 {
		t.Fatal("read created a model invocation")
	}
	if result := capabilityRequest(t, m, "/internal/model/generate", c, input); result.Code != 200 {
		t.Fatal("fixture generation failed")
	}
	spent := store.spent[capabilityScopeHash(c)]
	if result := capabilityRequest(t, m, "/internal/model/receipt", c, input); result.Code != 200 || !strings.Contains(result.Body.String(), `"status":"completed"`) || !strings.Contains(result.Body.String(), `"text"`) || store.spent[capabilityScopeHash(c)] != spent || len(store.records) != 1 {
		t.Fatal("read failed or changed spend")
	}
	input["messages"] = []map[string]string{{"role": "user", "content": "changed"}}
	if result := capabilityRequest(t, m, "/internal/model/receipt", c, input); result.Code != 409 || strings.Contains(result.Body.String(), `"text"`) {
		t.Fatal("read ignored generation fingerprint")
	}
}
