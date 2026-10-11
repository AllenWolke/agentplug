package capability

import (
	"context"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/modelgateway"
)

func TestEmbeddingReceiptPreservesPurposeAndReadsOnly(t *testing.T) {
	for _, purpose := range []string{"query", "document", ""} {
		name := purpose
		if name == "" {
			name = "legacy-empty"
		}
		t.Run(name, func(t *testing.T) {
			policy := governedInvocationResolver()
			policy.snapshot.Hash = strings.Repeat("b", 64)
			policy.snapshot.Model.EmbeddingModelVersionID = "embedding-v1"
			policy.snapshot.Model.EmbeddingProvider = "embedding-provider"
			policy.snapshot.Model.EmbeddingModel = "embedding-model"
			selected, err := policy.snapshot.Model.ForEmbedding()
			if err != nil {
				t.Fatal(err)
			}
			m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, policy)
			c := capabilityContext()
			messages := []modelgateway.Message{{Role: "user", Content: "teaching query"}}
			base, err := modelCommandFingerprint(messages, 0, 1, policy.snapshot.Prompt.TemplateHash, selected, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			fingerprint := modelPurposeFingerprint(base, purpose)
			store := m.modelStore.(*memoryModelInvocationStore)
			const key = "purpose-bound-embedding"
			if _, _, err := store.Reserve(context.Background(), capabilityScopeHash(c), key, fingerprint, 0, 0); err != nil {
				t.Fatal(err)
			}
			if err := store.Complete(context.Background(), capabilityScopeHash(c), key, fingerprint, map[string]any{"embeddings": [][]float64{{0.1, 0.2}}, "usage": map[string]any{"input_tokens": 3}}, 0); err != nil {
				t.Fatal(err)
			}
			input := map[string]any{"texts": []string{"teaching query"}, "idempotency_key": key}
			if purpose != "" {
				input["input_purpose"] = purpose
			}
			for n := 0; n < 2; n++ {
				result := capabilityRequest(t, m, "/internal/model/embed/receipt", c, input)
				if result.Code != 200 || !strings.Contains(result.Body.String(), `"status":"completed"`) || !strings.Contains(result.Body.String(), `"embeddings"`) {
					t.Fatalf("purpose=%q receipt status=%d: %s", purpose, result.Code, result.Body.String())
				}
			}
			changed := "query"
			if purpose == "query" {
				changed = "document"
			}
			input["input_purpose"] = changed
			result := capabilityRequest(t, m, "/internal/model/embed/receipt", c, input)
			if result.Code != 409 || strings.Contains(result.Body.String(), `"embeddings"`) {
				t.Fatal("changed purpose disclosed another encoding receipt")
			}
			input["input_purpose"] = "arbitrary"
			result = capabilityRequest(t, m, "/internal/model/embed/receipt", c, input)
			if result.Code != 400 || strings.Contains(result.Body.String(), `"embeddings"`) {
				t.Fatal("invalid purpose accepted")
			}
			generation := map[string]any{"messages": messages, "input_purpose": "query", "idempotency_key": "no-cross-operation-purpose"}
			result = capabilityRequest(t, m, "/internal/model/receipt", c, generation)
			if result.Code != 400 || strings.Contains(result.Body.String(), `"embeddings"`) {
				t.Fatal("generation receipt accepted an embedding-only purpose")
			}
			if len(store.records) != 1 || store.spent[capabilityScopeHash(c)] != 0 {
				t.Fatal("read-only receipt changed invocation or spend")
			}
		})
	}
}
