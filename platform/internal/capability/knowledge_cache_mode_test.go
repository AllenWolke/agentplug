package capability

import (
	"context"
	"net/http"
	"testing"
)

func TestKnowledgeCacheModesAreValidatedBeforeProvider(t *testing.T) {
	for _, mode := range []string{"", "use", "cold", "bypass", "unknown", "USE"} {
		t.Run("mode-"+mode, func(t *testing.T) {
			m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedModelResolver("local", false, 0))
			calls := 0
			m.knowledge = knowledgeProviderFunc(func(_ context.Context, _ harnessContext, q knowledgeQuery) (map[string]any, error) {
				calls++
				if q.CacheMode != mode {
					t.Fatal("cache mode lost at provider")
				}
				return map[string]any{"references": []map[string]any{}}, nil
			})
			response := capabilityRequest(t, m, "/internal/knowledge/search", capabilityContext(), map[string]any{"query": "question", "knowledge_scope": "platform-knowledge", "cache_mode": mode})
			if mode == "unknown" || mode == "USE" {
				if response.Code != http.StatusBadRequest || calls != 0 {
					t.Fatal("invalid mode reached provider", response.Code, calls)
				}
			} else if response.Code != http.StatusOK || calls != 1 {
				t.Fatal("valid mode refused", response.Code, calls)
			}
		})
	}
}
