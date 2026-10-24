package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
)

func TestKnowledgeRoutedReceiptChecksActualModelAndKeepsEmbeddingPinned(t *testing.T) {
	for _, mode := range []string{"allowed", "primary-denied", "selected-revoked", "complex-cannot-use-medium", "fixed-cannot-use-candidate", "unbound-cannot-use-candidate", "unknown-candidate", "profile-revoked", "embedding-pinned", "embedding-cannot-use-chat", "retained-after-request"} {
		t.Run(mode, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			_, routing, catalog, _ := routeFixture()
			resolver := governedInvocationResolver()
			resolver.snapshot.Hash = strings.Repeat("b", 64)
			resolver.snapshot.Model.Provider = "provider-large"
			resolver.snapshot.Model.Model = "large"
			resolver.snapshot.Model.ModelVersionID = "large"
			resolver.snapshot.Model.AllowExternal = true
			resolver.snapshot.Model.EmbeddingModelVersionID = "embedding-version"
			resolver.snapshot.Model.EmbeddingProvider = "embedding-provider"
			resolver.snapshot.Model.EmbeddingModel = "embedding-model"
			routing.ExecutionContextSHA256 = policyasset.RoutingExecutionContextSHA256(resolver.snapshot)
			resolver.snapshot.Model.Routing = &routing
			catalog.models["embedding-version"] = modelgateway.RoutingMetadata{Kind: "embedding", Selection: modelgateway.Selection{ModelVersionID: "embedding-version", ProviderID: "embed-provider-id", ProviderKey: "embedding-provider", ModelID: "embed-id", ModelKey: "embedding-model", TrustZone: modelgovernance.TrustLocal}}
			m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
			authority := &resourceAuthorityFixture{}
			m.SetLiveExecutionAuthority(authority)
			gateway := &cacheCheckUsageGateway{}
			m.SetGovernedModelInvocation(catalog, gateway)
			c := capabilityContext()
			c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
			selection, complexity := "automatic", "simple"
			if mode == "fixed-cannot-use-candidate" {
				selection = "manual"
			}
			if mode == "complex-cannot-use-medium" {
				complexity = "complex"
			}
			if mode != "unbound-cannot-use-candidate" {
				if err := m.modelStore.(policyasset.ModelSelectionStore).BindModelSelection(context.Background(), scopeFromHarness(c), policyasset.ModelSelectionBinding{Selection: policyasset.ModelSelection{Mode: selection}, PolicySHA256: resolver.snapshot.Hash, CommandFingerprint: strings.Repeat("a", 64), TaskComplexity: complexity, TaskSHA256: strings.Repeat("d", 64)}); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "primary-denied" {
				catalog.denied["large"] = modelgovernance.ErrModelAccessDenied
			}
			if mode == "selected-revoked" {
				catalog.denied["medium"] = modelgovernance.ErrModelAccessDenied
			}
			var retained KnowledgeModelReceiptCheck
			m.knowledge = knowledgeProviderFunc(func(ctx context.Context, _ harnessContext, q knowledgeQuery) (map[string]any, error) {
				retained = q.ModelReceiptCheck
				if q.ModelReceiptCheck == nil || q.ModelCacheBinding == nil {
					t.Fatal("trusted authority callbacks lost")
				}
				if mode == "profile-revoked" {
					authority.denied = true
				}
				if err := q.ModelCheck(ctx, "generate"); err != nil {
					return nil, err
				}
				operation, version := "generate", "medium"
				if mode == "unknown-candidate" {
					version = "invented"
				}
				if mode == "embedding-pinned" {
					operation, version = "embed", "embedding-version"
				}
				if mode == "embedding-cannot-use-chat" {
					operation = "embed"
				}
				if err := q.ModelReceiptCheck(ctx, operation, version); err != nil {
					return nil, err
				}
				return map[string]any{"references": []map[string]any{}}, nil
			})
			response := capabilityRequest(t, m, "/internal/knowledge/search", c, map[string]any{"query": "question", "knowledge_scope": "platform-knowledge"})
			want := http.StatusForbidden
			if mode == "allowed" || mode == "primary-denied" || mode == "embedding-pinned" || mode == "retained-after-request" {
				want = http.StatusOK
			}
			if response.Code != want || gateway.calls != 0 || catalog.priceCalls != 0 {
				t.Fatalf("authority check selected/sent/charged or returned wrong status: mode=%s status=%d want=%d body=%s", mode, response.Code, want, response.Body.String())
			}
			if mode == "retained-after-request" {
				if err := retained(context.Background(), "generate", "medium"); err == nil {
					t.Fatal("receipt callback escaped its request lifetime")
				}
			}
		})
	}
}

func TestKnowledgeRoutingCachePartitionUsesOriginalTaskAndSelection(t *testing.T) {
	m, original, _, _ := routeInvocationFixture(t)
	store := m.modelStore.(policyasset.ModelSelectionStore)
	hashes := []string{}
	for i, task := range []string{strings.Repeat("a", 64), strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		op := original
		op.Context.TaskID = "cache-run-" + string(rune('a'+i))
		b := policyasset.ModelSelectionBinding{Selection: policyasset.ModelSelection{Mode: "automatic"}, PolicySHA256: op.Policy.Hash, CommandFingerprint: strings.Repeat("e", 64), TaskComplexity: "simple", TaskSHA256: task}
		if err := store.BindModelSelection(context.Background(), scopeFromHarness(op.Context), b); err != nil {
			t.Fatal(err)
		}
		value, err := m.knowledgeModelCacheBinding(op, context.Background())(context.Background())
		if err != nil || len(value) != 64 {
			t.Fatal("cache boundary missing", err)
		}
		hashes = append(hashes, value)
	}
	if hashes[0] != hashes[1] || hashes[1] == hashes[2] {
		t.Fatal("cache partition confused Run identity with original task")
	}
}
