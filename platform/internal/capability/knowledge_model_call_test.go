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
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestKnowledgeInternalModelCallRequiresIndependentCurrentResourceGrant(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := governedModelResolver("local", false, 0)
	resolver.snapshot.Hash = strings.Repeat("b", 64)
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
	authority := &resourceAuthorityFixture{}
	m.SetLiveExecutionAuthority(authority)
	accessCalls := 0
	m.SetGovernedModelInvocation(modelAccessResolverFunc(func(context.Context, sharedkernel.Scope, string) (modelgateway.Selection, error) {
		accessCalls++
		return modelgateway.Selection{}, nil
	}), &captureModelGateway{})
	m.knowledge = knowledgeProviderFunc(func(ctx context.Context, _ harnessContext, q knowledgeQuery) (map[string]any, error) {
		// Knowledge access was allowed. Revoke independent model access before
		// the nested stage; it must fail before resolving model/price or sending.
		authority.denied = true
		return q.ModelCall(ctx, "generate", map[string]any{"messages": []map[string]string{{"role": "user", "content": "rewrite"}}})
	})
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	response := capabilityRequest(t, m, "/internal/knowledge/search", c, map[string]any{"query": "question", "knowledge_scope": "platform-knowledge"})
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "CAPABILITY_DENIED") || accessCalls != 0 || authority.access.Action != "model.generate" || authority.access.ResourceID != "model-a" {
		t.Fatalf("knowledge resource granted model effect: status=%d access_calls=%d action=%s", response.Code, accessCalls, authority.access.Action)
	}
}

type cacheCheckUsageGateway struct{ captureModelGateway }

func (g *cacheCheckUsageGateway) EmbedWithUsage(context.Context, sharedkernel.Scope, policyasset.Snapshot, []string) (modelgateway.EmbeddingResult, error) {
	g.calls++
	return modelgateway.EmbeddingResult{}, modelgateway.ErrProviderUnavailable
}

func TestKnowledgeCacheCheckSelectsPublishedEmbeddingTarget(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := governedInvocationResolver()
	resolver.snapshot.Hash = strings.Repeat("b", 64)
	resolver.snapshot.Model.EmbeddingModelVersionID = "embedding-version"
	resolver.snapshot.Model.EmbeddingProvider = "embedding-provider"
	resolver.snapshot.Model.EmbeddingModel = "embedding-model"
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
	authority := &resourceAuthorityFixture{}
	m.SetLiveExecutionAuthority(authority)
	resolved := 0
	gateway := &cacheCheckUsageGateway{}
	m.SetGovernedModelInvocation(modelAccessResolverFunc(func(_ context.Context, scope sharedkernel.Scope, version string) (modelgateway.Selection, error) {
		resolved++
		if scope.PrincipalID != "user-a" || version != "embedding-version" {
			t.Fatal("cached embedding checked primary model instead of published embedding target")
		}
		return modelgateway.Selection{ModelVersionID: version, ProviderID: "embedding-provider-id", ProviderKey: "embedding-provider", ModelID: "embedding-model-id", ModelKey: "embedding-model", TrustZone: modelgovernance.TrustLocal}, nil
	}), gateway)
	m.knowledge = knowledgeProviderFunc(func(ctx context.Context, _ harnessContext, q knowledgeQuery) (map[string]any, error) {
		if err := q.ModelCheck(ctx, "embed"); err != nil {
			return nil, err
		}
		if authority.access.Action != "model.embed" || authority.access.ResourceID != "model-a" {
			t.Fatal("embedding cache check did not enforce model resource grant", authority.access)
		}
		return map[string]any{"references": []map[string]any{}}, nil
	})
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	response := capabilityRequest(t, m, "/internal/knowledge/search", c, map[string]any{"query": "question", "knowledge_scope": "platform-knowledge"})
	if response.Code != http.StatusOK || resolved != 1 || gateway.calls != 0 {
		t.Fatal("cached embedding target check", response.Code, resolved, gateway.calls, authority.access)
	}
}

func TestKnowledgeCacheCheckRequiresCurrentSignedModelAuthority(t *testing.T) {
	for _, mode := range []string{"allowed", "resource-denied", "approval-revoked", "selection-mismatch", "resource-revoked-during-resolution", "retained-after-request"} {
		t.Run(mode, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			resolver := governedInvocationResolver()
			resolver.snapshot.Hash = strings.Repeat("b", 64)
			m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
			authority := &resourceAuthorityFixture{}
			m.SetLiveExecutionAuthority(authority)
			accessCalls := 0
			gateway := &captureModelGateway{}
			m.SetGovernedModelInvocation(modelAccessResolverFunc(func(_ context.Context, scope sharedkernel.Scope, version string) (modelgateway.Selection, error) {
				accessCalls++
				if scope.PrincipalID != "user-a" || version != "version-a" {
					t.Fatal("cache check used untrusted identity or model")
				}
				if mode == "approval-revoked" {
					return modelgateway.Selection{}, modelgovernance.ErrModelAccessDenied
				}
				if mode == "resource-revoked-during-resolution" {
					authority.denied = true
				}
				selection := modelgateway.Selection{ModelVersionID: "version-a", ProviderID: "provider-id", ProviderKey: "provider-a", ModelID: "model-id", ModelKey: "chat-model-a", TrustZone: modelgovernance.TrustLocal}
				if mode == "selection-mismatch" {
					selection.ModelKey = "other"
				}
				return selection, nil
			}), gateway)
			var retained KnowledgeModelCheck
			m.knowledge = knowledgeProviderFunc(func(ctx context.Context, _ harnessContext, q knowledgeQuery) (map[string]any, error) {
				retained = q.ModelCheck
				if mode == "resource-denied" {
					authority.denied = true
				}
				if err := q.ModelCheck(ctx, "generate"); err != nil {
					return nil, err
				}
				return map[string]any{"references": []map[string]any{}}, nil
			})
			c := capabilityContext()
			c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
			response := capabilityRequest(t, m, "/internal/knowledge/search", c, map[string]any{"query": "question", "knowledge_scope": "platform-knowledge"})
			expected := http.StatusForbidden
			if mode == "allowed" || mode == "retained-after-request" {
				expected = http.StatusOK
			}
			if response.Code != expected || gateway.calls != 0 {
				t.Fatal("cache check status/provider invocation", response.Code, gateway.calls)
			}
			if mode == "resource-denied" && accessCalls != 0 {
				t.Fatal("denied resource reached model resolver")
			}
			if mode == "retained-after-request" {
				before := accessCalls
				if err := retained(context.Background(), "generate"); err == nil || accessCalls != before {
					t.Fatal("retained callback escaped request lifetime")
				}
			}
		})
	}
}
