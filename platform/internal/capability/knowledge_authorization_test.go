package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type documentAuthorityFixture struct {
	resourceAuthorityFixture
	calls  int
	revoke bool
	empty  bool
}

type knowledgeProviderFunc func(context.Context, harnessContext, knowledgeQuery) (map[string]any, error)

type knowledgePortFunc func(context.Context, sharedkernel.Scope, KnowledgeSearchRequest) (map[string]any, error)

func (f knowledgePortFunc) SearchKnowledge(ctx context.Context, scope sharedkernel.Scope, q KnowledgeSearchRequest) (map[string]any, error) {
	return f(ctx, scope, q)
}

func (f knowledgeProviderFunc) Search(ctx context.Context, h harnessContext, q knowledgeQuery) (map[string]any, error) {
	return f(ctx, h, q)
}

func (f *documentAuthorityFixture) FilterKnowledgeDocuments(_ context.Context, s sharedkernel.Scope, scope string, documents []policyasset.KnowledgeDocumentBinding) (KnowledgeDocumentPlan, error) {
	f.calls++
	plan := KnowledgeDocumentPlan{Documents: []policyasset.KnowledgeDocumentBinding{}}
	if f.empty || f.revoke && f.calls > 1 {
		return plan, nil
	}
	for _, d := range documents {
		if d.KnowledgeScope == scope && d.OwnerID == s.PrincipalID && d.Effective(time.Now()) {
			plan.Documents = append(plan.Documents, d)
		}
	}
	return plan, nil
}

func TestSignedKnowledgeFiltersActualProviderIdentitiesBeforeFinalTopK(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"allowed", "revoked-after-provider", "empty-authority"} {
		t.Run(mode, func(t *testing.T) {
			providerCalls := 0
			provider := NewGovernedKnowledgeProvider(knowledgePortFunc(func(_ context.Context, scope sharedkernel.Scope, input KnowledgeSearchRequest) (map[string]any, error) {
				providerCalls++
				if scope.ValidateTrusted() != nil || scope.PrincipalID != "user-a" || scope.RunID != "run-a" || input.Policy.Revision != 10 || input.Policy.KnowledgePolicyID != "knowledge-a" || len(input.Documents) != 1 || input.Documents[0].ProviderDocumentID != "9007199254740993" || input.TopK != 1 {
					t.Error("trusted candidate filter not forwarded")
				}
				input.Documents[0].ProviderDocumentID = "provider-mutated"
				input.Policy.Knowledge.AllowedScopes[0] = "provider-mutated"
				return map[string]any{"references": []map[string]any{
					{"source": "platform-knowledge", "provider_knowledge_base_id": "7", "provider_document_id": "43", "content": "DENIED-PRIVATE-BODY", "retrieval_score": .99},
					{"source": "platform-knowledge", "provider_knowledge_base_id": "7", "provider_document_id": "9007199254740993", "doc_id": "platform-knowledge/7/9007199254740993", "content": "ALLOWED-BODY", "retrieval_score": .91},
					{"source": "platform-knowledge", "provider_document_id": "42", "content": "UNKNOWN-PRIVATE-BODY", "retrieval_score": .90},
				}}, nil
			}))
			resolver := governedModelResolver("local", false, 0)
			resolver.snapshot.Hash = strings.Repeat("b", 64)
			resolver.snapshot.Knowledge.DocumentBindings = []policyasset.KnowledgeDocumentBinding{{KnowledgeScope: "platform-knowledge", ProviderID: "platform-knowledge", KnowledgeBaseID: "7", ProviderDocumentID: "9007199254740993", OwnerID: "user-a", OwnershipSource: "reviewed:provider-id", DocumentVersion: "v1", Status: "active"}}
			m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", provider, resolver)
			f := &documentAuthorityFixture{revoke: mode == "revoked-after-provider", empty: mode == "empty-authority"}
			m.SetLiveExecutionAuthority(f)
			c := capabilityContext()
			c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
			response := capabilityRequest(t, m, "/internal/knowledge/search", c, map[string]any{"query": "question", "knowledge_scope": "platform-knowledge", "top_k": 1, "owner_id": "forged", "document_ids": []string{"43"}})
			body := response.Body.String()
			if resolver.snapshot.Knowledge.AllowedScopes[0] != "platform-knowledge" || resolver.snapshot.Knowledge.DocumentBindings[0].ProviderDocumentID != "9007199254740993" {
				t.Fatal("provider mutated published policy or final authorization facts")
			}
			if strings.Contains(body, "DENIED-PRIVATE") || strings.Contains(body, "UNKNOWN-PRIVATE") {
				t.Fatal("denied body escaped", body)
			}
			if mode == "allowed" {
				if response.Code != http.StatusOK || !strings.Contains(body, "ALLOWED-BODY") || !strings.Contains(body, "platform-knowledge/7/9007199254740993") || !strings.Contains(body, `"retrieval_score":0.91`) {
					t.Fatal("authorized evidence missing or ID lost precision", response.Code, body)
				}
			} else if response.Code != http.StatusForbidden || strings.Contains(body, "ALLOWED-BODY") {
				t.Fatal("revoked or empty authority disclosed content", response.Code, body)
			}
			if mode == "empty-authority" && providerCalls != 0 {
				t.Fatal("provider called without document authority")
			}
		})
	}
}

func TestKnowledgeFilteringDoesNotReturnUnfilteredProviderMetadata(t *testing.T) {
	doc := policyasset.KnowledgeDocumentBinding{ProviderID: "platform-knowledge", KnowledgeBaseID: "7", ProviderDocumentID: "42"}
	filtered := filterKnowledgeReferences(map[string]any{
		"references":        []map[string]any{{"source": "platform-knowledge", "provider_knowledge_base_id": "7", "provider_document_id": "42", "content": "allowed"}},
		"retrieved_sources": []string{"DENIED-METADATA"}, "failed_sources": []string{"DENIED-METADATA"}, "request_id": "DENIED-METADATA", "debug": "DENIED-METADATA",
	}, KnowledgeDocumentPlan{Documents: []policyasset.KnowledgeDocumentBinding{doc}}, 1)
	encoded, err := json.Marshal(filtered)
	if err != nil || strings.Contains(string(encoded), "DENIED-METADATA") || !strings.Contains(string(encoded), "allowed") {
		t.Fatalf("unfiltered metadata escaped: %s, %v", encoded, err)
	}
}
