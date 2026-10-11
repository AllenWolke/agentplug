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

func TestSignedKnowledgeAnswerRejectsWholeAnswerWhenEvidenceOrModelIsDenied(t *testing.T) {
	for _, mode := range []string{"allowed", "evidence-revoked", "partial-denied-evidence", "model-revoked", "unknown-citation"} {
		t.Run(mode, func(t *testing.T) {
			public, private, _ := ed25519.GenerateKey(rand.Reader)
			resolver := governedInvocationResolver()
			resolver.snapshot.Hash = strings.Repeat("b", 64)
			resolver.snapshot.Knowledge.DocumentBindings = []policyasset.KnowledgeDocumentBinding{{KnowledgeScope: "platform-knowledge", ProviderID: "platform-knowledge", KnowledgeBaseID: "docs", ProviderDocumentID: "doc-1", OwnerID: "user-a", OwnershipSource: "source:doc-1", DocumentVersion: "v1", Status: "active"}}
			authority := &documentAuthorityFixture{revoke: mode == "evidence-revoked"}
			m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
			m.SetLiveExecutionAuthority(authority)
			m.SetGovernedModelInvocation(modelAccessResolverFunc(func(_ context.Context, _ sharedkernel.Scope, version string) (modelgateway.Selection, error) {
				return modelgateway.Selection{ModelVersionID: version, ProviderID: "provider-id-a", ProviderKey: "provider-a", ModelID: "model-id-a", ModelKey: "chat-model-a", TrustZone: modelgovernance.TrustLocal}, nil
			}), &captureModelGateway{})
			m.knowledge = knowledgeProviderFunc(func(_ context.Context, _ harnessContext, q knowledgeQuery) (map[string]any, error) {
				if !q.Answer {
					t.Error("answer route became plain retrieval")
				}
				refs := []map[string]any{{"source": "platform-knowledge", "provider_knowledge_base_id": "docs", "provider_document_id": "doc-1", "clause_or_chunk_id": "chunk-1", "doc_id": "platform-knowledge/docs/doc-1", "kb_version": "g1", "content": "canonical evidence"}}
				if mode == "partial-denied-evidence" {
					refs = append(refs, map[string]any{"source": "platform-knowledge", "provider_knowledge_base_id": "docs", "provider_document_id": "private", "content": "private evidence"})
				}
				if mode == "model-revoked" {
					authority.denied = true
				}
				ids := []string{"chunk-1"}
				if mode == "unknown-citation" {
					ids = []string{"invented"}
				}
				return map[string]any{"references": refs, "text": "COMPLETE-ANSWER", "citation_ids": ids, "answer_cache_hit": true, "grounding": map[string]bool{"supported": true}, "debug": "FORBIDDEN-DEBUG"}, nil
			})
			c := capabilityContext()
			c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
			response := capabilityRequest(t, m, "/internal/knowledge/answer", c, map[string]any{"query": "teaching question", "knowledge_scope": "platform-knowledge", "top_k": 3})
			body := response.Body.String()
			if mode == "allowed" {
				if response.Code != http.StatusOK || !strings.Contains(body, "evaluation_claims") || !strings.Contains(body, `"text":"COMPLETE-ANSWER"`) || !strings.Contains(body, "evaluation_citations") || strings.Contains(body, "FORBIDDEN-DEBUG") || strings.Contains(body, "supported") {
					t.Fatal("trusted answer evidence boundary failed", response.Code, body)
				}
			} else if response.Code < 400 || strings.Contains(body, "COMPLETE-ANSWER") || strings.Contains(body, "private evidence") {
				t.Fatal("answer disclosed rejected evidence", mode, response.Code, body)
			}
		})
	}
}

func TestKnowledgeAnswerHasNoLegacyUngovernedFallback(t *testing.T) {
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	response := capabilityRequest(t, m, "/internal/knowledge/answer", capabilityContext(), map[string]any{"query": "question", "knowledge_scope": "platform-knowledge"})
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "KNOWLEDGE_ANSWER_UNAVAILABLE") {
		t.Fatal("ungoverned answer fallback", response.Code)
	}
}
