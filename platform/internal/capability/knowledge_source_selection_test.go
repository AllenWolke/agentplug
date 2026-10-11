package capability

import (
	"github.com/lexagent/platform/internal/policyasset"
	"testing"
)

func TestKnowledgeSourceSelectionCannotExpandAuthority(t *testing.T) {
	plan := KnowledgeDocumentPlan{Documents: []policyasset.KnowledgeDocumentBinding{{ProviderID: "platform-knowledge", KnowledgeBaseID: "kb", ProviderDocumentID: "1", DocumentVersion: "v1"}, {ProviderID: "other", KnowledgeBaseID: "kb", ProviderDocumentID: "2", DocumentVersion: "v2"}}}
	for _, ids := range [][]string{{"missing"}, {"platform-knowledge", "platform-knowledge"}, {" platform-knowledge"}} {
		if _, err := selectKnowledgeSources(plan, ids); err == nil {
			t.Fatal("expanded or ambiguous source selection allowed", ids)
		}
	}
	narrowed, err := selectKnowledgeSources(plan, []string{"platform-knowledge"})
	if err != nil || len(narrowed.Documents) != 1 || narrowed.Documents[0].ProviderDocumentID != "1" || len(plan.Documents) != 2 {
		t.Fatal("source selection changed published facts")
	}
	if _, err := selectKnowledgeSources(KnowledgeDocumentPlan{Legacy: true}, []string{"other"}); err == nil {
		t.Fatal("unverified source selection allowed")
	}
}

func TestKnowledgeDegradationDoesNotExposeUnauthorizedProviders(t *testing.T) {
	plan := KnowledgeDocumentPlan{Documents: []policyasset.KnowledgeDocumentBinding{{ProviderID: "authorized", KnowledgeBaseID: "kb", ProviderDocumentID: "1", DocumentVersion: "v2"}}}
	out := filterKnowledgeReferences(map[string]any{"references": []map[string]any{{"source": "authorized", "provider_knowledge_base_id": "kb", "provider_document_id": "1", "document_version": "v1", "content": "old version"}}, "failed_sources": []string{"denied", "authorized", "authorized"}}, plan, 5)
	if len(out["references"].([]map[string]any)) != 0 {
		t.Fatal("wrong evidence version accepted")
	}
	failed := out["failed_sources"].([]string)
	if len(failed) != 1 || failed[0] != "authorized" || out["partial_degraded"] != true {
		t.Fatal("source failure boundary or degradation lost", out)
	}
}
