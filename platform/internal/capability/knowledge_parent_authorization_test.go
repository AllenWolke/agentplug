package capability

import (
	"github.com/lexagent/platform/internal/policyasset"
	"testing"
)

func TestParentIsRemovedWhenSiblingPermissionChanges(t *testing.T) {
	reference := map[string]any{"source": "platform-knowledge", "provider_knowledge_base_id": "kb",
		"content": "allowed child", "parent_context": map[string]any{"schema_version": "authorized-parent-context/v1",
			"content": "sibling content", "source_documents": []map[string]any{
				{"source": "platform-knowledge", "provider_knowledge_base_id": "kb", "provider_document_id": "child", "document_version": "v1"},
				{"source": "platform-knowledge", "provider_knowledge_base_id": "kb", "provider_document_id": "sibling", "document_version": "v1"}}}}
	filterParentContext(reference, map[string]policyasset.KnowledgeDocumentBinding{
		"platform-knowledge/kb/child": {DocumentVersion: "v1"}})
	if _, exists := reference["parent_context"]; exists {
		t.Fatal("denied sibling leaked through parent context")
	}
	if reference["content"] != "allowed child" {
		t.Fatal("authorized child was changed")
	}
}

func TestRemoteProviderCannotSupplyParentExpansion(t *testing.T) {
	reference := map[string]any{"source": "retrievalops", "parent_context": map[string]any{
		"schema_version": "authorized-parent-context/v1", "content": "forged"}}
	filterParentContext(reference, nil)
	if _, exists := reference["parent_context"]; exists {
		t.Fatal("untrusted parent bypass")
	}
}

func TestCompletePublishedParentRetainsItsAuthorizedChild(t *testing.T) {
	reference := map[string]any{"source": "platform-knowledge", "provider_knowledge_base_id": "kb", "provider_document_id": "child",
		"parent_context": map[string]any{"schema_version": "authorized-parent-context/v1", "content": "complete",
			"source_documents": []map[string]any{{"source": "platform-knowledge", "provider_knowledge_base_id": "kb",
				"provider_document_id": "child", "document_version": "v1"}}}}
	filterParentContext(reference, map[string]policyasset.KnowledgeDocumentBinding{"platform-knowledge/kb/child": {DocumentVersion: "v1"}})
	if _, ok := reference["parent_context"]; !ok {
		t.Fatal("complete authorized parent rejected")
	}
}
