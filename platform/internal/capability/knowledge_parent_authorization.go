package capability

import "github.com/lexagent/platform/internal/policyasset"

func filterParentContext(reference map[string]any, allowed map[string]policyasset.KnowledgeDocumentBinding) {
	raw, exists := reference["parent_context"]
	if !exists {
		return
	}
	parent, ok := raw.(map[string]any)
	valid := ok && stringValue(reference["source"]) == "platform-knowledge" && stringValue(parent["schema_version"]) == "authorized-parent-context/v1"
	if valid {
		documents, ok := parent["source_documents"].([]map[string]any)
		valid = ok && len(documents) > 0 && len(documents) <= 1000
		childFound := false
		seen := map[string]bool{}
		for _, document := range documents {
			id := stringValue(document["source"]) + "/" + stringValue(document["provider_knowledge_base_id"]) + "/" + stringValue(document["provider_document_id"])
			published, found := allowed[id]
			if !found || seen[id] || stringValue(document["source"]) != "platform-knowledge" ||
				stringValue(document["provider_knowledge_base_id"]) != stringValue(reference["provider_knowledge_base_id"]) ||
				stringValue(document["document_version"]) != published.DocumentVersion {
				valid = false
				break
			}
			seen[id] = true
			if stringValue(document["provider_document_id"]) == stringValue(reference["provider_document_id"]) {
				childFound = true
			}
		}
		valid = valid && childFound
	}
	if !valid {
		delete(reference, "parent_context")
		reference["parent_context_status"] = "current_authority_unavailable"
	}
}
