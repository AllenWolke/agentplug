package capability

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/lexagent/platform/internal/policyasset"
)

// Authorize cached reference identities without retrieving private text or
// invoking any model. Current document ACL and immutable publication both apply.
func (m *Module) authorizeKnowledgeReferences(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	var input struct {
		Version    string `json:"version"`
		Scope      string `json:"knowledge_scope"`
		References []struct {
			Source          string `json:"source"`
			KnowledgeBaseID string `json:"provider_knowledge_base_id"`
			DocumentID      string `json:"provider_document_id"`
			Version         string `json:"document_version"`
		} `json:"references"`
	}
	decoder := json.NewDecoder(bytes.NewReader(op.Input))
	decoder.DisallowUnknownFields()
	invalid := decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.Version != "knowledge-reference-authorization/v1" || len(input.References) < 1 || len(input.References) > 128
	if !invalid {
		invalid = !slices.Contains(op.Policy.Knowledge.AllowedScopes, input.Scope)
		for _, ref := range input.References {
			for _, value := range []string{ref.Source, ref.KnowledgeBaseID, ref.DocumentID, ref.Version} {
				if value == "" || len(value) > 256 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/*\x00\r\n") {
					invalid = true
				}
			}
		}
	}
	if invalid {
		m.error(w, 400, "INVALID_REQUEST", "bounded reference identities required", op.Context.TraceID)
		return
	}
	// Resolve only the requested identities from the trusted publication. A
	// cached answer with one document must not evaluate every unrelated document
	// in a large corpus twice. Owners, versions and validity remain server facts.
	wanted := make(map[string]string, len(input.References))
	for _, ref := range input.References {
		id := ref.Source + "/" + ref.KnowledgeBaseID + "/" + ref.DocumentID
		if version, exists := wanted[id]; exists && version != ref.Version {
			m.error(w, 403, "KNOWLEDGE_DOCUMENTS_DENIED", "current reference authorization denied", op.Context.TraceID)
			return
		}
		wanted[id] = ref.Version
	}
	bindings := make([]policyasset.KnowledgeDocumentBinding, 0, len(wanted))
	seen := make(map[string]bool, len(wanted))
	for _, document := range op.Policy.Knowledge.DocumentBindings {
		if version, exists := wanted[document.ObjectID()]; exists && document.KnowledgeScope == input.Scope && version == document.DocumentVersion {
			if seen[document.ObjectID()] {
				m.error(w, 403, "KNOWLEDGE_DOCUMENTS_DENIED", "current reference authority unavailable", op.Context.TraceID)
				return
			}
			seen[document.ObjectID()] = true
			bindings = append(bindings, document)
		}
	}
	if len(bindings) != len(wanted) {
		m.error(w, 403, "KNOWLEDGE_DOCUMENTS_DENIED", "current reference authorization denied", op.Context.TraceID)
		return
	}
	// Recheck the current plan before and after processing, just as normal
	// retrieval does before final disclosure. Return only a boolean aggregate.
	for iteration := 0; iteration < 2; iteration++ {
		if !m.currentCapability(w, r, op) {
			return
		}
		plan, err := m.knowledgeDocumentPlanForBindings(r, op, input.Scope, bindings)
		if err != nil || plan.Legacy {
			m.error(w, 403, "KNOWLEDGE_DOCUMENTS_DENIED", "current reference authority unavailable", op.Context.TraceID)
			return
		}
		allowed := map[string]string{}
		for _, document := range plan.Documents {
			allowed[document.ObjectID()] = document.DocumentVersion
		}
		for _, ref := range input.References {
			if allowed[ref.Source+"/"+ref.KnowledgeBaseID+"/"+ref.DocumentID] != ref.Version {
				m.error(w, 403, "KNOWLEDGE_DOCUMENTS_DENIED", "current reference authorization denied", op.Context.TraceID)
				return
			}
		}
	}
	m.currentResult(w, r, op, map[string]any{"version": "knowledge-reference-authorization/v1", "authorized": true,
		"reference_count": len(input.References), "model_requests_sent": 0})
}
