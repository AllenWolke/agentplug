package capability

import (
	"context"
	"errors"
	"net/http"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

var errKnowledgeDocumentAuthority = errors.New("knowledge document authority unavailable")

type KnowledgeDocumentPlan struct {
	Legacy    bool
	Documents []policyasset.KnowledgeDocumentBinding
}
type KnowledgeDocumentAuthority interface {
	FilterKnowledgeDocuments(context.Context, sharedkernel.Scope, string, []policyasset.KnowledgeDocumentBinding) (KnowledgeDocumentPlan, error)
}

func (m *Module) knowledgeDocumentPlan(r *http.Request, op envelope, scope string) (KnowledgeDocumentPlan, error) {
	if m.publicKey == nil {
		return KnowledgeDocumentPlan{Legacy: true}, nil
	}
	authority, ok := m.liveAuthority.(KnowledgeDocumentAuthority)
	if !ok {
		return KnowledgeDocumentPlan{}, errKnowledgeDocumentAuthority
	}
	c := op.Context
	s := sharedkernel.Scope{TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID, AgentInstanceID: c.AgentInstanceID, AgentID: c.AgentID, PrincipalType: c.PrincipalType, PrincipalID: c.ActorID, InstallationID: c.InstallationID, AgentVersionID: c.AgentVersionID, SessionID: c.SessionID, RunID: c.TaskID, ParentRunID: c.ParentRunID, AuthorizationEpoch: c.AuthorizationEpoch, TraceID: c.TraceID}
	return authority.FilterKnowledgeDocuments(r.Context(), s, scope, op.Policy.Knowledge.DocumentBindings)
}

// No raw provider reference or its ownership metadata bypasses this boundary.
func filterKnowledgeReferences(result map[string]any, plan KnowledgeDocumentPlan, topK int) map[string]any {
	if plan.Legacy {
		return result
	}
	allowed := map[string]policyasset.KnowledgeDocumentBinding{}
	allowedSources := map[string]bool{}
	for _, d := range plan.Documents {
		allowed[d.ObjectID()] = d
		allowedSources[d.ProviderID] = true
	}
	references := []map[string]any{}
	sources := []string{}
	seenSources := map[string]bool{}
	items, _ := result["references"].([]map[string]any)
	for _, item := range items {
		id := stringValue(item["source"]) + "/" + stringValue(item["provider_knowledge_base_id"]) + "/" + stringValue(item["provider_document_id"])
		if document, ok := allowed[id]; ok {
			if version := stringValue(item["document_version"]); version != "" && version != document.DocumentVersion {
				continue
			}
			copy := make(map[string]any, len(item))
			for k, v := range item {
				copy[k] = v
			}
			copy["authorization_document_id"], copy["authorized_document_version"] = document.ObjectID(), document.DocumentVersion
			filterParentContext(copy, allowed)
			references = append(references, copy)
			source := document.ProviderID
			if !seenSources[source] {
				sources = append(sources, source)
				seenSources[source] = true
			}
			if topK > 0 && len(references) >= topK {
				break
			}
		}
	}
	// Keep only documented aggregate fields; unfiltered provider totals/debug
	// payloads can disclose denied documents even when references are removed.
	failed, seenFailed := []string{}, map[string]bool{}
	if values, ok := result["failed_sources"].([]string); ok {
		for _, source := range values {
			if allowedSources[source] && !seenFailed[source] {
				failed = append(failed, source)
				seenFailed[source] = true
			}
		}
	}
	return map[string]any{"references": references, "retrieved_sources": sources, "failed_sources": failed, "partial_degraded": len(failed) > 0}
}

func (m *Module) knowledgeResult(w http.ResponseWriter, r *http.Request, op envelope, knowledgeScope string, topK int, result map[string]any) {
	if !m.currentCapability(w, r, op) {
		return
	}
	plan, err := m.knowledgeDocumentPlan(r, op, knowledgeScope)
	if err != nil || !plan.Legacy && len(plan.Documents) == 0 {
		m.error(w, http.StatusForbidden, "KNOWLEDGE_DOCUMENTS_DENIED", "current knowledge document authorization denied", op.Context.TraceID)
		return
	}
	result = filterKnowledgeReferences(result, plan, topK)
	if op.Policy.Knowledge.RequireReferences {
		refs, _ := result["references"].([]map[string]any)
		if len(refs) == 0 {
			m.error(w, http.StatusUnprocessableEntity, "KNOWLEDGE_REFERENCES_REQUIRED", "published policy requires authorized references", op.Context.TraceID)
			return
		}
	}
	m.ok(w, result, op.Context.TraceID)
}
