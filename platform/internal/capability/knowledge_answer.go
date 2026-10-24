package capability

import (
	"net/http"
	"strings"
)

// An answer may contain every supplied passage. Filtering citations after
// generation cannot remove leaked prose: any lost authorization rejects the
// entire answer, including a cache hit. Evaluator input is built here from the
// platform's references, never from a model's claimed grounding verdict.
func (m *Module) knowledgeAnswerResult(w http.ResponseWriter, r *http.Request, op envelope, knowledgeScope string, topK int, result map[string]any) {
	if !m.currentCapability(w, r, op) {
		return
	}
	plan, err := m.knowledgeDocumentPlan(r, op, knowledgeScope)
	if err != nil || plan.Legacy || len(plan.Documents) == 0 {
		m.error(w, http.StatusForbidden, "KNOWLEDGE_DOCUMENTS_DENIED", "current answer evidence authorization denied", op.Context.TraceID)
		return
	}
	original, _ := result["references"].([]map[string]any)
	filtered := filterKnowledgeReferences(result, plan, topK)
	refs, _ := filtered["references"].([]map[string]any)
	text, _ := result["text"].(string)
	if len(original) == 0 || len(refs) != len(original) || strings.TrimSpace(text) == "" || len(text) > 32768 {
		m.error(w, http.StatusForbidden, "KNOWLEDGE_ANSWER_EVIDENCE_DENIED", "complete currently authorized answer evidence is required", op.Context.TraceID)
		return
	}
	if err := m.knowledgeModelReceiptCheck(r, op, r.Context())(r.Context(), "generate", stringValue(result["answer_model_version"])); err != nil {
		m.error(w, http.StatusForbidden, "CAPABILITY_DENIED", "current answer model authorization denied", op.Context.TraceID)
		return
	}
	ids, _ := result["citation_ids"].([]string)
	known := map[string]bool{}
	citations := []map[string]any{}
	for _, ref := range refs {
		id := stringValue(ref["clause_or_chunk_id"])
		if id == "" || known[id] {
			m.error(w, http.StatusBadGateway, "KNOWLEDGE_ANSWER_INVALID", "invalid answer reference identity", op.Context.TraceID)
			return
		}
		known[id] = true
		citations = append(citations, map[string]any{"id": id, "revision": ref["kb_version"], "source": ref["doc_id"], "content": ref["content"]})
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !known[id] || seen[id] {
			m.error(w, http.StatusBadGateway, "KNOWLEDGE_ANSWER_INVALID", "answer cited unavailable evidence", op.Context.TraceID)
			return
		}
		seen[id] = true
	}
	if len(ids) == 0 {
		m.error(w, http.StatusBadGateway, "KNOWLEDGE_ANSWER_INVALID", "answer citations are required", op.Context.TraceID)
		return
	}
	for _, key := range []string{"text", "citation_ids", "answer_cache_hit", "answer_model_version", "answer_prompt_version", "answer_invocation_id", "usage", "billing", "saved_usage", "saved_billing"} {
		filtered[key] = result[key]
	}
	filtered["evaluation_citations"] = citations
	// Conservatively score the complete answer; the model cannot omit false
	// sentences by submitting only selected claims for Evaluation.
	filtered["evaluation_claims"] = []map[string]any{{"id": "answer-1", "text": text, "citation_ids": ids}}
	if recovering, _ := r.Context().Value(knowledgeRecoveryOnlyKey{}).(bool); recovering {
		filtered["recovery_only"] = true
		filtered["model_requests_sent"] = 0
		// Usage/billing describe original receipts, not a new provider charge.
		filtered["usage_scope"] = "original answer invocation; read-only recovery sends no model request"
	}
	if !m.currentCapability(w, r, op) {
		return
	}
	m.ok(w, filtered, op.Context.TraceID)
}
