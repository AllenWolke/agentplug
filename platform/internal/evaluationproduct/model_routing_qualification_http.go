package evaluationproduct

import (
	"errors"
	"net/http"
)

// Read-only verification deliberately shares the exact policy publication
// validator. The result is an observation, not a persisted new quality grant;
// publication and every native model call still recheck their own authority.
func (m *Module) verifyRoutingQualification(w http.ResponseWriter, r *http.Request, actor Actor) {
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	if !m.permit(w, r, actor, ActionRead) {
		return
	}
	if m.routingModels == nil {
		m.writeError(w, http.StatusServiceUnavailable, "ROUTING_QUALIFICATION_UNAVAILABLE")
		return
	}
	var command struct {
		EvidenceID        string                     `json:"evidence_id"`
		ReportHash        string                     `json:"report_hash"`
		ModelVersionID    string                     `json:"model_version_id"`
		MaximumComplexity string                     `json:"maximum_complexity"`
		Target            RoutingQualificationTarget `json:"target"`
	}
	if !m.decode(w, r, &command) {
		return
	}
	if !validID(command.EvidenceID) || !validSHA256(command.ReportHash) || !validID(command.ModelVersionID) ||
		!validID(command.Target.AgentID) || !validID(command.Target.AgentVersionID) || !validSHA256(command.Target.ExecutionContextSHA256) ||
		(command.MaximumComplexity != "simple" && command.MaximumComplexity != "medium" && command.MaximumComplexity != "complex") {
		m.writeError(w, http.StatusBadRequest, "INVALID_ROUTING_QUALIFICATION")
		return
	}
	row, err := m.store.Get(r.Context(), actor.Scope, KindEvidence, command.EvidenceID)
	if err != nil {
		m.storeError(w, err)
		return
	}
	if !m.protectSources(w, r, actor, row) {
		return
	}
	err = VerifyModelRoutingQualification(r.Context(), m.store, actor.Scope, command.EvidenceID,
		command.ReportHash, command.ModelVersionID, command.MaximumComplexity, m.routingModels, command.Target)
	if err != nil && !errors.Is(err, ErrSnapshotInvalid) {
		m.inspectionError(w, err)
		return
	}
	code := "VERIFIED_NATIVE_QUALIFICATION"
	if err != nil {
		code = "QUALIFICATION_NOT_MET"
	}
	m.writeJSON(w, http.StatusOK, map[string]any{
		"version": "model-routing-qualification-receipt/v1", "scope": actor.Scope,
		"evidence_id": command.EvidenceID, "report_hash": command.ReportHash,
		"model_version_id": command.ModelVersionID, "maximum_complexity": command.MaximumComplexity,
		"target": command.Target, "qualified": err == nil, "reason_code": code,
		"persistent_quality_grants": 0, "model_calls": 0,
	})
}
