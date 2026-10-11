package evaluationproduct

import (
	"encoding/json"
	"net/http"
	"strconv"

	agenteval "github.com/lexagent/agent-evaluation"
)

func (m *Module) feedback(w http.ResponseWriter, r *http.Request, a Actor, parts []string) {
	if !a.Browser || a.PrincipalType != "user" {
		m.writeError(w, 403, "AUTHENTICATED_USER_REQUIRED")
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		if !m.permit(w, r, a, ActionRead) {
			return
		}
		row, e := m.store.Get(r.Context(), a.Scope, KindFeedback, parts[0])
		if e != nil {
			m.storeError(w, e)
			return
		}
		var j agenteval.Judgement
		if json.Unmarshal(row.Data, &j) != nil || j.Source != "human" || m.sourceAuthorizer == nil {
			m.writeError(w, 503, "FEEDBACK_UNAVAILABLE")
			return
		}
		if e = m.sourceAuthorizer.AuthorizeSources(r.Context(), a, []agenteval.SourceReference{{RunID: j.SourceRunID, OutputHash: j.SourceOutputHash, RedactedOutputHash: j.SourceRedactedOutputHash}}); e != nil {
			m.inspectionError(w, e)
			return
		}
		m.writeJSON(w, 200, row)
		return
	}
	if len(parts) != 0 || r.Method != http.MethodPost {
		m.writeError(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if !m.permit(w, r, a, ActionReview) {
		return
	}
	if m.inspection == nil || m.sourceAuthorizer == nil {
		m.writeError(w, 503, "FEEDBACK_UNAVAILABLE")
		return
	}
	var cmd struct {
		SourceRunID      string              `json:"source_run_id"`
		SourceOutputHash string              `json:"source_output_hash"`
		Rubric           agenteval.Rubric    `json:"rubric"`
		RubricHash       string              `json:"rubric_hash"`
		Verdicts         []agenteval.Verdict `json:"verdicts"`
	}
	if !m.decode(w, r, &cmd) {
		return
	}
	revision, e := strconv.ParseUint(r.Header.Get("X-Authentication-Revision"), 10, 64)
	if e != nil || revision == 0 {
		m.writeError(w, 401, "SESSION_INVALID")
		return
	}
	t, e := m.inspection.Trajectory(r.Context(), a, cmd.SourceRunID, r.Header.Get("X-Authentication-Session"), revision)
	if e != nil {
		m.inspectionError(w, e)
		return
	}
	if t.OutputHash != cmd.SourceOutputHash || len(t.Output) == 0 {
		m.writeError(w, 409, "SOURCE_OUTPUT_CHANGED")
		return
	}
	in := agenteval.JudgeInput{Version: "agent-eval-judge-input/v1", SourceRunID: t.RunID, SourceOutputHash: t.OutputHash, Rubric: cmd.Rubric, RubricHash: cmd.RubricHash, Evidence: map[string]json.RawMessage{"output": t.Output}}
	for _, event := range agenteval.ReviewEvidenceEvents(t.Events) {
		if event.RunID != "" && event.RunID != t.RunID {
			continue
		}
		if reference := agenteval.EventReference(t.RunID, event); reference != "" {
			b, _ := json.Marshal(event)
			in.Evidence[reference] = b
		}
		if len(in.Evidence) == 64 {
			break
		}
	}
	if in.ValidateHuman() != nil || agenteval.ValidateVerdicts(in, cmd.Verdicts) != nil {
		m.writeError(w, 400, "INVALID_FEEDBACK")
		return
	}
	ref, err := in.HumanSourceReference()
	if err != nil {
		m.writeError(w, 400, "INVALID_FEEDBACK")
		return
	}
	if err = m.sourceAuthorizer.AuthorizeSources(r.Context(), a, []agenteval.SourceReference{ref}); err != nil {
		m.inspectionError(w, err)
		return
	}
	id, err := newID()
	if err != nil {
		m.writeError(w, 500, "ID_GENERATION_FAILED")
		return
	}
	for i := range cmd.Verdicts {
		cmd.Verdicts[i].Reason = agenteval.Sanitize(cmd.Verdicts[i].Reason).(string)
	}
	j := agenteval.Judgement{Version: agenteval.JudgementVersion, Source: "human", SourceRunID: t.RunID, SourceOutputHash: t.OutputHash, SourceRedactedOutputHash: ref.RedactedOutputHash, Rubric: in.Rubric, RubricHash: in.RubricHash, Verdicts: cmd.Verdicts, ReviewerID: a.PrincipalID, ReviewEvidenceID: id}
	row := newResource(a, KindFeedback, id, "completed", j)
	if err = m.store.Create(r.Context(), row); err != nil {
		m.storeError(w, err)
		return
	}
	m.writeJSON(w, 201, row)
}
