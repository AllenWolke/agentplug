package evaluationproduct

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	agenteval "github.com/lexagent/agent-evaluation"
)

// Inspection is read-only. It receives authenticated gateway headers and must
// apply object-level current IAM, independently of evaluation management rights.
type Inspection interface {
	Agents(context.Context, Actor, int, int) (agenteval.Discovery, error)
	Trajectory(context.Context, Actor, string, string, uint64) (agenteval.Trajectory, error)
}

func (m *Module) SetInspection(port Inspection) { m.inspection = port }

func (m *Module) inspect(w http.ResponseWriter, r *http.Request, actor Actor, parts []string) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		m.writeError(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if !actor.Browser || actor.PrincipalType != "user" {
		m.writeError(w, 403, "AUTHENTICATED_USER_REQUIRED")
		return
	}
	if m.inspection == nil {
		m.writeError(w, 503, "EVALUATION_INSPECTION_UNAVAILABLE")
		return
	}
	if parts[0] == "agents" && len(parts) == 1 {
		for key, values := range r.URL.Query() {
			if (key != "page" && key != "page_size") || len(values) != 1 {
				m.writeError(w, 400, "INVALID_QUERY")
				return
			}
		}
		page, size := 1, 20
		if v := r.URL.Query().Get("page"); v != "" {
			n, e := strconv.Atoi(v)
			if e != nil || n < 1 || n > 100000 {
				m.writeError(w, 400, "INVALID_QUERY")
				return
			}
			page = n
		}
		if v := r.URL.Query().Get("page_size"); v != "" {
			n, e := strconv.Atoi(v)
			if e != nil || n < 1 || n > 100 {
				m.writeError(w, 400, "INVALID_QUERY")
				return
			}
			size = n
		}
		result, err := m.inspection.Agents(r.Context(), actor, page, size)
		if err != nil {
			m.inspectionError(w, err)
			return
		}
		m.writeJSON(w, 200, result)
		return
	}
	if parts[0] == "trajectories" && len(parts) == 2 && validID(parts[1]) {
		if len(r.URL.Query()) != 0 {
			m.writeError(w, 400, "INVALID_QUERY")
			return
		}
		revision, err := strconv.ParseUint(r.Header.Get("X-Authentication-Revision"), 10, 64)
		if err != nil || revision == 0 {
			m.writeError(w, 401, "SESSION_INVALID")
			return
		}
		result, err := m.inspection.Trajectory(r.Context(), actor, parts[1], r.Header.Get("X-Authentication-Session"), revision)
		if err != nil {
			m.inspectionError(w, err)
			return
		}
		m.writeJSON(w, 200, result)
		return
	}
	m.writeError(w, 404, "NOT_FOUND")
}
func (m *Module) inspectionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrForbidden):
		m.writeError(w, 403, "FORBIDDEN")
	case errors.Is(err, ErrNotFound):
		m.writeError(w, 404, "NOT_FOUND")
	case errors.Is(err, ErrInvalid):
		m.writeError(w, 400, "INVALID_REQUEST")
	default:
		m.writeError(w, 503, "EVALUATION_INSPECTION_UNAVAILABLE")
	}
}
