package catalog

import "net/http"

// An explicit workspace submission authorizes release.submit in that workspace.
// Global catalog listing, evaluation, approval and deployments retain their
// existing boundaries. A caller cannot select another workspace with a query.
func (m *Module) submissionControlScope(w http.ResponseWriter, r *http.Request) (ControlScope, bool, bool) {
	q := r.URL.Query()
	if !q.Has("tenant_id") && !q.Has("department_id") && !q.Has("application_id") {
		return ControlScope{}, false, true
	}
	scope, valid := requestedControlScope(r)
	if !valid || len(q["tenant_id"]) != 1 || len(q["department_id"]) != 1 || len(q["application_id"]) != 1 {
		m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return ControlScope{}, true, false
	}
	actor := releaseActorFromRequest(r)
	if r.Header.Get("X-Browser-Module") != "1" || scope.TenantID != actor.TenantID || scope.DepartmentID != actor.DepartmentID || scope.ApplicationID != actor.ApplicationID {
		m.writeError(w, http.StatusForbidden, "FORBIDDEN")
		return ControlScope{}, true, false
	}
	return scope, true, true
}
