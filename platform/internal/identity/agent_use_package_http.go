package identity

import (
	"context"
	"net/http"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type AgentUsePackageRepository interface {
	AgentUsePackage(context.Context, sharedkernel.Scope, ManagementScope) (AgentUsePackage, error)
}

func (m *Module) agentUsePackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, _, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	repo, ok := m.store.(AgentUsePackageRepository)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	query := r.URL.Query()
	if len(query) != 3 || len(query["department_id"]) != 1 || len(query["application_id"]) != 1 || len(query["installation_id"]) != 1 {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	scope := ManagementScope{Type: "agent_installation", TenantID: actor.Scope.TenantID, DepartmentID: query.Get("department_id"), ApplicationID: query.Get("application_id"), ResourceID: query.Get("installation_id")}
	if scope.Validate() != nil {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	pack, err := repo.AgentUsePackage(r.Context(), actor.Scope, scope)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, pack)
}
