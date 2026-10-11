package identity

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type DepartmentAgentAccessRepository interface {
	DepartmentAgentPolicy(context.Context, sharedkernel.Scope, string, string) (DepartmentAgentPolicyState, error)
	PreviewDepartmentAgentChange(context.Context, sharedkernel.Scope, DepartmentAgentChangeCommand) (DepartmentAgentChangePlan, error)
	CommitDepartmentAgentChange(context.Context, sharedkernel.Scope, DepartmentAgentChangeCommand) (DepartmentAgentChangeReceipt, error)
	DepartmentAgentChangeReceipt(context.Context, sharedkernel.Scope, string) (DepartmentAgentChangeReceipt, error)
}

func (m *Module) departmentAgentAccess(w http.ResponseWriter, r *http.Request) {
	read := r.URL.Path == "/department-agent-policy" || strings.HasPrefix(r.URL.Path, "/department-agent-changes/")
	if read && r.Method != http.MethodGet || !read && r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, _, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	repo, ok := m.store.(DepartmentAgentAccessRepository)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	if r.URL.Path == "/department-agent-policy" {
		query := r.URL.Query()
		if len(query["tenant_id"]) != 1 || len(query["department_id"]) != 1 {
			m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
			return
		}
		state, err := repo.DepartmentAgentPolicy(r.Context(), actor.Scope, query.Get("tenant_id"), query.Get("department_id"))
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, state)
		return
	}
	if read {
		key := strings.TrimPrefix(r.URL.Path, "/department-agent-changes/")
		if !validPermissionResourceID(key) || strings.Contains(key, "/") {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		receipt, err := repo.DepartmentAgentChangeReceipt(r.Context(), actor.Scope, key)
		if errors.Is(err, sql.ErrNoRows) {
			m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
			return
		}
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, receipt)
		return
	}
	var command DepartmentAgentChangeCommand
	if err := decode(r, &command); err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if r.URL.Path == "/department-agent-changes:preview" {
		plan, err := repo.PreviewDepartmentAgentChange(r.Context(), actor.Scope, command)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, plan)
		return
	}
	receipt, err := repo.CommitDepartmentAgentChange(r.Context(), actor.Scope, command)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, receipt)
}
