package identity

import (
	"context"
	"net/http"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type DepartmentAgentPackageRepository interface {
	InspectDepartmentAgentPackages(context.Context, sharedkernel.Scope, DepartmentAgentSelection) (DepartmentAgentPackageInspection, error)
	PreviewAgentPackageApproval(context.Context, sharedkernel.Scope, AgentPackageApprovalCommand) (AgentPackageApprovalPlan, error)
	CommitAgentPackageApproval(context.Context, sharedkernel.Scope, AgentPackageApprovalCommand) (AgentPackageApprovalReceipt, error)
}

func (m *Module) departmentAgentPackages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, repo, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	store, ok := m.store.(DepartmentAgentPackageRepository)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	if r.URL.Path == "/department-agent-packages:inspect" {
		var selection DepartmentAgentSelection
		if decode(r, &selection) != nil {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		inspection, err := store.InspectDepartmentAgentPackages(r.Context(), actor.Scope, selection)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, inspection)
		return
	}
	var command AgentPackageApprovalCommand
	if decode(r, &command) != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	decision, err := repo.ResolvePermission(r.Context(), PrincipalUser, actor.Principal.ID, PermissionQuery{Action: "delegation.manage", Scope: command.Scope})
	if err != nil {
		m.permissionError(w, err)
		return
	}
	if !decision.Allowed {
		m.permissionError(w, ErrPermissionDenied)
		return
	}
	if r.URL.Path == "/department-agent-packages:preview" {
		plan, err := store.PreviewAgentPackageApproval(r.Context(), actor.Scope, command)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, plan)
		return
	}
	receipt, err := store.CommitAgentPackageApproval(r.Context(), actor.Scope, command)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, receipt)
}
