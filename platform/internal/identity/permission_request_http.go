package identity

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type permissionRequestRepository interface {
	CreatePermissionRequest(context.Context, sharedkernel.Scope, PermissionRequestCreate) (PermissionRequest, error)
	ListPermissionRequests(context.Context, sharedkernel.Scope, ManagementScope, bool, string, int, int) ([]PermissionRequest, int, error)
	GetPermissionRequest(context.Context, sharedkernel.Scope, string) (PermissionRequest, error)
	WithdrawPermissionRequest(context.Context, sharedkernel.Scope, PermissionRequestWithdrawal) (PermissionRequest, error)
	PreviewPermissionRequestDecision(context.Context, sharedkernel.Scope, PermissionRequestDecision) (PermissionRequestDecisionPlan, error)
	DecidePermissionRequest(context.Context, sharedkernel.Scope, PermissionRequestDecision) (PermissionRequestDecisionReceipt, error)
}

func (m *Module) permissionRequests(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	repo, ok := m.store.(permissionRequestRepository)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	if r.URL.Path == "/permission-requests" {
		switch r.Method {
		case http.MethodPost:
			if actor.Policy != nil {
				system, err := systemManagementAccount(*actor.Policy, time.Now().UTC())
				if err != nil {
					m.permissionError(w, err)
					return
				}
				if system {
					m.error(w, http.StatusForbidden, "SYSTEM_ADMIN_PERSONAL_REQUEST_DISABLED")
					return
				}
			}
			var c PermissionRequestCreate
			if decode(r, &c) != nil {
				m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
				return
			}
			request, err := repo.CreatePermissionRequest(r.Context(), actor.Scope, c)
			if err != nil {
				m.permissionError(w, err)
				return
			}
			m.json(w, http.StatusCreated, request)
		case http.MethodGet:
			q := r.URL.Query()
			scope := ManagementScope{Type: q.Get("scope_type"), TenantID: q.Get("tenant_id"), DepartmentID: q.Get("department_id"), ApplicationID: q.Get("application_id")}
			if scope.Type == "" {
				scope = ManagementScope{Type: "application", TenantID: actor.Scope.TenantID, DepartmentID: actor.Scope.DepartmentID, ApplicationID: actor.Scope.ApplicationID}
			}
			if q.Get("view") != "" && q.Get("view") != "mine" && q.Get("view") != "review" {
				m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
				return
			}
			page, size := 1, 20
			var err error
			if q.Get("page") != "" {
				page, err = strconv.Atoi(q.Get("page"))
				if err != nil {
					m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
					return
				}
			}
			if q.Get("page_size") != "" {
				size, err = strconv.Atoi(q.Get("page_size"))
				if err != nil {
					m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
					return
				}
			}
			items, total, err := repo.ListPermissionRequests(r.Context(), actor.Scope, scope, q.Get("view") == "review", q.Get("status"), page, size)
			if err != nil {
				m.permissionError(w, err)
				return
			}
			m.json(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page, "page_size": size})
		default:
			m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		}
		return
	}
	if strings.HasPrefix(r.URL.Path, "/permission-requests/") && r.Method == http.MethodGet {
		id := strings.TrimPrefix(r.URL.Path, "/permission-requests/")
		if id == "" || strings.Contains(id, "/") {
			m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
			return
		}
		request, err := repo.GetPermissionRequest(r.Context(), actor.Scope, id)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, request)
		return
	}
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	if r.URL.Path == "/permission-requests:withdraw" {
		var c PermissionRequestWithdrawal
		if decode(r, &c) != nil {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		request, err := repo.WithdrawPermissionRequest(r.Context(), actor.Scope, c)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, request)
		return
	}
	var c PermissionRequestDecision
	if decode(r, &c) != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if r.URL.Path == "/permission-requests:preview-decision" {
		plan, err := repo.PreviewPermissionRequestDecision(r.Context(), actor.Scope, c)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, plan)
		return
	}
	if r.URL.Path != "/permission-requests:decide" {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	receipt, err := repo.DecidePermissionRequest(r.Context(), actor.Scope, c)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, receipt)
}
