package identity

import (
	"context"
	"errors"
	"net/http"
)

type RefreshSessionRepository interface {
	CreateRefreshSession(context.Context, string, EnrollmentScope, uint64) (RefreshSessionResult, error)
	CreateOIDCRefreshSession(context.Context, string, string) (RefreshSessionResult, error)
	RotateRefreshSession(context.Context, string) (RefreshSessionResult, error)
	RevokeRefreshSession(context.Context, string) error
}

// Only the trusted authentication gateway can call these endpoints; refresh
// bearer values and credential revisions are never exposed by public modules.
func (m *Module) refreshSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !m.requireAuth(w, r) {
		return
	}
	if r.Header.Get("X-Browser-Module") == "1" {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	store, ok := m.store.(RefreshSessionRepository)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "REFRESH_SERVICE_UNAVAILABLE")
		return
	}
	var in struct {
		Username      string `json:"username"`
		TenantID      string `json:"tenant_id"`
		DepartmentID  string `json:"department_id"`
		ApplicationID string `json:"application_id"`
		AuthRevision  uint64 `json:"auth_revision"`
		RefreshToken  string `json:"refresh_token"`
		Issuer        string `json:"issuer"`
		Subject       string `json:"subject"`
	}
	if decode(r, &in) != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	var result RefreshSessionResult
	var err error
	switch r.URL.Path {
	case "/internal/refresh-sessions":
		if in.Issuer != "" || in.Subject != "" {
			if in.Username != "" || in.AuthRevision != 0 {
				m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
				return
			}
			result, err = store.CreateOIDCRefreshSession(r.Context(), in.Issuer, in.Subject)
		} else {
			result, err = store.CreateRefreshSession(r.Context(), in.Username, EnrollmentScope{TenantID: in.TenantID, DepartmentID: in.DepartmentID, ApplicationID: in.ApplicationID}, in.AuthRevision)
		}
	case "/internal/refresh-sessions:rotate":
		result, err = store.RotateRefreshSession(r.Context(), in.RefreshToken)
	case "/internal/refresh-sessions:workspace":
		workspaces, ok := m.store.(WorkspaceRepository)
		if !ok {
			m.error(w, http.StatusServiceUnavailable, "WORKSPACE_SERVICE_UNAVAILABLE")
			return
		}
		result, err = workspaces.SwitchRefreshWorkspace(r.Context(), in.RefreshToken, in.Username, in.AuthRevision, EnrollmentScope{TenantID: in.TenantID, DepartmentID: in.DepartmentID, ApplicationID: in.ApplicationID})
	case "/internal/refresh-sessions:revoke":
		err = store.RevokeRefreshSession(r.Context(), in.RefreshToken)
	default:
		m.error(w, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if errors.Is(err, ErrRefreshSessionRejected) {
		m.error(w, http.StatusUnauthorized, "REFRESH_SESSION_REJECTED")
		return
	}
	if err != nil {
		if errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrScopeMismatch) {
			m.error(w, http.StatusForbidden, "WORKSPACE_FORBIDDEN")
			return
		}
		m.error(w, http.StatusServiceUnavailable, "REFRESH_SERVICE_UNAVAILABLE")
		return
	}
	m.json(w, http.StatusOK, result)
}
