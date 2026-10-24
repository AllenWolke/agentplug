package identity

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type CompanyManagementDirectory interface {
	PageManagementCompanies(context.Context, sharedkernel.Scope, string, string, int, int) (OrganizationPage[Tenant], error)
}

func (s *SQLStore) PageManagementCompanies(ctx context.Context, actor sharedkernel.Scope, id, status string, page, size int) (OrganizationPage[Tenant], error) {
	if actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) || len(id) > 128 || status != "" && status != "active" && status != "disabled" {
		return OrganizationPage[Tenant]{}, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return OrganizationPage[Tenant]{}, err
	}
	defer tx.Rollback()
	owner, err := permissionRequestOwner(ctx, tx, actor)
	if err != nil {
		return OrganizationPage[Tenant]{}, err
	}
	allowed, err := managementCapabilityAvailable(owner, PermissionQuery{Action: "organization.manage", Scope: ManagementScope{Type: "global"}, Now: s.clock().UTC()})
	if err != nil {
		return OrganizationPage[Tenant]{}, err
	}
	if !allowed {
		return OrganizationPage[Tenant]{}, ErrPermissionDenied
	}
	result, err := pageCompanyDirectory(ctx, tx, id, status, page, size)
	if err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func (m *Module) companyManagementDirectory(w http.ResponseWriter, r *http.Request, id string) {
	if len(r.URL.Query()["view"]) != 1 {
		m.error(w, http.StatusBadRequest, "INVALID_VIEW")
		return
	}
	actor, _, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	page, size, ok := organizationPageFromRequest(m, w, r)
	if !ok {
		return
	}
	store, ok := m.store.(CompanyManagementDirectory)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	requested := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if id != "" {
		if requested != "" && requested != id {
			m.error(w, http.StatusBadRequest, "SCOPE_MISMATCH")
			return
		}
		requested = id
	}
	result, err := store.PageManagementCompanies(r.Context(), actor.Scope, requested, strings.TrimSpace(r.URL.Query().Get("status")), page, size)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, result)
}
