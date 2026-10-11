package identity

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type MembershipCandidateRepository interface {
	PageMembershipCandidates(context.Context, sharedkernel.Scope, string, int, int) (OrganizationPage[Principal], error)
}

// A member manager may search existing active accounts in the same company to
// invite them into their department. This exposes identity metadata only,
// never another department's roles, grants, memberships or credentials.
func (s *SQLStore) PageMembershipCandidates(ctx context.Context, actor sharedkernel.Scope, id string, page, size int) (OrganizationPage[Principal], error) {
	result := OrganizationPage[Principal]{Items: []Principal{}, Page: page, PageSize: size}
	if actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) || page < 1 || page > 100000 || size < 1 || size > 100 || len(id) > 128 {
		return result, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	scope := ManagementScope{Type: "department", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID}
	if err := validatePermissionScope(ctx, tx, scope); err != nil {
		return result, err
	}
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return result, err
	}
	allowed, err := managementCapabilityAvailable(owner, PermissionQuery{Action: "membership.manage", Scope: scope, Now: s.clock().UTC()})
	if err != nil {
		return result, err
	}
	if !allowed {
		return result, ErrPermissionDenied
	}
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_principal WHERE principal_type='user' AND tenant_id=? AND active=TRUE AND (?='' OR id=?)`), actor.TenantID, id, id).Scan(&result.Total); err != nil {
		return result, err
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT id,principal_type,tenant_id,active,revision FROM platform_identity_principal WHERE principal_type='user' AND tenant_id=? AND active=TRUE AND (?='' OR id=?) ORDER BY id LIMIT ? OFFSET ?`), actor.TenantID, id, id, size, (page-1)*size)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var item Principal
		if err := rows.Scan(&item.ID, &item.Type, &item.TenantID, &item.IsActive, &item.Revision); err != nil {
			return result, err
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func (m *Module) membershipCandidates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
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
	store, ok := m.store.(MembershipCandidateRepository)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	result, err := store.PageMembershipCandidates(r.Context(), actor.Scope, strings.TrimSpace(r.URL.Query().Get("principal_id")), page, size)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, result)
}
