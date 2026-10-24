package identity

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type PermissionPrincipalDirectory interface {
	PagePermissionPrincipals(context.Context, sharedkernel.Scope, ManagementScope, string, int, int) (OrganizationPage[Principal], error)
}

// The directory exposes human metadata only. Execution grants, role arrays,
// authentication credentials and another application's membership never leave
// this projection. Separate machine management has its own ownership contract.
func (s *SQLStore) PagePermissionPrincipals(ctx context.Context, actor sharedkernel.Scope, scope ManagementScope, id string, page, size int) (OrganizationPage[Principal], error) {
	result := OrganizationPage[Principal]{Items: []Principal{}, Page: page, PageSize: size}
	if actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) || scope.Validate() != nil || scope.Type == "global" || scope.Type == "agent_installation" || page < 1 || page > 100000 || size < 1 || size > 100 || len(id) > 128 {
		return result, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if err := validatePermissionScope(ctx, tx, scope); err != nil {
		return result, err
	}
	snapshot, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return result, err
	}
	now := s.clock().UTC()
	decision, err := EvaluatePermission(snapshot, PermissionQuery{Action: "principal.read", Scope: scope, Now: now})
	if err != nil {
		return result, err
	}
	if !decision.Allowed {
		return result, ErrPermissionDenied
	}
	where, args := permissionPrincipalWhere(scope, id, now)
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_principal p WHERE `+where), args...).Scan(&result.Total)
	if err != nil {
		return result, err
	}
	args = append(args, size, (page-1)*size)
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT p.id,p.principal_type,p.tenant_id,p.active,p.revision FROM platform_identity_principal p WHERE `+where+` ORDER BY p.id LIMIT ? OFFSET ?`), args...)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var p Principal
		if err := rows.Scan(&p.ID, &p.Type, &p.TenantID, &p.IsActive, &p.Revision); err != nil {
			rows.Close()
			return result, err
		}
		result.Items = append(result.Items, p)
	}
	rowErr := rows.Err()
	closeErr := rows.Close()
	if rowErr != nil {
		return result, rowErr
	}
	if closeErr != nil {
		return result, closeErr
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

// Only fixed predicates are assembled. The uncorrelated membership subquery
// builds the authorized subject set once, rather than probing it for every
// principal counted. IS TRUE retains a hashed subplan even with stale bulk-load
// statistics and excludes non-matches without duplicating multi-app members.
// Count and page share the same predicate and repeatable-read snapshot.
func permissionPrincipalWhere(scope ManagementScope, id string, now time.Time) (string, []any) {
	where := `p.principal_type='user' AND p.tenant_id=?`
	args := []any{scope.TenantID}
	if id != "" {
		where += ` AND p.id=?`
		args = append(args, id)
	}
	if scope.DepartmentID != "" {
		where += ` AND (p.id IN (SELECT m.subject_id FROM platform_identity_membership m WHERE m.tenant_id=? AND m.department_id=?`
		args = append(args, scope.TenantID, scope.DepartmentID)
		if scope.ApplicationID != "" {
			where += ` AND m.application_id=?`
			args = append(args, scope.ApplicationID)
		}
		where += ` AND m.status='active' AND (m.starts_at IS NULL OR m.starts_at<=?) AND (m.expires_at IS NULL OR m.expires_at>?))) IS TRUE`
		args = append(args, now, now)
	}
	return where, args
}

func (m *Module) permissionPrincipalDirectory(w http.ResponseWriter, r *http.Request, actor browserActor) {
	kind := strings.TrimSpace(r.URL.Query().Get("principal_type"))
	if kind == "service_principal" {
		page, size, ok := organizationPageFromRequest(m, w, r)
		if !ok {
			return
		}
		store, ok := m.store.(PermissionMachineDirectory)
		if !ok {
			m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
			return
		}
		result, err := store.PagePermissionMachines(r.Context(), actor.Scope, strings.TrimSpace(r.URL.Query().Get("principal_id")), page, size)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, result)
		return
	}
	if kind != "" && kind != "user" {
		m.error(w, http.StatusNotImplemented, "SCOPED_MACHINE_DIRECTORY_REQUIRED")
		return
	}
	page, size, ok := organizationPageFromRequest(m, w, r)
	if !ok {
		return
	}
	scope := ManagementScope{Type: "application", TenantID: actor.Scope.TenantID, DepartmentID: actor.Scope.DepartmentID, ApplicationID: actor.Scope.ApplicationID}
	targetTenant := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if targetTenant == "" {
		targetTenant = actor.Scope.TenantID
	}
	if targetTenant != actor.Scope.TenantID {
		scope = ManagementScope{Type: "tenant", TenantID: targetTenant}
	}
	// Choose the widest currently authorized organization boundary within this
	// authenticated tenant; application admins never gain tenant-wide metadata.
	for _, candidate := range []ManagementScope{{Type: "tenant", TenantID: targetTenant}, {Type: "department", TenantID: targetTenant, DepartmentID: actor.Scope.DepartmentID}} {
		decision, err := EvaluatePermission(*actor.Policy, PermissionQuery{Action: "principal.read", Scope: candidate, Now: time.Now().UTC()})
		if err != nil {
			m.permissionError(w, err)
			return
		}
		if decision.Allowed {
			scope = candidate
			break
		}
	}
	store, ok := m.store.(PermissionPrincipalDirectory)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	result, err := store.PagePermissionPrincipals(r.Context(), actor.Scope, scope, strings.TrimSpace(r.URL.Query().Get("principal_id")), page, size)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, result)
}

func (s *SQLStore) PageDepartmentMembers(ctx context.Context, actor sharedkernel.Scope, scope ManagementScope, id string, page, size int) (OrganizationPage[Principal], error) {
	if scope.Type != "department" {
		return OrganizationPage[Principal]{}, ErrInvalidResource
	}
	return s.pageHumanDirectory(ctx, actor, scope, scope, "membership.manage", id, page, size)
}

func (s *SQLStore) pageHumanDirectory(ctx context.Context, actor sharedkernel.Scope, scope, filterScope ManagementScope, action, id string, page, size int) (OrganizationPage[Principal], error) {
	result := OrganizationPage[Principal]{Items: []Principal{}, Page: page, PageSize: size}
	if actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) || scope.Validate() != nil || scope.Type == "global" || scope.Type == "agent_installation" || page < 1 || page > 100000 || size < 1 || size > 100 || len(id) > 128 {
		return result, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if err := validatePermissionScope(ctx, tx, scope); err != nil {
		return result, err
	}
	snapshot, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return result, err
	}
	now := s.clock().UTC()
	if snapshot.Principal.TenantID != actor.TenantID {
		return result, ErrPermissionDenied
	}
	decision, err := EvaluatePermission(snapshot, PermissionQuery{Action: action, Scope: scope, Now: now})
	if err != nil {
		return result, err
	}
	if !decision.Allowed {
		return result, ErrPermissionDenied
	}
	where, args := permissionPrincipalWhere(filterScope, id, now)
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_principal p WHERE `+where), args...).Scan(&result.Total)
	if err != nil {
		return result, err
	}
	args = append(args, size, (page-1)*size)
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT p.id,p.principal_type,p.tenant_id,p.active,p.revision FROM platform_identity_principal p WHERE `+where+` ORDER BY p.id LIMIT ? OFFSET ?`), args...)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var p Principal
		if err := rows.Scan(&p.ID, &p.Type, &p.TenantID, &p.IsActive, &p.Revision); err != nil {
			rows.Close()
			return result, err
		}
		result.Items = append(result.Items, p)
	}
	rowErr := rows.Err()
	closeErr := rows.Close()
	if rowErr != nil {
		return result, rowErr
	}
	if closeErr != nil {
		return result, closeErr
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}
