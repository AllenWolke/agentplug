package identity

import (
	"context"
	"database/sql"
	"slices"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

// Administrative account purpose follows current, versioned bindings. Account
// names and expired/revoked historical roles never confer this identity.
func administrationKind(snapshot PermissionSnapshot, now time.Time) string {
	if snapshot.Mode != "v2" || !snapshot.Principal.IsActive || snapshot.Principal.Type != PrincipalUser {
		return ""
	}
	kind := ""
	for _, b := range snapshot.Bindings {
		if b.SubjectID != snapshot.Principal.ID || b.Status != "active" || !b.Effective(now) {
			continue
		}
		for _, role := range snapshot.Roles {
			if role.Code != b.RoleCode || role.Version != b.RoleVersion || !slices.Contains(role.ScopeTypes, b.Scope.Type) {
				continue
			}
			if role.Code == "super_admin" {
				return "platform"
			}
			if companyAdministratorBinding(b, snapshot.Principal.TenantID) {
				kind = "company"
			}
			if role.Code == "permission_admin" && kind != "company" {
				kind = "permission"
			}
			if role.Code == "department_admin" && kind == "" {
				kind = "department"
			}
		}
	}
	return kind
}

// Read-only role qualification is not a delegated authority to handle a case.
// Each returned workspace has at least one currently usable management action.
var workspaceAdministrationActions = []string{
	"organization.manage", "authorization.change", "access_request.decide", "membership.manage", "principal.disable",
}

type AdministrationDepartmentRepository interface {
	ListAdministrationDepartments(context.Context, string) ([]ApplicationWorkspace, error)
}

// Departments are independent of Agent installation containers. An empty
// department must still be available for company-controlled member admission.
func (s *SQLStore) ListAdministrationDepartments(ctx context.Context, subject string) ([]ApplicationWorkspace, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	snapshot, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, subject)
	if err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	items := []ApplicationWorkspace{}
	if administrationKind(snapshot, now) == "" {
		return items, tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT d.tenant_id,d.id,d.name,t.name FROM platform_identity_department d JOIN platform_identity_tenant t ON t.id=d.tenant_id AND t.status='active' WHERE d.tenant_id=? AND d.status='active' ORDER BY d.name,d.id`), snapshot.Principal.TenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item ApplicationWorkspace
		item.Type = "department"
		if err := rows.Scan(&item.TenantID, &item.DepartmentID, &item.DepartmentName, &item.WorkspaceName); err != nil {
			return nil, err
		}
		for _, action := range workspaceAdministrationActions {
			allowed, err := managementCapabilityAvailable(snapshot, PermissionQuery{Action: action, Scope: item.ManagementScope, Now: now})
			if err != nil {
				return nil, err
			}
			if allowed {
				item.ManagementActions = append(item.ManagementActions, action)
			}
		}
		if len(item.ManagementActions) > 0 {
			items = append(items, item)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return items, tx.Commit()
}

func (s *SQLStore) ListAdministrationWorkspaces(ctx context.Context, subject string) ([]ApplicationWorkspace, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	snapshot, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, subject)
	if err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	items := []ApplicationWorkspace{}
	if administrationKind(snapshot, now) == "" {
		return items, tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT a.tenant_id,a.department_id,a.id,d.name,a.name,t.name FROM platform_identity_application a JOIN platform_identity_department d ON d.id=a.department_id AND d.tenant_id=a.tenant_id AND d.status='active' JOIN platform_identity_tenant t ON t.id=a.tenant_id AND t.status='active' WHERE a.tenant_id=? AND a.status='active' ORDER BY a.department_id,a.id`), snapshot.Principal.TenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item ApplicationWorkspace
		item.Type = "application"
		if err := rows.Scan(&item.TenantID, &item.DepartmentID, &item.ApplicationID, &item.DepartmentName, &item.ApplicationName, &item.WorkspaceName); err != nil {
			return nil, err
		}
		for _, action := range workspaceAdministrationActions {
			allowed, err := managementCapabilityAvailable(snapshot, PermissionQuery{Action: action, Scope: item.ManagementScope, Now: now})
			if err != nil {
				return nil, err
			}
			if allowed {
				item.ManagementActions = append(item.ManagementActions, action)
			}
		}
		if len(item.ManagementActions) > 0 {
			items = append(items, item)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return items, tx.Commit()
}
