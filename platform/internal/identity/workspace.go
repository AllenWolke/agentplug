package identity

import (
	"context"
	"database/sql"
	"github.com/lexagent/platform/internal/sqlutil"
	"time"
)

type ApplicationWorkspace struct {
	ManagementScope
	WorkspaceName     string   `json:"workspace_name"`
	DepartmentName    string   `json:"department_name"`
	ApplicationName   string   `json:"application_name"`
	ManagementActions []string `json:"management_actions,omitempty"`
}

type WorkspaceRepository interface {
	ListApplicationWorkspaces(context.Context, string) ([]ApplicationWorkspace, error)
	ListAdministrationWorkspaces(context.Context, string) ([]ApplicationWorkspace, error)
	SwitchRefreshWorkspace(context.Context, string, string, uint64, EnrollmentScope) (RefreshSessionResult, error)
}

func validateWorkspace(ctx context.Context, reader permissionReader, subject string, target EnrollmentScope, now time.Time) error {
	snapshot, err := loadPermissionSnapshot(ctx, reader, PrincipalUser, subject)
	if err != nil {
		return err
	}
	if snapshot.Mode != "v2" || !snapshot.Principal.IsActive || target.TenantID != snapshot.Principal.TenantID {
		return ErrPermissionDenied
	}
	scope := ManagementScope{Type: "application", TenantID: target.TenantID, DepartmentID: target.DepartmentID, ApplicationID: target.ApplicationID}
	if scope.Validate() != nil {
		return ErrPermissionDenied
	}
	if err := validatePermissionScope(ctx, reader, scope); err != nil {
		return err
	}
	// A global platform administrator may enter a management context without
	// becoming a business member. Runtime resource checks still require both
	// business membership and explicit role/resource permissions.
	if kind := administrationKind(snapshot, now); kind == "platform" || kind == "company" {
		allowed, err := managementCapabilityAvailable(snapshot, PermissionQuery{Action: "organization.manage", Scope: scope, Now: now})
		if err != nil {
			return err
		}
		if allowed {
			return nil
		}
	}
	// A delegated approval context is independent of the department's business
	// membership ceiling. Qualification and current delegation are both required.
	if administrationKind(snapshot, now) == "permission" {
		for _, action := range workspaceAdministrationActions {
			allowed, err := managementCapabilityAvailable(snapshot, PermissionQuery{Action: action, Scope: scope, Now: now})
			if err != nil {
				return err
			}
			if allowed {
				return nil
			}
		}
	}
	managed, err := departmentAgentPolicyManaged(ctx, reader, scope.TenantID, scope.DepartmentID)
	if err != nil {
		return err
	}
	if managed && !departmentMembershipCovers(snapshot, scope, now) {
		return ErrPermissionDenied
	}
	for _, m := range snapshot.Memberships {
		if m.Status == "active" && m.Effective(now) && m.Scope.Contains(scope) {
			return nil
		}
	}
	return ErrPermissionDenied
}

// A credential's origin can remain a read-only authentication context. Explicit
// workspace selection must use the same live authority as the selection list;
// broad historical membership must not bypass a limited admin delegation.
func validateWorkspaceSelection(ctx context.Context, reader permissionReader, subject string, target EnrollmentScope, now time.Time) error {
	if err := validateWorkspace(ctx, reader, subject, target, now); err != nil {
		return err
	}
	snapshot, err := loadPermissionSnapshot(ctx, reader, PrincipalUser, subject)
	if err != nil {
		return err
	}
	if administrationKind(snapshot, now) == "" {
		return nil
	}
	scope := ManagementScope{Type: "application", TenantID: target.TenantID, DepartmentID: target.DepartmentID, ApplicationID: target.ApplicationID}
	for _, action := range workspaceAdministrationActions {
		allowed, err := managementCapabilityAvailable(snapshot, PermissionQuery{Action: action, Scope: scope, Now: now})
		if err != nil {
			return err
		}
		if allowed {
			return nil
		}
	}
	return ErrPermissionDenied
}

// Workspaces contain active organization metadata only. Membership never grants
// the business actions of a role or access to an Agent installation.
func (s *SQLStore) ListApplicationWorkspaces(ctx context.Context, subject string) ([]ApplicationWorkspace, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	snapshot, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, subject)
	if err != nil {
		return nil, err
	}
	if !snapshot.Principal.IsActive || snapshot.Mode != "v2" {
		return nil, ErrPermissionDenied
	}
	now := s.clock().UTC()
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT a.tenant_id,a.department_id,a.id,d.name,a.name,t.name FROM platform_identity_application a JOIN platform_identity_department d ON d.id=a.department_id AND d.tenant_id=a.tenant_id AND d.status='active' JOIN platform_identity_tenant t ON t.id=a.tenant_id AND t.status='active' WHERE a.tenant_id=? AND a.status='active' AND EXISTS (SELECT 1 FROM platform_identity_membership m WHERE m.subject_id=? AND m.status='active' AND (NOT EXISTS (SELECT 1 FROM platform_identity_department_agent_policy dp WHERE dp.tenant_id=a.tenant_id AND dp.department_id=a.department_id) OR m.department_id=a.department_id) AND (m.starts_at IS NULL OR m.starts_at<=?) AND (m.expires_at IS NULL OR m.expires_at>?) AND (m.tenant_id='' OR m.tenant_id=a.tenant_id) AND (m.department_id='' OR m.department_id=a.department_id) AND (m.application_id='' OR m.application_id=a.id)) ORDER BY a.department_id,a.id`), snapshot.Principal.TenantID, subject, now, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ApplicationWorkspace{}
	for rows.Next() {
		var item ApplicationWorkspace
		item.Type = "application"
		if err := rows.Scan(&item.TenantID, &item.DepartmentID, &item.ApplicationID, &item.DepartmentName, &item.ApplicationName, &item.WorkspaceName); err != nil {
			return nil, err
		}
		for _, m := range snapshot.Memberships {
			if m.Status == "active" && m.Effective(now) && m.Scope.Contains(item.ManagementScope) {
				items = append(items, item)
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return items, tx.Commit()
}
