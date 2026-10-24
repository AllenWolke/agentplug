package identity

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// ListWorkloadBindings returns metadata for one explicitly authorized application.
// Revoked rows remain visible so clients can supply the correct CAS revision.
func (s *SQLStore) ListWorkloadBindings(ctx context.Context, actor sharedkernel.Scope, scope ManagementScope) ([]WorkloadBinding, error) {
	if actor.Validate() != nil || actor.PrincipalType != "user" || scope.Type != "application" || scope.Validate() != nil {
		return nil, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return nil, err
	}
	if owner.Mode != "v2" || owner.Principal.TenantID != actor.TenantID {
		return nil, ErrPermissionDenied
	}
	decision, err := EvaluatePermission(owner, PermissionQuery{Action: "machine.manage", Scope: scope, Now: s.clock().UTC()})
	if err != nil {
		return nil, err
	}
	if !decision.Allowed {
		return nil, ErrPermissionDenied
	}
	if err := validatePermissionScope(ctx, tx, scope); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_identity_workload_binding WHERE tenant_id=? AND department_id=? AND application_id=? ORDER BY installation_id LIMIT 1001`), scope.TenantID, scope.DepartmentID, scope.ApplicationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []WorkloadBinding{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var b WorkloadBinding
		if json.Unmarshal(raw, &b) != nil || validateWorkloadBindingVersions(b) != nil || b.TenantID != scope.TenantID || b.DepartmentID != scope.DepartmentID || b.ApplicationID != scope.ApplicationID || b.Revision == 0 || (b.Status != "active" && b.Status != "revoked") {
			return nil, ErrInvalidResource
		}
		items = append(items, b)
		if len(items) > 1000 {
			return nil, ErrInvalidResource
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return items, tx.Commit()
}
