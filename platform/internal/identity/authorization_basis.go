package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Read the same principal, active hierarchy and legacy grant rows in one
// statement. MATERIALIZED dependencies retain principal -> hierarchy -> grant
// acquisition order and every original SHARE row fence. Current permissions,
// temporal fingerprints, packages and the committed epoch are still checked
// independently by authorizationEpochFactsTx; no authorization fact is cached.
func readAuthorizationBasisTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, action string) (Principal, []Grant, []uint64, error) {
	principal := Principal{ID: scope.PrincipalID, Type: PrincipalType(scope.PrincipalType), TenantID: scope.TenantID}
	var roles, groups string
	var tenantRevision, departmentRevision, applicationRevision uint64
	var grantJSON []byte
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`WITH principal AS MATERIALIZED (
 SELECT roles_json,groups_json,active,revision
 FROM platform_identity_principal
 WHERE principal_type=? AND id=? AND tenant_id=? FOR SHARE
), hierarchy AS MATERIALIZED (
 SELECT t.revision AS tenant_revision,d.revision AS department_revision,a.revision AS application_revision
 FROM platform_identity_tenant t
 JOIN platform_identity_department d ON d.tenant_id=t.id
 JOIN platform_identity_application a ON a.tenant_id=t.id AND a.department_id=d.id
 WHERE t.id=? AND d.id=? AND a.id=? AND t.status='active' AND d.status='active' AND a.status='active'
 AND EXISTS(SELECT 1 FROM principal) FOR SHARE OF t,d,a
), legacy_grants AS MATERIALIZED (
 SELECT g.id,g.tenant_id,g.department_id,g.application_id,g.agent_instance_id,
 g.subject_type,g.subject_id,g.action,g.effect,g.status,g.revision
 FROM platform_identity_grant g
 WHERE g.tenant_id=? AND g.department_id=? AND g.application_id=? AND g.agent_instance_id=?
 AND g.subject_type=? AND g.subject_id=? AND g.action=?
 AND EXISTS(SELECT 1 FROM hierarchy) ORDER BY g.id FOR SHARE OF g
)
SELECT p.roles_json,p.groups_json,p.active,p.revision,
 h.tenant_revision,h.department_revision,h.application_revision,
 COALESCE((SELECT json_agg(row_to_json(g) ORDER BY g.id) FROM legacy_grants g),'[]'::json)
FROM principal p CROSS JOIN hierarchy h`),
		scope.PrincipalType, scope.PrincipalID, scope.TenantID,
		scope.TenantID, scope.DepartmentID, scope.ApplicationID,
		scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentInstanceID, scope.PrincipalType, scope.PrincipalID, action,
	).Scan(&roles, &groups, &principal.IsActive, &principal.Revision,
		&tenantRevision, &departmentRevision, &applicationRevision, &grantJSON)
	if err != nil {
		return Principal{}, nil, nil, err
	}
	if json.Unmarshal([]byte(roles), &principal.Roles) != nil || json.Unmarshal([]byte(groups), &principal.Groups) != nil {
		return Principal{}, nil, nil, errors.New("identity principal data is invalid")
	}
	grants, err := decodePermissionGrantRows(ctx, grantJSON)
	if err != nil {
		return Principal{}, nil, nil, err
	}
	return principal, grants, []uint64{tenantRevision, departmentRevision, applicationRevision}, nil
}
