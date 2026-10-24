package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/lexagent/platform/internal/sqlutil"
)

// Read all header facts in one statement in the caller's repeatable-read
// transaction. This saves round trips; no authorization or snapshot is cached.
func loadPermissionSnapshotHeader(ctx context.Context, reader permissionReader, kind PrincipalType, id string) (PermissionSnapshot, error) {
	return loadPermissionSnapshotFacts(ctx, reader, kind, id, false)
}

// All ordinary snapshot facts share one SQL statement and its MVCC view. The
// surrounding transaction and subsequent package validation remain unchanged.
// Columns remain authoritative over JSON metadata; no permission decision or
// database snapshot survives this call.
func loadPermissionSnapshotFacts(ctx context.Context, reader permissionReader, kind PrincipalType, id string, details bool) (PermissionSnapshot, error) {
	s := PermissionSnapshot{Mode: "legacy", Memberships: []Membership{}, Bindings: []RoleBinding{}, Roles: []RoleDefinition{}, Grants: []Grant{}, Delegations: []Delegation{}}
	var roles, groups string
	var definitions, memberships, bindings, delegations []byte
	var grants, assignments, departmentPolicies []byte
	query := `SELECT p.id,p.principal_type,p.tenant_id,p.roles_json,p.groups_json,p.active,p.revision,
 COALESCE((SELECT policy_mode FROM platform_identity_policy_migration WHERE principal_type=p.principal_type AND subject_id=p.id),'legacy'),
 COALESCE((SELECT json_agg(payload ORDER BY role_code,role_version) FROM platform_identity_role_definition),'[]'::json),
 COALESCE((SELECT json_agg(payload ORDER BY id) FROM platform_identity_membership WHERE subject_id=p.id),'[]'::json),
 COALESCE((SELECT json_agg(payload ORDER BY id) FROM platform_identity_role_binding WHERE subject_id=p.id),'[]'::json),
 COALESCE((SELECT json_agg(payload ORDER BY id) FROM platform_identity_delegation WHERE subject_id=p.id),'[]'::json)`
	values := []any{
		&s.Principal.ID, &s.Principal.Type, &s.Principal.TenantID, &roles, &groups, &s.Principal.IsActive, &s.Principal.Revision,
		&s.Mode, &definitions, &memberships, &bindings, &delegations}
	if details {
		query += `,COALESCE((SELECT json_agg(row_to_json(g) ORDER BY g.id) FROM platform_identity_grant g WHERE g.subject_type=p.principal_type AND g.subject_id=p.id),'[]'::json)`
		values = append(values, &grants)
		if kind == PrincipalUser {
			query += `,COALESCE((SELECT json_agg(row_to_json(a) ORDER BY a.id) FROM platform_identity_task_assignment a WHERE a.subject_id=p.id),'[]'::json)`
			values = append(values, &assignments)
		}
	}
	query += `,COALESCE((SELECT json_agg(json_build_object('tenant_id',h.tenant_id,'department_id',h.department_id,'revision',h.revision,'entries_digest',h.entries_digest,'entries',
      COALESCE((SELECT json_agg(json_build_object('application_id',e.application_id,'installation_id',e.installation_id,'actions',e.actions_json,'action_versions',e.action_versions_json,'starts_at',e.starts_at,'expires_at',e.expires_at) ORDER BY e.application_id,e.installation_id)
      FROM platform_identity_department_agent_entry e WHERE e.tenant_id=h.tenant_id AND e.department_id=h.department_id AND EXISTS(SELECT 1 FROM platform_identity_grant g WHERE g.subject_type=p.principal_type AND g.subject_id=p.id AND g.tenant_id=p.tenant_id AND g.agent_instance_id=e.installation_id)),'[]'::json)) ORDER BY h.department_id)
      FROM platform_identity_department_agent_policy h WHERE h.tenant_id=p.tenant_id AND (
       EXISTS(SELECT 1 FROM platform_identity_membership m WHERE m.subject_id=p.id AND m.tenant_id=p.tenant_id AND m.department_id=h.department_id) OR
       EXISTS(SELECT 1 FROM platform_identity_role_binding b WHERE b.subject_id=p.id AND b.tenant_id=p.tenant_id AND b.department_id=h.department_id) OR
       EXISTS(SELECT 1 FROM platform_identity_grant g WHERE g.subject_type=p.principal_type AND g.subject_id=p.id AND g.tenant_id=p.tenant_id AND g.department_id=h.department_id))),'[]'::json)`
	values = append(values, &departmentPolicies)
	query += ` FROM platform_identity_principal p WHERE p.principal_type=? AND p.id=?`
	err := reader.QueryRowContext(ctx, sqlutil.Bind(query), kind, id).Scan(values...)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrPrincipalNotFound
	}
	if err != nil {
		return s, err
	}
	if s.Mode != "legacy" && s.Mode != "shadow" && s.Mode != "v2" {
		return s, ErrInvalidResource
	}
	if json.Unmarshal([]byte(roles), &s.Principal.Roles) != nil || json.Unmarshal([]byte(groups), &s.Principal.Groups) != nil {
		return s, ErrInvalidResource
	}
	s.Roles, err = decodePermissionRoleRows(ctx, definitions)
	if err != nil {
		return s, err
	}
	for _, pair := range []struct {
		raw []byte
		dst any
	}{{memberships, &s.Memberships}, {bindings, &s.Bindings}, {delegations, &s.Delegations}} {
		if err := json.Unmarshal(pair.raw, pair.dst); err != nil {
			return s, err
		}
	}
	if details {
		s.Grants, err = decodePermissionGrantRows(ctx, grants)
		if err != nil {
			return s, err
		}
		if kind == PrincipalUser {
			s.Assignments, err = parseTaskAssignmentRows(assignments)
			if err != nil {
				return s, err
			}
		}
	}
	if json.Unmarshal(departmentPolicies, &s.DepartmentAgentPolicies) != nil {
		return s, ErrInvalidResource
	}
	for _, policy := range s.DepartmentAgentPolicies {
		if policy.TenantID != s.Principal.TenantID || policy.Revision == 0 || !validPermissionDigest(policy.EntriesDigest) {
			return s, ErrInvalidResource
		}
		for _, entry := range policy.Entries {
			if validatePersistedDepartmentAgentEntry(entry, policy.Revision) != nil {
				return s, ErrInvalidResource
			}
		}
	}
	return s, nil
}
