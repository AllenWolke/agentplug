package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"

	"github.com/lexagent/platform/internal/sqlutil"
)

func departmentAgentPolicyManaged(ctx context.Context, reader permissionReader, tenant, department string) (bool, error) {
	var managed bool
	err := reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_identity_department_agent_policy WHERE tenant_id=? AND department_id=?)`), tenant, department).Scan(&managed)
	return managed, err
}

func readDepartmentAgentPolicy(ctx context.Context, reader permissionReader, tenant, department string) (DepartmentAgentPolicy, bool, error) {
	policy := DepartmentAgentPolicy{TenantID: tenant, DepartmentID: department, Entries: []DepartmentAgentPolicyEntry{}}
	err := reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,entries_digest FROM platform_identity_department_agent_policy WHERE tenant_id=? AND department_id=?`), tenant, department).Scan(&policy.Revision, &policy.EntriesDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return policy, false, nil
	}
	if err != nil {
		return policy, false, err
	}
	rows, err := reader.QueryContext(ctx, sqlutil.Bind(`SELECT application_id,installation_id,actions_json,action_versions_json,starts_at,expires_at FROM platform_identity_department_agent_entry WHERE tenant_id=? AND department_id=? ORDER BY application_id,installation_id LIMIT 257`), tenant, department)
	if err != nil {
		return policy, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var entry DepartmentAgentPolicyEntry
		var raw, versions []byte
		if err := rows.Scan(&entry.ApplicationID, &entry.InstallationID, &raw, &versions, &entry.StartsAt, &entry.ExpiresAt); err != nil {
			return policy, false, err
		}
		if json.Unmarshal(raw, &entry.Actions) != nil || json.Unmarshal(versions, &entry.ActionVersions) != nil || validatePersistedDepartmentAgentEntry(entry, policy.Revision) != nil {
			return policy, false, ErrInvalidResource
		}
		policy.Entries = append(policy.Entries, entry)
	}
	if err := rows.Err(); err != nil {
		return policy, false, err
	}
	if len(policy.Entries) > 256 || departmentAgentEntriesDigest(policy.Entries) != policy.EntriesDigest {
		return policy, false, ErrInvalidResource
	}
	return policy, true, nil
}

// Only load departments referenced by this identity's facts and installations
// referenced by its grants. The policy head binds the complete entry digest, so
// a change to an unloaded item still invalidates a dependent plan/version.
func loadDepartmentAgentPolicies(ctx context.Context, reader permissionReader, snapshot PermissionSnapshot) ([]DepartmentAgentPolicy, error) {
	departments, installations := []string{}, []string{}
	departmentSet, installationSet := map[string]bool{}, map[string]bool{}
	addDepartment := func(tenant, department string) {
		if tenant == snapshot.Principal.TenantID && department != "" && !departmentSet[department] {
			departmentSet[department] = true
			departments = append(departments, department)
		}
	}
	for _, member := range snapshot.Memberships {
		addDepartment(member.Scope.TenantID, member.Scope.DepartmentID)
	}
	for _, binding := range snapshot.Bindings {
		addDepartment(binding.Scope.TenantID, binding.Scope.DepartmentID)
	}
	for _, grant := range snapshot.Grants {
		addDepartment(grant.TenantID, grant.DepartmentID)
		if grant.TenantID == snapshot.Principal.TenantID && grant.AgentInstanceID != "" && !installationSet[grant.AgentInstanceID] {
			installationSet[grant.AgentInstanceID] = true
			installations = append(installations, grant.AgentInstanceID)
		}
	}
	policies := []DepartmentAgentPolicy{}
	if len(departments) == 0 {
		return policies, nil
	}
	sort.Strings(departments)
	rows, err := reader.QueryContext(ctx, sqlutil.Bind(`SELECT department_id,revision,entries_digest FROM platform_identity_department_agent_policy WHERE tenant_id=? AND department_id=ANY(?) ORDER BY department_id`), snapshot.Principal.TenantID, departments)
	if err != nil {
		return nil, err
	}
	indexes := map[string]int{}
	for rows.Next() {
		policy := DepartmentAgentPolicy{TenantID: snapshot.Principal.TenantID, Entries: []DepartmentAgentPolicyEntry{}}
		if err := rows.Scan(&policy.DepartmentID, &policy.Revision, &policy.EntriesDigest); err != nil {
			rows.Close()
			return nil, err
		}
		indexes[policy.DepartmentID] = len(policies)
		policies = append(policies, policy)
	}
	err, closeErr := rows.Err(), rows.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(policies) == 0 || len(installations) == 0 {
		return policies, nil
	}
	rows, err = reader.QueryContext(ctx, sqlutil.Bind(`SELECT department_id,application_id,installation_id,actions_json,action_versions_json,starts_at,expires_at FROM platform_identity_department_agent_entry WHERE tenant_id=? AND department_id=ANY(?) AND installation_id=ANY(?) ORDER BY department_id,application_id,installation_id`), snapshot.Principal.TenantID, departments, installations)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var department string
		var entry DepartmentAgentPolicyEntry
		var raw, versions []byte
		if err := rows.Scan(&department, &entry.ApplicationID, &entry.InstallationID, &raw, &versions, &entry.StartsAt, &entry.ExpiresAt); err != nil {
			return nil, err
		}
		index, ok := indexes[department]
		if !ok || json.Unmarshal(raw, &entry.Actions) != nil || json.Unmarshal(versions, &entry.ActionVersions) != nil || validatePersistedDepartmentAgentEntry(entry, policies[index].Revision) != nil {
			return nil, ErrInvalidResource
		}
		policies[index].Entries = append(policies[index].Entries, entry)
	}
	return policies, rows.Err()
}
