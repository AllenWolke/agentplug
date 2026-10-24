package identity

import (
	"net/http"
	"strings"
)

func memberDepartmentScope(r *http.Request, actor browserActor) ManagementScope {
	tenant, department := strings.TrimSpace(r.URL.Query().Get("tenant_id")), strings.TrimSpace(r.URL.Query().Get("department_id"))
	if tenant == "" {
		tenant = actor.Scope.TenantID
	}
	if department == "" {
		department = actor.Scope.DepartmentID
	}
	return ManagementScope{Type: "department", TenantID: tenant, DepartmentID: department}
}

// Minimal profile for adding a same-company human to a department. Broad
// authorization.read is not required to look up a new candidate's revision.
// Membership-only managers receive no role/grant data, and nothing outside
// the explicitly authorized department is projected.
func (m *Module) membershipProfile(w http.ResponseWriter, r *http.Request, actor browserActor, repo PermissionRepository, id string) {
	scope := memberDepartmentScope(r, actor)
	decision, err := repo.ResolvePermission(r.Context(), PrincipalUser, actor.Principal.ID, PermissionQuery{Action: "membership.manage", Scope: scope})
	if err != nil || !decision.Allowed {
		if err == nil {
			err = ErrPermissionDenied
		}
		m.permissionError(w, err)
		return
	}
	snapshot, err := repo.PermissionSnapshot(r.Context(), PrincipalUser, id)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	if snapshot.Principal.TenantID != scope.TenantID {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	out := PermissionSnapshot{Principal: snapshot.Principal, Mode: snapshot.Mode,
		Memberships: []Membership{}, Bindings: []RoleBinding{}, Grants: []Grant{}, Roles: []RoleDefinition{}, Delegations: []Delegation{}}
	out.Principal.Roles, out.Principal.Groups = nil, nil
	for _, member := range snapshot.Memberships {
		if scope.Contains(member.Scope) {
			out.Memberships = append(out.Memberships, member)
		}
	}
	read, err := repo.ResolvePermission(r.Context(), PrincipalUser, actor.Principal.ID, PermissionQuery{Action: "authorization.read", Scope: scope})
	if err != nil {
		m.permissionError(w, err)
		return
	}
	if read.Allowed {
		for _, binding := range snapshot.Bindings {
			if scope.Contains(binding.Scope) {
				out.Bindings = append(out.Bindings, binding)
			}
		}
		for _, grant := range snapshot.Grants {
			if scope.Contains(grantAuthorizationScope(grant)) {
				out.Grants = append(out.Grants, grant)
			}
		}
	}
	m.json(w, http.StatusOK, out)
}
