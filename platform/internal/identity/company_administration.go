package identity

import "time"

// Version 1 remains the published, limited tenant-organization role. Version 2
// is an appointment-only company administrator and never a business role.
func companyAdministratorBinding(binding RoleBinding, tenant string) bool {
	return binding.RoleCode == "tenant_admin" && binding.RoleVersion == 2 && binding.Scope.Type == "tenant" && binding.Scope.TenantID == tenant && binding.Scope.Validate() == nil
}

func protectedAdministratorBinding(binding RoleBinding) bool {
	return binding.RoleCode == "super_admin" || binding.RoleCode == "permission_admin" || binding.RoleCode == "tenant_admin" && binding.RoleVersion == 2
}

func companyAdministrationAllows(snapshot PermissionSnapshot, scope ManagementScope, action string, now time.Time) bool {
	if snapshot.Mode != "v2" || snapshot.Principal.Type != PrincipalUser || !snapshot.Principal.IsActive || scope.TenantID != snapshot.Principal.TenantID || scope.Type == "global" {
		return false
	}
	decision, err := EvaluatePermission(snapshot, PermissionQuery{Scope: scope, Action: action, Now: now})
	if err != nil || !decision.Allowed {
		return false
	}
	for _, binding := range snapshot.Bindings {
		if !companyAdministratorBinding(binding, snapshot.Principal.TenantID) {
			continue
		}
		for _, id := range decision.BindingIDs {
			if id == binding.ID {
				return true
			}
		}
	}
	return false
}

// A fresh authentication proof qualifies an action; the consuming transaction
// still validates the exact target and delegated boundary. Company admins may
// delegate within their company but cannot appoint company/global peers.
func requireAdministrativeStepUp(snapshot PermissionSnapshot, action, tenant string, now time.Time) error {
	if requireSuperAdministrator(snapshot, action, now) == nil {
		return nil
	}
	if action == "delegation.manage" && tenant == snapshot.Principal.TenantID && companyAdministrationAllows(snapshot, ManagementScope{Type: "tenant", TenantID: tenant}, action, now) {
		return nil
	}
	return ErrPermissionDenied
}

func authorizeCompanyDelegation(owner, target PermissionSnapshot, delegation Delegation, creating bool, now time.Time) error {
	if requireSuperAdministrator(owner, "delegation.manage", now) == nil {
		return nil
	}
	if owner.Principal.ID == target.Principal.ID || owner.Principal.TenantID != target.Principal.TenantID || !companyAdministrationAllows(owner, delegation.Scope, "delegation.manage", now) {
		return ErrPermissionDenied
	}
	for _, binding := range target.Bindings {
		if binding.Status == "active" && (binding.RoleCode == "super_admin" || companyAdministratorBinding(binding, target.Principal.TenantID)) {
			return ErrPermissionDenied
		}
	}
	if !creating {
		return nil
	}
	// Issued delegation may not outlive the company authority that issued it.
	for _, binding := range owner.Bindings {
		if !companyAdministratorBinding(binding, owner.Principal.TenantID) || binding.Status != "active" || !binding.Effective(now) {
			continue
		}
		if binding.ExpiresAt == nil || delegation.ExpiresAt != nil && !delegation.ExpiresAt.After(*binding.ExpiresAt) && !delegation.AllowPermanent {
			return nil
		}
	}
	return ErrPermissionDenied
}
