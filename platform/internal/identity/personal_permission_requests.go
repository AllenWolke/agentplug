package identity

import "time"

// Global system management and personal business use are separate identities.
// Decide from live authority, never from an account name or legacy role label.
func systemManagementAccount(snapshot PermissionSnapshot, now time.Time) (bool, error) {
	if snapshot.Mode != "v2" || snapshot.Principal.Type != PrincipalUser || !snapshot.Principal.IsActive {
		return false, nil
	}
	for _, action := range []string{"organization.manage", "authorization.change", "administrator.appoint"} {
		allowed, err := managementCapabilityAvailable(snapshot, PermissionQuery{Action: action, Scope: ManagementScope{Type: "global"}, Now: now})
		if err != nil || !allowed {
			return false, err
		}
	}
	return true, nil
}
