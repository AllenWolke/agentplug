package identity

// Action metadata describes eligible target scopes, not an entitlement. The
// decision still requires the subject's exact role version, Grant and scope.
func completePermissionActionMetadata(actions []PermissionAction) []PermissionAction {
	for i := range actions {
		action := &actions[i]
		action.SensitivityLevel = "normal"
		if action.Sensitive {
			action.SensitivityLevel = "sensitive"
		}
		if action.Management {
			action.ScopeTypes = []string{"global", "tenant", "department", "application", "agent_installation"}
			if action.Code == "administrator.appoint" || action.Code == "delegation.manage" {
				action.SensitivityLevel = "reauthentication"
			}
			continue
		}
		action.ScopeTypes = []string{"application", "agent_installation"}
		action.DefaultDataScope = &DataScope{Type: "owner"}
		if action.Code == "business.review" || action.Code == "business.content.read" {
			action.DefaultDataScope.Type = "assigned_task"
		}
	}
	return actions
}
