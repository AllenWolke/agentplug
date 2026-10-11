package identity

import "slices"

// Advisory qualification for a resource-scoped review entry, never approval of
// an individual object. Object ownership and participants remain live checks.
func reviewDataOpportunity(plan ResourceDataPlan) bool {
	for _, allow := range plan.Allow {
		if allow.DataScope.Type != "approved_organization" && allow.DataScope.Type != "explicit_set" {
			continue
		}
		fullyDenied := false
		deniedIDs := []string{}
		for _, deny := range plan.Deny {
			if deny.ResourceID != allow.ResourceID {
				continue
			}
			if deny.DataScope.Type == "approved_organization" {
				fullyDenied = true
			}
			if deny.DataScope.Type == "explicit_set" {
				deniedIDs = append(deniedIDs, deny.DataScope.IDs...)
			}
		}
		if fullyDenied {
			continue
		}
		if allow.DataScope.Type == "approved_organization" {
			return true
		}
		for _, id := range allow.DataScope.IDs {
			if !slices.Contains(deniedIDs, id) {
				return true
			}
		}
	}
	return false
}
