package identity

import "time"

// ResourceDataPlan is a transport-neutral projection of one current data action.
// Consumers must apply (any allow) AND NOT (any deny) before count/pagination.
type ResourceDataPlan struct {
	Allow []ResourceDataClause
	Deny  []ResourceDataClause
}

type ResourceDataClause struct {
	ResourceID      string
	DataScope       DataScope
	AssignedObjects []DataObject
}

// CompileResourceDataPlan shares the authoritative role/member/validity rules
// with EvaluatePermission. It never interpolates SQL or supplies business facts.
func CompileResourceDataPlan(snapshot PermissionSnapshot, action string, application ManagementScope, now time.Time) (ResourceDataPlan, error) {
	plan := ResourceDataPlan{Allow: []ResourceDataClause{}, Deny: []ResourceDataClause{}}
	if snapshot.Mode != "v2" || application.Type != "application" || application.Validate() != nil || now.IsZero() || action != "history.read" && action != "business.content.read" && action != "business.review" {
		return plan, ErrInvalidResource
	}
	if !snapshot.Principal.IsActive {
		return plan, nil
	}
	if snapshot.Principal.Validate() != nil {
		return plan, ErrInvalidPrincipal
	}
	for _, grant := range snapshot.Grants {
		if grant.SubjectID != snapshot.Principal.ID || grant.SubjectType != snapshot.Principal.Type || grant.Status != "active" || !grant.Validity.Effective(now) || grant.Action != action || grant.ResourceType != "agent_installation" || grant.ResourceID == "" {
			continue
		}
		grantScope := ManagementScope{Type: "application", TenantID: grant.TenantID, DepartmentID: grant.DepartmentID, ApplicationID: grant.ApplicationID}
		if !grantScope.Contains(application) {
			continue
		}
		if grant.DataScope.Validate() != nil || grant.Effect != "allow" && grant.Effect != "deny" {
			return plan, ErrInvalidResource
		}
		candidate := snapshot
		eligibility := grant
		eligibility.Effect = "allow"
		if grant.Effect == "deny" {
			eligibility.DepartmentAgentActionVersion = 0
		}
		candidate.Grants = []Grant{eligibility}
		installation := application
		installation.Type, installation.ResourceID = "agent_installation", grant.ResourceID
		decision, err := EvaluatePermission(candidate, PermissionQuery{Action: action, Scope: installation, ResourceType: "agent_installation", ResourceID: grant.ResourceID, Now: now})
		if err != nil {
			return plan, err
		}
		if !decision.Allowed {
			continue
		}
		clause := ResourceDataClause{ResourceID: grant.ResourceID, DataScope: DataScope{Type: grant.DataScope.Type, IDs: append([]string(nil), grant.DataScope.IDs...)}}
		if grant.DataScope.Type == "assigned_task" {
			clause.AssignedObjects = assignedObjects(snapshot, action, installation, now)
			if len(clause.AssignedObjects) == 0 {
				continue
			}
		}
		if grant.Effect == "deny" {
			plan.Deny = append(plan.Deny, clause)
		} else {
			plan.Allow = append(plan.Allow, clause)
		}
	}
	return plan, nil
}
