package identity

import (
	"slices"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

const departmentAgentAccessPurpose = "department_agent_access"

type DepartmentAgentTarget struct {
	ApplicationID   string   `json:"application_id"`
	InstallationIDs []string `json:"installation_ids"`
}
type DepartmentAgentSelection struct {
	Scope               ManagementScope         `json:"scope"`
	Targets             []DepartmentAgentTarget `json:"targets"`
	IncludeDependencies bool                    `json:"include_dependencies,omitempty"`
	Validity
}

func departmentAgentPresetSelections(c AuthorizationChangeCommand) []PresetSelection {
	if c.Preset != nil {
		return []PresetSelection{*c.Preset}
	}
	selections := []PresetSelection{}
	if c.AgentSelection != nil {
		for _, target := range c.AgentSelection.Targets {
			selections = append(selections, PresetSelection{Code: "operator", Version: 1, Scope: ManagementScope{Type: "application", TenantID: c.AgentSelection.Scope.TenantID, DepartmentID: c.AgentSelection.Scope.DepartmentID, ApplicationID: target.ApplicationID}, ResourceIDs: target.InstallationIDs, Validity: c.AgentSelection.Validity})
		}
	}
	return selections
}

func expandDepartmentAgentSelection(c AuthorizationChangeCommand) ([]RoleBinding, []Grant, error) {
	selection := c.AgentSelection
	if c.Purpose != departmentAgentAccessPurpose || c.Preset != nil || c.RevokePackageUse || selection.Scope.Type != "department" || selection.Scope.Validate() != nil ||
		selection.Validity.Validate() != nil || len(selection.Targets) == 0 || len(selection.Targets) > 16 || len(c.Bindings)+len(c.Grants)+len(c.RevokeGrantIDs) != 0 {
		return nil, nil, ErrInvalidResource
	}
	var preset IdentityPreset
	for _, item := range BuiltinIdentityPresets() {
		if item.Code == "operator" && item.Version == 1 {
			preset = item
			break
		}
	}
	bindings, grants := []RoleBinding{}, []Grant{}
	seen, total := map[string]bool{}, 0
	for _, p := range departmentAgentPresetSelections(c) {
		if seen[p.Scope.ApplicationID] || len(p.ResourceIDs) == 0 {
			return nil, nil, ErrInvalidResource
		}
		seen[p.Scope.ApplicationID] = true
		total += len(p.ResourceIDs)
		if total > 16 {
			return nil, nil, ErrInvalidResource
		}
		b, g, err := ExpandIdentityPreset(preset, c.SubjectType, c.SubjectID, "department-agent:"+c.IdempotencyKey+":"+p.Scope.ApplicationID, p)
		if err != nil {
			return nil, nil, err
		}
		bindings, grants = append(bindings, b...), append(grants, g...)
	}
	return bindings, grants, nil
}

var basicAgentUseActions = []string{"discover", "run", "cancel", "history.read", "history.continue"}

// This qualification is narrower than authorization.change. Published v1
// department roles retain their original contract; v2 must be assigned explicitly.
func canManageDepartmentAgentAccess(owner PermissionSnapshot, scope ManagementScope, now time.Time) (bool, error) {
	if scope.Type != "department" && scope.Type != "application" && scope.Type != "agent_installation" {
		return false, nil
	}
	decision, err := EvaluatePermission(owner, PermissionQuery{Action: "department.agent_access.manage", Scope: scope, Now: now})
	if err != nil || decision.Allowed {
		return decision.Allowed, err
	}
	decision, err = EvaluatePermission(owner, PermissionQuery{Action: "authorization.change", Scope: scope, Now: now})
	if err != nil {
		return false, err
	}
	if decision.Allowed && companyAdministrationAllows(owner, scope, "authorization.change", now) {
		return true, nil
	}
	return slices.ContainsFunc(owner.Bindings, func(b RoleBinding) bool {
		return b.RoleCode == "super_admin" && slices.Contains(decision.BindingIDs, b.ID)
	}), nil
}

func memberOfDepartment(target PermissionSnapshot, scope ManagementScope, now time.Time) bool {
	return slices.ContainsFunc(target.Memberships, func(m Membership) bool {
		return m.SubjectID == target.Principal.ID && m.Status == "active" && m.Effective(now) &&
			m.Scope.TenantID == scope.TenantID && m.Scope.DepartmentID == scope.DepartmentID
	})
}

// Validate the ORIGINAL command, before preset expansion/automatic revocations.
// The workflow grants a pinned basic-use preset. Complete use adds only the
// exact server-resolved dependencies approved by the company. Raw roles,
// resources, reviews, exports and deny removals remain outside this workflow.
func validateDepartmentAgentChange(owner, target PermissionSnapshot, actor sharedkernel.Scope, c AuthorizationChangeCommand, now time.Time) (bool, error) {
	if c.Purpose == "" || c.Purpose == departmentRemovalPurpose {
		if c.RevokePackageUse {
			return false, ErrPermissionDenied
		}
		return false, nil
	}
	if c.Purpose != departmentAgentAccessPurpose || c.SubjectType != PrincipalUser ||
		c.SubjectID == actor.PrincipalID || len(c.Bindings)+len(c.Grants)+len(c.Assignments)+len(c.RevokeAssignmentIDs)+len(c.RevokeBindingIDs) != 0 {
		return false, ErrPermissionDenied
	}
	var department ManagementScope
	selections := departmentAgentPresetSelections(c)
	if len(selections) != 0 {
		if c.RevokePackageUse {
			return false, ErrPermissionDenied
		}
		p := selections[0]
		if p.Code != "operator" || p.Version != 1 || p.Scope.Type != "application" || p.Scope.Validate() != nil ||
			len(p.ResourceIDs) == 0 || len(p.ResourceIDs) > 16 || len(c.RevokeGrantIDs) != 0 {
			return false, ErrPermissionDenied
		}
		department = ManagementScope{Type: "department", TenantID: p.Scope.TenantID, DepartmentID: p.Scope.DepartmentID}
		for _, selected := range selections {
			if selected.Scope.TenantID != department.TenantID || selected.Scope.DepartmentID != department.DepartmentID || selected.Scope.Type != "application" {
				return false, ErrPermissionDenied
			}
		}
		for _, m := range c.Memberships {
			if m.Status != "active" || m.Scope != department && !slices.ContainsFunc(selections, func(p PresetSelection) bool { return p.Scope == m.Scope }) {
				return false, ErrPermissionDenied
			}
		}
	} else {
		if len(c.Memberships) != 0 || len(c.RevokeGrantIDs) == 0 {
			return false, ErrPermissionDenied
		}
		for _, id := range c.RevokeGrantIDs {
			index := slices.IndexFunc(target.Grants, func(g Grant) bool { return g.ID == id })
			if index < 0 {
				return false, ErrIdentityConflict
			}
			g := target.Grants[index]
			next := ManagementScope{Type: "department", TenantID: g.TenantID, DepartmentID: g.DepartmentID}
			basic := g.ResourceType == "agent_installation" && g.ResourceID == g.AgentInstanceID && g.DataScope.Type == "owner" && len(g.DataScope.IDs) == 0 && slices.Contains(basicAgentUseActions, g.Action)
			packageDependency := c.RevokePackageUse && validStampedAgentDependency(g)
			if g.SubjectType != PrincipalUser || g.SubjectID != c.SubjectID || g.Status != "active" || g.Effect != "allow" ||
				!basic && !packageDependency || department.Type != "" && next != department {
				return false, ErrPermissionDenied
			}
			department = next
		}
	}
	joining := slices.ContainsFunc(c.Memberships, func(m MembershipMutation) bool { return m.Scope == department && m.Status == "active" })
	if department.TenantID != target.Principal.TenantID || !memberOfDepartment(target, department, now) && !joining {
		return false, ErrPermissionDenied
	}
	allowed, err := canManageDepartmentAgentAccess(owner, department, now)
	if err != nil || !allowed {
		return false, ErrPermissionDenied
	}
	// Ordinary department managers cannot alter protected administrator accounts.
	for _, binding := range target.Bindings {
		if binding.Status == "active" && binding.Effective(now) && slices.Contains([]string{"super_admin", "permission_admin"}, binding.RoleCode) {
			return false, ErrPermissionDenied
		}
	}
	return true, nil
}

func validateExpandedDepartmentAgentPreset(original, expanded AuthorizationChangeCommand) error {
	selections := departmentAgentPresetSelections(original)
	if len(selections) == 0 {
		return nil
	}
	total := 0
	for _, p := range selections {
		total += len(p.ResourceIDs)
	}
	if len(expanded.Bindings) != len(selections) || len(expanded.Grants) != total*len(basicAgentUseActions) {
		return ErrPermissionDenied
	}
	for _, b := range expanded.Bindings {
		if b.RoleCode != "operator" || b.RoleVersion != 1 || !slices.ContainsFunc(selections, func(p PresetSelection) bool { return p.Scope == b.Scope }) {
			return ErrPermissionDenied
		}
	}
	seen := map[string]bool{}
	for _, g := range expanded.Grants {
		index := slices.IndexFunc(selections, func(p PresetSelection) bool { return p.Scope.ApplicationID == g.ApplicationID })
		if index < 0 {
			return ErrPermissionDenied
		}
		p := selections[index]
		key := g.ApplicationID + "\x00" + g.ResourceID + "\x00" + g.Action
		if seen[key] || g.ResourceType != "agent_installation" || g.ResourceID != g.AgentInstanceID ||
			g.TenantID != p.Scope.TenantID || g.DepartmentID != p.Scope.DepartmentID || g.ApplicationID != p.Scope.ApplicationID ||
			g.Effect != "allow" || g.DataScope.Type != "owner" || len(g.DataScope.IDs) != 0 ||
			!slices.Contains(p.ResourceIDs, g.ResourceID) || !slices.Contains(basicAgentUseActions, g.Action) {
			return ErrPermissionDenied
		}
		seen[key] = true
	}
	return nil
}
