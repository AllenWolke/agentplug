package identity

import (
	"encoding/json"
	"slices"
)

type PresetSelection struct {
	Code        string          `json:"preset_code"`
	Version     uint64          `json:"preset_version"`
	Scope       ManagementScope `json:"scope"`
	ResourceIDs []string        `json:"resource_ids"`
	Validity
}

// ExpandIdentityPreset produces concrete, immutable facts for selected existing
// resources. No wildcard, sensitive-action default or latest-version reference.
func ExpandIdentityPreset(p IdentityPreset, kind PrincipalType, subject, source string, selection PresetSelection) ([]RoleBinding, []Grant, error) {
	if p.Code != selection.Code || p.Version != selection.Version || p.AppointmentOnly || p.SubjectType != kind || subject == "" || source == "" || selection.Scope.Validate() != nil || !slices.Contains(p.ScopeTypes, selection.Scope.Type) || selection.Validity.Validate() != nil || len(selection.ResourceIDs) > 16 {
		return nil, nil, ErrInvalidResource
	}
	if selection.Scope.Type == "agent_installation" && (len(selection.ResourceIDs) != 1 || selection.ResourceIDs[0] != selection.Scope.ResourceID) {
		return nil, nil, ErrInvalidResource
	}
	key, err := json.Marshal([]any{subject, source, selection})
	if err != nil {
		return nil, nil, err
	}
	id := permissionHash(key)
	bindings := []RoleBinding{}
	if p.RoleCode != "" {
		bindings = append(bindings, RoleBinding{ID: "binding-" + id, SubjectID: subject, RoleCode: p.RoleCode, RoleVersion: p.RoleVersion, Scope: selection.Scope, Validity: selection.Validity, Status: "active", Revision: 1, SourceID: source, PresetCode: p.Code, PresetVersion: p.Version})
	}
	grants := []Grant{}
	seen := map[string]bool{}
	for _, resource := range selection.ResourceIDs {
		if resource == "" || seen[resource] {
			return nil, nil, ErrInvalidResource
		}
		seen[resource] = true
		for _, action := range p.ResourceActions {
			raw, err := json.Marshal([]string{id, resource, action})
			if err != nil {
				return nil, nil, err
			}
			grants = append(grants, Grant{ID: "grant-" + permissionHash(raw), TenantID: selection.Scope.TenantID, DepartmentID: selection.Scope.DepartmentID, ApplicationID: selection.Scope.ApplicationID, AgentInstanceID: resource, SubjectType: kind, SubjectID: subject, Action: action, Effect: "allow", Status: "active", Revision: 1, ResourceType: "agent_installation", ResourceID: resource, DataScope: p.DataScope, Validity: selection.Validity, SourceID: source, PresetCode: p.Code, PresetVersion: p.Version})
		}
	}
	return bindings, grants, nil
}
