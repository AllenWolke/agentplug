package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

// ManagementScope is deliberately separate from the complete execution Scope.
// Empty execution coordinates must never represent a global administrator.
type ManagementScope struct {
	Type          string `json:"scope_type"`
	TenantID      string `json:"tenant_id,omitempty"`
	DepartmentID  string `json:"department_id,omitempty"`
	ApplicationID string `json:"application_id,omitempty"`
	ResourceID    string `json:"resource_id,omitempty"`
}

func (s ManagementScope) Validate() error {
	for _, value := range []string{s.TenantID, s.DepartmentID, s.ApplicationID, s.ResourceID} {
		if strings.TrimSpace(value) != value || strings.ContainsAny(value, "*\x00") {
			return ErrInvalidResource
		}
	}
	switch s.Type {
	case "global":
		if s.TenantID != "" || s.DepartmentID != "" || s.ApplicationID != "" || s.ResourceID != "" {
			return ErrInvalidResource
		}
	case "tenant":
		if s.TenantID == "" || s.DepartmentID != "" || s.ApplicationID != "" || s.ResourceID != "" {
			return ErrInvalidResource
		}
	case "department":
		if s.TenantID == "" || s.DepartmentID == "" || s.ApplicationID != "" || s.ResourceID != "" {
			return ErrInvalidResource
		}
	case "application":
		if s.TenantID == "" || s.DepartmentID == "" || s.ApplicationID == "" || s.ResourceID != "" {
			return ErrInvalidResource
		}
	case "agent_installation":
		if s.TenantID == "" || s.DepartmentID == "" || s.ApplicationID == "" || s.ResourceID == "" {
			return ErrInvalidResource
		}
	default:
		return ErrInvalidResource
	}
	return nil
}

// Contains assumes both scopes have already been resolved against authoritative
// organization/resource records. It does not establish ownership itself.
func (s ManagementScope) Contains(target ManagementScope) bool {
	if s.Validate() != nil || target.Validate() != nil {
		return false
	}
	if s.Type == "global" {
		return true
	}
	if target.Type == "global" || s.TenantID != target.TenantID {
		return false
	}
	if s.Type == "tenant" {
		return true
	}
	if s.DepartmentID != target.DepartmentID {
		return false
	}
	if s.Type == "department" {
		return true
	}
	if s.ApplicationID != target.ApplicationID {
		return false
	}
	if s.Type == "application" {
		return true
	}
	return s.ResourceID == target.ResourceID
}

type Validity struct {
	StartsAt  *time.Time `json:"starts_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (v Validity) Validate() error {
	if v.StartsAt != nil && v.ExpiresAt != nil && !v.ExpiresAt.After(*v.StartsAt) {
		return ErrInvalidResource
	}
	return nil
}

func (v Validity) Effective(now time.Time) bool {
	return v.Validate() == nil && (v.StartsAt == nil || !now.Before(*v.StartsAt)) && (v.ExpiresAt == nil || now.Before(*v.ExpiresAt))
}

type PermissionAction struct {
	Code             string     `json:"code"`
	Management       bool       `json:"management"`
	ResourceType     string     `json:"resource_type,omitempty"`
	Sensitive        bool       `json:"sensitive"`
	ScopeTypes       []string   `json:"scope_types"`
	DefaultDataScope *DataScope `json:"default_data_scope,omitempty"`
	SensitivityLevel string     `json:"sensitivity_level"`
}

type RoleDefinition struct {
	Code       string   `json:"role_code"`
	Version    uint64   `json:"role_version"`
	Name       string   `json:"name"`
	ScopeTypes []string `json:"scope_types"`
	Actions    []string `json:"actions"`
	Assignable bool     `json:"assignable"`
}

type RoleBinding struct {
	ID          string          `json:"id"`
	SubjectID   string          `json:"subject_id"`
	RoleCode    string          `json:"role_code"`
	RoleVersion uint64          `json:"role_version"`
	Scope       ManagementScope `json:"scope"`
	Validity
	Status        string `json:"status"`
	Revision      uint64 `json:"revision"`
	SourceID      string `json:"source_id"`
	PresetCode    string `json:"preset_code,omitempty"`
	PresetVersion uint64 `json:"preset_version,omitempty"`
	DelegationID  string `json:"delegation_id,omitempty"`
}

type Membership struct {
	ID        string          `json:"id"`
	SubjectID string          `json:"subject_id"`
	Scope     ManagementScope `json:"scope"`
	Validity
	Status       string `json:"status"`
	Revision     uint64 `json:"revision"`
	SourceID     string `json:"source_id,omitempty"`
	DelegationID string `json:"delegation_id,omitempty"`
}

type DataScope struct {
	Type string   `json:"type"`
	IDs  []string `json:"ids,omitempty"`
}

func (s DataScope) Validate() error {
	switch s.Type {
	case "owner", "assigned_task", "approved_organization":
		if len(s.IDs) != 0 {
			return ErrInvalidResource
		}
	case "explicit_set":
		if len(s.IDs) == 0 {
			return ErrInvalidResource
		}
		for _, id := range s.IDs {
			if strings.TrimSpace(id) == "" || strings.ContainsAny(id, "*\x00") {
				return ErrInvalidResource
			}
		}
	default:
		return ErrInvalidResource
	}
	return nil
}

type DataObject struct {
	ID           string          `json:"id,omitempty"`
	OwnerID      string          `json:"owner_id,omitempty"`
	ActorID      string          `json:"actor_id,omitempty"`
	AssignedTo   []string        `json:"assigned_to,omitempty"`
	Scope        ManagementScope `json:"scope"`
	Participants []string        `json:"participants,omitempty"`
}

func (s DataScope) Allows(subject string, resource ManagementScope, object DataObject) bool {
	if s.Validate() != nil {
		return false
	}
	return s.allowsValidated(subject, resource, object, nil)
}

type DelegatedResource struct {
	ResourceType   string `json:"resource_type"`
	ResourceID     string `json:"resource_id"`
	InstallationID string `json:"installation_id"`
}

type Delegation struct {
	ID                 string              `json:"id"`
	SubjectID          string              `json:"subject_id"`
	Scope              ManagementScope     `json:"scope"`
	Roles              []string            `json:"roles"`
	Actions            []string            `json:"actions"`
	Resources          []string            `json:"resources"`
	ResourceBindings   []DelegatedResource `json:"resource_bindings,omitempty"`
	DataScopeTypes     []string            `json:"data_scope_types"`
	DataIDs            []string            `json:"data_ids,omitempty"`
	ManagementActions  []string            `json:"management_actions"`
	MaxDurationSeconds int64               `json:"max_duration_seconds"`
	AllowPermanent     bool                `json:"allow_permanent"`
	Validity
	Status   string `json:"status"`
	Revision uint64 `json:"revision"`
}

// Covers checks ONE delegation's complete boundary. Callers cannot combine
// a role from one delegation with a resource or duration from another.
func (d Delegation) Covers(subject, managementAction, role, action, resource string, target ManagementScope, data DataScope, validity Validity, now time.Time) bool {
	if d.SubjectID != subject || d.Status != "active" || !d.Effective(now) || !d.Scope.Contains(target) || !slices.Contains(d.ManagementActions, managementAction) || validity.Validate() != nil {
		return false
	}
	if role == "super_admin" || role == "permission_admin" {
		return false
	}
	if role != "" && !slices.Contains(d.Roles, role) {
		return false
	}
	if action != "" {
		resourceType := ""
		for _, definition := range BuiltinPermissionActions() {
			if definition.Code == action && !definition.Management {
				resourceType = definition.ResourceType
			}
		}
		covered := resourceType == "agent_installation" && slices.Contains(d.Resources, resource)
		if target.Type == "agent_installation" {
			for _, binding := range d.ResourceBindings {
				if binding.ResourceType == resourceType && binding.ResourceID == resource && binding.InstallationID == target.ResourceID {
					covered = true
				}
			}
		}
		if resourceType == "" || !slices.Contains(d.Actions, action) || !covered || data.Validate() != nil || !slices.Contains(d.DataScopeTypes, data.Type) {
			return false
		}
	}
	if data.Type == "explicit_set" {
		for _, id := range data.IDs {
			if !slices.Contains(d.DataIDs, id) {
				return false
			}
		}
	}
	if validity.ExpiresAt == nil {
		return d.AllowPermanent && d.ExpiresAt == nil
	}
	if !validity.ExpiresAt.After(now) || (d.ExpiresAt != nil && validity.ExpiresAt.After(*d.ExpiresAt)) {
		return false
	}
	start := now
	if validity.StartsAt != nil && validity.StartsAt.After(start) {
		start = *validity.StartsAt
	}
	return d.MaxDurationSeconds > 0 && validity.ExpiresAt.Sub(start) <= time.Duration(d.MaxDurationSeconds)*time.Second
}

type IdentityPreset struct {
	Code            string        `json:"preset_code"`
	Version         uint64        `json:"preset_version"`
	Name            string        `json:"name"`
	RoleCode        string        `json:"role_code,omitempty"`
	RoleVersion     uint64        `json:"role_version,omitempty"`
	SubjectType     PrincipalType `json:"subject_type"`
	ScopeTypes      []string      `json:"scope_types"`
	ResourceActions []string      `json:"resource_actions"`
	DataScope       DataScope     `json:"data_scope"`
	AppointmentOnly bool          `json:"appointment_only"`
}

func BuiltinPermissionActions() []PermissionAction {
	var result []PermissionAction
	result = append(result, PermissionAction{Code: "skill.load", ResourceType: "skill"})
	result = append(result, PermissionAction{Code: "agent.delegate", ResourceType: "agent_installation"})
	for _, code := range []string{"organization.manage", "membership.manage", "principal.read", "principal.disable", "authorization.read", "authorization.change", "department.agent_access.manage", "access_request.decide", "administrator.appoint", "delegation.manage", "platform.monitor", "model.configure", "catalog.manage", "agent.develop", "agent.debug", "evaluation.run", "release.submit", "release.approve", "prompt.manage", "tool.manage", "policy.manage", "machine.manage", "audit.metadata.read", "catalog.requestable.read"} {
		result = append(result, PermissionAction{Code: code, Management: true, Sensitive: code == "administrator.appoint" || code == "delegation.manage"})
	}
	for _, code := range []string{"discover", "run", "cancel", "history.read", "history.continue", "history.revise", "history.regenerate", "history.share", "history.export", "history.delete.request", "business.review", "business.content.read", "audit.content.read", "audit.export", "knowledge.search", "tool.invoke", "model.generate", "model.embed", "memory.read", "memory.write"} {
		resource := "agent_installation"
		if strings.HasPrefix(code, "knowledge.") {
			resource = "knowledge"
		}
		if strings.HasPrefix(code, "tool.") {
			resource = "tool"
		}
		if strings.HasPrefix(code, "model.") {
			resource = "model"
		}
		if strings.HasPrefix(code, "memory.") {
			resource = "memory"
		}
		result = append(result, PermissionAction{Code: code, ResourceType: resource, Sensitive: strings.HasSuffix(code, "export") || strings.HasSuffix(code, "share") || code == "audit.content.read"})
	}
	return completePermissionActionMetadata(result)
}

func BuiltinRoleDefinitions() []RoleDefinition {
	app := []string{"application", "agent_installation"}
	org := []string{"tenant", "department", "application"}
	return []RoleDefinition{
		{Code: "department_admin", Version: 3, Name: "部门 Agent 管理员", ScopeTypes: []string{"department"}, Actions: []string{"membership.manage", "principal.read", "authorization.read", "department.agent_access.manage", "access_request.decide"}, Assignable: true},
		// A new immutable version for ordinary Agent use. It cannot activate a
		// previously stored share/export Grant when a user receives this package.
		{Code: "operator", Version: 2, Name: "Agent使用者", ScopeTypes: app, Actions: []string{"discover", "run", "cancel", "history.read", "history.continue", "knowledge.search", "tool.invoke", "model.generate", "model.embed", "memory.read", "memory.write"}, Assignable: true},
		{Code: "tenant_admin", Version: 2, Name: "公司管理员", ScopeTypes: []string{"tenant"}, Actions: []string{"organization.manage", "membership.manage", "principal.read", "principal.disable", "authorization.read", "authorization.change", "access_request.decide", "delegation.manage", "catalog.manage", "machine.manage"}, Assignable: true},
		{Code: "department_admin", Version: 2, Name: "部门管理员", ScopeTypes: []string{"department"}, Actions: []string{"membership.manage", "principal.read", "authorization.read", "authorization.change", "access_request.decide"}, Assignable: true},
		{Code: "skill_user", Version: 2, Name: "Skill使用者", ScopeTypes: app, Actions: []string{"skill.load"}, Assignable: true},
		{Code: "agent_delegate", Version: 2, Name: "Agent协作发起者", ScopeTypes: app, Actions: []string{"agent.delegate"}, Assignable: true},
		{Code: "super_admin", Version: 1, Name: "超级管理员", ScopeTypes: []string{"global"}, Actions: []string{"organization.manage", "membership.manage", "principal.read", "principal.disable", "authorization.read", "authorization.change", "access_request.decide", "administrator.appoint", "delegation.manage", "catalog.manage", "model.configure", "platform.monitor", "machine.manage", "prompt.manage", "tool.manage", "policy.manage", "evaluation.run", "release.submit", "release.approve"}, Assignable: true},
		{Code: "permission_admin", Version: 1, Name: "权限管理员", ScopeTypes: org, Actions: []string{"principal.read", "principal.disable", "authorization.read", "authorization.change", "access_request.decide"}, Assignable: true},
		{Code: "platform_ops_admin", Version: 1, Name: "平台运维管理员", ScopeTypes: []string{"global", "tenant"}, Actions: []string{"platform.monitor", "model.configure"}, Assignable: true},
		{Code: "tenant_admin", Version: 1, Name: "租户管理员", ScopeTypes: []string{"tenant"}, Actions: []string{"organization.manage", "membership.manage", "catalog.manage"}, Assignable: true},
		{Code: "department_admin", Version: 1, Name: "部门管理员", ScopeTypes: []string{"department"}, Actions: []string{"organization.manage", "membership.manage", "catalog.manage"}, Assignable: true},
		{Code: "application_admin", Version: 1, Name: "应用管理员", ScopeTypes: []string{"application"}, Actions: []string{"membership.manage", "catalog.manage"}, Assignable: true},
		{Code: "agent_developer", Version: 1, Name: "Agent 开发者", ScopeTypes: app, Actions: []string{"agent.develop", "agent.debug", "evaluation.run", "release.submit", "prompt.manage", "tool.manage", "policy.manage"}, Assignable: true},
		{Code: "operator", Version: 1, Name: "业务操作员", ScopeTypes: app, Actions: []string{"discover", "run", "cancel", "history.read", "history.continue", "history.revise", "history.regenerate", "history.share", "history.export", "history.delete.request", "knowledge.search", "tool.invoke", "model.generate", "model.embed", "memory.read", "memory.write"}, Assignable: true},
		{Code: "reviewer", Version: 1, Name: "业务审核员", ScopeTypes: app, Actions: []string{"business.review", "business.content.read"}, Assignable: true},
		{Code: "auditor", Version: 1, Name: "审计员", ScopeTypes: append([]string{"global"}, org...), Actions: []string{"audit.metadata.read", "authorization.read", "audit.content.read", "audit.export"}, Assignable: true},
		{Code: "integration_admin", Version: 1, Name: "集成管理员", ScopeTypes: []string{"application"}, Actions: []string{"machine.manage"}, Assignable: true},
	}
}

func BuiltinIdentityPresets() []IdentityPreset {
	var result []IdentityPreset
	for _, role := range BuiltinRoleDefinitions() {
		// A later role version must not replace or duplicate a published v1
		// preset. Preset upgrades are separately versioned catalog entries.
		if role.Version != 1 {
			continue
		}
		data := DataScope{Type: "owner"}
		var actions []string
		if role.Code == "operator" {
			actions = []string{"discover", "run", "cancel", "history.read", "history.continue"}
		}
		if role.Code == "reviewer" {
			actions = []string{"business.review", "business.content.read"}
			data.Type = "assigned_task"
		}
		result = append(result, IdentityPreset{Code: role.Code, Version: 1, Name: role.Name, RoleCode: role.Code, RoleVersion: 1, SubjectType: PrincipalUser, ScopeTypes: role.ScopeTypes, ResourceActions: actions, DataScope: data, AppointmentOnly: role.Code == "super_admin" || role.Code == "permission_admin"})
	}
	result = append(result, IdentityPreset{Code: "machine_caller", Version: 1, Name: "机器调用", SubjectType: PrincipalServicePrincipal, ScopeTypes: []string{"agent_installation"}, ResourceActions: []string{"run"}, DataScope: DataScope{Type: "owner"}})
	// New public roles and presets are catalog v2 entries; v1 stays immutable.
	for _, role := range BuiltinRoleDefinitions() {
		if role.Version != 2 || (role.Code != "skill_user" && role.Code != "agent_delegate" && role.Code != "department_admin" && role.Code != "tenant_admin") {
			continue
		}
		result = append(result, IdentityPreset{Code: role.Code, Version: 2, Name: role.Name, RoleCode: role.Code, RoleVersion: role.Version, SubjectType: PrincipalUser, ScopeTypes: role.ScopeTypes, DataScope: DataScope{Type: "owner"}, AppointmentOnly: role.Code == "tenant_admin"})
	}
	result = append(result, IdentityPreset{Code: "department_admin", Version: 3, Name: "部门 Agent 管理员", RoleCode: "department_admin", RoleVersion: 3, SubjectType: PrincipalUser, ScopeTypes: []string{"department"}, DataScope: DataScope{Type: "owner"}})
	return result
}

type PermissionSnapshot struct {
	AgentPackages           []DepartmentAgentPackage `json:"agent_use_packages,omitempty"`
	Principal               Principal                `json:"principal"`
	Mode                    string                   `json:"policy_mode"`
	Memberships             []Membership             `json:"memberships"`
	Bindings                []RoleBinding            `json:"role_bindings"`
	Roles                   []RoleDefinition         `json:"role_definitions"`
	Grants                  []Grant                  `json:"resource_grants"`
	Delegations             []Delegation             `json:"delegations"`
	Assignments             []TaskAssignment         `json:"task_assignments,omitempty"`
	DepartmentAgentPolicies []DepartmentAgentPolicy  `json:"department_agent_policies,omitempty"`
}

type PermissionQuery struct {
	PublishedAgentVersionID string          `json:"-"`
	RequirePublishedVersion bool            `json:"-"`
	Action                  string          `json:"action"`
	Scope                   ManagementScope `json:"scope"`
	ResourceType            string          `json:"resource_type,omitempty"`
	ResourceID              string          `json:"resource_id,omitempty"`
	Object                  *DataObject     `json:"object,omitempty"`
	Now                     time.Time       `json:"-"`
}

type PermissionDecision struct {
	Allowed    bool        `json:"allowed"`
	Reason     string      `json:"reason_code"`
	BindingIDs []string    `json:"binding_ids,omitempty"`
	GrantIDs   []string    `json:"grant_ids,omitempty"`
	DataScopes []DataScope `json:"data_scopes,omitempty"`
}

func EvaluatePermission(snapshot PermissionSnapshot, q PermissionQuery) (PermissionDecision, error) {
	deny := func(reason string) (PermissionDecision, error) { return PermissionDecision{Reason: reason}, nil }
	if q.Now.IsZero() || q.Scope.Validate() != nil || q.Action == "" {
		return PermissionDecision{}, ErrInvalidResource
	}
	if snapshot.Mode != "v2" {
		return PermissionDecision{}, errors.New("v2 permission snapshot required")
	}
	if !snapshot.Principal.IsActive {
		return deny("PRINCIPAL_DISABLED")
	}
	if snapshot.Principal.Validate() != nil {
		return PermissionDecision{}, ErrInvalidPrincipal
	}
	var action PermissionAction
	found := false
	for _, a := range BuiltinPermissionActions() {
		if a.Code == q.Action {
			action = a
			found = true
			break
		}
	}
	if !found {
		return deny("UNKNOWN_ACTION")
	}
	if !action.Management && (q.Scope.Type == "global" || q.Scope.TenantID != snapshot.Principal.TenantID) {
		return deny("TENANT_MISMATCH")
	}
	if !action.Management && action.ResourceType == "agent_installation" && q.Scope.Type == "agent_installation" && q.Scope.ResourceID != q.ResourceID {
		return deny("INSTALLATION_SCOPE_MISMATCH")
	}
	if !action.Management && action.ResourceType != "agent_installation" && q.Scope.Type != "agent_installation" {
		return deny("INSTALLATION_SCOPE_REQUIRED")
	}
	// Application APIs still name the exact Agent resource. Narrow that
	// business query before matching membership and roles so an installation
	// role works there without becoming an application-wide entitlement.
	if !action.Management && action.ResourceType == "agent_installation" && q.Scope.Type == "application" && validPermissionResourceID(q.ResourceID) {
		q.Scope.Type, q.Scope.ResourceID = "agent_installation", q.ResourceID
	}
	decision := PermissionDecision{}
	if snapshot.Principal.Type == PrincipalUser {
		member := false
		for _, m := range snapshot.Memberships {
			if m.SubjectID == snapshot.Principal.ID && m.Status == "active" && m.Effective(q.Now) && m.Scope.Contains(q.Scope) {
				member = true
				break
			}
		}
		for _, b := range snapshot.Bindings {
			if b.SubjectID != snapshot.Principal.ID || b.Status != "active" || !b.Effective(q.Now) || !b.Scope.Contains(q.Scope) {
				continue
			}
			if b.RoleCode == "tenant_admin" && b.RoleVersion == 2 && !companyAdministratorBinding(b, snapshot.Principal.TenantID) {
				continue
			}
			if !member && (!action.Management || b.Scope.Type != "global" && !companyAdministratorBinding(b, snapshot.Principal.TenantID)) {
				continue
			}
			for _, role := range snapshot.Roles {
				if role.Code == b.RoleCode && role.Version == b.RoleVersion && slices.Contains(role.ScopeTypes, b.Scope.Type) && slices.Contains(role.Actions, q.Action) {
					decision.BindingIDs = append(decision.BindingIDs, b.ID)
				}
			}
		}
		if q.Action == "catalog.requestable.read" && member {
			return PermissionDecision{Allowed: true, Reason: "MEMBERSHIP_METADATA"}, nil
		}
		if len(decision.BindingIDs) == 0 {
			return deny("ROLE_REQUIRED")
		}
	} else if action.Management {
		return deny("MACHINE_MANAGEMENT_DENIED")
	}
	if action.Management {
		decision.Allowed = true
		decision.Reason = "SCOPED_ROLE"
		return decision, nil
	}
	if q.ResourceType != action.ResourceType || q.ResourceID == "" {
		return PermissionDecision{}, ErrInvalidResource
	}
	packageDenyReason := ""
	for _, g := range snapshot.Grants {
		if g.Status != "active" || g.SubjectID != snapshot.Principal.ID || g.SubjectType != snapshot.Principal.Type || g.Action != q.Action || g.ResourceType != q.ResourceType || g.ResourceID != q.ResourceID || !g.Validity.Effective(q.Now) {
			continue
		}
		if g.ResourceType != "agent_installation" && q.Scope.Type == "agent_installation" && g.AgentInstanceID != q.Scope.ResourceID {
			continue
		}
		if g.ResourceType == "agent_installation" && g.AgentInstanceID != q.ResourceID {
			continue
		}
		grantScope := ManagementScope{Type: "application", TenantID: g.TenantID, DepartmentID: g.DepartmentID, ApplicationID: g.ApplicationID}
		if !grantScope.Contains(q.Scope) {
			continue
		}
		if g.DataScope.Validate() != nil {
			return PermissionDecision{}, ErrInvalidResource
		}
		if q.Object != nil {
			object := *q.Object
			// The request's assigned_to array is not an assignment authority.
			object.AssignedTo = nil
			if g.DataScope.Type == "assigned_task" && assignedObjectMatches(snapshot, q) {
				object.AssignedTo = []string{snapshot.Principal.ID}
			}
			if !g.DataScope.Allows(snapshot.Principal.ID, grantScope, object) {
				continue
			}
		}
		if g.Effect == "deny" {
			return deny("EXPLICIT_DENY")
		}
		if g.Effect != "allow" {
			return PermissionDecision{}, ErrInvalidResource
		}
		if !agentPackageAllowsGrant(snapshot, g, q.Now) {
			packageDenyReason = "AGENT_PACKAGE_APPROVAL_REQUIRED"
			continue
		}
		if hasAgentPackageStamp(g) && (q.RequirePublishedVersion && q.PublishedAgentVersionID == "" || q.PublishedAgentVersionID != "" && !agentPackageMatchesVersion(snapshot, g, q.PublishedAgentVersionID)) {
			packageDenyReason = "AGENT_PACKAGE_STALE"
			continue
		}
		if !departmentAgentGrantSourceEffective(snapshot, g) {
			continue
		}
		decision.GrantIDs = append(decision.GrantIDs, g.ID)
		decision.DataScopes = append(decision.DataScopes, g.DataScope)
	}
	if len(decision.GrantIDs) == 0 {
		if packageDenyReason != "" {
			return deny(packageDenyReason)
		}
		return deny("RESOURCE_GRANT_REQUIRED")
	}
	if reason := departmentAgentBlockReason(snapshot, q); reason != "" {
		return deny(reason)
	}
	if q.Action == "business.review" && q.Object != nil && (q.Object.OwnerID == snapshot.Principal.ID || q.Object.ActorID == snapshot.Principal.ID || slices.Contains(q.Object.Participants, snapshot.Principal.ID)) {
		return deny("SELF_REVIEW_DENIED")
	}
	decision.Allowed = true
	decision.Reason = "EXPLICIT_ALLOW"
	return decision, nil
}

func PermissionSnapshotDigest(snapshot PermissionSnapshot) (string, error) {
	// Sort copies: callers retain their original data and stable ordering.
	snapshot.Memberships = append([]Membership(nil), snapshot.Memberships...)
	snapshot.Bindings = append([]RoleBinding(nil), snapshot.Bindings...)
	snapshot.Grants = append([]Grant(nil), snapshot.Grants...)
	snapshot.Delegations = append([]Delegation(nil), snapshot.Delegations...)
	snapshot.Roles = append([]RoleDefinition(nil), snapshot.Roles...)
	snapshot.Assignments = append([]TaskAssignment(nil), snapshot.Assignments...)
	snapshot.AgentPackages = append([]DepartmentAgentPackage(nil), snapshot.AgentPackages...)
	slices.SortFunc(snapshot.AgentPackages, func(a, b DepartmentAgentPackage) int { return strings.Compare(a.ID, b.ID) })
	snapshot.DepartmentAgentPolicies = append([]DepartmentAgentPolicy(nil), snapshot.DepartmentAgentPolicies...)
	for i := range snapshot.DepartmentAgentPolicies {
		snapshot.DepartmentAgentPolicies[i].Entries = normalizedDepartmentAgentEntries(snapshot.DepartmentAgentPolicies[i].Entries)
	}
	slices.SortFunc(snapshot.DepartmentAgentPolicies, func(a, b DepartmentAgentPolicy) int {
		if a.TenantID != b.TenantID {
			return strings.Compare(a.TenantID, b.TenantID)
		}
		return strings.Compare(a.DepartmentID, b.DepartmentID)
	})
	slices.SortFunc(snapshot.Assignments, func(a, b TaskAssignment) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(snapshot.Memberships, func(a, b Membership) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(snapshot.Bindings, func(a, b RoleBinding) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(snapshot.Grants, func(a, b Grant) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(snapshot.Delegations, func(a, b Delegation) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(snapshot.Roles, func(a, b RoleDefinition) int {
		if a.Code != b.Code {
			return strings.Compare(a.Code, b.Code)
		}
		if a.Version < b.Version {
			return -1
		}
		if a.Version > b.Version {
			return 1
		}
		return 0
	})
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}

// EffectivePermissionSnapshotDigest binds durable facts and their current
// temporal state. Raw timestamps alone do not change when one source expires
// while another source continues to permit the same action.
func EffectivePermissionSnapshotDigest(snapshot PermissionSnapshot, now time.Time) (string, error) {
	digest, err := PermissionSnapshotDigest(snapshot)
	if err != nil {
		return "", err
	}
	active := struct {
		Snapshot                                                string
		Memberships, Bindings, Grants, Delegations, Assignments []string
		DepartmentAgentEntries                                  []string `json:"DepartmentAgentEntries,omitempty"`
	}{Snapshot: digest, Memberships: []string{}, Bindings: []string{}, Grants: []string{}, Delegations: []string{}, Assignments: []string{}}
	for _, value := range snapshot.Memberships {
		if value.Status == "active" && value.Effective(now) {
			active.Memberships = append(active.Memberships, value.ID)
		}
	}
	for _, value := range snapshot.Bindings {
		if value.Status == "active" && value.Effective(now) {
			active.Bindings = append(active.Bindings, value.ID)
		}
	}
	for _, value := range snapshot.Grants {
		if value.Status == "active" && value.Validity.Effective(now) && (value.Effect != "allow" || agentPackageAllowsGrant(snapshot, value, now)) {
			active.Grants = append(active.Grants, value.ID)
		}
	}
	for _, value := range snapshot.Delegations {
		if value.Status == "active" && value.Effective(now) {
			active.Delegations = append(active.Delegations, value.ID)
		}
	}
	slices.Sort(active.Memberships)
	slices.Sort(active.Bindings)
	slices.Sort(active.Grants)
	slices.Sort(active.Delegations)
	for _, value := range snapshot.Assignments {
		if value.Status == "active" && value.Effective(now) {
			active.Assignments = append(active.Assignments, value.ID)
		}
	}
	slices.Sort(active.Assignments)
	for _, policy := range snapshot.DepartmentAgentPolicies {
		for _, entry := range policy.Entries {
			if entry.Validity.Effective(now) {
				active.DepartmentAgentEntries = append(active.DepartmentAgentEntries, policy.TenantID+"/"+policy.DepartmentID+"/"+entry.ApplicationID+"/"+entry.InstallationID)
			}
		}
	}
	slices.Sort(active.DepartmentAgentEntries)
	raw, err := json.Marshal(active)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}

func (s DataScope) allowsValidated(subject string, resource ManagementScope, object DataObject, ids map[string]struct{}) bool {
	if !resource.Contains(object.Scope) {
		return false
	}
	switch s.Type {
	case "owner":
		return object.OwnerID == subject
	case "assigned_task":
		return slices.Contains(object.AssignedTo, subject)
	case "explicit_set":
		if ids != nil {
			_, found := ids[object.ID]
			return object.ID != "" && found
		}
		return object.ID != "" && slices.Contains(s.IDs, object.ID)
	case "approved_organization":
		return true
	}
	return false
}
