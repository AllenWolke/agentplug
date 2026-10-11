package identity

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type PermissionRepository interface {
	PermissionSnapshot(context.Context, PrincipalType, string) (PermissionSnapshot, error)
	ResolvePermission(context.Context, PrincipalType, string, PermissionQuery) (PermissionDecision, error)
	PreviewAuthorizationChange(context.Context, sharedkernel.Scope, AuthorizationChangeCommand) (AuthorizationChangePlan, error)
	CommitAuthorizationChange(context.Context, sharedkernel.Scope, AuthorizationChangeCommand) (AuthorizationChangeReceipt, error)
}

func (m *Module) permissionActor(w http.ResponseWriter, r *http.Request) (browserActor, PermissionRepository, bool) {
	if !m.requireAuth(w, r) {
		return browserActor{}, nil, false
	}
	actor, ok := m.loadBrowserActor(w, r)
	if !ok {
		return browserActor{}, nil, false
	}
	if !actor.Browser {
		m.error(w, http.StatusForbidden, "TRUSTED_USER_CONTEXT_REQUIRED")
		return actor, nil, false
	}
	repository, ok := m.store.(PermissionRepository)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return actor, nil, false
	}
	return actor, repository, true
}

func (m *Module) permissionMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, repo, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	snapshot, err := repo.PermissionSnapshot(r.Context(), PrincipalUser, actor.Principal.ID)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	if r.URL.Path == "/me/workspaces" {
		items := []ManagementScope{}
		for _, member := range snapshot.Memberships {
			if member.Status == "active" && member.Effective(time.Now().UTC()) {
				items = append(items, member.Scope)
			}
		}
		applications := []ApplicationWorkspace{}
		administration := []ApplicationWorkspace{}
		departments := []ApplicationWorkspace{}
		if snapshot.Mode == "v2" {
			if store, ok := m.store.(WorkspaceRepository); ok {
				applications, err = store.ListApplicationWorkspaces(r.Context(), actor.Principal.ID)
				if err != nil {
					m.permissionError(w, err)
					return
				}
				administration, err = store.ListAdministrationWorkspaces(r.Context(), actor.Principal.ID)
				if err != nil {
					m.permissionError(w, err)
					return
				}
			}
		}
		if snapshot.Mode == "v2" {
			if store, ok := m.store.(AdministrationDepartmentRepository); ok {
				departments, err = store.ListAdministrationDepartments(r.Context(), actor.Principal.ID)
				if err != nil {
					m.permissionError(w, err)
					return
				}
			}
		}
		m.json(w, http.StatusOK, map[string]any{"items": items, "application_workspaces": applications, "administration_workspaces": administration, "administration_departments": departments, "policy_mode": snapshot.Mode})
		return
	}
	scope := ManagementScope{Type: "application", TenantID: actor.Scope.TenantID, DepartmentID: actor.Scope.DepartmentID, ApplicationID: actor.Scope.ApplicationID}
	capabilities := []string{}
	globalCapabilities := []string{}
	dataCapabilities := []string{}
	if snapshot.Mode == "v2" {
		now := time.Now().UTC()
		for _, action := range BuiltinPermissionActions() {
			if !action.Management {
				continue
			}
			// Capability projection is advisory. Use one consistent snapshot;
			// protected handlers still validate live organization/resource facts.
			available, err := managementCapabilityAvailable(snapshot, PermissionQuery{Action: action.Code, Scope: scope, Now: now})
			if err != nil {
				m.permissionError(w, err)
				return
			}
			if available {
				capabilities = append(capabilities, action.Code)
			}
			globalAvailable, err := managementCapabilityAvailable(snapshot, PermissionQuery{Action: action.Code, Scope: ManagementScope{Type: "global"}, Now: now})
			if err != nil {
				m.permissionError(w, err)
				return
			}
			if globalAvailable {
				globalCapabilities = append(globalCapabilities, action.Code)
			}
		}
		plan, err := CompileResourceDataPlan(snapshot, "business.review", scope, now)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		if reviewDataOpportunity(plan) {
			dataCapabilities = append(dataCapabilities, "business.review")
		}
	}
	kind := administrationKind(snapshot, time.Now().UTC())
	m.json(w, http.StatusOK, map[string]any{"policy_mode": snapshot.Mode, "scope": scope, "capabilities": capabilities, "global_capabilities": globalCapabilities, "data_capabilities": dataCapabilities, "role_bindings": snapshot.Bindings, "revision": snapshot.Principal.Revision, "administration_kind": kind, "self_service_permissions": snapshot.Mode == "v2" && kind == ""})
}

func (m *Module) permissionDirectories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	_, _, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	switch r.URL.Path {
	case "/permission-actions":
		m.json(w, http.StatusOK, map[string]any{"items": BuiltinPermissionActions()})
	case "/role-definitions":
		m.json(w, http.StatusOK, map[string]any{"items": BuiltinRoleDefinitions()})
	case "/identity-presets":
		m.json(w, http.StatusOK, map[string]any{"items": BuiltinIdentityPresets()})
	}
}

func (m *Module) permissionProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, repo, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/principals/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "access-profile" {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	kind := PrincipalUser
	if values, exists := r.URL.Query()["principal_type"]; exists {
		if len(values) != 1 || values[0] != string(PrincipalUser) && values[0] != string(PrincipalServicePrincipal) {
			m.error(w, http.StatusBadRequest, "INVALID_PRINCIPAL_TYPE")
			return
		}
		kind = PrincipalType(values[0])
	}
	self := kind == PrincipalUser && parts[0] == actor.Principal.ID
	if !self {
		scope := ManagementScope{Type: "application", TenantID: actor.Scope.TenantID, DepartmentID: actor.Scope.DepartmentID, ApplicationID: actor.Scope.ApplicationID}
		decision, err := repo.ResolvePermission(r.Context(), PrincipalUser, actor.Principal.ID, PermissionQuery{Action: "authorization.read", Scope: scope})
		if err != nil {
			m.permissionError(w, err)
			return
		}
		if !decision.Allowed {
			m.permissionError(w, ErrPermissionDenied)
			return
		}
	}
	snapshot, err := repo.PermissionSnapshot(r.Context(), kind, parts[0])
	if err != nil {
		m.permissionError(w, err)
		return
	}
	if !self {
		// 缓存仅在本次请求内有效，并以完整作用域为键；下一次请求重新校验实时权限。
		// 多条任务指派共用作用域，避免为每条记录重复加载同一权限快照。
		decisions := map[ManagementScope]bool{{Type: "application", TenantID: actor.Scope.TenantID, DepartmentID: actor.Scope.DepartmentID, ApplicationID: actor.Scope.ApplicationID}: true}
		allowed := func(scope ManagementScope) (bool, error) {
			if permitted, found := decisions[scope]; found {
				return permitted, nil
			}
			decision, err := repo.ResolvePermission(r.Context(), PrincipalUser, actor.Principal.ID, PermissionQuery{Action: "authorization.read", Scope: scope})
			if err != nil {
				return false, err
			}
			decisions[scope] = decision.Allowed
			return decision.Allowed, nil
		}
		members := []Membership{}
		bindings := []RoleBinding{}
		grants := []Grant{}
		delegations := []Delegation{}
		assignments := []TaskAssignment{}
		for _, v := range snapshot.Assignments {
			ok, err := allowed(v.Scope)
			if err != nil {
				m.permissionError(w, err)
				return
			}
			if ok {
				assignments = append(assignments, v)
			}
		}
		for _, v := range snapshot.Memberships {
			ok, err := allowed(v.Scope)
			if err != nil {
				m.permissionError(w, err)
				return
			}
			if ok {
				members = append(members, v)
			}
		}
		for _, v := range snapshot.Bindings {
			ok, err := allowed(v.Scope)
			if err != nil {
				m.permissionError(w, err)
				return
			}
			if ok {
				bindings = append(bindings, v)
			}
		}
		for _, v := range snapshot.Grants {
			scope := ManagementScope{Type: "application", TenantID: v.TenantID, DepartmentID: v.DepartmentID, ApplicationID: v.ApplicationID}
			ok, err := allowed(scope)
			if err != nil {
				m.permissionError(w, err)
				return
			}
			if ok {
				grants = append(grants, v)
			}
		}
		for _, v := range snapshot.Delegations {
			ok, err := allowed(v.Scope)
			if err != nil {
				m.permissionError(w, err)
				return
			}
			if ok {
				delegations = append(delegations, v)
			}
		}
		if len(members)+len(bindings)+len(grants)+len(delegations)+len(assignments) == 0 {
			// A new unbound machine has no application ownership facts yet.
			// Only a reader covering its tenant may inspect its empty profile.
			visible, err := allowed(ManagementScope{Type: "tenant", TenantID: snapshot.Principal.TenantID})
			if err != nil {
				m.permissionError(w, err)
				return
			}
			if !visible {
				// Admit an existing same-company human into the current department,
				// without exposing any of their other organizational facts.
				candidate := false
				if kind == PrincipalUser && snapshot.Principal.IsActive && snapshot.Principal.TenantID == actor.Scope.TenantID && actor.Policy != nil {
					candidate, err = managementCapabilityAvailable(*actor.Policy, PermissionQuery{Action: "membership.manage", Scope: ManagementScope{Type: "department", TenantID: actor.Scope.TenantID, DepartmentID: actor.Scope.DepartmentID}, Now: time.Now().UTC()})
					if err != nil {
						m.permissionError(w, err)
						return
					}
				}
				if !candidate {
					m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
					return
				}
			}
		}
		snapshot.Memberships, snapshot.Bindings, snapshot.Grants, snapshot.Delegations = members, bindings, grants, delegations
		snapshot.Assignments = assignments
		// This profile has already filtered individual organizational facts.
		// A department ceiling may include entries outside the reader's app;
		// retrieve it through its separately authorized department endpoint.
		snapshot.DepartmentAgentPolicies = nil
		snapshot.Principal.Roles = nil
		snapshot.Principal.Groups = nil
	}
	m.json(w, http.StatusOK, snapshot)
}

func (m *Module) permissionChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, repo, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	var command AuthorizationChangeCommand
	if err := decode(r, &command); err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/memberships:") && (len(command.Memberships) == 0 || command.Preset != nil || len(command.Bindings)+len(command.Grants)+len(command.RevokeBindingIDs)+len(command.RevokeGrantIDs)+len(command.Assignments)+len(command.RevokeAssignmentIDs) > 0) {
		m.error(w, http.StatusBadRequest, "INVALID_MEMBERSHIP_CHANGE")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/grants") {
		if command.Preset != nil || len(command.Bindings)+len(command.Memberships)+len(command.Assignments)+len(command.RevokeBindingIDs)+len(command.RevokeAssignmentIDs) > 0 || len(command.Grants)+len(command.RevokeGrantIDs) == 0 {
			m.error(w, http.StatusBadRequest, "INVALID_GRANT_CHANGE")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/grants/") {
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/grants/"), "/")
			if len(parts) != 2 || parts[1] != "revoke" || len(command.Grants) != 0 || len(command.RevokeGrantIDs) != 1 || command.RevokeGrantIDs[0] != parts[0] {
				m.error(w, http.StatusBadRequest, "GRANT_PATH_MISMATCH")
				return
			}
		}
	}
	if r.URL.Path == "/authorization-changes:preview" || r.URL.Path == "/memberships:preview" || r.URL.Path == "/grants:preview" {
		plan, err := repo.PreviewAuthorizationChange(r.Context(), actor.Scope, command)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, plan)
		return
	}
	receipt, err := repo.CommitAuthorizationChange(r.Context(), actor.Scope, command)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, receipt)
}

func (m *Module) permissionExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, repo, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	var query struct {
		PermissionQuery
		SubjectID   string        `json:"subject_id,omitempty"`
		SubjectType PrincipalType `json:"subject_type,omitempty"`
		ObjectID    string        `json:"object_id,omitempty"`
	}
	if err := decode(r, &query); err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	// Ownership and assignment facts must be resolved by the business module.
	if query.Object != nil {
		m.error(w, http.StatusBadRequest, "TRUSTED_OBJECT_CONTEXT_REQUIRED")
		return
	}
	if query.SubjectID == "" {
		query.SubjectID = actor.Principal.ID
	}
	if query.SubjectType == "" {
		query.SubjectType = PrincipalUser
	}
	explainer, supported := repo.(PermissionExplanationRepository)
	if !supported {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	var decision PermissionExplanation
	var err error
	if query.ObjectID != "" {
		objects, ok := repo.(PermissionObjectExplanationRepository)
		if !ok {
			m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
			return
		}
		decision, err = objects.ExplainPermissionObject(r.Context(), actor.Scope, query.SubjectType, query.SubjectID, query.PermissionQuery, query.ObjectID)
	} else {
		decision, err = explainer.ExplainPermission(r.Context(), actor.Scope, query.SubjectType, query.SubjectID, query.PermissionQuery)
	}
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, decision)
}

func (m *Module) permissionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPermissionExplanationObjectNotFound):
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
	case errors.Is(err, ErrPermissionExplanationStale):
		m.error(w, http.StatusConflict, "PERMISSION_EXPLANATION_STALE")
	case errors.Is(err, ErrAccessRequestNotFound), errors.Is(err, ErrEnrollmentNotFound):
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
	case errors.Is(err, ErrStepUpRequired):
		m.error(w, http.StatusUnauthorized, "STEP_UP_REQUIRED")
	case errors.Is(err, ErrLastAdministrator):
		m.error(w, http.StatusConflict, "LAST_ADMINISTRATOR_PROTECTED")
	case errors.Is(err, ErrPermissionDenied):
		m.error(w, http.StatusForbidden, "PERMISSION_DENIED")
	case errors.Is(err, ErrPermissionPlanStale):
		m.error(w, http.StatusConflict, "PLAN_STALE")
	case errors.Is(err, ErrMachineCredentialConflict):
		m.error(w, http.StatusConflict, "REVISION_CONFLICT")
	case errors.Is(err, ErrPermissionRecorderUnavailable):
		m.error(w, http.StatusServiceUnavailable, "AUTHORIZATION_CHANGE_UNAVAILABLE")
	case errors.Is(err, ErrInvalidResource), errors.Is(err, ErrInvalidPrincipal), errors.Is(err, ErrIdentityConflict), errors.Is(err, ErrPrincipalNotFound), errors.Is(err, ErrAgentInstallationNotFound), errors.Is(err, ErrScopeMismatch):
		m.storeError(w, err)
	default:
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
	}
}
