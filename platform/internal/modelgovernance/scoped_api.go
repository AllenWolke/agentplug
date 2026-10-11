package modelgovernance

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/modelcapacity"
)

func (m *Module) deployments(w http.ResponseWriter, r *http.Request) {
	actor, ok := m.authorize(w, r, ActionManageDeployment)
	if !ok {
		return
	}
	scope := actorScope(actor)
	if !completeScope(scope) {
		m.error(w, http.StatusForbidden, "FORBIDDEN", "a tenant, department, and application scope is required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		limit, ok := readLimit(w, r)
		if !ok {
			return
		}
		rows, err := m.store.ListDeployments(r.Context(), scope, strings.TrimSpace(r.URL.Query().Get("model_version_id")), limit)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusOK, map[string]any{"items": rows})
	case http.MethodPost:
		var in CreateDeploymentRequest
		if !m.decode(w, r, &in) {
			return
		}
		// Browser input may repeat the current scope as a consistency hint, but
		// it never establishes ownership. Empty fields are filled from the
		// authenticated Gateway actor; non-empty mismatches are rejected.
		// 浏览器输入只能重复当前 Scope 作为一致性提示，不能决定资源归属。
		// 空字段由可信 Gateway 身份补齐，非空不匹配则拒绝。
		if (in.TenantID != "" && in.TenantID != scope.TenantID) ||
			(in.DepartmentID != "" && in.DepartmentID != scope.DepartmentID) ||
			(in.ApplicationID != "" && in.ApplicationID != scope.ApplicationID) {
			m.error(w, http.StatusForbidden, "FORBIDDEN", "deployment scope must match the authenticated application")
			return
		}
		in.TenantID, in.DepartmentID, in.ApplicationID = scope.TenantID, scope.DepartmentID, scope.ApplicationID
		row, err := validateDeployment(in, m.endpointCheck, m.allowLocal)
		if err != nil {
			m.storeError(w, err)
			return
		}
		row.ID, err = newID()
		if err != nil {
			m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "could not allocate deployment id")
			return
		}
		if err = m.store.CreateDeployment(r.Context(), &row); err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusCreated, row)
	default:
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	}
}

func (m *Module) deployment(w http.ResponseWriter, r *http.Request) {
	parts := pathParts(r.URL.Path, "/deployments/")
	if len(parts) == 0 {
		m.error(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
		return
	}
	actor, ok := m.authorize(w, r, ActionManageDeployment)
	if !ok {
		return
	}
	scope := actorScope(actor)
	if !completeScope(scope) {
		m.error(w, http.StatusForbidden, "FORBIDDEN", "a tenant, department, and application scope is required")
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		row, err := m.store.GetDeployment(r.Context(), scope, parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusOK, row)
		return
	}
	if len(parts) == 2 && parts[1] == "health" && r.Method == http.MethodPost {
		if actor.Browser || actor.PrincipalType != "service" || actor.PrincipalID == "" {
			m.error(w, http.StatusForbidden, "SERVICE_IDENTITY_REQUIRED", "only a trusted service may report observed deployment health")
			return
		}
		var in struct {
			Health   string `json:"health_status"`
			Revision uint64 `json:"revision"`
		}
		if !m.decode(w, r, &in) {
			return
		}
		if in.Revision == 0 {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "positive revision is required")
			return
		}
		status, valid := healthDeploymentStatus(in.Health)
		if !valid {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "health_status is invalid")
			return
		}
		if err := m.store.UpdateDeploymentHealth(r.Context(), scope, parts[0], in.Revision, in.Health, status); err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusOK, map[string]any{"health_status": in.Health, "status": status, "observed_revision": in.Revision, "revision": in.Revision + 1})
		return
	}
	m.error(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
}

func (m *Module) accessPolicies(w http.ResponseWriter, r *http.Request) {
	actor, ok := m.authorize(w, r, ActionManagePolicy)
	if !ok {
		return
	}
	visibleScope := actorScope(actor)
	if !completeScope(visibleScope) {
		m.error(w, http.StatusForbidden, "FORBIDDEN", "a tenant, department, and application scope is required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		limit, ok := readLimit(w, r)
		if !ok {
			return
		}
		rows, err := m.store.ListAccessPolicies(r.Context(), visibleScope, limit)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusOK, map[string]any{"items": rows})
	case http.MethodPost:
		var in CreateAccessPolicyRequest
		if !m.decode(w, r, &in) {
			return
		}
		if !policyTargetVisible(in, visibleScope) {
			m.error(w, http.StatusForbidden, "FORBIDDEN", "policy scope is outside the authenticated tenant or application")
			return
		}
		// App administrators can only create policies for their exact
		// authenticated application. Blank legacy scope hints are normalized to
		// that scope instead of becoming tenant-wide policies.
		// 应用管理员只能为当前认证应用创建策略。空 Scope 提示补成精确应用
		// 范围，不能被解释为租户级策略。
		in.TenantID, in.DepartmentID, in.ApplicationID = visibleScope.TenantID, visibleScope.DepartmentID, visibleScope.ApplicationID
		row, err := validateAccessPolicy(in)
		if err != nil {
			m.storeError(w, err)
			return
		}
		row.ID, err = newID()
		if err != nil {
			m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "could not allocate access policy id")
			return
		}
		if err = m.store.CreateAccessPolicy(r.Context(), &row); err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusCreated, row)
	default:
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	}
}

func (m *Module) accessPolicy(w http.ResponseWriter, r *http.Request) {
	parts := pathParts(r.URL.Path, "/access-policies/")
	if len(parts) == 0 {
		m.error(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
		return
	}
	actor, ok := m.authorize(w, r, ActionManagePolicy)
	if !ok {
		return
	}
	scope := actorScope(actor)
	if !completeScope(scope) {
		m.error(w, http.StatusForbidden, "FORBIDDEN", "a tenant, department, and application scope is required")
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		row, err := m.store.GetAccessPolicy(r.Context(), scope, parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusOK, row)
		return
	}
	if len(parts) == 2 && (parts[1] == "approve" || parts[1] == "revoke") && r.Method == http.MethodPost {
		var in struct {
			Revision uint64 `json:"revision"`
		}
		if !m.decode(w, r, &in) {
			return
		}
		if in.Revision == 0 {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "positive revision is required")
			return
		}
		row, err := m.store.GetAccessPolicy(r.Context(), scope, parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		if !policyMatchesApplication(row, scope) {
			m.error(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
			return
		}
		status := PolicyApproved
		if parts[1] == "revoke" {
			status = PolicyRevoked
		}
		if err = m.store.UpdateAccessPolicyStatus(r.Context(), scope, parts[0], in.Revision, status); err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusOK, map[string]any{"status": status, "revision": in.Revision + 1})
		return
	}
	m.error(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
}

func validateDeployment(in CreateDeploymentRequest, endpointCheck func(string, bool) error, allowLocal bool) (Deployment, error) {
	in.ModelVersionID = strings.TrimSpace(in.ModelVersionID)
	in.Environment = strings.TrimSpace(in.Environment)
	in.EndpointRef = strings.TrimSpace(in.EndpointRef)
	in.RuntimeKind = strings.TrimSpace(in.RuntimeKind)
	if !completeScope(Scope{TenantID: in.TenantID, DepartmentID: in.DepartmentID, ApplicationID: in.ApplicationID}) || in.ModelVersionID == "" || !providerKeyPattern.MatchString(in.Environment) || !providerKeyPattern.MatchString(in.RuntimeKind) || endpointCheck == nil {
		return Deployment{}, ErrInvalidRequest
	}
	if err := endpointCheck(in.EndpointRef, allowLocal); err != nil {
		return Deployment{}, err
	}
	resource, err := normalizeJSONObject(in.ResourceProfile)
	if err != nil {
		return Deployment{}, err
	}
	capacity, err := normalizeJSONObject(in.Capacity)
	if err != nil {
		return Deployment{}, err
	}
	if _, err = modelcapacity.ParseCapacityUnits(capacity); err != nil {
		return Deployment{}, err
	}
	if in.MinReplicas == 0 {
		in.MinReplicas = 1
	}
	if in.MaxReplicas == 0 {
		in.MaxReplicas = in.MinReplicas
	}
	if in.MinReplicas < 1 || in.MaxReplicas < in.MinReplicas || in.MaxReplicas > 1000 {
		return Deployment{}, ErrInvalidRequest
	}
	return Deployment{TenantID: in.TenantID, DepartmentID: in.DepartmentID, ApplicationID: in.ApplicationID, ModelVersionID: in.ModelVersionID, Environment: in.Environment, EndpointRef: in.EndpointRef, RuntimeKind: in.RuntimeKind, ResourceProfile: resource, MinReplicas: in.MinReplicas, MaxReplicas: in.MaxReplicas, Capacity: capacity, HealthStatus: "unknown", Status: DeploymentPending, Revision: 1}, nil
}

func validateAccessPolicy(in CreateAccessPolicyRequest) (AccessPolicy, error) {
	row := AccessPolicy{TenantID: strings.TrimSpace(in.TenantID), DepartmentID: strings.TrimSpace(in.DepartmentID), ApplicationID: strings.TrimSpace(in.ApplicationID), InstallationID: strings.TrimSpace(in.InstallationID), AgentVersionID: strings.TrimSpace(in.AgentVersionID), PrincipalID: strings.TrimSpace(in.PrincipalID), AllowLocal: in.AllowLocal, AllowPrivate: in.AllowPrivate, AllowExternal: in.AllowExternal, EffectiveFrom: in.EffectiveFrom, EffectiveUntil: in.EffectiveUntil, Status: PolicyDraft, Revision: 1}
	if !validPolicyScope(row) || !validIDList(in.AllowedProviders) || !validIDList(in.AllowedModels) {
		return AccessPolicy{}, ErrInvalidRequest
	}
	if row.EffectiveFrom != nil && row.EffectiveUntil != nil && row.EffectiveUntil.Before(*row.EffectiveFrom) {
		return AccessPolicy{}, ErrInvalidRequest
	}
	row.AllowedProviders = normalizeIDs(in.AllowedProviders)
	row.AllowedModels = normalizeIDs(in.AllowedModels)
	return row, nil
}

func validIDList(values []string) bool {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if !validGovernanceID(trimmed, 128) {
			return false
		}
	}
	return true
}

func actorScope(actor Actor) Scope {
	return Scope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
}

func policyTargetVisible(policy CreateAccessPolicyRequest, actor Scope) bool {
	if policy.TenantID != "" && policy.TenantID != actor.TenantID {
		return false
	}
	if policy.DepartmentID != "" && policy.DepartmentID != actor.DepartmentID {
		return false
	}
	if policy.ApplicationID != "" && policy.ApplicationID != actor.ApplicationID {
		return false
	}
	return true
}

func policyMatchesApplication(policy AccessPolicy, actor Scope) bool {
	return policy.TenantID == actor.TenantID && (policy.DepartmentID == "" || policy.DepartmentID == actor.DepartmentID) && (policy.ApplicationID == "" || policy.ApplicationID == actor.ApplicationID)
}

func healthDeploymentStatus(health string) (string, bool) {
	return DeploymentStatusForHealth(health)
}

// DeploymentStatusForHealth is shared by the HTTP adapter and trusted controller.
func DeploymentStatusForHealth(health string) (string, bool) {
	switch health {
	case "unknown", "warming":
		return DeploymentPending, true
	case "ready", "degraded":
		return DeploymentReady, true
	case "unavailable":
		return DeploymentFailed, true
	case "draining":
		return DeploymentDraining, true
	default:
		return "", false
	}
}

// EvaluateModelAccess is the fail-closed runtime enforcement point. Consumers
// must pass scope taken from authenticated run context, never request payloads.
func (m *Module) EvaluateModelAccess(ctx context.Context, scope ModelAccessScope, modelVersionID string) error {
	if !validAccessScope(scope) || strings.TrimSpace(modelVersionID) == "" {
		return ErrInvalidRequest
	}
	model, err := m.store.GetResolvedVersion(ctx, modelVersionID)
	if err != nil {
		return err
	}
	if model.VersionStatus != StatusApproved || model.ProviderStatus != StatusApproved {
		return ErrModelAccessDenied
	}
	policies, err := m.store.ListApplicableAccessPolicies(ctx, scope)
	if err != nil {
		return err
	}
	return evaluateAccessPolicies(policies, scope, model.ProviderID, model.DefinitionID, model.TrustZone, time.Now().UTC())
}

func evaluateAccessPolicies(policies []AccessPolicy, scope ModelAccessScope, providerID, modelID, trustZone string, now time.Time) error {
	matched := 0
	for _, policy := range policies {
		if !accessPolicyApplies(policy, scope, now) {
			continue
		}
		matched++
		switch trustZone {
		case TrustLocal:
			if !policy.AllowLocal {
				return ErrModelAccessDenied
			}
		case TrustPrivate:
			if !policy.AllowPrivate {
				return ErrModelAccessDenied
			}
		case TrustExternal:
			if !policy.AllowExternal {
				return ErrModelAccessDenied
			}
		default:
			return ErrModelAccessDenied
		}
		if len(policy.AllowedProviders) > 0 && !contains(policy.AllowedProviders, providerID) {
			return ErrModelAccessDenied
		}
		if len(policy.AllowedModels) > 0 && !contains(policy.AllowedModels, modelID) {
			return ErrModelAccessDenied
		}
	}
	if matched == 0 {
		return ErrModelAccessDenied
	}
	return nil
}

func accessPolicyApplies(policy AccessPolicy, scope ModelAccessScope, now time.Time) bool {
	if policy.Status != PolicyApproved || policy.TenantID != scope.TenantID {
		return false
	}
	if policy.DepartmentID != "" && policy.DepartmentID != scope.DepartmentID || policy.ApplicationID != "" && policy.ApplicationID != scope.ApplicationID || policy.InstallationID != "" && policy.InstallationID != scope.InstallationID || policy.AgentVersionID != "" && policy.AgentVersionID != scope.AgentVersionID || policy.PrincipalID != "" && policy.PrincipalID != scope.PrincipalID {
		return false
	}
	if policy.EffectiveFrom != nil && now.Before(*policy.EffectiveFrom) || policy.EffectiveUntil != nil && now.After(*policy.EffectiveUntil) {
		return false
	}
	return true
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
