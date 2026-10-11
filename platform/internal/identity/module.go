package identity

// The identity module owns platform tenant, application and grant boundaries.
// identity 模块拥有平台租户、应用、主体和授权边界。

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type Module struct {
	cleanupMu            sync.Mutex
	cleanupCancel        context.CancelFunc
	cleanupDone          chan struct{}
	store                Store
	internalToken        string
	installationResolver AgentInstallationResolver
	enrollmentConfig     *EnrollmentConfig
}

func NewModule(store Store, internalToken string) *Module {
	return &Module{store: store, internalToken: strings.TrimSpace(internalToken), enrollmentConfig: &EnrollmentConfig{Environment: "production"}}
}

func (m *Module) Name() string { return "identity" }

// SetAgentInstallationResolver injects the Catalog-owned active installation
// lookup without coupling Identity to the Catalog implementation.
// SetAgentInstallationResolver 注入 Catalog 所拥有的活动安装解析端口，避免 Identity 依赖 Catalog 实现。
func (m *Module) SetAgentInstallationResolver(resolver AgentInstallationResolver) {
	m.installationResolver = resolver
	if store, ok := m.store.(*SQLStore); ok {
		store.SetPermissionResourceResolver(resolver)
	}
}

func (m *Module) Start(ctx context.Context) error {
	if m.store == nil {
		return errors.New("identity store is required")
	}
	// Schema is installed by the versioned migration command, never Start.
	// Schema由独立版本迁移命令安装，Start不得改库。
	if err := ctx.Err(); err != nil {
		return err
	}
	if janitor, ok := m.store.(RefreshSessionJanitor); ok {
		m.cleanupMu.Lock()
		defer m.cleanupMu.Unlock()
		if m.cleanupCancel != nil {
			return nil
		}
		workerCtx, cancel := context.WithCancel(ctx)
		m.cleanupCancel = cancel
		m.cleanupDone = make(chan struct{})
		done := m.cleanupDone
		go func() {
			defer close(done)
			ticker := time.NewTicker(10 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-workerCtx.Done():
					return
				case <-ticker.C:
					batchCtx, stop := context.WithTimeout(workerCtx, 10*time.Second)
					_, err := janitor.PurgeExpiredRefreshSessions(batchCtx, 100)
					stop()
					if err != nil && workerCtx.Err() == nil {
						log.Print("Identity expired session cleanup failed; retrying on next interval")
					}
				}
			}
		}()
	}
	return nil
}

func (m *Module) Ready() error {
	return m.ReadyContext(context.Background())
}

func (m *Module) ReadyContext(ctx context.Context) error {
	if m.store == nil {
		return errors.New("identity store is required")
	}
	return bootstrap.ProbeDependency(ctx, m.store.Ping)
}

func (m *Module) Close(ctx context.Context) error {
	m.cleanupMu.Lock()
	cancel, done := m.cleanupCancel, m.cleanupDone
	m.cleanupMu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Module) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/tenants", m.tenants)
	mux.HandleFunc("/tenants/", m.tenant)
	mux.HandleFunc("/departments", m.departments)
	mux.HandleFunc("/departments/", m.department)
	mux.HandleFunc("/applications", m.applications)
	mux.HandleFunc("/applications/", m.application)
	mux.HandleFunc("/principals", m.principals)
	mux.HandleFunc("/membership-candidates", m.membershipCandidates)
	mux.HandleFunc("/principals/", m.permissionProfile)
	mux.HandleFunc("/me/workspaces", m.permissionMe)
	mux.HandleFunc("/me/permissions", m.permissionMe)
	mux.HandleFunc("/permission-actions", m.permissionDirectories)
	mux.HandleFunc("/role-definitions", m.permissionDirectories)
	mux.HandleFunc("/identity-presets", m.permissionDirectories)
	mux.HandleFunc("/authorization-changes:preview", m.permissionChange)
	mux.HandleFunc("/authorization-changes", m.permissionChange)
	mux.HandleFunc("/memberships:preview", m.permissionChange)
	mux.HandleFunc("/memberships:change", m.permissionChange)
	mux.HandleFunc("/principals:preview", m.permissionPrincipalCreation)
	mux.HandleFunc("/principals:create", m.permissionPrincipalCreation)
	mux.HandleFunc("/enrollments:preview-approval", m.enrollmentPermissionApproval)
	mux.HandleFunc("/enrollments:approve", m.enrollmentPermissionApproval)
	mux.HandleFunc("/enrollments:preview-rejection", m.enrollmentPermissionRejection)
	mux.HandleFunc("/enrollments:reject", m.enrollmentPermissionRejection)
	mux.HandleFunc("/permission-requests", m.permissionRequests)
	mux.HandleFunc("/permission-requests/", m.permissionRequests)
	mux.HandleFunc("/permission-requests:withdraw", m.permissionRequests)
	mux.HandleFunc("/permission-requests:preview-decision", m.permissionRequests)
	mux.HandleFunc("/permission-requests:decide", m.permissionRequests)
	mux.HandleFunc("/permissions:explain", m.permissionExplain)
	mux.HandleFunc("/step-up", m.stepUp)
	mux.HandleFunc("/internal/oidc/step-up:challenge", m.oidcStepUp)
	mux.HandleFunc("/internal/oidc/step-up:complete", m.oidcStepUp)
	mux.HandleFunc("/administrators:preview", m.appointAdministrator)
	mux.HandleFunc("/administrators:appoint", m.appointAdministrator)
	mux.HandleFunc("/delegations:preview", m.delegationChange)
	mux.HandleFunc("/delegations", m.delegationChange)
	mux.HandleFunc("/department-agent-policy", m.departmentAgentAccess)
	mux.HandleFunc("/agent-use-package", m.agentUsePackage)
	mux.HandleFunc("/department-agent-changes:preview", m.departmentAgentAccess)
	mux.HandleFunc("/permission-batches:preview", m.permissionBatch)
	mux.HandleFunc("/permission-batches", m.permissionBatch)
	mux.HandleFunc("/permission-batches/", m.permissionBatch)
	mux.HandleFunc("/department-agent-changes", m.departmentAgentAccess)
	mux.HandleFunc("/department-agent-changes/", m.departmentAgentAccess)
	mux.HandleFunc("/principals:disable", m.disablePrincipal)
	mux.HandleFunc("/credentials:change-password", m.changeOwnPassword)
	mux.HandleFunc("/grants", m.grants)
	mux.HandleFunc("/grants:preview", m.permissionChange)
	mux.HandleFunc("/grants:explain", m.explainGrant)
	mux.HandleFunc("/grants/", m.grant)
	mux.HandleFunc("/access-requests", m.agentAccessRequests)
	mux.HandleFunc("/access-requests/", m.agentAccessRequest)
	mux.HandleFunc("/registration-agent-catalog", m.registrationAgentCatalog)
	mux.HandleFunc("/registrations", m.registrations)
	mux.HandleFunc("/registrations/", m.registrations)
	mux.HandleFunc("/enrollments", m.enrollments)
	mux.HandleFunc("/enrollments/", m.enrollments)
	mux.HandleFunc("/internal/credentials/verify", m.enrollmentInternal)
	mux.HandleFunc("/internal/sessions/validate", m.enrollmentInternal)
	mux.HandleFunc("/internal/browser-sessions/validate", m.browserSession)
	mux.HandleFunc("/internal/refresh-sessions", m.refreshSession)
	mux.HandleFunc("/internal/refresh-sessions:rotate", m.refreshSession)
	mux.HandleFunc("/internal/refresh-sessions:workspace", m.refreshSession)
	mux.HandleFunc("/internal/refresh-sessions:revoke", m.refreshSession)
	mux.HandleFunc("/internal/oidc/resolve", m.resolveOIDC)
	mux.HandleFunc("/oidc-bindings", m.oidcBindings)
	mux.HandleFunc("/oidc-bindings:disable", m.disableOIDCBinding)
	mux.HandleFunc("/workload-bindings", m.workloadBindingChange)
	mux.HandleFunc("/workload-principals", m.workloadPrincipal)
	mux.HandleFunc("/machine-credentials", m.machineCredentials)
	mux.HandleFunc("/machine-credentials/", m.machineCredential)
	mux.HandleFunc("/oauth/token", m.machineToken)
	mux.HandleFunc("/access/check", m.accessCheck)
	return mux
}

func (m *Module) tenants(w http.ResponseWriter, r *http.Request) {
	if !m.requireAuth(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		m.listTenants(w, r, "")
		return
	}
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, ok := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin")
	if !ok {
		return
	}
	var value Tenant
	if err := decode(r, &value); err != nil || value.Status == "" {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if !actor.canManage(value.ID, "", "") {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	if err := m.store.CreateTenant(r.Context(), value); err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusCreated, value)
}

func (m *Module) tenant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !m.requireAuth(w, r) {
		if r.Method != http.MethodGet {
			m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		}
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/tenants/"), "/")
	if id == "" || strings.Contains(id, "/") {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	m.listTenants(w, r, id)
}

func (m *Module) listTenants(w http.ResponseWriter, r *http.Request, id string) {
	scope, err := identityScopeFromRequest(r)
	if err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	requested := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if requested == "" {
		requested = id
	}
	if requested != "" && requested != scope.TenantID {
		m.error(w, http.StatusBadRequest, "SCOPE_MISMATCH")
		return
	}
	page, pageSize, ok := organizationPageFromRequest(m, w, r)
	if !ok {
		return
	}
	store, ok := m.organizationPageStore(w)
	if !ok {
		return
	}
	items, err := store.PageTenants(r.Context(), scope.TenantID, strings.TrimSpace(r.URL.Query().Get("status")), page, pageSize)
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusOK, items)
}

func (m *Module) departments(w http.ResponseWriter, r *http.Request) {
	if !m.requireAuth(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		m.listDepartments(w, r, "")
		return
	}
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, ok := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin")
	if !ok {
		return
	}
	var value Department
	if err := decode(r, &value); err != nil || value.Status == "" {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if actor.Browser && value.TenantID != actor.Scope.TenantID || !actor.canManage(value.TenantID, "", "") {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	var err error
	if actor.Browser {
		if store, ok := m.store.(DepartmentAdministrationCreationRepository); ok {
			err = store.CreateDepartmentWithAdministrationContext(r.Context(), value)
		} else {
			err = m.store.CreateDepartment(r.Context(), value)
		}
	} else {
		err = m.store.CreateDepartment(r.Context(), value)
	}
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusCreated, value)
}

func (m *Module) department(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !m.requireAuth(w, r) {
		if r.Method != http.MethodGet {
			m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		}
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/departments/"), "/")
	if id == "" || strings.Contains(id, "/") {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	m.listDepartments(w, r, id)
}

func (m *Module) listDepartments(w http.ResponseWriter, r *http.Request, id string) {
	scope, err := identityScopeFromRequest(r)
	if err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if value := strings.TrimSpace(r.URL.Query().Get("tenant_id")); value != "" && value != scope.TenantID {
		m.error(w, http.StatusBadRequest, "SCOPE_MISMATCH")
		return
	}
	departmentID := strings.TrimSpace(r.URL.Query().Get("department_id"))
	if departmentID == "" {
		departmentID = id
	}
	actor, ok := m.loadBrowserActor(w, r)
	if !ok {
		return
	}
	if actor.Browser && actor.Policy != nil {
		if departmentID != "" && departmentID != actor.Scope.DepartmentID && !actor.canManage(scope.TenantID, departmentID, "") {
			m.error(w, http.StatusForbidden, "FORBIDDEN")
			return
		}
		if departmentID == "" && !actor.canManage(scope.TenantID, "", "") {
			departmentID = actor.Scope.DepartmentID
		}
	} else if actor.Browser && !containsIdentityRole(actor.Principal.Roles, "system_admin", "admin", "platform_admin") {
		if departmentID != "" && departmentID != actor.Scope.DepartmentID {
			m.error(w, http.StatusForbidden, "FORBIDDEN")
			return
		}
		departmentID = actor.Scope.DepartmentID
	}
	page, pageSize, ok := organizationPageFromRequest(m, w, r)
	if !ok {
		return
	}
	paged, ok := m.organizationPageStore(w)
	if !ok {
		return
	}
	items, err := paged.PageDepartments(r.Context(), scope.TenantID, departmentID, strings.TrimSpace(r.URL.Query().Get("status")), page, pageSize)
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusOK, items)
}

func (m *Module) applications(w http.ResponseWriter, r *http.Request) {
	if !m.requireAuth(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		m.listApplications(w, r, "")
		return
	}
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, ok := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin", "department_admin")
	if !ok {
		return
	}
	var value Application
	if err := decode(r, &value); err != nil || value.Status == "" {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if !actor.canManage(value.TenantID, value.DepartmentID, "") {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	if err := m.store.CreateApplication(r.Context(), value); err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusCreated, value)
}

func (m *Module) application(w http.ResponseWriter, r *http.Request) {
	if !m.requireAuth(w, r) {
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/applications/"), "/"), "/")
	if len(parts) == 2 && parts[0] != "" && parts[1] == "disable" {
		if r.Method != http.MethodPost {
			m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		m.disableApplication(w, r, parts[0])
		return
	}
	if r.Method != http.MethodGet {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	if len(parts) != 1 || parts[0] == "" {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	m.listApplications(w, r, parts[0])
}

func (m *Module) listApplications(w http.ResponseWriter, r *http.Request, id string) {
	scope, err := identityScopeFromRequest(r)
	if err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if value := strings.TrimSpace(r.URL.Query().Get("tenant_id")); value != "" && value != scope.TenantID {
		m.error(w, http.StatusBadRequest, "SCOPE_MISMATCH")
		return
	}
	departmentID := strings.TrimSpace(r.URL.Query().Get("department_id"))
	applicationID := strings.TrimSpace(r.URL.Query().Get("application_id"))
	if applicationID == "" {
		applicationID = id
	}
	actor, ok := m.loadBrowserActor(w, r)
	if !ok {
		return
	}
	if actor.Browser && actor.Policy != nil {
		tenantManaged := actor.canManage(scope.TenantID, "", "")
		if !tenantManaged && (departmentID != "" && departmentID != actor.Scope.DepartmentID && !actor.canManage(scope.TenantID, departmentID, applicationID) || applicationID != "" && applicationID != actor.Scope.ApplicationID && !actor.canManage(scope.TenantID, departmentID, applicationID)) {
			m.error(w, http.StatusForbidden, "FORBIDDEN")
			return
		}
		if !tenantManaged {
			departmentID = actor.Scope.DepartmentID
			if !actor.canManage(scope.TenantID, departmentID, "") {
				applicationID = actor.Scope.ApplicationID
			}
		}
	} else if actor.Browser && containsIdentityRole(actor.Principal.Roles, "department_admin") && !containsIdentityRole(actor.Principal.Roles, "platform_admin", "system_admin", "admin") {
		if departmentID != "" && departmentID != actor.Scope.DepartmentID {
			m.error(w, http.StatusForbidden, "FORBIDDEN")
			return
		}
		departmentID = actor.Scope.DepartmentID
	} else if actor.Browser && !containsIdentityRole(actor.Principal.Roles, "system_admin", "admin", "platform_admin") {
		if departmentID != "" && departmentID != actor.Scope.DepartmentID || applicationID != "" && applicationID != actor.Scope.ApplicationID {
			m.error(w, http.StatusForbidden, "FORBIDDEN")
			return
		}
		departmentID = actor.Scope.DepartmentID
		applicationID = actor.Scope.ApplicationID
	}
	page, pageSize, ok := organizationPageFromRequest(m, w, r)
	if !ok {
		return
	}
	store, ok := m.organizationPageStore(w)
	if !ok {
		return
	}
	items, err := store.PageApplications(r.Context(), scope.TenantID, departmentID, applicationID, strings.TrimSpace(r.URL.Query().Get("status")), page, pageSize)
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusOK, items)
}

type disableApplicationRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
}

func (m *Module) disableApplication(w http.ResponseWriter, r *http.Request, id string) {
	actor, ok := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin", "department_admin")
	if !ok {
		return
	}
	scope, err := identityScopeFromRequest(r)
	if err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	departmentID := strings.TrimSpace(r.URL.Query().Get("department_id"))
	if departmentID == "" {
		departmentID = actor.Scope.DepartmentID
	}
	if !actor.canManage(scope.TenantID, departmentID, id) {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	var command disableApplicationRequest
	if err := decode(r, &command); err != nil || command.ExpectedRevision == 0 {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	lifecycle, ok := m.store.(ApplicationLifecycleStore)
	if !ok {
		m.error(w, http.StatusNotImplemented, "APPLICATION_LIFECYCLE_NOT_AVAILABLE")
		return
	}
	if err := lifecycle.DisableApplication(r.Context(), scope.TenantID, departmentID, id, command.ExpectedRevision); err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusOK, map[string]any{"id": id, "tenant_id": scope.TenantID, "department_id": departmentID, "status": "disabled", "revision": command.ExpectedRevision + 1})
}

type principalRequest struct {
	Principal
}

func (m *Module) principals(w http.ResponseWriter, r *http.Request) {
	if !m.requireAuth(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		m.listPrincipals(w, r)
		return
	}
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, ok := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin", "department_admin", "application_admin")
	if !ok {
		return
	}
	var value principalRequest
	if err := decode(r, &value); err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if actor.Policy != nil {
		// The legacy writer cannot atomically establish versioned membership,
		// bindings, audit and epoch; never use it to create a legacy admin.
		m.error(w, http.StatusForbidden, "USE_VERSIONED_PRINCIPAL_CREATION")
		return
	}
	if !actor.canManage(value.TenantID, "", "") {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	if value.Type == PrincipalServicePrincipal && len(value.Roles) != 0 {
		// Machine identities receive permissions only through exact-scope grants;
		// they never inherit human administrative roles.
		// 机器主体只能通过精确作用域 Grant 获权，不能继承人员管理角色。
		m.error(w, http.StatusBadRequest, "SERVICE_PRINCIPAL_ROLES_NOT_ALLOWED")
		return
	}
	if actor.Browser && !containsIdentityRole(actor.Principal.Roles, "system_admin", "admin", "platform_admin") && value.Type != PrincipalServicePrincipal {
		// Scoped administrators may register machine identities, but only
		// platform administrators may provision human users.
		// 部门/应用管理员只能登记机器主体；人员身份由平台管理员创建。
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	if actor.Browser && containsIdentityRole(value.Roles, "system_admin", "admin") &&
		!containsIdentityRole(actor.Principal.Roles, "system_admin", "admin") {
		// A tenant platform administrator may provision tenant principals but
		// cannot elevate one to a global system role.
		// 租户平台管理员可以创建租户主体，但不能授予全局系统角色。
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	value.Revision = 1
	if err := m.store.CreatePrincipal(r.Context(), value.Principal); err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusCreated, value.Principal)
}

type disablePrincipalRequest struct {
	PrincipalID      string `json:"principal_id"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

// principalLifecycle handles platform-admin scoped lifecycle commands. Target
// tenant and actor identity come from the authenticated Gateway context, never
// from the request body.
// principalLifecycle 处理平台管理员的主体生命周期命令；目标租户和操作者均来自可信会话。
func (m *Module) disablePrincipal(w http.ResponseWriter, r *http.Request) {
	if !m.requireAuth(w, r) {
		return
	}
	if r.URL.Path != "/principals:disable" || r.Method != http.MethodPost {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	if requestedType := strings.TrimSpace(r.URL.Query().Get("principal_type")); requestedType != "" && requestedType != string(PrincipalUser) {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	actor, ok := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin")
	if !ok {
		return
	}
	scope, err := identityScopeFromRequest(r)
	if err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if !actor.canManage(scope.TenantID, "", "") {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	lifecycle, ok := m.store.(PrincipalLifecycleStore)
	if !ok {
		m.error(w, http.StatusNotImplemented, "PRINCIPAL_LIFECYCLE_NOT_AVAILABLE")
		return
	}
	var command disablePrincipalRequest
	if err := decode(r, &command); err != nil || command.ExpectedRevision == 0 {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	command.PrincipalID = strings.TrimSpace(command.PrincipalID)
	if command.PrincipalID == "" {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if actor.Browser && scope.PrincipalID == command.PrincipalID {
		m.error(w, http.StatusForbidden, "SELF_DISABLE_FORBIDDEN")
		return
	}
	principal, err := lifecycle.DisablePrincipal(r.Context(), scope, command.PrincipalID, command.ExpectedRevision)
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusOK, principal)
}

func (m *Module) listPrincipals(w http.ResponseWriter, r *http.Request) {
	scope, err := identityScopeFromRequest(r)
	if err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if value := strings.TrimSpace(r.URL.Query().Get("tenant_id")); value != "" && value != scope.TenantID {
		m.error(w, http.StatusBadRequest, "SCOPE_MISMATCH")
		return
	}
	actor, ok := m.loadBrowserActor(w, r)
	if !ok {
		return
	}
	if actor.Policy != nil {
		m.permissionPrincipalDirectory(w, r, actor)
		return
	}
	typ := PrincipalType(strings.TrimSpace(r.URL.Query().Get("principal_type")))
	if typ != "" && typ != PrincipalUser && typ != PrincipalServicePrincipal {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if actor.Browser && !containsIdentityRole(actor.Principal.Roles, "system_admin", "admin", "platform_admin") {
		if !containsIdentityRole(actor.Principal.Roles, "department_admin", "application_admin") || typ != PrincipalServicePrincipal {
			m.error(w, http.StatusForbidden, "FORBIDDEN")
			return
		}
	}
	store, ok := m.readStore(w)
	if !ok {
		return
	}
	principalID := strings.TrimSpace(r.URL.Query().Get("principal_id"))
	if actor.Browser && !containsIdentityRole(actor.Principal.Roles, "system_admin", "admin", "platform_admin") {
		if !containsIdentityRole(actor.Principal.Roles, "department_admin", "application_admin") || typ != PrincipalServicePrincipal {
			m.error(w, http.StatusForbidden, "FORBIDDEN")
			return
		}
		// Tenant-scoped machine identities are non-secret metadata. Scoped
		// administrators may inspect/select these identities, while every grant remains app-bound.
		// 租户机器主体仅是非敏感元数据；实际授权仍由完整应用作用域约束。
	}
	items, err := store.ListPrincipals(r.Context(), scope.TenantID, typ, principalID)
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusOK, items)
}

func (m *Module) grants(w http.ResponseWriter, r *http.Request) {
	if !m.requireAuth(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		m.listIdentityGrants(w, r)
		return
	}
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	current, ok := m.loadBrowserActor(w, r)
	if !ok {
		return
	}
	if current.Policy != nil {
		m.permissionChange(w, r)
		return
	}
	actor, ok := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin", "department_admin", "application_admin")
	if !ok {
		return
	}
	var value Grant
	if err := decode(r, &value); err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if !actor.canManage(value.TenantID, value.DepartmentID, value.ApplicationID) {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	if err := m.store.CreateGrant(r.Context(), value); err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusCreated, value)
}

// explainGrant evaluates the same authoritative grant rules used by runtime
// authorization, but only for an administrator acting inside an authorized
// application scope. It is a diagnostic projection, never an authorization
// bypass or a browser-callable principal oracle.
// explainGrant 使用与运行时相同的授权规则；浏览器仅允许管理员在获准应用范围内查询。
func (m *Module) explainGrant(w http.ResponseWriter, r *http.Request) {
	if !m.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, ok := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin", "department_admin", "application_admin")
	if !ok {
		return
	}
	var request accessRequest
	if err := decode(r, &request); err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	scope := request.Scope.domain()
	if !actor.canManage(scope.TenantID, scope.DepartmentID, scope.ApplicationID) {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	principal, err := m.store.GetPrincipal(r.Context(), request.PrincipalType, request.PrincipalID)
	if err != nil {
		m.storeError(w, err)
		return
	}
	decision, err := checkPrincipalAccess(r.Context(), m.store, scope, principal, request.Action)
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusOK, decision)
}

type revokeGrantRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
}

func (m *Module) grant(w http.ResponseWriter, r *http.Request) {
	if !m.requireAuth(w, r) {
		return
	}
	parts := strings.FieldsFunc(strings.TrimPrefix(r.URL.Path, "/grants/"), func(r rune) bool { return r == '/' })
	if len(parts) != 2 || parts[1] != "revoke" || r.Method != http.MethodPost {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	current, ok := m.loadBrowserActor(w, r)
	if !ok {
		return
	}
	if current.Policy != nil {
		m.permissionChange(w, r)
		return
	}
	actor, ok := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin", "department_admin", "application_admin")
	if !ok {
		return
	}
	lifecycle, ok := m.store.(GrantLifecycleStore)
	if !ok {
		m.error(w, http.StatusNotImplemented, "LIFECYCLE_NOT_AVAILABLE")
		return
	}
	baseScope, err := identityScopeFromRequest(r)
	if err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	scope, err := grantTargetScope(r, baseScope)
	if err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if !actor.canManage(scope.TenantID, scope.DepartmentID, scope.ApplicationID) {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	var request revokeGrantRequest
	if err := decode(r, &request); err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := lifecycle.RevokeGrant(r.Context(), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentInstanceID, parts[0], request.ExpectedRevision); err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusOK, map[string]any{"id": parts[0], "status": GrantRevoked, "revision": request.ExpectedRevision + 1})
}

func (m *Module) listIdentityGrants(w http.ResponseWriter, r *http.Request) {
	baseScope, err := identityScopeFromRequest(r)
	if err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	actor, ok := m.loadBrowserActor(w, r)
	if !ok {
		return
	}
	if actor.Browser && actor.Policy == nil && !containsIdentityRole(actor.Principal.Roles, "system_admin", "admin", "platform_admin", "department_admin", "application_admin") {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	scope, err := grantTargetScope(r, baseScope)
	if err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if actor.Policy != nil {
		repository, ok := m.store.(PermissionRepository)
		if !ok {
			m.permissionError(w, ErrPermissionDenied)
			return
		}
		decision, err := repository.ResolvePermission(r.Context(), PrincipalUser, actor.Principal.ID, PermissionQuery{Action: "authorization.read",
			Scope: ManagementScope{Type: "application", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}})
		if err != nil {
			m.permissionError(w, err)
			return
		}
		if !decision.Allowed {
			m.permissionError(w, ErrPermissionDenied)
			return
		}
	} else if !actor.canManage(scope.TenantID, scope.DepartmentID, scope.ApplicationID) {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	typ := PrincipalType(strings.TrimSpace(r.URL.Query().Get("subject_type")))
	if typ != "" && typ != PrincipalUser && typ != PrincipalServicePrincipal {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	store, ok := m.readStore(w)
	if !ok {
		return
	}
	items, err := store.ListIdentityGrants(r.Context(), scope.TenantID, scope.DepartmentID, scope.ApplicationID,
		strings.TrimSpace(r.URL.Query().Get("agent_instance_id")), typ,
		strings.TrimSpace(r.URL.Query().Get("subject_id")), strings.TrimSpace(r.URL.Query().Get("action")),
		strings.TrimSpace(r.URL.Query().Get("status")))
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusOK, items)
}

// grantTargetScope resolves an exact grant scope. Tenant-wide administrators
// may query/revoke grants in another application in their authorized tenant;
// other browser users stay bound to the authenticated application.
// grantTargetScope 解析授权的完整资源作用域；应用管理员仍限制在当前应用。
func grantTargetScope(r *http.Request, base sharedkernel.Scope) (sharedkernel.Scope, error) {
	target := base
	requested := map[string]*string{
		"tenant_id": &target.TenantID, "department_id": &target.DepartmentID,
		"application_id": &target.ApplicationID, "agent_instance_id": &target.AgentInstanceID,
	}
	provided := false
	for key, destination := range requested {
		if value := strings.TrimSpace(r.URL.Query().Get(key)); value != "" {
			*destination = value
			provided = true
		}
	}
	if provided && (target.TenantID == "" || target.DepartmentID == "" || target.ApplicationID == "" || target.AgentInstanceID == "") {
		return sharedkernel.Scope{}, sharedkernel.ErrInvalidScope
	}
	if err := target.Validate(); err != nil {
		return sharedkernel.Scope{}, err
	}
	return target, nil
}

type accessRequest struct {
	Scope         scopeRequest  `json:"scope"`
	PrincipalType PrincipalType `json:"principal_type"`
	PrincipalID   string        `json:"principal_id"`
	Action        string        `json:"action"`
}

type scopeRequest struct {
	TenantID        string `json:"tenant_id"`
	DepartmentID    string `json:"department_id"`
	ApplicationID   string `json:"application_id"`
	AgentInstanceID string `json:"agent_instance_id"`
}

func (s scopeRequest) domain() sharedkernel.Scope {
	return sharedkernel.Scope{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, AgentInstanceID: s.AgentInstanceID}
}

func (m *Module) accessCheck(w http.ResponseWriter, r *http.Request) {
	if !m.requireAuth(w, r) {
		return
	}
	if r.Header.Get(browserModuleHeader) == "1" {
		// Access-check is a machine-side authorization primitive, not a browser
		// oracle for probing principals or installation grants.
		// Access-check 是机器侧授权原语，不能作为浏览器探测主体/安装授权的接口。
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	var request accessRequest
	if err := decode(r, &request); err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	principal, err := m.store.GetPrincipal(r.Context(), request.PrincipalType, request.PrincipalID)
	if err != nil {
		m.storeError(w, err)
		return
	}
	// A principal from another tenant is a deterministic deny, not an
	// infrastructure error. This keeps cross-tenant probes non-disclosing while
	// preserving a stable decision contract for callers.
	// 跨租户主体必须返回确定性拒绝，而不是基础设施错误，避免探测泄露并保持稳定契约。
	if principal.TenantID != request.Scope.TenantID {
		m.json(w, http.StatusOK, AccessDecision{Allowed: false, Reason: "tenant_mismatch"})
		return
	}
	scope := request.Scope.domain()
	// Scope validation includes the caller identity so that the same access
	// check cannot be replayed with a different principal after storage lookup.
	// 作用域校验包含调用主体，避免存储查询后被替换成其他主体重放。
	scope.PrincipalID = request.PrincipalID
	scope.PrincipalType = string(request.PrincipalType)
	decision, err := checkPrincipalAccess(r.Context(), m.store, scope, principal, request.Action)
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusOK, decision)
}

// CheckPrincipalAccess resolves the authoritative principal and grants for an
// exact installation scope. It is the Identity port for other local modules;
// a future service split can replace it with an HTTP/gRPC adapter.
// CheckPrincipalAccess 按完整安装作用域解析权威主体与授权；未来拆服务时可替换成 HTTP/gRPC Adapter。
func CheckPrincipalAccess(ctx context.Context, store Store, scope sharedkernel.Scope, principalType PrincipalType, principalID, action string) (AccessDecision, error) {
	if store == nil {
		return AccessDecision{}, errors.New("identity store is required")
	}
	principal, err := store.GetPrincipal(ctx, principalType, principalID)
	if err != nil {
		return AccessDecision{}, err
	}
	return checkPrincipalAccess(ctx, store, scope, principal, action)
}

func checkPrincipalAccess(ctx context.Context, store Store, scope sharedkernel.Scope, principal Principal, action string) (AccessDecision, error) {
	if principal.TenantID != scope.TenantID {
		return AccessDecision{Allowed: false, Reason: "tenant_mismatch"}, nil
	}
	if policy, ok := store.(PermissionRepository); ok {
		snapshot, err := policy.PermissionSnapshot(ctx, principal.Type, principal.ID)
		if err != nil {
			return AccessDecision{}, err
		}
		if snapshot.Mode == "v2" {
			decision, err := policy.ResolvePermission(ctx, principal.Type, principal.ID, PermissionQuery{
				Action: action, Scope: ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: scope.AgentInstanceID},
				ResourceType: "agent_installation", ResourceID: scope.AgentInstanceID,
			})
			return AccessDecision{Allowed: decision.Allowed, Reason: decision.Reason}, err
		}
		if snapshot.Mode != "legacy" && snapshot.Mode != "shadow" {
			return AccessDecision{}, ErrInvalidResource
		}
		if departmentAgentPolicyFor(snapshot, ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: scope.AgentInstanceID}) != nil {
			if action == "cancel" {
				now := time.Now().UTC()
				if sqlStore, ok := store.(*SQLStore); ok {
					now = sqlStore.clock().UTC()
				}
				return evaluateManagedLegacyCancellation(snapshot, scope, now)
			}
			return AccessDecision{Reason: "DEPARTMENT_PERMISSION_MIGRATION_REQUIRED"}, nil
		}
	}
	rules, err := store.ListGrants(ctx, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentInstanceID, principal.Type, principal.ID, action)
	if err != nil {
		return AccessDecision{}, err
	}
	scope.PrincipalID = principal.ID
	scope.PrincipalType = string(principal.Type)
	return EvaluateAccess(AccessContext{Scope: scope, Principal: principal, Action: action}, rules)
}

// evaluateAccess keeps the storage-backed identity module independent from
// the authorization package. The package-level evaluator remains available
// to other adapters; this local projection avoids an import cycle between the
// identity owner and its policy consumer.
// evaluateAccess 让身份模块不反向依赖 authorization 包，避免身份所有者与策略消费者形成循环依赖。
// EvaluateAccess applies active-grant deny-overrides semantics to a validated
// caller and resource scope. Modules may depend on this policy function through
// a narrow port without reimplementing Identity authorization rules.
// EvaluateAccess 对已校验的调用主体和资源作用域执行活动授权规则的拒绝优先判断。
func EvaluateAccess(ctx AccessContext, rules []Grant) (AccessDecision, error) {
	if err := ctx.Validate(); err != nil {
		return AccessDecision{}, err
	}
	matched := false
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return AccessDecision{}, err
		}
		if rule.Status != GrantActive || rule.TenantID != ctx.Scope.TenantID || rule.DepartmentID != ctx.Scope.DepartmentID || rule.ApplicationID != ctx.Scope.ApplicationID || rule.AgentInstanceID != ctx.Scope.AgentInstanceID || rule.SubjectType != ctx.Principal.Type || rule.SubjectID != ctx.Principal.ID || rule.Action != ctx.Action {
			continue
		}
		matched = true
		if rule.Effect == "deny" {
			return AccessDecision{Allowed: false, Reason: "explicit_deny"}, nil
		}
	}
	if matched {
		return AccessDecision{Allowed: true, Reason: "explicit_allow"}, nil
	}
	return AccessDecision{Allowed: false, Reason: "no_matching_grant"}, nil
}

func (m *Module) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if m.authorized(r) {
		return true
	}
	m.error(w, http.StatusUnauthorized, "UNAUTHENTICATED")
	return false
}

func (m *Module) authorized(r *http.Request) bool {
	if m.internalToken == "" {
		return true
	}
	value := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if value == "" {
		value = strings.TrimSpace(r.Header.Get("X-Internal-Token"))
	}
	return len(value) == len(m.internalToken) && subtle.ConstantTimeCompare([]byte(value), []byte(m.internalToken)) == 1
}

func decode(r *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("multiple json values")
	}
	return nil
}

func (m *Module) storeError(w http.ResponseWriter, err error) {
	status, code := http.StatusInternalServerError, "INTERNAL_ERROR"
	switch {
	case errors.Is(err, ErrTenantNotFound), errors.Is(err, ErrDepartmentNotFound), errors.Is(err, ErrApplicationNotFound), errors.Is(err, ErrPrincipalNotFound), errors.Is(err, ErrGrantNotFound), errors.Is(err, ErrAccessRequestNotFound), errors.Is(err, ErrAgentInstallationNotFound), errors.Is(err, ErrOIDCBindingNotFound):
		status, code = http.StatusNotFound, "RESOURCE_NOT_FOUND"
	case errors.Is(err, ErrInvalidPrincipal), errors.Is(err, ErrInvalidResource), errors.Is(err, ErrInvalidAccessRequest), errors.Is(err, sharedkernel.ErrInvalidScope):
		status, code = http.StatusBadRequest, "SCHEMA_VALIDATION_FAILED"
	case errors.Is(err, ErrInvalidOrganizationPage):
		status, code = http.StatusBadRequest, "INVALID_PAGINATION"
	case errors.Is(err, ErrAccessRequestSelfReview):
		status, code = http.StatusForbidden, "SELF_REVIEW_FORBIDDEN"
	case errors.Is(err, ErrPrincipalLifecycleSelfDisable):
		status, code = http.StatusForbidden, "SELF_DISABLE_FORBIDDEN"
	case errors.Is(err, ErrLastAdministrator):
		status, code = http.StatusConflict, "LAST_ADMINISTRATOR_PROTECTED"
	case errors.Is(err, ErrScopeMismatch):
		status, code = http.StatusForbidden, "SCOPE_MISMATCH"
	case errors.Is(err, ErrPrincipalLifecycleRecorderUnavailable):
		status, code = http.StatusServiceUnavailable, "PRINCIPAL_LIFECYCLE_UNAVAILABLE"
	case errors.Is(err, ErrOIDCBindingRecorderUnavailable):
		status, code = http.StatusServiceUnavailable, "OIDC_BINDING_RECORDER_UNAVAILABLE"
	case errors.Is(err, ErrIdentityConflict):
		status, code = http.StatusConflict, "REVISION_CONFLICT"
	}
	m.error(w, status, code)
}

func (m *Module) readStore(w http.ResponseWriter) (ReadStore, bool) {
	store, ok := m.store.(ReadStore)
	if !ok {
		m.error(w, http.StatusNotImplemented, "READ_PROJECTION_NOT_AVAILABLE")
		return nil, false
	}
	return store, true
}

func (m *Module) organizationPageStore(w http.ResponseWriter) (OrganizationPageStore, bool) {
	store, ok := m.store.(OrganizationPageStore)
	if !ok {
		m.error(w, http.StatusNotImplemented, "ORGANIZATION_PAGE_NOT_AVAILABLE")
		return nil, false
	}
	return store, true
}

func organizationPageFromRequest(m *Module, w http.ResponseWriter, r *http.Request) (int, int, bool) {
	page, pageSize := 1, 20
	if raw := strings.TrimSpace(r.URL.Query().Get("page")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			return 0, 0, identityPageError(m, w)
		}
		page = parsed
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("page_size")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return 0, 0, identityPageError(m, w)
		}
		pageSize = parsed
	}
	return page, pageSize, true
}

func identityPageError(m *Module, w http.ResponseWriter) bool {
	m.error(w, http.StatusBadRequest, "INVALID_PAGINATION")
	return false
}

// identityScopeFromRequest accepts only the gateway-derived identity headers.
// The browser never supplies these values directly; the frontend gateway
// derives them from its HttpOnly session before forwarding to this module.
func identityScopeFromRequest(r *http.Request) (sharedkernel.Scope, error) {
	scope := sharedkernel.Scope{
		TenantID: r.Header.Get("X-Tenant-ID"), DepartmentID: r.Header.Get("X-Department-ID"), ApplicationID: r.Header.Get("X-Application-ID"), AgentInstanceID: r.Header.Get("X-Agent-Instance-ID"),
		PrincipalType: r.Header.Get("X-Principal-Type"), PrincipalID: r.Header.Get("X-Principal-ID"), TraceID: r.Header.Get("X-Trace-ID"),
	}
	if scope.PrincipalType == "" {
		scope.PrincipalType = string(PrincipalUser)
	}
	if err := scope.Validate(); err != nil {
		return sharedkernel.Scope{}, err
	}
	if scope.PrincipalType != string(PrincipalUser) && scope.PrincipalType != string(PrincipalServicePrincipal) {
		return sharedkernel.Scope{}, sharedkernel.ErrInvalidScope
	}
	return scope, nil
}

func (m *Module) error(w http.ResponseWriter, status int, code string) {
	m.json(w, status, map[string]any{"error": map[string]string{"code": code}})
}

func (m *Module) json(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

var _ bootstrap.Module = (*Module)(nil)
var _ bootstrap.ReadyModule = (*Module)(nil)
