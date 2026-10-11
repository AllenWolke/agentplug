package identity

import (
	"net/http"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

const browserModuleHeader = "X-Browser-Module"

type browserActor struct {
	Scope            sharedkernel.Scope
	Principal        Principal
	Browser          bool
	Policy           *PermissionSnapshot
	ManagementAction string
}

// requireBrowserRoles derives the browser actor from the platform Identity
// store. The browser gateway's internal token is not itself an authorization
// decision; roles must come from the active Principal record.
// requireBrowserRoles 从平台 Identity 存储解析浏览器主体；网关内部令牌本身不是
// 授权结论，角色必须来自有效的 Principal 记录。
func (m *Module) requireBrowserRoles(w http.ResponseWriter, r *http.Request, roles ...string) (browserActor, bool) {
	if !m.requireAuth(w, r) {
		return browserActor{}, false
	}
	actor, ok := m.loadBrowserActor(w, r)
	if !ok {
		return browserActor{}, false
	}
	if !actor.Browser {
		return actor, true
	}
	if actor.Policy != nil {
		if strings.HasPrefix(r.URL.Path, "/grants") && r.Method != http.MethodGet {
			m.error(w, http.StatusForbidden, "USE_AUTHORIZATION_CHANGE")
			return browserActor{}, false
		}
		actor.ManagementAction = identityManagementAction(r)
		if actor.ManagementAction == "" || !actor.canManage(actor.Scope.TenantID, actor.Scope.DepartmentID, actor.Scope.ApplicationID) {
			m.error(w, http.StatusForbidden, "FORBIDDEN")
			return browserActor{}, false
		}
		return actor, true
	}
	if !containsIdentityRole(actor.Principal.Roles, roles...) {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return browserActor{}, false
	}
	return actor, true
}

func (m *Module) loadBrowserActor(w http.ResponseWriter, r *http.Request) (browserActor, bool) {
	if r.Header.Get(browserModuleHeader) != "1" {
		// Non-browser callers authenticated with the private service token are
		// trusted service-to-service callers and keep the existing API contract.
		// 私有服务令牌认证的非浏览器调用仍按服务间 API 契约处理。
		return browserActor{}, true
	}
	scope, err := identityScopeFromRequest(r)
	if err != nil || scope.PrincipalType != string(PrincipalUser) {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return browserActor{}, false
	}
	principal, err := m.store.GetPrincipal(r.Context(), PrincipalUser, scope.PrincipalID)
	if err != nil || !principal.IsActive || principal.TenantID != scope.TenantID {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return browserActor{}, false
	}
	actor := browserActor{Scope: scope, Principal: principal, Browser: true}
	if repository, ok := m.store.(PermissionRepository); ok {
		snapshot, err := repository.PermissionSnapshot(r.Context(), PrincipalUser, principal.ID)
		if err != nil {
			m.permissionError(w, err)
			return browserActor{}, false
		}
		if snapshot.Mode == "v2" {
			actor.Policy = &snapshot
			actor.ManagementAction = identityManagementAction(r)
			actor.Principal.Roles = nil
			actor.Principal.Groups = nil
		} else if snapshot.Mode != "legacy" && snapshot.Mode != "shadow" {
			m.permissionError(w, ErrInvalidResource)
			return browserActor{}, false
		}
	}
	return actor, true
}

// CanManage limits browser-side administration to the actor's trusted scope.
// System admins are global; platform admins are tenant-wide; department admins
// can manage applications and grants only inside their department; application
// admins remain within their current application.
// CanManage 将浏览器管理操作限制在可信主体作用域内：系统管理员全局、平台管理员租户级、
// 部门管理员限本部门、应用管理员限当前应用。
func (a browserActor) canManage(tenantID, departmentID, applicationID string) bool {
	if !a.Browser {
		return true
	}
	if a.Policy != nil {
		scope := ManagementScope{Type: "global"}
		if tenantID != "" {
			scope = ManagementScope{Type: "tenant", TenantID: tenantID}
		}
		if departmentID != "" {
			scope.Type = "department"
			scope.DepartmentID = departmentID
		}
		if applicationID != "" {
			scope.Type = "application"
			scope.ApplicationID = applicationID
		}
		decision, err := EvaluatePermission(*a.Policy, PermissionQuery{Action: a.ManagementAction, Scope: scope, Now: time.Now().UTC()})
		return err == nil && decision.Allowed
	}
	roles := a.Principal.Roles
	if containsIdentityRole(roles, "system_admin", "admin") {
		return true
	}
	if tenantID != a.Scope.TenantID {
		return false
	}
	if containsIdentityRole(roles, "platform_admin") {
		return true
	}
	if departmentID != "" && departmentID != a.Scope.DepartmentID {
		return false
	}
	if applicationID != "" && applicationID != a.Scope.ApplicationID && !containsIdentityRole(roles, "department_admin") {
		return false
	}
	return true
}

func identityManagementAction(r *http.Request) string {
	switch {
	case strings.HasPrefix(r.URL.Path, "/tenants"), strings.HasPrefix(r.URL.Path, "/departments"), strings.HasPrefix(r.URL.Path, "/applications"):
		return "organization.manage"
	case r.URL.Path == "/principals:disable":
		return "principal.disable"
	case strings.HasPrefix(r.URL.Path, "/principals"):
		if r.Method == http.MethodGet {
			return "principal.read"
		}
		return "membership.manage"
	case strings.HasPrefix(r.URL.Path, "/grants"):
		return "authorization.read"
	case strings.HasPrefix(r.URL.Path, "/enrollments"), strings.HasPrefix(r.URL.Path, "/access-requests"):
		return "access_request.decide"
	case strings.HasPrefix(r.URL.Path, "/oidc-bindings"):
		return "administrator.appoint"
	case strings.HasPrefix(r.URL.Path, "/machine-credentials"), strings.HasPrefix(r.URL.Path, "/workload-bindings"), strings.HasPrefix(r.URL.Path, "/workload-principals"):
		return "machine.manage"
	default:
		return ""
	}
}

func containsIdentityRole(owned []string, allowed ...string) bool {
	set := make(map[string]struct{}, len(owned))
	for _, role := range owned {
		set[strings.TrimSpace(role)] = struct{}{}
	}
	for _, role := range allowed {
		if _, ok := set[role]; ok {
			return true
		}
	}
	return false
}
