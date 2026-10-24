package catalog

// Package catalog exposes the platform-owned Agent catalog boundary.
// catalog 包暴露平台拥有的 Agent Catalog 边界；Agent 业务模块不直接访问这些表。

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/lexagent/platform/internal/bootstrap"
)

// Module is the HTTP composition seam for catalog, installation and release
// lifecycle operations. Store is intentionally injected so this module can be
// moved behind a service API without changing the request contract.
// Module 是 Catalog/安装/发布生命周期的 HTTP 组合边界；Store 通过依赖注入，
// 未来可替换成远程服务而不改变请求契约。
type Module struct {
	store          Store
	internalToken  string
	scopeValidator ScopeValidator
	agentAccess    AgentAccessChecker
	controlAuth    ControlAuthorizer
}

type ControlAction string

const (
	ControlRead                   ControlAction = "read"
	ControlManage                 ControlAction = "manage"
	ControlDeploy                 ControlAction = "deploy"
	ControlRequestable            ControlAction = "requestable.read"
	ControlPromptTargets          ControlAction = "prompt.targets.read"
	ControlToolTargets            ControlAction = "tool.targets.read"
	ControlPolicyTargets          ControlAction = "policy.targets.read"
	ControlAuthorizationTargets   ControlAction = "authorization.targets.read"
	ControlWorkloadTargets        ControlAction = "workload.targets.read"
	ControlDelegationTargets      ControlAction = "delegation.targets.read"
	ControlDepartmentAgentTargets ControlAction = "department.agent.targets.read"
	ControlSubmit                 ControlAction = "release.submit"
	ControlApprove                ControlAction = "release.approve"
)

// ControlActor is derived only from the trusted browser gateway headers. The
// request body is never an authority for user, role, or tenant identity.
// ControlActor 只从可信浏览器网关注入的身份头派生；请求体不能声明用户、角色或租户身份。
type ControlActor struct {
	TenantID      string
	DepartmentID  string
	ApplicationID string
	PrincipalType string
	PrincipalID   string
	TraceID       string
}

type ControlScope struct {
	TenantID      string
	DepartmentID  string
	ApplicationID string
}

// ControlAuthorizer is the Identity policy port used by Catalog control-plane
// operations. Keeping it separate from SQLStore allows a future service
// adapter without moving identity tables into Catalog.
// ControlAuthorizer 是 Catalog 控制面操作使用的 Identity 授权端口；未来可替换远程 Adapter。
type ControlAuthorizer interface {
	AuthorizeCatalogControl(context.Context, ControlActor, ControlAction, ControlScope) error
}

var ErrCatalogForbidden = errors.New("catalog control operation forbidden")

// AgentAccessChecker delegates browser run authorization to the Identity
// module's policy port. Catalog remains the owner of installation discovery;
// Identity remains the owner of grants and principal status.
// AgentAccessChecker 将浏览器运行授权委托给 Identity 模块，Catalog 负责安装发现，Identity 负责主体与授权。
type AgentAccessChecker interface {
	CanDiscoverAgent(context.Context, string, string, string, string, string, string) (bool, error)
}

// AgentActionProjector supplies installation-level UI hints from one current
// identity snapshot. Object operations must still authorize their own data.
type AgentActionProjector interface {
	ProjectAgentActions(context.Context, ControlActor, []string) (map[string]map[string]bool, error)
}

func NewModule(store Store, internalToken string) *Module {
	return &Module{store: store, internalToken: strings.TrimSpace(internalToken)}
}

// ScopeValidator is the identity Port used when an installation is created.
// Catalog must not duplicate tenant/application tables or join another
// module's database; the local adapter is supplied by identity and can later
// be replaced by a remote client without changing this HTTP contract.
type ScopeValidator interface {
	ValidateApplicationScope(context.Context, string, string, string) error
}

// NewModuleWithScopeValidator wires the real identity Port into the catalog
// module. The plain constructor remains useful for isolated unit tests and
// remote deployments where scope validation happens upstream.
func NewModuleWithScopeValidator(store Store, internalToken string, validator ScopeValidator) *Module {
	return &Module{store: store, internalToken: strings.TrimSpace(internalToken), scopeValidator: validator}
}

// SetAgentAccessChecker wires the local Identity adapter before the module is
// registered. A remote deployment can supply an HTTP-backed implementation.
// SetAgentAccessChecker 在模块注册前注入本地 Identity Adapter；远程部署可替换为 HTTP 实现。
func (m *Module) SetAgentAccessChecker(checker AgentAccessChecker) {
	if m != nil {
		m.agentAccess = checker
	}
}

// SetControlAuthorizer injects Identity's authoritative browser control-plane
// policy. Browser requests fail closed if no authorizer is configured.
// SetControlAuthorizer 注入 Identity 权威控制面策略；浏览器请求未配置时必须拒绝。
func (m *Module) SetControlAuthorizer(authorizer ControlAuthorizer) {
	if m != nil {
		m.controlAuth = authorizer
	}
}

func (m *Module) Name() string { return "catalog" }

func (m *Module) Start(ctx context.Context) error {
	if m.store == nil {
		return errors.New("catalog store is required")
	}
	// Schema is installed by the versioned migration command, never Start.
	// Schema由独立版本迁移命令安装，Start不得改库。
	return ctx.Err()
}

func (m *Module) Ready() error {
	return m.ReadyContext(context.Background())
}

func (m *Module) ReadyContext(ctx context.Context) error {
	if m.store == nil {
		return errors.New("catalog store is required")
	}
	return bootstrap.ProbeDependency(ctx, m.store.Ping)
}

func (m *Module) Close(context.Context) error { return nil }

// Handler is mounted at /modules/catalog by ModuleRegistry.
// Handler 由 ModuleRegistry 挂载到 /modules/catalog。
func (m *Module) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/available", m.availableAgents)
	mux.HandleFunc("/available-definitions", m.availableDefinitions)
	mux.HandleFunc("/available-definitions/", m.availableDefinitionVersions)
	mux.HandleFunc("/definitions", m.definitions)
	mux.HandleFunc("/definitions/", m.definition)
	mux.HandleFunc("/versions/", m.version)
	mux.HandleFunc("/installations", m.installations)
	mux.HandleFunc("/installations/", m.installation)
	return mux
}

// availableDefinitions exposes only published installation candidates and
// requires a complete authenticated application scope.
// availableDefinitions 仅暴露已发布的可安装候选，并要求完整的已认证应用作用域。
func (m *Module) availableDefinitions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	scope, ok := requestedControlScope(r)
	if !ok {
		m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if !m.authorizeControl(w, r, ControlRead, scope) {
		return
	}
	limit, ok := requestLimit(r)
	if !ok {
		m.writeError(w, http.StatusBadRequest, "INVALID_LIMIT")
		return
	}
	reader, ok := m.store.(InstallableCatalogReader)
	if !ok {
		m.writeError(w, http.StatusServiceUnavailable, "INSTALLABLE_CATALOG_UNAVAILABLE")
		return
	}
	items, err := reader.ListPublishedDefinitions(r.Context(), limit)
	if err != nil {
		m.writeStoreError(w, err)
		return
	}
	m.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// availableDefinitionVersions returns only published version metadata; the
// raw runtime Manifest and schemas remain in the platform control plane.
// availableDefinitionVersions 只返回已发布版本元数据，不向应用管理员暴露原始运行时 Manifest 和 Schema。
func (m *Module) availableDefinitionVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	parts := splitPath(r.URL.Path, "/available-definitions/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != "versions" {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	scope, ok := requestedControlScope(r)
	if !ok {
		m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if !m.authorizeControl(w, r, ControlRead, scope) {
		return
	}
	limit, ok := requestLimit(r)
	if !ok {
		m.writeError(w, http.StatusBadRequest, "INVALID_LIMIT")
		return
	}
	reader, ok := m.store.(InstallableCatalogReader)
	if !ok {
		m.writeError(w, http.StatusServiceUnavailable, "INSTALLABLE_CATALOG_UNAVAILABLE")
		return
	}
	items, err := reader.ListPublishedVersions(r.Context(), parts[0], limit)
	if err != nil {
		m.writeStoreError(w, err)
		return
	}
	m.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func requestedControlScope(r *http.Request) (ControlScope, bool) {
	scope := ControlScope{
		TenantID:      strings.TrimSpace(r.URL.Query().Get("tenant_id")),
		DepartmentID:  strings.TrimSpace(r.URL.Query().Get("department_id")),
		ApplicationID: strings.TrimSpace(r.URL.Query().Get("application_id")),
	}
	return scope, scope.TenantID != "" && scope.DepartmentID != "" && scope.ApplicationID != ""
}

func (m *Module) authorizeControl(w http.ResponseWriter, r *http.Request, action ControlAction, scope ControlScope, hideForbidden ...bool) bool {
	if !m.authorized(r) {
		m.writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return false
	}
	if r.Header.Get("X-Browser-Module") != "1" {
		// Internal service calls are authenticated by the private service token;
		// browser sessions must additionally pass the Identity policy port.
		return true
	}
	actor := ControlActor{
		TenantID:      strings.TrimSpace(r.Header.Get("X-Tenant-ID")),
		DepartmentID:  strings.TrimSpace(r.Header.Get("X-Department-ID")),
		ApplicationID: strings.TrimSpace(r.Header.Get("X-Application-ID")),
		PrincipalType: strings.TrimSpace(r.Header.Get("X-Principal-Type")),
		PrincipalID:   strings.TrimSpace(r.Header.Get("X-Principal-ID")),
	}
	if actor.TenantID == "" || actor.DepartmentID == "" || actor.ApplicationID == "" || actor.PrincipalType != "user" || actor.PrincipalID == "" {
		m.writeError(w, http.StatusForbidden, "FORBIDDEN")
		return false
	}
	if m.controlAuth == nil {
		m.writeError(w, http.StatusServiceUnavailable, "CATALOG_AUTHORIZATION_UNAVAILABLE")
		return false
	}
	if err := m.controlAuth.AuthorizeCatalogControl(r.Context(), actor, action, scope); err != nil {
		if errors.Is(err, ErrCatalogForbidden) {
			if len(hideForbidden) != 0 && hideForbidden[0] {
				m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
			} else {
				m.writeError(w, http.StatusForbidden, "FORBIDDEN")
			}
		} else {
			m.writeError(w, http.StatusServiceUnavailable, "CATALOG_AUTHORIZATION_UNAVAILABLE")
		}
		return false
	}
	return true
}

type availableAgentResponse struct {
	AgentID         string          `json:"agent_id"`
	Name            string          `json:"name"`
	SemanticVersion string          `json:"semantic_version"`
	VersionID       string          `json:"version_id"`
	InstallationID  string          `json:"installation_id"`
	AccessStatus    string          `json:"access_status"`
	Permissions     map[string]bool `json:"permissions,omitempty"`
}

// availableAgents lists only the authenticated user's active app installations
// and delegates the final run decision to Identity. It is intentionally a
// browser projection, not an authorization oracle for arbitrary principals.
// availableAgents 只列出当前登录用户应用范围内的活动安装，并由 Identity 判定运行授权。
func (m *Module) availableAgents(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(r) {
		m.writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return
	}
	if r.Method != http.MethodGet {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	if r.Header.Get("X-Browser-Module") != "1" || strings.TrimSpace(r.Header.Get("X-Principal-Type")) != "user" {
		m.writeError(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	reader, ok := m.store.(AvailableAgentReader)
	if !ok || m.agentAccess == nil {
		m.writeError(w, http.StatusServiceUnavailable, "AGENT_CATALOG_UNAVAILABLE")
		return
	}
	tenantID := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	departmentID := strings.TrimSpace(r.Header.Get("X-Department-ID"))
	applicationID := strings.TrimSpace(r.Header.Get("X-Application-ID"))
	principalID := strings.TrimSpace(r.Header.Get("X-Principal-ID"))
	if tenantID == "" || departmentID == "" || applicationID == "" || principalID == "" {
		m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if !m.authorizeControl(w, r, ControlRequestable, ControlScope{TenantID: tenantID, DepartmentID: departmentID, ApplicationID: applicationID}) {
		return
	}
	items, err := reader.ListAvailableAgents(r.Context(), tenantID, departmentID, applicationID)
	if err != nil {
		m.writeStoreError(w, err)
		return
	}
	result := make([]availableAgentResponse, 0, len(items))
	var permissions map[string]map[string]bool
	if projector, ok := m.agentAccess.(AgentActionProjector); ok {
		ids := make([]string, 0, len(items))
		for _, item := range items {
			ids = append(ids, item.InstallationID)
		}
		permissions, err = projector.ProjectAgentActions(r.Context(), ControlActor{TenantID: tenantID, DepartmentID: departmentID, ApplicationID: applicationID, PrincipalType: "user", PrincipalID: principalID}, ids)
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		if permissions == nil {
			m.writeError(w, http.StatusServiceUnavailable, "AGENT_PERMISSION_PROJECTION_UNAVAILABLE")
			return
		}
	}
	for _, item := range items {
		allowed := false
		if permissions != nil {
			allowed = permissions[item.InstallationID]["discover"]
		} else {
			allowed, err = m.agentAccess.CanDiscoverAgent(r.Context(), tenantID, departmentID, applicationID, item.InstallationID, "user", principalID)
			if err != nil {
				m.writeStoreError(w, err)
				return
			}
		}
		accessStatus := "restricted"
		if allowed {
			accessStatus = "granted"
		}
		result = append(result, availableAgentResponse{AgentID: item.AgentID, Name: item.Name, SemanticVersion: item.SemanticVersion, VersionID: item.VersionID, InstallationID: item.InstallationID, AccessStatus: accessStatus, Permissions: permissions[item.InstallationID]})
	}
	m.writeJSON(w, http.StatusOK, map[string]any{"items": result})
}

type definitionRequest struct {
	ID          string           `json:"id"`
	PublisherID string           `json:"publisher_id"`
	AgentKey    string           `json:"agent_key"`
	DisplayName string           `json:"display_name"`
	Description string           `json:"description"`
	Status      DefinitionStatus `json:"status"`
	Revision    uint64           `json:"revision"`
}

func (r definitionRequest) domain() Definition {
	return Definition{ID: r.ID, PublisherID: r.PublisherID, AgentKey: r.AgentKey, DisplayName: r.DisplayName, Description: r.Description, Status: r.Status, Revision: r.Revision}
}

type versionRequest struct {
	ID              string           `json:"id"`
	DefinitionID    string           `json:"definition_id"`
	SemanticVersion string           `json:"semantic_version"`
	Manifest        json.RawMessage  `json:"manifest"`
	ArtifactDigest  string           `json:"artifact_digest"`
	InputSchema     json.RawMessage  `json:"input_schema"`
	OutputSchema    json.RawMessage  `json:"output_schema"`
	Status          DefinitionStatus `json:"status"`
	Revision        uint64           `json:"revision"`
}

func (r versionRequest) domain() (Version, error) {
	hash, err := VersionContentHash(r.Manifest, r.InputSchema, r.OutputSchema)
	if err != nil {
		return Version{}, ErrInvalidVersion
	}
	return Version{ID: r.ID, DefinitionID: r.DefinitionID, SemanticVersion: r.SemanticVersion, ManifestHash: hash, Manifest: r.Manifest, ArtifactDigest: r.ArtifactDigest, InputSchema: r.InputSchema, OutputSchema: r.OutputSchema, Status: r.Status, Revision: r.Revision}, nil
}

type installationRequest struct {
	ID                string             `json:"id"`
	TenantID          string             `json:"tenant_id"`
	DepartmentID      string             `json:"department_id"`
	ApplicationID     string             `json:"application_id"`
	AgentID           string             `json:"agent_id"`
	VersionID         string             `json:"version_id"`
	DisplayName       string             `json:"display_name"`
	DeploymentMode    string             `json:"deployment_mode"`
	DrainPolicy       string             `json:"drain_policy"`
	RetentionPolicyID string             `json:"retention_policy_id"`
	Status            InstallationStatus `json:"status"`
	Revision          uint64             `json:"revision"`
}

func (r installationRequest) domain() Installation {
	return Installation{ID: r.ID, TenantID: r.TenantID, DepartmentID: r.DepartmentID, ApplicationID: r.ApplicationID, AgentID: r.AgentID, VersionID: r.VersionID, DisplayName: r.DisplayName, DeploymentMode: r.DeploymentMode, DrainPolicy: r.DrainPolicy, RetentionPolicyID: r.RetentionPolicyID, Status: r.Status, Revision: r.Revision}
}

type transitionRequest struct {
	From             string `json:"from"`
	To               string `json:"to"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

type definitionTransitionRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
}

type uninstallRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
}

type rollbackRequest struct {
	VersionID        string `json:"version_id"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

type deploymentRequest struct {
	ID                  string           `json:"id"`
	TenantID            string           `json:"tenant_id"`
	DepartmentID        string           `json:"department_id"`
	ApplicationID       string           `json:"application_id"`
	AgentVersionID      string           `json:"agent_version_id"`
	AgentInstallationID string           `json:"agent_installation_id"`
	ArtifactDigest      string           `json:"artifact_digest"`
	ManifestHash        string           `json:"manifest_hash"`
	Transport           string           `json:"transport"`
	EndpointRef         string           `json:"endpoint_ref"`
	PlacementPolicy     json.RawMessage  `json:"placement_policy"`
	ResourcePolicy      json.RawMessage  `json:"resource_policy"`
	Status              DeploymentStatus `json:"status"`
	DesiredRevision     uint64           `json:"desired_revision"`
}

func (r deploymentRequest) domain(installationID string) Deployment {
	if r.AgentInstallationID == "" {
		r.AgentInstallationID = installationID
	}
	if r.Status == "" {
		r.Status = DeploymentPending
	}
	return Deployment{ID: r.ID, TenantID: r.TenantID, DepartmentID: r.DepartmentID, ApplicationID: r.ApplicationID, AgentVersionID: r.AgentVersionID, AgentInstallationID: r.AgentInstallationID, ArtifactDigest: r.ArtifactDigest, ManifestHash: r.ManifestHash, Transport: r.Transport, EndpointRef: r.EndpointRef, PlacementPolicy: r.PlacementPolicy, ResourcePolicy: r.ResourcePolicy, Status: r.Status, DesiredRevision: r.DesiredRevision}
}

type observeRequest struct {
	DesiredRevision uint64           `json:"desired_revision"`
	Status          DeploymentStatus `json:"status"`
}

func (m *Module) definitions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if !m.authorizeControl(w, r, ControlRead, ControlScope{}) {
			return
		}
		limit, ok := requestLimit(r)
		if !ok {
			m.writeError(w, http.StatusBadRequest, "INVALID_LIMIT")
			return
		}
		reader, ok := m.store.(CatalogListReader)
		if !ok {
			m.writeError(w, http.StatusServiceUnavailable, "CATALOG_LIST_UNAVAILABLE")
			return
		}
		items, err := reader.ListDefinitions(r.Context(), limit)
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, map[string]any{"items": items})
		return
	}
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	submissionScope, scopedSubmission, ok := m.submissionControlScope(w, r)
	if !ok || !m.authorizeControl(w, r, ControlSubmit, submissionScope) {
		return
	}
	var request definitionRequest
	if err := decode(r, &request); err != nil || request.Status != DefinitionDraft || request.Revision != 1 {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if scopedSubmission && request.PublisherID != releaseActorFromRequest(r).PrincipalID {
		m.writeError(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	var createErr error
	if r.Header.Get("X-Browser-Module") == "1" {
		store, ok := m.store.(SubmittedReleaseStore)
		if !ok {
			m.writeStoreError(w, ErrReleaseUnavailable)
			return
		}
		createErr = store.CreateSubmittedDefinition(r.Context(), request.domain(), releaseActorFromRequest(r))
	} else {
		createErr = m.store.CreateDefinition(r.Context(), request.domain())
	}
	if err := createErr; err != nil {
		m.writeStoreError(w, err)
		return
	}
	m.writeJSON(w, http.StatusCreated, request.domain())
}

func (m *Module) definition(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(r.URL.Path, "/definitions/")
	if len(parts) == 1 && r.Method == http.MethodGet {
		if !m.authorizeControl(w, r, ControlRead, ControlScope{}) {
			return
		}
		definition, err := m.store.GetDefinition(r.Context(), parts[0])
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, definition)
		return
	}
	if len(parts) == 2 && r.Method == http.MethodPost && (parts[1] == "evaluate" || parts[1] == "publish" || parts[1] == "disable" || parts[1] == "retire") {
		action := ControlManage
		if parts[1] == "publish" {
			action = ControlApprove
		}
		if !m.authorizeControl(w, r, action, ControlScope{}) {
			return
		}
		var request definitionTransitionRequest
		if err := decode(r, &request); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		from, to := DefinitionStatus(""), DefinitionStatus("")
		switch parts[1] {
		case "evaluate":
			from, to = DefinitionDraft, DefinitionEvaluated
		case "publish":
			from, to = DefinitionEvaluated, DefinitionPublished
		case "disable":
			from, to = DefinitionPublished, DefinitionDisabled
		case "retire":
			from, to = DefinitionPublished, DefinitionRetired
		}
		lifecycle, ok := m.store.(DefinitionLifecycleStore)
		if !ok {
			m.writeError(w, http.StatusNotImplemented, "LIFECYCLE_NOT_AVAILABLE")
			return
		}
		var transitionErr error
		if parts[1] == "publish" && r.Header.Get("X-Browser-Module") == "1" {
			store, ok := m.store.(SubmittedReleaseStore)
			if !ok {
				m.writeStoreError(w, ErrReleaseUnavailable)
				return
			}
			transitionErr = store.PublishSubmittedObject(r.Context(), "definition", parts[0], request.ExpectedRevision, releaseActorFromRequest(r))
		} else {
			transitionErr = lifecycle.TransitionDefinition(r.Context(), parts[0], from, to, request.ExpectedRevision)
		}
		if err := transitionErr; err != nil {
			m.writeStoreError(w, err)
			return
		}
		definition, err := m.store.GetDefinition(r.Context(), parts[0])
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, definition)
		return
	}
	if len(parts) == 2 && parts[1] == "versions" && r.Method == http.MethodGet {
		if !m.authorizeControl(w, r, ControlRead, ControlScope{}) {
			return
		}
		limit, ok := requestLimit(r)
		if !ok {
			m.writeError(w, http.StatusBadRequest, "INVALID_LIMIT")
			return
		}
		reader, ok := m.store.(CatalogListReader)
		if !ok {
			m.writeError(w, http.StatusServiceUnavailable, "CATALOG_LIST_UNAVAILABLE")
			return
		}
		items, err := reader.ListVersions(r.Context(), parts[0], limit)
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, map[string]any{"items": items})
		return
	}
	if len(parts) == 2 && parts[1] == "versions" && r.Method == http.MethodPost {
		submissionScope, scopedSubmission, ok := m.submissionControlScope(w, r)
		if !ok || !m.authorizeControl(w, r, ControlSubmit, submissionScope) {
			return
		}
		if scopedSubmission {
			parent, err := m.store.GetDefinition(r.Context(), parts[0])
			if err != nil {
				m.writeStoreError(w, err)
				return
			}
			if parent.PublisherID != releaseActorFromRequest(r).PrincipalID {
				m.writeError(w, http.StatusForbidden, "FORBIDDEN")
				return
			}
		}
		var request versionRequest
		if err := decode(r, &request); err != nil || request.DefinitionID != parts[0] || request.Status != DefinitionDraft || request.Revision != 1 {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		version, err := request.domain()
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		var createErr error
		if r.Header.Get("X-Browser-Module") == "1" {
			store, ok := m.store.(SubmittedReleaseStore)
			if !ok {
				m.writeStoreError(w, ErrReleaseUnavailable)
				return
			}
			createErr = store.CreateSubmittedVersion(r.Context(), version, releaseActorFromRequest(r))
		} else {
			createErr = m.store.CreateVersion(r.Context(), version)
		}
		if err := createErr; err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusCreated, version)
		return
	}
	m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
}

func (m *Module) version(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(r.URL.Path, "/versions/")
	if len(parts) == 1 && r.Method == http.MethodGet {
		if !m.authorizeControl(w, r, ControlRead, ControlScope{}) {
			return
		}
		version, err := m.store.GetVersion(r.Context(), parts[0])
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, version)
		return
	}
	if len(parts) != 2 || r.Method != http.MethodPost || (parts[1] != "evaluate" && parts[1] != "publish") {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	action := ControlManage
	if parts[1] == "publish" {
		action = ControlApprove
	}
	if !m.authorizeControl(w, r, action, ControlScope{}) {
		return
	}
	var request transitionRequest
	if err := decode(r, &request); err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	from, to := DefinitionStatus(request.From), DefinitionStatus(request.To)
	if parts[1] == "evaluate" {
		from, to = DefinitionDraft, DefinitionEvaluated
	}
	if parts[1] == "publish" {
		from, to = DefinitionEvaluated, DefinitionPublished
	}
	var transitionErr error
	if parts[1] == "publish" && r.Header.Get("X-Browser-Module") == "1" {
		store, ok := m.store.(SubmittedReleaseStore)
		if !ok {
			m.writeStoreError(w, ErrReleaseUnavailable)
			return
		}
		transitionErr = store.PublishSubmittedObject(r.Context(), "version", parts[0], request.ExpectedRevision, releaseActorFromRequest(r))
	} else {
		transitionErr = m.store.TransitionVersion(r.Context(), parts[0], from, to, request.ExpectedRevision)
	}
	if err := transitionErr; err != nil {
		m.writeStoreError(w, err)
		return
	}
	version, err := m.store.GetVersion(r.Context(), parts[0])
	if err != nil {
		m.writeStoreError(w, err)
		return
	}
	m.writeJSON(w, http.StatusOK, version)
}

func (m *Module) installations(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		scope := ControlScope{TenantID: r.URL.Query().Get("tenant_id"), DepartmentID: r.URL.Query().Get("department_id"), ApplicationID: r.URL.Query().Get("application_id")}
		if scope.TenantID == "" || (scope.DepartmentID == "") != (scope.ApplicationID == "") {
			m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
			return
		}
		action := ControlRead
		policyTargets := r.URL.Query().Get("view") == "policy-assets"
		permissionTargets := r.URL.Query().Get("view") == "permission-targets"
		if permissionTargets {
			if scope.DepartmentID == "" || scope.ApplicationID == "" || len(r.URL.Query()["purpose"]) != 1 {
				m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
				return
			}
			switch r.URL.Query().Get("purpose") {
			case "department-access":
				action = ControlDepartmentAgentTargets
			case "authorization":
				action = ControlAuthorizationTargets
			case "workload":
				action = ControlWorkloadTargets
			case "delegation":
				action = ControlDelegationTargets
			default:
				m.writeError(w, http.StatusBadRequest, "INVALID_PURPOSE")
				return
			}
		}
		if policyTargets {
			if scope.DepartmentID == "" || scope.ApplicationID == "" {
				m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
				return
			}
			switch r.URL.Query().Get("asset_type") {
			case "prompt":
				action = ControlPromptTargets
			case "tool":
				action = ControlToolTargets
			case "model", "memory", "knowledge", "runtime":
				action = ControlPolicyTargets
			default:
				m.writeError(w, http.StatusBadRequest, "INVALID_ASSET_TYPE")
				return
			}
		}
		if !m.authorizeControl(w, r, action, scope) {
			return
		}
		limit, ok := requestLimit(r)
		if !ok {
			m.writeError(w, http.StatusBadRequest, "INVALID_LIMIT")
			return
		}
		reader, ok := m.store.(CatalogListReader)
		if !ok {
			m.writeError(w, http.StatusServiceUnavailable, "CATALOG_LIST_UNAVAILABLE")
			return
		}
		var items []Installation
		var err error
		nextCursor := ""
		if permissionTargets && action == ControlDepartmentAgentTargets {
			pager, ok := m.store.(PermissionTargetPager)
			if !ok {
				m.writeError(w, http.StatusServiceUnavailable, "PERMISSION_DIRECTORY_UNAVAILABLE")
				return
			}
			cursor := r.URL.Query().Get("cursor")
			if len(r.URL.Query()["cursor"]) > 1 || len(cursor) > 256 || strings.TrimSpace(cursor) != cursor || strings.ContainsRune(cursor, '\x00') {
				m.writeError(w, http.StatusBadRequest, "INVALID_CURSOR")
				return
			}
			items, nextCursor, err = pager.PagePermissionTargets(r.Context(), scope.TenantID, scope.DepartmentID, scope.ApplicationID, cursor, limit)
		} else {
			items, err = reader.ListInstallations(r.Context(), scope.TenantID, scope.DepartmentID, scope.ApplicationID, limit)
		}
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		if policyTargets || permissionTargets {
			projection := make([]map[string]string, 0, len(items))
			for _, item := range items {
				metadata := map[string]string{"id": item.ID, "tenant_id": item.TenantID, "department_id": item.DepartmentID, "application_id": item.ApplicationID, "agent_id": item.AgentID, "version_id": item.VersionID, "display_name": item.DisplayName}
				if permissionTargets {
					metadata["status"] = string(item.Status)
				}
				projection = append(projection, metadata)
			}
			response := map[string]any{"items": projection}
			if action == ControlDepartmentAgentTargets {
				response["next_cursor"] = nextCursor
			}
			m.writeJSON(w, http.StatusOK, response)
			return
		}
		m.writeJSON(w, http.StatusOK, map[string]any{"items": items})
		return
	}
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	var request installationRequest
	if err := decode(r, &request); err != nil || request.Status != InstallationProvisioning || request.Revision != 1 {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if !m.authorizeControl(w, r, ControlManage, ControlScope{TenantID: request.TenantID, DepartmentID: request.DepartmentID, ApplicationID: request.ApplicationID}) {
		return
	}
	if m.scopeValidator != nil {
		if err := m.scopeValidator.ValidateApplicationScope(r.Context(), request.TenantID, request.DepartmentID, request.ApplicationID); err != nil {
			m.writeStoreError(w, fmt.Errorf("%w: %v", ErrScopeReference, err))
			return
		}
	}
	if err := m.store.CreateInstallation(r.Context(), request.domain()); err != nil {
		m.writeStoreError(w, err)
		return
	}
	m.writeJSON(w, http.StatusCreated, request.domain())
}

func (m *Module) installation(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(r.URL.Path, "/installations/")
	if len(parts) == 0 {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	installation, err := m.store.GetInstallation(r.Context(), parts[0])
	if err != nil {
		m.writeStoreError(w, err)
		return
	}
	scope := ControlScope{TenantID: installation.TenantID, DepartmentID: installation.DepartmentID, ApplicationID: installation.ApplicationID}
	action := ControlManage
	if r.Method == http.MethodGet && (len(parts) == 1 || (len(parts) == 2 && parts[1] == "deployments")) {
		action = ControlRead
	}
	if !m.authorizeControl(w, r, action, scope, true) {
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		m.writeJSON(w, http.StatusOK, installation)
		return
	}
	if len(parts) == 2 && parts[1] == "deployments" {
		if r.Method == http.MethodGet {
			limit := 50
			if raw := r.URL.Query().Get("limit"); raw != "" {
				if parsed, err := strconv.Atoi(raw); err == nil {
					limit = parsed
				}
			}
			// Always derive the query scope from the installation itself. URL
			// parameters are not authority and must not widen a guessed resource ID.
			// 查询作用域只能来自已授权安装记录；URL 参数不能扩大猜测到的资源 ID。
			rows, err := m.store.ListDeployments(r.Context(), installation.TenantID, installation.DepartmentID, installation.ApplicationID, installation.ID, limit)
			if err != nil {
				m.writeStoreError(w, err)
				return
			}
			m.writeJSON(w, http.StatusOK, map[string]any{"items": rows})
			return
		}
		if r.Method != http.MethodPost {
			m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		var request deploymentRequest
		if err := decode(r, &request); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		deployment := request.domain(parts[0])
		if deployment.TenantID == "" || deployment.DepartmentID == "" || deployment.ApplicationID == "" {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if deployment.TenantID != installation.TenantID || deployment.DepartmentID != installation.DepartmentID || deployment.ApplicationID != installation.ApplicationID || deployment.AgentInstallationID != installation.ID {
			m.writeError(w, http.StatusBadRequest, "INSTALLATION_SCOPE_MISMATCH")
			return
		}
		if !m.authorizeControl(w, r, ControlDeploy, scope) {
			return
		}
		created, err := m.store.CreateDeployment(r.Context(), deployment)
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusCreated, created)
		return
	}
	if len(parts) == 4 && parts[1] == "deployments" && parts[3] == "observe" && r.Method == http.MethodPost {
		if r.Header.Get("X-Browser-Module") == "1" {
			m.writeError(w, http.StatusForbidden, "FORBIDDEN")
			return
		}
		var request observeRequest
		if err := decode(r, &request); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if err := m.store.ObserveDeployment(r.Context(), installation.TenantID, installation.DepartmentID, installation.ApplicationID, installation.ID, parts[2], request.DesiredRevision, request.Status); err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, map[string]string{"status": "observed"})
		return
	}
	if len(parts) == 2 && parts[1] == "uninstall" && r.Method == http.MethodPost {
		var request uninstallRequest
		if err := decode(r, &request); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		lifecycle, ok := m.store.(InstallationLifecycleStore)
		if !ok {
			m.writeError(w, http.StatusNotImplemented, "LIFECYCLE_NOT_AVAILABLE")
			return
		}
		if err := lifecycle.UninstallInstallation(r.Context(), parts[0], request.ExpectedRevision); err != nil {
			m.writeStoreError(w, err)
			return
		}
		installation, err = m.store.GetInstallation(r.Context(), parts[0])
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, installation)
		return
	}
	if len(parts) != 2 || r.Method != http.MethodPost {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	if parts[1] == "upgrade" {
		var request rollbackRequest
		if err := decode(r, &request); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		upgrades, ok := m.store.(InstallationUpgradeStore)
		if !ok {
			m.writeError(w, http.StatusNotImplemented, "LIFECYCLE_NOT_AVAILABLE")
			return
		}
		if err := upgrades.UpgradeInstallation(r.Context(), parts[0], request.VersionID, request.ExpectedRevision); err != nil {
			m.writeStoreError(w, err)
			return
		}
		installation, err = m.store.GetInstallation(r.Context(), parts[0])
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, installation)
		return
	}
	if parts[1] == "rollback" {
		var request rollbackRequest
		if err := decode(r, &request); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if err := m.store.RollbackInstallation(r.Context(), parts[0], request.VersionID, request.ExpectedRevision); err != nil {
			m.writeStoreError(w, err)
			return
		}
		installation, err = m.store.GetInstallation(r.Context(), parts[0])
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, installation)
		return
	}
	if parts[1] != "transition" {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	var request transitionRequest
	if err := decode(r, &request); err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := m.store.TransitionInstallation(r.Context(), parts[0], InstallationStatus(request.From), InstallationStatus(request.To), request.ExpectedRevision); err != nil {
		m.writeStoreError(w, err)
		return
	}
	installation, err = m.store.GetInstallation(r.Context(), parts[0])
	if err != nil {
		m.writeStoreError(w, err)
		return
	}
	m.writeJSON(w, http.StatusOK, installation)
}

func splitPath(path, prefix string) []string {
	return strings.FieldsFunc(strings.TrimPrefix(path, prefix), func(r rune) bool { return r == '/' })
}

func requestLimit(r *http.Request) (int, bool) {
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return 0, false
		}
		limit = parsed
	}
	return limit, true
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

func (m *Module) writeStoreError(w http.ResponseWriter, err error) {
	status, code := http.StatusInternalServerError, "INTERNAL_ERROR"
	switch {
	case errors.Is(err, ErrCatalogForbidden):
		status, code = http.StatusForbidden, "FORBIDDEN"
	case errors.Is(err, ErrReleaseUnavailable):
		status, code = http.StatusServiceUnavailable, "CATALOG_RELEASE_AUTHORIZATION_UNAVAILABLE"
	case errors.Is(err, ErrReleaseSubmissionMissing):
		status, code = http.StatusConflict, "RELEASE_SUBMISSION_PROVENANCE_REQUIRED"
	case errors.Is(err, ErrDefinitionNotFound), errors.Is(err, ErrVersionNotFound), errors.Is(err, ErrInstallationNotFound):
		status, code = http.StatusNotFound, "RESOURCE_NOT_FOUND"
	case errors.Is(err, ErrInvalidDefinition), errors.Is(err, ErrInvalidVersion):
		status, code = http.StatusBadRequest, "SCHEMA_VALIDATION_FAILED"
	case errors.Is(err, ErrInvalidInstallation), errors.Is(err, ErrInvalidDeployment), errors.Is(err, ErrVersionNotPublished), errors.Is(err, ErrAgentMismatch), errors.Is(err, ErrDeploymentVersionMismatch), errors.Is(err, ErrScopeReference):
		status, code = http.StatusBadRequest, "CATALOG_CONTRACT_VIOLATION"
	case errors.Is(err, ErrDeploymentNotReady):
		status, code = http.StatusConflict, "DEPLOYMENT_NOT_READY"
	case errors.Is(err, ErrIllegalTransition), errors.Is(err, ErrRevisionConflict), errors.Is(err, ErrCatalogConflict):
		status, code = http.StatusConflict, "REVISION_CONFLICT"
	}
	m.writeError(w, status, code)
}

func (m *Module) writeError(w http.ResponseWriter, status int, code string) {
	m.writeJSON(w, status, map[string]any{"error": map[string]string{"code": code}})
}

func (m *Module) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

var _ bootstrap.Module = (*Module)(nil)
var _ bootstrap.ReadyModule = (*Module)(nil)
