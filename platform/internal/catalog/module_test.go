package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// memoryStore exercises the HTTP boundary without coupling the handler tests
// to a particular SQL driver. The production path uses SQLStore; the port is
// deliberately identical so a remote repository can be substituted later.
// memoryStore 用于验证 HTTP 边界，不把 Handler 测试绑定到具体 SQL 驱动；生产使用 SQLStore，
// 相同 Port 也支持未来替换为远程仓储。
type memoryStore struct {
	definition         Definition
	version            Version
	installation       Installation
	definitions        []Definition
	versions           []Version
	publishedVersions  []PublishedVersion
	installations      []Installation
	deployments        []Deployment
	availableAgents    []AvailableAgent
	lastAvailableScope [3]string
}

type agentAccessChecker struct {
	allowed bool
	err     error
	args    []string
}

func (c *agentAccessChecker) CanDiscoverAgent(_ context.Context, tenant, department, application, installation, principalType, principalID string) (bool, error) {
	c.args = []string{tenant, department, application, installation, principalType, principalID}
	return c.allowed, c.err
}

type scopeValidator struct{ err error }

func (v scopeValidator) ValidateApplicationScope(context.Context, string, string, string) error {
	return v.err
}

type controlAuthorizerFunc func(context.Context, ControlActor, ControlAction, ControlScope) error

func (f controlAuthorizerFunc) AuthorizeCatalogControl(ctx context.Context, actor ControlActor, action ControlAction, scope ControlScope) error {
	return f(ctx, actor, action, scope)
}

func (m *memoryStore) EnsureSchema(context.Context) error { return nil }
func (m *memoryStore) Ping(context.Context) error         { return nil }
func (m *memoryStore) CreateDefinition(_ context.Context, v Definition) error {
	if err := v.Validate(); err != nil {
		return err
	}
	m.definition = v
	return nil
}
func (m *memoryStore) GetDefinition(_ context.Context, id string) (Definition, error) {
	if m.definition.ID != id {
		return Definition{}, ErrDefinitionNotFound
	}
	return m.definition, nil
}
func (m *memoryStore) ListDefinitions(_ context.Context, limit int) ([]Definition, error) {
	items := append([]Definition(nil), m.definitions...)
	if len(items) == 0 && m.definition.ID != "" {
		items = []Definition{m.definition}
	}
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}
func (m *memoryStore) TransitionDefinition(_ context.Context, id string, from, to DefinitionStatus, expected uint64) error {
	if m.definition.ID != id || m.definition.Status != from || m.definition.Revision != expected {
		return ErrRevisionConflict
	}
	if err := ValidateDefinitionTransition(from, to); err != nil {
		return err
	}
	m.definition.Status, m.definition.Revision = to, m.definition.Revision+1
	return nil
}
func (m *memoryStore) CreateVersion(_ context.Context, v Version) error {
	if err := v.Validate(); err != nil {
		return err
	}
	m.version = v
	return nil
}
func (m *memoryStore) GetVersion(_ context.Context, id string) (Version, error) {
	if m.version.ID != id {
		return Version{}, ErrVersionNotFound
	}
	return m.version, nil
}
func (m *memoryStore) ListVersions(_ context.Context, definitionID string, limit int) ([]Version, error) {
	items := append([]Version(nil), m.versions...)
	if len(items) == 0 && m.version.ID != "" {
		items = []Version{m.version}
	}
	filtered := make([]Version, 0, len(items))
	for _, item := range items {
		if item.DefinitionID == definitionID {
			filtered = append(filtered, item)
		}
	}
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return filtered, nil
}
func (m *memoryStore) ListPublishedDefinitions(_ context.Context, limit int) ([]Definition, error) {
	items := append([]Definition(nil), m.definitions...)
	if len(items) == 0 && m.definition.ID != "" {
		items = []Definition{m.definition}
	}
	result := make([]Definition, 0, len(items))
	for _, item := range items {
		if item.Status == DefinitionPublished {
			result = append(result, item)
		}
	}
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}
func (m *memoryStore) ListPublishedVersions(_ context.Context, definitionID string, limit int) ([]PublishedVersion, error) {
	result := make([]PublishedVersion, 0, len(m.publishedVersions))
	for _, item := range m.publishedVersions {
		if item.DefinitionID == definitionID && item.Status == DefinitionPublished {
			result = append(result, item)
		}
	}
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}
func (m *memoryStore) TransitionVersion(_ context.Context, id string, from, to DefinitionStatus, expected uint64) error {
	if m.version.ID != id || m.version.Status != from || m.version.Revision != expected {
		return ErrRevisionConflict
	}
	m.version.Status, m.version.Revision = to, m.version.Revision+1
	return nil
}
func (m *memoryStore) CreateInstallation(_ context.Context, v Installation) error {
	if err := v.Validate(); err != nil || v.Status != InstallationProvisioning || v.Revision != 1 {
		return ErrInvalidInstallation
	}
	if m.version.ID != v.VersionID || m.version.Status != DefinitionPublished {
		return ErrVersionNotPublished
	}
	if m.definition.ID == "" || m.definition.Status != DefinitionPublished {
		return ErrDefinitionNotPublished
	}
	m.installation = v
	return nil
}

func definitionRequestJSON(id, agentID, name string) string {
	return fmt.Sprintf(`{"id":%q,"publisher_id":"platform","agent_key":%q,"display_name":%q,"description":"A test Agent definition.","status":"draft","revision":1}`, id, agentID, name)
}

func versionRequestJSON(id, definitionID, agentID, semanticVersion string) string {
	manifest := json.RawMessage(fmt.Sprintf(`{"manifest_version":"agent-manifest/v1","agent_id":%q,"version":%q,"execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],"schemas":{"input":"schema://%s/input/v1","output":"schema://%s/output/v1","event":"schema://%s/event/v1","checkpoint":"schema://%s/checkpoint/v1"},"runtime":{"transport":"http","isolation":"container","health_path":"/health/ready"}}`, agentID, semanticVersion, agentID, agentID, agentID, agentID))
	input := json.RawMessage(`{"type":"object","properties":{"question":{"type":"string"}}}`)
	output := json.RawMessage(`{"type":"object","properties":{"answer":{"type":"string"}}}`)
	body, _ := json.Marshal(struct {
		ID              string           `json:"id"`
		DefinitionID    string           `json:"definition_id"`
		SemanticVersion string           `json:"semantic_version"`
		Manifest        json.RawMessage  `json:"manifest"`
		ArtifactDigest  string           `json:"artifact_digest"`
		InputSchema     json.RawMessage  `json:"input_schema"`
		OutputSchema    json.RawMessage  `json:"output_schema"`
		Status          DefinitionStatus `json:"status"`
		Revision        uint64           `json:"revision"`
	}{id, definitionID, semanticVersion, manifest, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", input, output, DefinitionDraft, 1})
	return string(body)
}

func installationRequestJSON(id, tenant, department, application, agentID, versionID string) string {
	body, _ := json.Marshal(Installation{ID: id, TenantID: tenant, DepartmentID: department, ApplicationID: application, AgentID: agentID, VersionID: versionID, DisplayName: "QA Agent", DeploymentMode: "managed", DrainPolicy: "wait", RetentionPolicyID: "default", Status: InstallationProvisioning, Revision: 1})
	return string(body)
}
func (m *memoryStore) GetInstallation(_ context.Context, id string) (Installation, error) {
	if m.installation.ID != id {
		return Installation{}, ErrInstallationNotFound
	}
	return m.installation, nil
}
func (m *memoryStore) ListInstallations(_ context.Context, tenantID, departmentID, applicationID string, limit int) ([]Installation, error) {
	items := append([]Installation(nil), m.installations...)
	if len(items) == 0 && m.installation.ID != "" {
		items = []Installation{m.installation}
	}
	filtered := make([]Installation, 0, len(items))
	for _, item := range items {
		if item.TenantID == tenantID && (departmentID == "" || item.DepartmentID == departmentID) && (applicationID == "" || item.ApplicationID == applicationID) {
			filtered = append(filtered, item)
		}
	}
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return filtered, nil
}
func (m *memoryStore) ListAvailableAgents(_ context.Context, tenant, department, application string) ([]AvailableAgent, error) {
	m.lastAvailableScope = [3]string{tenant, department, application}
	return append([]AvailableAgent(nil), m.availableAgents...), nil
}
func (m *memoryStore) TransitionInstallation(_ context.Context, id string, from, to InstallationStatus, expected uint64) error {
	if m.installation.ID != id || m.installation.Status != from || m.installation.Revision != expected {
		return ErrRevisionConflict
	}
	if err := ValidateInstallationTransition(from, to); err != nil {
		return err
	}
	if to == InstallationActive && !latestDeploymentReadyForActivation(m.installation, m.deployments) {
		return ErrDeploymentNotReady
	}
	m.installation.Status, m.installation.Revision = to, m.installation.Revision+1
	return nil
}
func (m *memoryStore) RollbackInstallation(_ context.Context, id, versionID string, expected uint64) error {
	if m.installation.ID != id || m.installation.Revision != expected || m.version.Status != DefinitionPublished {
		return ErrRevisionConflict
	}
	m.installation.VersionID, m.installation.Revision = versionID, m.installation.Revision+1
	return nil
}
func (m *memoryStore) UninstallInstallation(_ context.Context, id string, expected uint64) error {
	if m.installation.ID != id || m.installation.Revision != expected {
		return ErrRevisionConflict
	}
	if m.installation.Status != InstallationActive && m.installation.Status != InstallationSuspended && m.installation.Status != InstallationDraining {
		return ErrRevisionConflict
	}
	m.installation.Status, m.installation.Revision = InstallationUninstalling, m.installation.Revision+1
	return nil
}
func (m *memoryStore) CreateDeployment(_ context.Context, value Deployment) (Deployment, error) {
	if value.DesiredRevision == 0 {
		value.DesiredRevision = 1
		for _, deployment := range m.deployments {
			if deployment.DesiredRevision >= value.DesiredRevision {
				value.DesiredRevision = deployment.DesiredRevision + 1
			}
		}
	}
	if err := value.Validate(); err != nil {
		return Deployment{}, err
	}
	if value.AgentInstallationID != m.installation.ID || value.TenantID != m.installation.TenantID || value.DepartmentID != m.installation.DepartmentID || value.ApplicationID != m.installation.ApplicationID {
		return Deployment{}, ErrInstallationNotFound
	}
	if value.AgentVersionID != m.installation.VersionID {
		return Deployment{}, ErrDeploymentVersionMismatch
	}
	if value.ArtifactDigest != m.version.ArtifactDigest || value.ManifestHash != m.version.ManifestHash || m.version.Status != DefinitionPublished {
		return Deployment{}, ErrVersionNotPublished
	}
	m.deployments = append(m.deployments, value)
	return value, nil
}
func (m *memoryStore) ListDeployments(_ context.Context, tenant, department, application, installation string, limit int) ([]Deployment, error) {
	result := make([]Deployment, 0)
	for i := len(m.deployments) - 1; i >= 0 && len(result) < limit; i-- {
		value := m.deployments[i]
		if value.TenantID == tenant && value.DepartmentID == department && value.ApplicationID == application && value.AgentInstallationID == installation {
			result = append(result, value)
		}
	}
	return result, nil
}
func (m *memoryStore) ObserveDeployment(_ context.Context, tenant, department, application, installation, id string, desired uint64, status DeploymentStatus) error {
	for i := range m.deployments {
		if m.deployments[i].ID == id && m.deployments[i].TenantID == tenant && m.deployments[i].DepartmentID == department && m.deployments[i].ApplicationID == application && m.deployments[i].AgentInstallationID == installation && m.deployments[i].DesiredRevision == desired && m.deployments[i].ObservedRevision < desired {
			if !validDeploymentStatus(status) {
				return ErrRevisionConflict
			}
			m.deployments[i].ObservedRevision, m.deployments[i].Status = desired, status
			return nil
		}
	}
	return ErrRevisionConflict
}

func TestModuleCatalogLifecycleAndAuthorization(t *testing.T) {
	store := &memoryStore{}
	handler := NewModule(store, "catalog-token").Handler()
	request := func(method, path, body, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if got := request(http.MethodPost, "/definitions", definitionRequestJSON("def-1", "qa", "QA"), "").Code; got != http.StatusUnauthorized {
		t.Fatalf("missing catalog token status=%d", got)
	}
	if got := request(http.MethodPost, "/definitions", definitionRequestJSON("def-1", "qa", "QA"), "catalog-token").Code; got != http.StatusCreated {
		t.Fatalf("create definition status=%d", got)
	}
	if out := request(http.MethodGet, "/definitions?limit=10", "", "catalog-token"); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"id":"def-1"`) {
		t.Fatalf("list definitions status=%d body=%s", out.Code, out.Body.String())
	}
	if out := request(http.MethodPost, "/definitions/def-1/versions", versionRequestJSON("v1", "def-1", "qa", "1.0.0"), "catalog-token"); out.Code != http.StatusCreated {
		t.Fatalf("create version status=%d body=%s", out.Code, out.Body.String())
	}
	if out := request(http.MethodGet, "/definitions/def-1/versions?limit=10", "", "catalog-token"); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"id":"v1"`) {
		t.Fatalf("list versions status=%d body=%s", out.Code, out.Body.String())
	}
	if got := request(http.MethodPost, "/versions/v1/evaluate", `{"expected_revision":1}`, "catalog-token").Code; got != http.StatusOK {
		t.Fatalf("evaluate version status=%d", got)
	}
	if got := request(http.MethodPost, "/versions/v1/publish", `{"expected_revision":2}`, "catalog-token").Code; got != http.StatusOK {
		t.Fatalf("publish version status=%d", got)
	}
	if got := request(http.MethodPost, "/definitions/def-1/evaluate", `{"expected_revision":1}`, "catalog-token").Code; got != http.StatusOK {
		t.Fatalf("evaluate definition status=%d", got)
	}
	if got := request(http.MethodPost, "/definitions/def-1/publish", `{"expected_revision":2}`, "catalog-token").Code; got != http.StatusOK {
		t.Fatalf("publish definition status=%d", got)
	}
	if got := request(http.MethodPost, "/installations", installationRequestJSON("install-1", "tenant-a", "risk", "app", "qa", "v1"), "catalog-token").Code; got != http.StatusCreated {
		t.Fatalf("create installation status=%d", got)
	}
	if out := request(http.MethodGet, "/installations?tenant_id=tenant-a&department_id=risk&application_id=app&limit=10", "", "catalog-token"); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"id":"install-1"`) {
		t.Fatalf("list installations status=%d body=%s", out.Code, out.Body.String())
	}
	if out := request(http.MethodPost, "/installations/install-1/transition", `{"from":"provisioning","to":"active","expected_revision":1}`, "catalog-token"); out.Code != http.StatusConflict || !strings.Contains(out.Body.String(), "DEPLOYMENT_NOT_READY") {
		t.Fatalf("activation without observed ready deployment status=%d body=%s", out.Code, out.Body.String())
	}
	deployment, _ := json.Marshal(struct {
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
	}{"deployment-1", "tenant-a", "risk", "app", "v1", "install-1", store.version.ArtifactDigest, store.version.ManifestHash, "http", "http://qa:8080", json.RawMessage(`{"region":"default"}`), json.RawMessage(`{"cpu":1}`), DeploymentPending, 0})
	deploymentBody := string(deployment)
	var mismatchedVersion map[string]any
	if err := json.Unmarshal(deployment, &mismatchedVersion); err != nil {
		t.Fatal(err)
	}
	mismatchedVersion["agent_version_id"] = "another-version"
	mismatchedBody, _ := json.Marshal(mismatchedVersion)
	if out := request(http.MethodPost, "/installations/install-1/deployments", string(mismatchedBody), "catalog-token"); out.Code != http.StatusBadRequest {
		t.Fatalf("deployment for a version other than the installation's selected version must fail: status=%d body=%s", out.Code, out.Body.String())
	}
	if created := request(http.MethodPost, "/installations/install-1/deployments", deploymentBody, "catalog-token"); created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"desired_revision":1`) {
		t.Fatalf("create deployment must allocate and return server revision 1: status=%d body=%s", created.Code, created.Body.String())
	}
	if got := request(http.MethodPost, "/installations/install-1/deployments/deployment-1/observe", `{"desired_revision":1,"status":"ready"}`, "catalog-token").Code; got != http.StatusOK {
		t.Fatalf("observe deployment status=%d", got)
	}
	if got := request(http.MethodGet, "/installations/install-1/deployments?tenant_id=tenant-a&department_id=risk&application_id=app", "", "catalog-token").Code; got != http.StatusOK {
		t.Fatalf("list deployments status=%d", got)
	}
	if got := request(http.MethodPost, "/installations/install-1/transition", `{"from":"provisioning","to":"active","expected_revision":1}`, "catalog-token").Code; got != http.StatusOK {
		t.Fatalf("activate installation after observed ready deployment status=%d", got)
	}
	if got := request(http.MethodPost, "/installations/install-1/transition", `{"from":"active","to":"suspended","expected_revision":2}`, "catalog-token").Code; got != http.StatusOK {
		t.Fatalf("suspend installation status=%d", got)
	}
	if got := request(http.MethodPost, "/installations/install-1/rollback", `{"version_id":"v1","expected_revision":3}`, "catalog-token").Code; got != http.StatusOK {
		t.Fatalf("rollback installation status=%d", got)
	}
	if got := request(http.MethodPost, "/installations/install-1/transition", `{"from":"suspended","to":"uninstalling","expected_revision":4}`, "catalog-token").Code; got != http.StatusOK {
		t.Fatalf("uninstall transition status=%d", got)
	}
	if got := request(http.MethodGet, "/installations/missing", "", "catalog-token").Code; got != http.StatusNotFound {
		t.Fatalf("missing installation status=%d", got)
	}
}

func TestLatestDeploymentReadyForActivationUsesExactScopeVersionAndRevision(t *testing.T) {
	installation := Installation{ID: "i-1", TenantID: "tenant-1", DepartmentID: "dept-1", ApplicationID: "app-1", VersionID: "v-1"}
	ready := Deployment{ID: "d-1", TenantID: "tenant-1", DepartmentID: "dept-1", ApplicationID: "app-1", AgentVersionID: "v-1", AgentInstallationID: "i-1", Status: DeploymentReady, DesiredRevision: 1, ObservedRevision: 1}
	if !latestDeploymentReadyForActivation(installation, []Deployment{ready}) {
		t.Fatal("the current exact-scope observed-ready deployment should allow activation")
	}
	pending := ready
	pending.ID, pending.DesiredRevision, pending.ObservedRevision, pending.Status = "d-2", 2, 1, DeploymentPending
	if latestDeploymentReadyForActivation(installation, []Deployment{ready, pending}) {
		t.Fatal("an older ready deployment must not bypass a newer pending revision")
	}
	wrongVersion := ready
	wrongVersion.AgentVersionID = "v-old"
	if latestDeploymentReadyForActivation(installation, []Deployment{wrongVersion}) {
		t.Fatal("deployment for a different installation version must not allow activation")
	}
	wrongScope := ready
	wrongScope.TenantID = "other-tenant"
	if latestDeploymentReadyForActivation(installation, []Deployment{wrongScope}) {
		t.Fatal("deployment from another scope must not allow activation")
	}
	staleObservation := ready
	staleObservation.DesiredRevision, staleObservation.ObservedRevision = 2, 1
	if latestDeploymentReadyForActivation(installation, []Deployment{staleObservation}) {
		t.Fatal("a stale observed revision must not allow activation")
	}
}

func TestModuleRejectsUnknownJSONAndRevisionConflict(t *testing.T) {
	store := &memoryStore{}
	handler := NewModule(store, "token").Handler()
	req := httptest.NewRequest(http.MethodPost, "/definitions", strings.NewReader(`{"id":"def","publisher_id":"p","agent_key":"a","display_name":"A","description":"description","status":"draft","revision":1,"unexpected":true}`))
	req.Header.Set("Authorization", "Bearer token")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != http.StatusBadRequest {
		t.Fatalf("unknown JSON status=%d", out.Code)
	}
	if !errors.Is((&memoryStore{}).TransitionVersion(context.Background(), "missing", DefinitionDraft, DefinitionEvaluated, 1), ErrRevisionConflict) {
		t.Fatal("memory port must preserve CAS conflict")
	}
}

func TestModuleDoesNotAllowClientsToSkipDraftOrProvisioningStates(t *testing.T) {
	store := &memoryStore{}
	handler := NewModule(store, "token").Handler()
	request := func(path, body string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer token")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out.Code
	}
	if got := request("/definitions", `{"id":"def","publisher_id":"p","agent_key":"a","display_name":"A","description":"description","status":"published","revision":1}`); got != http.StatusBadRequest {
		t.Fatalf("published definition must not bypass evaluation: %d", got)
	}
	if got := request("/definitions", `{"id":"def","publisher_id":"p","agent_key":"a","display_name":"A","description":"description","status":"draft","revision":2}`); got != http.StatusBadRequest {
		t.Fatalf("new definition must start at revision one: %d", got)
	}
	if got := request("/installations", `{"id":"i","tenant_id":"t","department_id":"d","application_id":"a","agent_id":"agent","version_id":"v","display_name":"Agent","deployment_mode":"managed","drain_policy":"wait","retention_policy_id":"default","status":"active","revision":1}`); got != http.StatusBadRequest {
		t.Fatalf("installation must start provisioning: %d", got)
	}
}

func TestBrowserAvailableAgentsUseTrustedScopeAndIdentityDiscoverGrant(t *testing.T) {
	store := &memoryStore{availableAgents: []AvailableAgent{{AgentID: "ticket-assistant", Name: "校验执行 Agent", SemanticVersion: "0.1.0", VersionID: "version:check", InstallationID: "installation:check"}}}
	access := &agentAccessChecker{allowed: true}
	module := NewModule(store, "catalog-token")
	module.SetAgentAccessChecker(access)
	module.SetControlAuthorizer(controlAuthorizerFunc(func(_ context.Context, actor ControlActor, action ControlAction, scope ControlScope) error {
		if action != ControlRequestable || actor.PrincipalID != "alice" || scope != (ControlScope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}) {
			t.Fatalf("requestable catalog must use trusted scope: actor=%+v action=%s scope=%+v", actor, action, scope)
		}
		return nil
	}))
	handler := module.Handler()
	request := httptest.NewRequest(http.MethodGet, "/available?tenant_id=attacker-tenant", nil)
	request.Header.Set("X-Internal-Token", "catalog-token")
	request.Header.Set("X-Browser-Module", "1")
	request.Header.Set("X-Principal-Type", "user")
	request.Header.Set("X-Principal-ID", "alice")
	request.Header.Set("X-Tenant-ID", "tenant-a")
	request.Header.Set("X-Department-ID", "dept-a")
	request.Header.Set("X-Application-ID", "app-a")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("available agents status=%d body=%s", response.Code, response.Body.String())
	}
	if store.lastAvailableScope != [3]string{"tenant-a", "dept-a", "app-a"} {
		t.Fatalf("caller scope was not used: %+v", store.lastAvailableScope)
	}
	if len(access.args) != 6 || access.args[0] != "tenant-a" || access.args[1] != "dept-a" || access.args[2] != "app-a" || access.args[3] != "installation:check" || access.args[4] != "user" || access.args[5] != "alice" {
		t.Fatalf("identity grant check did not use trusted principal/scope: %#v", access.args)
	}
	if !strings.Contains(response.Body.String(), `"access_status":"granted"`) || !strings.Contains(response.Body.String(), `"agent_id":"ticket-assistant"`) || !strings.Contains(response.Body.String(), `"version_id":"version:check"`) {
		t.Fatalf("browser projection missing granted agent: %s", response.Body.String())
	}
}

func TestBrowserAvailableAgentsFailClosedWithoutTrustedBrowserOrIdentityPort(t *testing.T) {
	store := &memoryStore{availableAgents: []AvailableAgent{{AgentID: "agent", InstallationID: "install"}}}
	module := NewModule(store, "catalog-token")
	handler := module.Handler()
	request := httptest.NewRequest(http.MethodGet, "/available", nil)
	request.Header.Set("X-Internal-Token", "catalog-token")
	request.Header.Set("X-Principal-Type", "user")
	request.Header.Set("X-Principal-ID", "alice")
	request.Header.Set("X-Tenant-ID", "tenant-a")
	request.Header.Set("X-Department-ID", "dept-a")
	request.Header.Set("X-Application-ID", "app-a")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unmarked request status=%d body=%s", response.Code, response.Body.String())
	}
	if store.lastAvailableScope != [3]string{} {
		t.Fatalf("untrusted request reached Catalog store: %+v", store.lastAvailableScope)
	}

	request = httptest.NewRequest(http.MethodGet, "/available", nil)
	request.Header.Set("X-Internal-Token", "catalog-token")
	request.Header.Set("X-Browser-Module", "1")
	request.Header.Set("X-Principal-Type", "user")
	request.Header.Set("X-Principal-ID", "alice")
	request.Header.Set("X-Tenant-ID", "tenant-a")
	request.Header.Set("X-Department-ID", "dept-a")
	request.Header.Set("X-Application-ID", "app-a")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing identity access adapter status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestBrowserCannotUseCatalogControlPlaneWithGatewayInternalToken(t *testing.T) {
	store := &memoryStore{}
	module := NewModule(store, "catalog-token")
	request := httptest.NewRequest(http.MethodPost, "/definitions", strings.NewReader(definitionRequestJSON("def", "a", "Agent")))
	request.Header.Set("X-Internal-Token", "catalog-token")
	request.Header.Set("X-Browser-Module", "1")
	response := httptest.NewRecorder()
	module.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "FORBIDDEN") {
		t.Fatalf("browser control-plane mutation status=%d body=%s", response.Code, response.Body.String())
	}
	if store.definition.ID != "" {
		t.Fatal("browser request without trusted principal fields reached the catalog store")
	}

	request = httptest.NewRequest(http.MethodPost, "/definitions", strings.NewReader(definitionRequestJSON("def", "a", "Agent")))
	request.Header.Set("X-Internal-Token", "catalog-token")
	request.Header.Set("X-Browser-Module", "1")
	request.Header.Set("X-Principal-Type", "user")
	request.Header.Set("X-Principal-ID", "alice")
	request.Header.Set("X-Tenant-ID", "tenant-a")
	request.Header.Set("X-Department-ID", "dept-a")
	request.Header.Set("X-Application-ID", "app-a")
	response = httptest.NewRecorder()
	module.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "CATALOG_AUTHORIZATION_UNAVAILABLE") {
		t.Fatalf("missing control authorizer status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestBrowserCatalogControlRequiresAuthoritativeRoleAndScopedList(t *testing.T) {
	store := &memoryStore{installations: []Installation{
		{ID: "in-scope", TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentID: "qa", VersionID: "v1", Status: InstallationActive, Revision: 1},
		{ID: "other-app", TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-b", AgentID: "qa", VersionID: "v1", Status: InstallationActive, Revision: 1},
	}}
	module := NewModule(store, "catalog-token")
	var authorizedActor ControlActor
	var authorizedScope ControlScope
	var authorizedAction ControlAction
	module.SetControlAuthorizer(controlAuthorizerFunc(func(_ context.Context, actor ControlActor, action ControlAction, scope ControlScope) error {
		authorizedActor, authorizedAction, authorizedScope = actor, action, scope
		if actor.PrincipalID != "platform.user" || action != ControlRead || scope != (ControlScope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}) {
			return ErrCatalogForbidden
		}
		return nil
	}))
	handler := module.Handler()
	request := func(appID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/installations?tenant_id=tenant-a&department_id=dept-a&application_id="+appID, nil)
		req.Header.Set("X-Internal-Token", "catalog-token")
		req.Header.Set("X-Browser-Module", "1")
		req.Header.Set("X-Principal-Type", "user")
		req.Header.Set("X-Principal-ID", "platform.user")
		req.Header.Set("X-Tenant-ID", "tenant-a")
		req.Header.Set("X-Department-ID", "dept-a")
		req.Header.Set("X-Application-ID", "app-a")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	response := request("app-a")
	if response.Code != http.StatusOK {
		t.Fatalf("scoped installation list status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "other-app") || !strings.Contains(response.Body.String(), "in-scope") {
		t.Fatalf("installation list escaped scope: %s", response.Body.String())
	}
	if authorizedActor.PrincipalID != "platform.user" || authorizedAction != ControlRead || authorizedScope.ApplicationID != "app-a" {
		t.Fatalf("control authorizer did not receive trusted actor/scope: actor=%+v action=%s scope=%+v", authorizedActor, authorizedAction, authorizedScope)
	}
	response = request("app-b")
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-application installation list status=%d body=%s", response.Code, response.Body.String())
	}
	requestByID := httptest.NewRequest(http.MethodGet, "/installations/other-app", nil)
	requestByID.Header.Set("X-Internal-Token", "catalog-token")
	requestByID.Header.Set("X-Browser-Module", "1")
	requestByID.Header.Set("X-Principal-Type", "user")
	requestByID.Header.Set("X-Principal-ID", "platform.user")
	requestByID.Header.Set("X-Tenant-ID", "tenant-a")
	requestByID.Header.Set("X-Department-ID", "dept-a")
	requestByID.Header.Set("X-Application-ID", "app-a")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, requestByID)
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "other-app") {
		t.Fatalf("cross-application installation IDOR must be hidden: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestScopedInstallableCatalogHidesDraftsAndRawVersionPayloads(t *testing.T) {
	store := &memoryStore{
		definitions: []Definition{
			{ID: "published-def", PublisherID: "platform", AgentKey: "qa", DisplayName: "Published QA", Description: "available", Status: DefinitionPublished, Revision: 2},
			{ID: "draft-def", PublisherID: "platform", AgentKey: "internal", DisplayName: "Draft", Description: "not available", Status: DefinitionDraft, Revision: 1},
		},
		publishedVersions: []PublishedVersion{
			{ID: "published-v1", DefinitionID: "published-def", SemanticVersion: "1.0.0", ManifestHash: "sha256:public", ArtifactDigest: "sha256:artifact", Status: DefinitionPublished, Revision: 2},
			{ID: "draft-v2", DefinitionID: "published-def", SemanticVersion: "2.0.0", ManifestHash: "sha256:draft", ArtifactDigest: "sha256:draft-artifact", Status: DefinitionDraft, Revision: 1},
		},
	}
	module := NewModule(store, "catalog-token")
	module.SetControlAuthorizer(controlAuthorizerFunc(func(_ context.Context, actor ControlActor, action ControlAction, scope ControlScope) error {
		if actor.PrincipalID != "app.admin" || action != ControlRead || scope != (ControlScope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}) {
			return ErrCatalogForbidden
		}
		return nil
	}))
	handler := module.Handler()
	request := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer catalog-token")
		req.Header.Set("X-Browser-Module", "1")
		req.Header.Set("X-Principal-Type", "user")
		req.Header.Set("X-Principal-ID", "app.admin")
		req.Header.Set("X-Tenant-ID", "tenant-a")
		req.Header.Set("X-Department-ID", "dept-a")
		req.Header.Set("X-Application-ID", "app-a")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	scope := "?tenant_id=tenant-a&department_id=dept-a&application_id=app-a&limit=10"
	definitions := request("/available-definitions" + scope)
	if definitions.Code != http.StatusOK || !strings.Contains(definitions.Body.String(), "published-def") || strings.Contains(definitions.Body.String(), "draft-def") {
		t.Fatalf("installable definitions must include published items only: status=%d body=%s", definitions.Code, definitions.Body.String())
	}
	versions := request("/available-definitions/published-def/versions" + scope)
	if versions.Code != http.StatusOK || !strings.Contains(versions.Body.String(), "published-v1") || strings.Contains(versions.Body.String(), "draft-v2") || strings.Contains(versions.Body.String(), "manifest\"") {
		t.Fatalf("installable versions must be published metadata only: status=%d body=%s", versions.Code, versions.Body.String())
	}
	denied := request("/available-definitions?tenant_id=tenant-a&department_id=dept-a&application_id=app-b&limit=10")
	if denied.Code != http.StatusForbidden {
		t.Fatalf("cross-application installable catalog status=%d body=%s", denied.Code, denied.Body.String())
	}
}

func TestBrowserCatalogAllowsTenantWideInstallationsOnlyWhenAuthorizerAllows(t *testing.T) {
	store := &memoryStore{installations: []Installation{
		{ID: "app-a-install", TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentID: "qa", VersionID: "v1", Status: InstallationActive, Revision: 1},
		{ID: "app-b-install", TenantID: "tenant-a", DepartmentID: "dept-b", ApplicationID: "app-b", AgentID: "validation", VersionID: "v1", Status: InstallationActive, Revision: 1},
	}}
	module := NewModule(store, "catalog-token")
	module.SetControlAuthorizer(controlAuthorizerFunc(func(_ context.Context, actor ControlActor, action ControlAction, scope ControlScope) error {
		if actor.PrincipalID == "platform.user" && action == ControlRead && scope == (ControlScope{TenantID: "tenant-a"}) {
			return nil
		}
		return ErrCatalogForbidden
	}))
	request := httptest.NewRequest(http.MethodGet, "/installations?tenant_id=tenant-a&limit=100", nil)
	request.Header.Set("X-Internal-Token", "catalog-token")
	request.Header.Set("X-Browser-Module", "1")
	request.Header.Set("X-Principal-Type", "user")
	request.Header.Set("X-Principal-ID", "platform.user")
	request.Header.Set("X-Tenant-ID", "tenant-a")
	request.Header.Set("X-Department-ID", "dept-platform")
	request.Header.Set("X-Application-ID", "app-platform")
	response := httptest.NewRecorder()
	module.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "app-a-install") || !strings.Contains(response.Body.String(), "app-b-install") {
		t.Fatalf("tenant-wide catalog list status=%d body=%s", response.Code, response.Body.String())
	}
	for _, target := range []string{"", "?tenant_id=tenant-a&department_id=dept-a", "?department_id=dept-a&application_id=app-a"} {
		bad := httptest.NewRequest(http.MethodGet, "/installations"+target, nil)
		bad.Header.Set("X-Internal-Token", "catalog-token")
		out := httptest.NewRecorder()
		module.Handler().ServeHTTP(out, bad)
		if out.Code != http.StatusBadRequest {
			t.Fatalf("invalid catalog list scope %q status=%d body=%s", target, out.Code, out.Body.String())
		}
	}
}

func TestModuleRejectsInstallationOutsideIdentityScope(t *testing.T) {
	store := &memoryStore{}
	handler := NewModuleWithScopeValidator(store, "token", scopeValidator{err: errors.New("inactive application")}).Handler()
	req := httptest.NewRequest(http.MethodPost, "/installations", strings.NewReader(installationRequestJSON("i", "t", "d", "a", "agent", "v")))
	req.Header.Set("Authorization", "Bearer token")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), "CATALOG_CONTRACT_VIOLATION") {
		t.Fatalf("identity scope rejection status=%d body=%s", out.Code, out.Body.String())
	}
}

func TestResolveMachineAgentTargetRequiresExactActivePublishedReadyDeployment(t *testing.T) {
	store := &memoryStore{
		definition:   Definition{ID: "definition-a", AgentKey: "example-agent", Status: DefinitionPublished},
		version:      Version{ID: "version-a", DefinitionID: "definition-a", Status: DefinitionPublished, Manifest: json.RawMessage(`{"manifest_version":"agent-manifest/v1","agent_id":"example-agent","version":"1.0.0","schemas":{"input":"schema://example-agent/input/v1"}}`)},
		installation: Installation{ID: "installation-a", TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", AgentID: "example-agent", VersionID: "version-a", Status: InstallationActive, Revision: 7},
		deployments:  []Deployment{{ID: "deployment-a", TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", AgentInstallationID: "installation-a", AgentVersionID: "version-a", Transport: "http", EndpointRef: "http://validation-agent:8001", Status: DeploymentReady, DesiredRevision: 3, ObservedRevision: 3}},
	}
	module := NewModule(store, "internal-token")
	scope := sharedkernel.Scope{TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", AgentInstanceID: "installation-a", PrincipalID: "external-system", PrincipalType: "service_principal"}
	target, err := module.ResolveMachineAgentTarget(context.Background(), scope)
	if err != nil {
		t.Fatalf("resolve ready target: %v", err)
	}
	if target.AgentID != "example-agent" || target.VersionID != "version-a" || target.InstallationID != "installation-a" || target.InputSchemaURI != "schema://example-agent/input/v1" || target.Endpoint != "http://validation-agent:8001" || target.Revision != 7 {
		t.Fatalf("resolved target = %+v", target)
	}

	crossScope := scope
	crossScope.ApplicationID = "application-b"
	if _, err := module.ResolveMachineAgentTarget(context.Background(), crossScope); err == nil {
		t.Fatal("cross-application machine scope must not resolve an installation")
	}

	store.deployments = append(store.deployments, Deployment{ID: "deployment-b", TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", AgentInstallationID: "installation-a", AgentVersionID: "version-a", Transport: "http", EndpointRef: "http://new-validation-agent:8001", Status: DeploymentPending, DesiredRevision: 4, ObservedRevision: 3})
	if _, err := module.ResolveMachineAgentTarget(context.Background(), scope); err == nil {
		t.Fatal("latest pending deployment must block fallback to the old ready endpoint")
	}
}

func TestModuleExposesDefinitionLifecycleAndUninstallCAS(t *testing.T) {
	store := &memoryStore{definition: Definition{ID: "def", PublisherID: "p", AgentKey: "a", DisplayName: "A", Description: "Definition", Status: DefinitionDraft, Revision: 1}, installation: Installation{ID: "install", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "a", VersionID: "v", DisplayName: "A", DeploymentMode: "managed", DrainPolicy: "wait", RetentionPolicyID: "default", Status: InstallationActive, Revision: 3}}
	handler := NewModule(store, "token").Handler()
	request := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer token")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if out := request("/definitions/def/evaluate", `{"expected_revision":1}`); out.Code != http.StatusOK || store.definition.Status != DefinitionEvaluated {
		t.Fatalf("definition evaluate status=%d body=%s state=%+v", out.Code, out.Body.String(), store.definition)
	}
	if out := request("/definitions/def/publish", `{"expected_revision":2}`); out.Code != http.StatusOK || store.definition.Status != DefinitionPublished {
		t.Fatalf("definition publish status=%d body=%s state=%+v", out.Code, out.Body.String(), store.definition)
	}
	if out := request("/definitions/def/disable", `{"expected_revision":1}`); out.Code != http.StatusConflict {
		t.Fatalf("stale definition revision status=%d body=%s", out.Code, out.Body.String())
	}
	if out := request("/installations/install/uninstall", `{"expected_revision":3}`); out.Code != http.StatusOK || store.installation.Status != InstallationUninstalling {
		t.Fatalf("uninstall status=%d body=%s state=%+v", out.Code, out.Body.String(), store.installation)
	}
}

func TestAvailableCatalogStopsBeforeStoreOnMembershipDenialOrOutage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure error
		code    int
	}{
		{"member revoked", ErrCatalogForbidden, http.StatusForbidden},
		{"policy outage", errors.New("policy unavailable"), http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &memoryStore{}
			module := NewModule(store, "catalog-token")
			access := &agentAccessChecker{}
			module.SetAgentAccessChecker(access)
			module.SetControlAuthorizer(controlAuthorizerFunc(func(context.Context, ControlActor, ControlAction, ControlScope) error { return tc.failure }))
			request := httptest.NewRequest(http.MethodGet, "/available", nil)
			for key, value := range map[string]string{"X-Internal-Token": "catalog-token", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": "alice", "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a"} {
				request.Header.Set(key, value)
			}
			response := httptest.NewRecorder()
			module.Handler().ServeHTTP(response, request)
			if response.Code != tc.code || store.lastAvailableScope != ([3]string{}) || len(access.args) != 0 {
				t.Fatalf("denied request reached catalog: code=%d scope=%v args=%v", response.Code, store.lastAvailableScope, access.args)
			}
		})
	}
}
