package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type memoryStore struct {
	tenant              Tenant
	department          Department
	application         Application
	applications        []Application
	principal           Principal
	principals          []Principal
	grants              []Grant
	agentAccessRequests []AgentAccessRequest
	machineCredentials  map[string]MachineCredential
	machineTokens       map[string]MachineAccessToken
}

func (m *memoryStore) EnsureSchema(context.Context) error { return nil }
func (m *memoryStore) Ping(context.Context) error         { return nil }
func (m *memoryStore) CreateTenant(_ context.Context, value Tenant) error {
	if err := value.Validate(); err != nil {
		return err
	}
	m.tenant = value
	return nil
}
func (m *memoryStore) CreateDepartment(_ context.Context, value Department) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if m.tenant.ID != value.TenantID {
		return ErrTenantNotFound
	}
	m.department = value
	return nil
}
func (m *memoryStore) CreateApplication(_ context.Context, value Application) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if m.department.ID != value.DepartmentID || m.department.TenantID != value.TenantID {
		return ErrDepartmentNotFound
	}
	m.application = value
	m.applications = append(m.applications, value)
	return nil
}
func (m *memoryStore) CreatePrincipal(_ context.Context, value Principal) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.Revision == 0 {
		value.Revision = 1
	}
	m.principals = append(m.principals, value)
	if m.principal.ID == "" {
		m.principal = value
	}
	return nil
}

func (m *memoryStore) DisablePrincipal(_ context.Context, scope sharedkernel.Scope, id string, expected uint64) (Principal, error) {
	for index := range m.principals {
		value := &m.principals[index]
		if value.ID != id || value.Type != PrincipalUser || value.TenantID != scope.TenantID {
			continue
		}
		if !value.IsActive || value.Revision != expected {
			return Principal{}, ErrIdentityConflict
		}
		value.IsActive = false
		value.Revision++
		return *value, nil
	}
	return Principal{}, ErrPrincipalNotFound
}
func (m *memoryStore) GetPrincipal(_ context.Context, typ PrincipalType, id string) (Principal, error) {
	if m.principal.Type == typ && m.principal.ID == id {
		return m.principal, nil
	}
	for _, principal := range m.principals {
		if principal.Type == typ && principal.ID == id {
			return principal, nil
		}
	}
	return Principal{}, ErrPrincipalNotFound
}
func (m *memoryStore) CreateGrant(_ context.Context, value Grant) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if m.application.ID != value.ApplicationID || m.application.TenantID != value.TenantID || m.application.DepartmentID != value.DepartmentID {
		return ErrApplicationNotFound
	}
	m.grants = append(m.grants, value)
	return nil
}
func (m *memoryStore) ListGrants(_ context.Context, tenant, department, application, installation string, typ PrincipalType, subject, action string) ([]Grant, error) {
	result := make([]Grant, 0)
	for _, value := range m.grants {
		if value.TenantID == tenant && value.DepartmentID == department && value.ApplicationID == application && value.AgentInstanceID == installation && value.SubjectType == typ && value.SubjectID == subject && value.Action == action {
			result = append(result, value)
		}
	}
	return result, nil
}

func (m *memoryStore) RevokeGrant(_ context.Context, tenant, department, application, installation, id string, expected uint64) error {
	for index := range m.grants {
		grant := &m.grants[index]
		if grant.ID != id || grant.TenantID != tenant || grant.DepartmentID != department || grant.ApplicationID != application || grant.AgentInstanceID != installation {
			continue
		}
		if grant.Status != GrantActive || grant.Revision != expected {
			return ErrIdentityConflict
		}
		grant.Status, grant.Revision = GrantRevoked, grant.Revision+1
		return nil
	}
	return ErrGrantNotFound
}

func (m *memoryStore) ListTenants(_ context.Context, tenantID, status string) ([]Tenant, error) {
	if m.tenant.ID == tenantID && (status == "" || m.tenant.Status == status) {
		return []Tenant{m.tenant}, nil
	}
	return []Tenant{}, nil
}
func (m *memoryStore) ListDepartments(_ context.Context, tenantID, departmentID, status string) ([]Department, error) {
	if m.department.TenantID == tenantID && (departmentID == "" || m.department.ID == departmentID) && (status == "" || m.department.Status == status) {
		return []Department{m.department}, nil
	}
	return []Department{}, nil
}
func (m *memoryStore) ListApplications(_ context.Context, tenantID, departmentID, applicationID, status string) ([]Application, error) {
	items := append([]Application(nil), m.applications...)
	if len(items) == 0 && m.application.ID != "" {
		items = append(items, m.application)
	}
	result := make([]Application, 0, len(items))
	for _, item := range items {
		if item.TenantID == tenantID && (departmentID == "" || item.DepartmentID == departmentID) && (applicationID == "" || item.ID == applicationID) && (status == "" || item.Status == status) {
			result = append(result, item)
		}
	}
	return result, nil
}

func identityTestPage[T any](items []T, page, size int) OrganizationPage[T] {
	start := (page - 1) * size
	if start > len(items) {
		start = len(items)
	}
	end := start + size
	if end > len(items) {
		end = len(items)
	}
	return OrganizationPage[T]{Items: append([]T(nil), items[start:end]...), Total: int64(len(items)), Page: page, PageSize: size}
}

func (m *memoryStore) PageTenants(ctx context.Context, tenantID, status string, page, size int) (OrganizationPage[Tenant], error) {
	items, err := m.ListTenants(ctx, tenantID, status)
	if err != nil {
		return OrganizationPage[Tenant]{}, err
	}
	return identityTestPage(items, page, size), nil
}
func (m *memoryStore) PageDepartments(ctx context.Context, tenantID, departmentID, status string, page, size int) (OrganizationPage[Department], error) {
	items, err := m.ListDepartments(ctx, tenantID, departmentID, status)
	if err != nil {
		return OrganizationPage[Department]{}, err
	}
	return identityTestPage(items, page, size), nil
}
func (m *memoryStore) PageApplications(ctx context.Context, tenantID, departmentID, applicationID, status string, page, size int) (OrganizationPage[Application], error) {
	items, err := m.ListApplications(ctx, tenantID, departmentID, applicationID, status)
	if err != nil {
		return OrganizationPage[Application]{}, err
	}
	return identityTestPage(items, page, size), nil
}
func (m *memoryStore) DisableApplication(_ context.Context, tenantID, departmentID, applicationID string, expected uint64) error {
	for index := range m.applications {
		item := &m.applications[index]
		if item.ID != applicationID || item.TenantID != tenantID || item.DepartmentID != departmentID {
			continue
		}
		if item.Status != "active" || item.Revision != expected {
			return ErrIdentityConflict
		}
		item.Status, item.Revision = "disabled", item.Revision+1
		if m.application.ID == item.ID {
			m.application = *item
		}
		return nil
	}
	if m.application.ID == applicationID && m.application.TenantID == tenantID && m.application.DepartmentID == departmentID {
		if m.application.Status != "active" || m.application.Revision != expected {
			return ErrIdentityConflict
		}
		m.application.Status, m.application.Revision = "disabled", m.application.Revision+1
		return nil
	}
	return ErrApplicationNotFound
}
func (m *memoryStore) ListPrincipals(_ context.Context, tenantID string, principalType PrincipalType, id string) ([]Principal, error) {
	items := append([]Principal(nil), m.principals...)
	if m.principal.ID != "" {
		items = append(items, m.principal)
	}
	result := make([]Principal, 0)
	for _, item := range items {
		if item.TenantID == tenantID && (principalType == "" || item.Type == principalType) && (id == "" || item.ID == id) {
			result = append(result, item)
		}
	}
	return result, nil
}
func (m *memoryStore) ListIdentityGrants(_ context.Context, tenant, department, application, installation string, typ PrincipalType, subject, action, status string) ([]Grant, error) {
	result := make([]Grant, 0)
	for _, item := range m.grants {
		if item.TenantID == tenant && item.DepartmentID == department && item.ApplicationID == application && (installation == "" || item.AgentInstanceID == installation) && (typ == "" || item.SubjectType == typ) && (subject == "" || item.SubjectID == subject) && (action == "" || item.Action == action) && (status == "" || item.Status == status) {
			result = append(result, item)
		}
	}
	return result, nil
}

func (m *memoryStore) CreateAgentAccessRequest(_ context.Context, request AgentAccessRequest) (AgentAccessRequest, error) {
	if err := validateAgentAccessRequest(request); err != nil {
		return AgentAccessRequest{}, err
	}
	for _, current := range m.agentAccessRequests {
		if current.Status == AgentAccessRequestPending && current.TenantID == request.TenantID && current.DepartmentID == request.DepartmentID && current.ApplicationID == request.ApplicationID && current.AgentInstanceID == request.AgentInstanceID && current.SubjectID == request.SubjectID {
			return AgentAccessRequest{}, ErrIdentityConflict
		}
	}
	request.CreatedAt, request.UpdatedAt = time.Now().UTC(), time.Now().UTC()
	m.agentAccessRequests = append(m.agentAccessRequests, request)
	return request, nil
}

func (m *memoryStore) ListAgentAccessRequests(_ context.Context, scope sharedkernel.Scope, subjectID, status string) ([]AgentAccessRequest, error) {
	items := make([]AgentAccessRequest, 0)
	for _, request := range m.agentAccessRequests {
		if request.TenantID == scope.TenantID && request.DepartmentID == scope.DepartmentID && request.ApplicationID == scope.ApplicationID && (subjectID == "" || request.SubjectID == subjectID) && (status == "" || request.Status == status) {
			items = append(items, request)
		}
	}
	return items, nil
}

func (m *memoryStore) DecideAgentAccessRequest(_ context.Context, scope sharedkernel.Scope, id, reviewerID, decision string, expected uint64, comment string) (AgentAccessRequest, error) {
	for index, request := range m.agentAccessRequests {
		if request.ID != id || request.TenantID != scope.TenantID || request.DepartmentID != scope.DepartmentID || request.ApplicationID != scope.ApplicationID {
			continue
		}
		if request.Status != AgentAccessRequestPending || request.Revision != expected {
			return AgentAccessRequest{}, ErrIdentityConflict
		}
		if request.SubjectID == reviewerID {
			return AgentAccessRequest{}, ErrAccessRequestSelfReview
		}
		if decision == AgentAccessRequestApproved {
			for _, action := range request.Actions {
				grant := Grant{ID: accessRequestGrantID(request.ID, action), TenantID: request.TenantID, DepartmentID: request.DepartmentID, ApplicationID: request.ApplicationID, AgentInstanceID: request.AgentInstanceID, SubjectType: request.SubjectType, SubjectID: request.SubjectID, Action: action, Effect: "allow", Status: GrantActive, Revision: 1}
				if err := grant.Validate(); err != nil {
					return AgentAccessRequest{}, err
				}
				m.grants = append(m.grants, grant)
			}
		}
		request.Status, request.ReviewerID, request.Comment = decision, reviewerID, comment
		request.Revision++
		request.UpdatedAt = time.Now().UTC()
		m.agentAccessRequests[index] = request
		return request, nil
	}
	return AgentAccessRequest{}, ErrAccessRequestNotFound
}

type staticAgentInstallationResolver struct {
	items map[string]AgentInstallation
}

func (r staticAgentInstallationResolver) ResolveAgentInstallation(_ context.Context, _ sharedkernel.Scope, installationID string) (AgentInstallation, error) {
	if item, ok := r.items[installationID]; ok {
		return item, nil
	}
	return AgentInstallation{}, ErrAgentInstallationNotFound
}

func machineStoreKey(tenantID, principalID string) string { return tenantID + "/" + principalID }

func (m *memoryStore) CreateMachineCredential(_ context.Context, value MachineCredential) error {
	if m.machineCredentials == nil {
		m.machineCredentials = make(map[string]MachineCredential)
	}
	key := machineStoreKey(value.TenantID, value.PrincipalID)
	if _, exists := m.machineCredentials[key]; exists {
		return ErrMachineCredentialConflict
	}
	value.NetworkCIDRs = append([]string(nil), value.NetworkCIDRs...)
	value.CreatedAt, value.UpdatedAt = time.Now().UTC(), time.Now().UTC()
	m.machineCredentials[key] = value
	return nil
}

func (m *memoryStore) GetMachineCredential(_ context.Context, tenantID, principalID string) (MachineCredential, error) {
	value, ok := m.machineCredentials[machineStoreKey(tenantID, principalID)]
	if !ok {
		return MachineCredential{}, ErrMachineCredentialNotFound
	}
	value.NetworkCIDRs = append([]string(nil), value.NetworkCIDRs...)
	return value, nil
}

func (m *memoryStore) ListMachineCredentials(_ context.Context, tenantID string) ([]MachineCredential, error) {
	result := make([]MachineCredential, 0)
	for _, value := range m.machineCredentials {
		if value.TenantID == tenantID {
			value.NetworkCIDRs = append([]string(nil), value.NetworkCIDRs...)
			result = append(result, value)
		}
	}
	return result, nil
}

func (m *memoryStore) RotateMachineCredential(_ context.Context, tenantID, principalID string, expected uint64, hash string, cidrs []string) (uint64, error) {
	key := machineStoreKey(tenantID, principalID)
	value, ok := m.machineCredentials[key]
	if !ok || value.Status != "active" || value.Revision != expected {
		return 0, ErrMachineCredentialConflict
	}
	value.SecretHash, value.NetworkCIDRs, value.Revision, value.UpdatedAt = hash, append([]string(nil), cidrs...), expected+1, time.Now().UTC()
	m.machineCredentials[key] = value
	return value.Revision, nil
}

func (m *memoryStore) DisableMachineCredential(_ context.Context, tenantID, principalID string, expected uint64) (uint64, error) {
	key := machineStoreKey(tenantID, principalID)
	value, ok := m.machineCredentials[key]
	if !ok || value.Status != "active" || value.Revision != expected {
		return 0, ErrMachineCredentialConflict
	}
	value.Status, value.Revision, value.UpdatedAt = "disabled", expected+1, time.Now().UTC()
	m.machineCredentials[key] = value
	return value.Revision, nil
}

func (m *memoryStore) CreateMachineAccessToken(_ context.Context, value MachineAccessToken) error {
	if m.machineTokens == nil {
		m.machineTokens = make(map[string]MachineAccessToken)
	}
	if _, exists := m.machineTokens[value.TokenHash]; exists {
		return ErrMachineCredentialsInvalid
	}
	value.Actions = append([]string(nil), value.Actions...)
	value.NetworkCIDRs = append([]string(nil), value.NetworkCIDRs...)
	m.machineTokens[value.TokenHash] = value
	return nil
}

func (m *memoryStore) GetMachineAccessToken(_ context.Context, hash string) (MachineAccessToken, error) {
	value, ok := m.machineTokens[hash]
	if !ok {
		return MachineAccessToken{}, ErrMachineCredentialsInvalid
	}
	value.Actions = append([]string(nil), value.Actions...)
	value.NetworkCIDRs = append([]string(nil), value.NetworkCIDRs...)
	return value, nil
}

func TestIdentityModuleEnforcesMachineAndUserGrantBoundaries(t *testing.T) {
	store := &memoryStore{}
	handler := NewModule(store, "identity-token").Handler()
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
	if got := request(http.MethodPost, "/tenants", `{"id":"tenant-a","code":"tenant-a","name":"Tenant A","status":"active","revision":1}`, "").Code; got != http.StatusUnauthorized {
		t.Fatalf("missing identity token status=%d", got)
	}
	if got := request(http.MethodPost, "/tenants", `{"id":"tenant-a","code":"tenant-a","name":"Tenant A","status":"active","revision":1}`, "identity-token").Code; got != http.StatusCreated {
		t.Fatalf("tenant status=%d", got)
	}
	if got := request(http.MethodPost, "/departments", `{"id":"dept-a","tenant_id":"tenant-a","code":"compliance","name":"Compliance","status":"active","revision":1}`, "identity-token").Code; got != http.StatusCreated {
		t.Fatalf("department status=%d", got)
	}
	if got := request(http.MethodPost, "/applications", `{"id":"app-a","tenant_id":"tenant-a","department_id":"dept-a","code":"business-app","name":"Regulatory","status":"active","revision":1}`, "identity-token").Code; got != http.StatusCreated {
		t.Fatalf("application status=%d", got)
	}
	if got := request(http.MethodPost, "/principals", `{"type":"user","id":"alice","tenant_id":"tenant-a","roles":["operator"],"is_active":true}`, "identity-token").Code; got != http.StatusCreated {
		t.Fatalf("principal status=%d", got)
	}
	if got := request(http.MethodPost, "/grants", `{"id":"grant-a","tenant_id":"tenant-a","department_id":"dept-a","application_id":"app-a","agent_instance_id":"validation-a","subject_type":"user","subject_id":"alice","action":"run","effect":"allow","status":"active","revision":1}`, "identity-token").Code; got != http.StatusCreated {
		t.Fatalf("grant status=%d", got)
	}
	allow := request(http.MethodPost, "/access/check", `{"scope":{"tenant_id":"tenant-a","department_id":"dept-a","application_id":"app-a","agent_instance_id":"validation-a"},"principal_type":"user","principal_id":"alice","action":"run"}`, "identity-token")
	if allow.Code != http.StatusOK || !strings.Contains(allow.Body.String(), `"allowed":true`) {
		t.Fatalf("allow decision status=%d body=%s", allow.Code, allow.Body.String())
	}
	deny := request(http.MethodPost, "/access/check", `{"scope":{"tenant_id":"tenant-b","department_id":"dept-a","application_id":"app-a","agent_instance_id":"validation-a"},"principal_type":"user","principal_id":"alice","action":"run"}`, "identity-token")
	if deny.Code != http.StatusOK || !strings.Contains(deny.Body.String(), `"allowed":false`) {
		t.Fatalf("cross-tenant decision status=%d body=%s", deny.Code, deny.Body.String())
	}
}

func TestApplicationDirectoryUsesScopedRolePaginationAndRevisionDisable(t *testing.T) {
	first := Application{ID: "app-a", TenantID: "tenant-a", DepartmentID: "dept-a", Code: "a", Name: "A", Status: "active", Revision: 1}
	store := &memoryStore{
		tenant:       Tenant{ID: "tenant-a", Code: "tenant-a", Name: "Tenant A", Status: "active", Revision: 1},
		department:   Department{ID: "dept-a", TenantID: "tenant-a", Code: "dept-a", Name: "Department A", Status: "active", Revision: 1},
		application:  first,
		applications: []Application{first},
		principal:    Principal{Type: PrincipalUser, ID: "dept-admin", TenantID: "tenant-a", Roles: []string{"department_admin"}, IsActive: true},
		principals:   []Principal{{Type: PrincipalUser, ID: "app-admin", TenantID: "tenant-a", Roles: []string{"application_admin"}, IsActive: true}},
	}
	handler := NewModule(store, "identity-token").Handler()
	call := func(principal Principal, method, path, body string, expected int) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setBrowserIdentityHeaders(req, principal, "dept-a", "app-a")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if out.Code != expected {
			t.Fatalf("%s %s status=%d want=%d body=%s", method, path, out.Code, expected, out.Body.String())
		}
		return out
	}
	newApp := `{"id":"app-b","tenant_id":"tenant-a","department_id":"dept-a","code":"b","name":"B","status":"active","revision":1}`
	call(store.principal, http.MethodPost, "/applications", newApp, http.StatusCreated)
	appAdmin := store.principals[0]
	if denied := call(appAdmin, http.MethodPost, "/applications", `{"id":"app-c","tenant_id":"tenant-a","department_id":"dept-a","code":"c","name":"C","status":"active","revision":1}`, http.StatusForbidden); denied == nil {
		t.Fatal("application administrator must not create a sibling application")
	}
	call(store.principal, http.MethodPost, "/applications", `{"id":"app-cross","tenant_id":"tenant-a","department_id":"dept-b","code":"x","name":"Cross scope","status":"active","revision":1}`, http.StatusForbidden)
	appAdminPage := call(appAdmin, http.MethodGet, "/applications?department_id=dept-a&page=1&page_size=10", "", http.StatusOK)
	var scopedPage OrganizationPage[Application]
	if err := json.Unmarshal(appAdminPage.Body.Bytes(), &scopedPage); err != nil {
		t.Fatal(err)
	}
	if scopedPage.Total != 1 || len(scopedPage.Items) != 1 || scopedPage.Items[0].ID != "app-a" {
		t.Fatalf("application administrator must only see its current application: %+v", scopedPage)
	}
	call(appAdmin, http.MethodGet, "/applications?department_id=dept-a&application_id=app-b", "", http.StatusForbidden)
	call(appAdmin, http.MethodPost, "/applications/app-b/disable?department_id=dept-a", `{"expected_revision":1}`, http.StatusForbidden)

	pageOne := call(store.principal, http.MethodGet, "/applications?department_id=dept-a&page=1&page_size=1", "", http.StatusOK)
	var page OrganizationPage[Application]
	if err := json.Unmarshal(pageOne.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || page.Page != 1 || page.PageSize != 1 || len(page.Items) != 1 {
		t.Fatalf("first application page contract mismatch: %+v", page)
	}
	pageTwo := call(store.principal, http.MethodGet, "/applications?department_id=dept-a&page=2&page_size=1", "", http.StatusOK)
	var next OrganizationPage[Application]
	if err := json.Unmarshal(pageTwo.Body.Bytes(), &next); err != nil {
		t.Fatal(err)
	}
	if next.Total != 2 || next.Page != 2 || len(next.Items) != 1 || next.Items[0].ID == page.Items[0].ID {
		t.Fatalf("second application page did not advance: first=%+v second=%+v", page, next)
	}
	call(store.principal, http.MethodGet, "/applications?department_id=dept-a&page=1&page_size=101", "", http.StatusBadRequest)

	disabled := call(store.principal, http.MethodPost, "/applications/app-b/disable?department_id=dept-a", `{"expected_revision":1}`, http.StatusOK)
	if !strings.Contains(disabled.Body.String(), `"status":"disabled"`) || !strings.Contains(disabled.Body.String(), `"revision":2`) {
		t.Fatalf("disable result missing new state: %s", disabled.Body.String())
	}
	call(store.principal, http.MethodPost, "/applications/app-b/disable?department_id=dept-a", `{"expected_revision":1}`, http.StatusConflict)
}

func TestIdentityModuleRejectsUnknownJSON(t *testing.T) {
	handler := NewModule(&memoryStore{}, "token").Handler()
	req := httptest.NewRequest(http.MethodPost, "/tenants", strings.NewReader(`{"id":"t","code":"t","name":"T","status":"active","revision":1,"unexpected":true}`))
	req.Header.Set("Authorization", "Bearer token")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != http.StatusBadRequest {
		t.Fatalf("unknown JSON status=%d", out.Code)
	}
}

func TestMachineCredentialHTTPExchangeAndRotationRevokesIssuedToken(t *testing.T) {
	store := &memoryStore{
		tenant:      Tenant{ID: "tenant-a", Code: "tenant-a", Name: "Tenant A", Status: "active", Revision: 1},
		department:  Department{ID: "dept-a", TenantID: "tenant-a", Code: "compliance", Name: "Compliance", Status: "active", Revision: 1},
		application: Application{ID: "app-a", TenantID: "tenant-a", DepartmentID: "dept-a", Code: "business-app", Name: "Regulatory", Status: "active", Revision: 1},
		principals:  []Principal{{Type: PrincipalServicePrincipal, ID: "external-system-a", TenantID: "tenant-a", IsActive: true}},
		grants: []Grant{{ID: "grant-a", TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentInstanceID: "validation-installation-a",
			SubjectType: PrincipalServicePrincipal, SubjectID: "external-system-a", Action: "run", Effect: "allow", Status: GrantActive, Revision: 1}},
	}
	handler := NewModule(store, "internal-platform-token").Handler()
	adminScopeHeaders := map[string]string{
		"X-Tenant-ID": "tenant-a", "X-Department-ID": "dept-a", "X-Application-ID": "app-a",
		"X-Principal-Type": string(PrincipalUser), "X-Principal-ID": "platform-admin",
	}
	call := func(method, path, body, remote string, headers map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		if remote != "" {
			req.RemoteAddr = remote
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	createHeaders := map[string]string{"Authorization": "Bearer internal-platform-token"}
	for key, value := range adminScopeHeaders {
		createHeaders[key] = value
	}
	created := call(http.MethodPost, "/machine-credentials", `{"principal_id":"external-system-a","network_cidrs":["127.0.0.1/32"]}`, "", createHeaders)
	if created.Code != http.StatusCreated {
		t.Fatalf("create credential status=%d body=%s", created.Code, created.Body.String())
	}
	var credential machineCredentialMutationResponse
	if err := json.Unmarshal(created.Body.Bytes(), &credential); err != nil {
		t.Fatal(err)
	}
	if credential.ClientSecret == "" || credential.Revision != 1 {
		t.Fatalf("one-time credential response missing secret/revision: %+v", credential)
	}
	if strings.Contains(created.Body.String(), digestMachineValue(credential.ClientSecret)) {
		t.Fatal("response unexpectedly exposed the stored secret hash")
	}

	issueBody, err := json.Marshal(MachineTokenIssueRequest{
		GrantType: "client_credentials", TenantID: "tenant-a", ClientID: credential.ClientID, ClientSecret: credential.ClientSecret,
		Scope: MachineGrantScope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentInstanceID: "validation-installation-a", Actions: []string{"run"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	issued := call(http.MethodPost, "/oauth/token", string(issueBody), "127.0.0.1:41414", nil)
	if issued.Code != http.StatusOK || issued.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("token exchange status=%d headers=%v body=%s", issued.Code, issued.Header(), issued.Body.String())
	}
	var token MachineTokenIssueResponse
	if err := json.Unmarshal(issued.Body.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	if token.AccessToken == "" || token.ExpiresIn != int(machineAccessTokenTTL.Seconds()) {
		t.Fatalf("invalid token response: %+v", token)
	}
	identityModule := NewModule(store, "internal-platform-token")
	if _, err := identityModule.AuthenticateMachineToken(context.Background(), token.AccessToken, "127.0.0.1:41414", "run"); err != nil {
		t.Fatalf("issued token should authenticate before rotation: %v", err)
	}

	rotatedHeaders := map[string]string{"Authorization": "Bearer internal-platform-token"}
	for key, value := range adminScopeHeaders {
		rotatedHeaders[key] = value
	}
	rotated := call(http.MethodPost, "/machine-credentials/external-system-a/rotate", `{"expected_revision":1,"network_cidrs":["127.0.0.1/32"]}`, "", rotatedHeaders)
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate credential status=%d body=%s", rotated.Code, rotated.Body.String())
	}
	if _, err := identityModule.AuthenticateMachineToken(context.Background(), token.AccessToken, "127.0.0.1:41414", "run"); err == nil {
		t.Fatal("credential rotation must immediately invalidate previously issued tokens")
	}
}

func TestMachineTokenExchangeRejectsUnapprovedInstallationAndSourceNetwork(t *testing.T) {
	store := &memoryStore{
		principals: []Principal{{Type: PrincipalServicePrincipal, ID: "external-system-a", TenantID: "tenant-a", IsActive: true}},
		machineCredentials: map[string]MachineCredential{
			machineStoreKey("tenant-a", "external-system-a"): {TenantID: "tenant-a", PrincipalID: "external-system-a", SecretHash: digestMachineValue("secret"), NetworkCIDRs: []string{"127.0.0.1/32"}, Status: "active", Revision: 1},
		},
		grants: []Grant{{ID: "grant-a", TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentInstanceID: "validation-installation-a",
			SubjectType: PrincipalServicePrincipal, SubjectID: "external-system-a", Action: "run", Effect: "allow", Status: GrantActive, Revision: 1}},
	}
	module := NewModule(store, "token")
	base := MachineTokenIssueRequest{GrantType: "client_credentials", TenantID: "tenant-a", ClientID: "external-system-a", ClientSecret: "secret",
		Scope: MachineGrantScope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentInstanceID: "validation-installation-a", Actions: []string{"run"}}}
	if _, err := module.ExchangeMachineToken(context.Background(), base, "192.0.2.10:1234"); err == nil {
		t.Fatal("token exchange must reject a source outside the registered CIDR")
	}
	base.Scope.AgentInstanceID = "qa-installation-not-granted"
	if _, err := module.ExchangeMachineToken(context.Background(), base, "127.0.0.1:1234"); err == nil {
		t.Fatal("token exchange must reject an installation without an exact grant")
	}
}

func TestIdentityModuleRevokesGrantWithTrustedScopeAndCAS(t *testing.T) {
	store := &memoryStore{tenant: Tenant{ID: "tenant-a"}, department: Department{ID: "dept-a", TenantID: "tenant-a"}, application: Application{ID: "app-a", TenantID: "tenant-a", DepartmentID: "dept-a"}, principal: Principal{Type: PrincipalUser, ID: "alice", TenantID: "tenant-a", IsActive: true}, grants: []Grant{{ID: "grant-a", TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentInstanceID: "agent-a", SubjectType: PrincipalUser, SubjectID: "alice", Action: "run", Effect: "allow", Status: GrantActive, Revision: 1}}}
	handler := NewModule(store, "identity-token").Handler()
	request := func(agent, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/grants/grant-a/revoke", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer identity-token")
		req.Header.Set("X-Tenant-ID", "tenant-a")
		req.Header.Set("X-Department-ID", "dept-a")
		req.Header.Set("X-Application-ID", "app-a")
		req.Header.Set("X-Agent-Instance-ID", agent)
		req.Header.Set("X-Principal-ID", "alice")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if out := request("wrong-agent", `{"expected_revision":1}`); out.Code != http.StatusNotFound {
		t.Fatalf("cross-installation revoke status=%d body=%s", out.Code, out.Body.String())
	}
	if out := request("agent-a", `{"expected_revision":1}`); out.Code != http.StatusOK || store.grants[0].Status != GrantRevoked {
		t.Fatalf("revoke status=%d body=%s grant=%+v", out.Code, out.Body.String(), store.grants[0])
	}
	if out := request("agent-a", `{"expected_revision":1}`); out.Code != http.StatusConflict {
		t.Fatalf("stale revoke status=%d body=%s", out.Code, out.Body.String())
	}
}

func TestCheckPrincipalAccessUsesExactApplicationAndInstallationGrant(t *testing.T) {
	store := &memoryStore{
		principal: Principal{Type: PrincipalUser, ID: "alice", TenantID: "tenant-a", IsActive: true},
		grants:    []Grant{{ID: "grant-a", TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentInstanceID: "install-a", SubjectType: PrincipalUser, SubjectID: "alice", Action: "discover", Effect: "allow", Status: GrantActive, Revision: 1}},
	}
	scope := sharedkernel.Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentInstanceID: "install-a"}
	decision, err := CheckPrincipalAccess(context.Background(), store, scope, PrincipalUser, "alice", "discover")
	if err != nil || !decision.Allowed || decision.Reason != "explicit_allow" {
		t.Fatalf("matching scoped grant decision=%+v err=%v", decision, err)
	}
	scope.ApplicationID = "other-app"
	decision, err = CheckPrincipalAccess(context.Background(), store, scope, PrincipalUser, "alice", "discover")
	if err != nil || decision.Allowed || decision.Reason != "no_matching_grant" {
		t.Fatalf("cross-application grant decision=%+v err=%v", decision, err)
	}
}

func setBrowserIdentityHeaders(req *http.Request, principal Principal, departmentID, applicationID string) {
	req.Header.Set("Authorization", "Bearer identity-token")
	req.Header.Set("X-Internal-Token", "identity-token")
	req.Header.Set(browserModuleHeader, "1")
	req.Header.Set("X-Tenant-ID", principal.TenantID)
	req.Header.Set("X-Department-ID", departmentID)
	req.Header.Set("X-Application-ID", applicationID)
	req.Header.Set("X-Principal-Type", string(principal.Type))
	req.Header.Set("X-Principal-ID", principal.ID)
}

func TestBrowserCannotCreatePrincipalOrSelfAssignPrivilegedRole(t *testing.T) {
	store := &memoryStore{tenant: Tenant{ID: "tenant-a", Status: "active"}, principal: Principal{
		Type: PrincipalUser, ID: "alice", TenantID: "tenant-a", Roles: []string{"operator"}, IsActive: true,
	}}
	handler := NewModule(store, "identity-token").Handler()
	req := httptest.NewRequest(http.MethodPost, "/principals", strings.NewReader(`{"type":"user","id":"alice","tenant_id":"tenant-a","roles":["admin","system_admin"],"is_active":true}`))
	req.Header.Set("Content-Type", "application/json")
	setBrowserIdentityHeaders(req, store.principal, "dept-a", "app-a")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("browser principal self-promotion status=%d body=%s", out.Code, out.Body.String())
	}
	if got := strings.Join(store.principal.Roles, ","); got != "operator" {
		t.Fatalf("principal roles changed after denied request: %s", got)
	}
}

func TestPlatformAdminDisablesOnlyTenantUserWithRevisionCAS(t *testing.T) {
	store := &memoryStore{
		principal: Principal{Type: PrincipalUser, ID: "platform-admin", TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true, Revision: 1},
		principals: []Principal{
			{Type: PrincipalUser, ID: "alice", TenantID: "tenant-a", IsActive: true, Revision: 4},
			{Type: PrincipalUser, ID: "other-tenant-user", TenantID: "tenant-b", IsActive: true, Revision: 1},
			{Type: PrincipalServicePrincipal, ID: "machine-a", TenantID: "tenant-a", IsActive: true, Revision: 1},
		},
	}
	handler := NewModule(store, "identity-token").Handler()
	call := func(targetID, body string, expected int) *httptest.ResponseRecorder {
		var command map[string]any
		if err := json.Unmarshal([]byte(body), &command); err != nil {
			t.Fatal(err)
		}
		command["principal_id"] = targetID
		encoded, err := json.Marshal(command)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/principals:disable", strings.NewReader(string(encoded)))
		req.Header.Set("Content-Type", "application/json")
		setBrowserIdentityHeaders(req, store.principal, "dept-a", "app-a")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if out.Code != expected {
			t.Fatalf("disable %s status=%d want=%d body=%s", targetID, out.Code, expected, out.Body.String())
		}
		return out
	}
	result := call("alice", `{"expected_revision":4}`, http.StatusOK)
	if !strings.Contains(result.Body.String(), `"is_active":false`) || !strings.Contains(result.Body.String(), `"revision":5`) {
		t.Fatalf("disabled Principal response missing new state: %s", result.Body.String())
	}
	if store.principals[0].IsActive || store.principals[0].Revision != 5 {
		t.Fatalf("principal was not fenced after disable: %+v", store.principals[0])
	}
	call("alice", `{"expected_revision":4}`, http.StatusConflict)
	call("platform-admin", `{"expected_revision":1}`, http.StatusForbidden)
	call("other-tenant-user", `{"expected_revision":1}`, http.StatusNotFound)
	call("machine-a", `{"expected_revision":1}`, http.StatusNotFound)
	if !store.principals[2].IsActive {
		t.Fatal("human-principal lifecycle endpoint unexpectedly changed machine identity")
	}
}

func TestBrowserApplicationAdminCanRegisterOnlyRolelessServicePrincipals(t *testing.T) {
	store := &memoryStore{tenant: Tenant{ID: "tenant-a", Status: "active"}, principal: Principal{
		Type: PrincipalUser, ID: "app-admin", TenantID: "tenant-a", Roles: []string{"application_admin"}, IsActive: true,
	}}
	handler := NewModule(store, "identity-token").Handler()
	request := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/principals", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setBrowserIdentityHeaders(req, store.principal, "dept-a", "app-a")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}

	created := request(`{"type":"service_principal","id":"batch-client","tenant_id":"tenant-a","is_active":true}`)
	if created.Code != http.StatusCreated || len(store.principals) != 1 || store.principals[0].ID != "batch-client" {
		t.Fatalf("service principal registration status=%d body=%s stored=%+v", created.Code, created.Body.String(), store.principals)
	}
	if denied := request(`{"type":"user","id":"new-user","tenant_id":"tenant-a","is_active":true}`); denied.Code != http.StatusForbidden {
		t.Fatalf("application admin created human principal: status=%d body=%s", denied.Code, denied.Body.String())
	}
	if denied := request(`{"type":"service_principal","id":"privileged-client","tenant_id":"tenant-a","roles":["platform_admin"],"is_active":true}`); denied.Code != http.StatusBadRequest {
		t.Fatalf("service principal received human roles: status=%d body=%s", denied.Code, denied.Body.String())
	}
	if len(store.principals) != 1 {
		t.Fatalf("denied principal registrations were persisted: %+v", store.principals)
	}
}

func TestScopedAdminCanListServicePrincipalMetadataButNotUsers(t *testing.T) {
	store := &memoryStore{
		principal:  Principal{Type: PrincipalUser, ID: "app-admin", TenantID: "tenant-a", Roles: []string{"application_admin"}, IsActive: true},
		principals: []Principal{{Type: PrincipalServicePrincipal, ID: "batch-client", TenantID: "tenant-a", IsActive: true}},
	}
	handler := NewModule(store, "identity-token").Handler()
	request := func(query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/principals?tenant_id=tenant-a&principal_type=service_principal"+query, nil)
		setBrowserIdentityHeaders(req, store.principal, "dept-a", "app-a")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if out := request(""); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), "batch-client") {
		t.Fatalf("scoped machine principal listing status=%d body=%s", out.Code, out.Body.String())
	}
	if out := request("&principal_id=batch-client"); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), "batch-client") {
		t.Fatalf("scoped machine principal selection status=%d body=%s", out.Code, out.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "/principals?tenant_id=tenant-a&principal_type=user", nil)
	setBrowserIdentityHeaders(req, store.principal, "dept-a", "app-a")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("scoped admin listed human principals: status=%d body=%s", out.Code, out.Body.String())
	}
}

func TestBrowserPlatformAdminCannotCreateGlobalSystemAdmin(t *testing.T) {
	store := &memoryStore{tenant: Tenant{ID: "tenant-a", Status: "active"}, principal: Principal{
		Type: PrincipalUser, ID: "platform-admin", TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true,
	}}
	handler := NewModule(store, "identity-token").Handler()
	req := httptest.NewRequest(http.MethodPost, "/principals", strings.NewReader(`{"type":"user","id":"new-admin","tenant_id":"tenant-a","roles":["system_admin"],"is_active":true}`))
	req.Header.Set("Content-Type", "application/json")
	setBrowserIdentityHeaders(req, store.principal, "dept-platform", "app-platform")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("tenant platform admin must not grant global role, status=%d body=%s", out.Code, out.Body.String())
	}
	if store.principal.ID != "platform-admin" || strings.Join(store.principal.Roles, ",") != "platform_admin" {
		t.Fatalf("denied global-role grant changed principal: %+v", store.principal)
	}
}

func TestBrowserApplicationAdminGrantIsBoundToAuthenticatedApplication(t *testing.T) {
	store := &memoryStore{
		application: Application{ID: "app-a", TenantID: "tenant-a", DepartmentID: "dept-a"},
		principal:   Principal{Type: PrincipalUser, ID: "alice", TenantID: "tenant-a", Roles: []string{"application_admin"}, IsActive: true},
	}
	handler := NewModule(store, "identity-token").Handler()
	request := func(applicationID string) *httptest.ResponseRecorder {
		body := `{"id":"grant-1","tenant_id":"tenant-a","department_id":"dept-a","application_id":"` + applicationID + `","agent_instance_id":"installation-a","subject_type":"user","subject_id":"alice","action":"run","effect":"allow","status":"active","revision":1}`
		req := httptest.NewRequest(http.MethodPost, "/grants", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		setBrowserIdentityHeaders(req, store.principal, "dept-a", "app-a")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if out := request("app-b"); out.Code != http.StatusForbidden {
		t.Fatalf("cross-application grant status=%d body=%s", out.Code, out.Body.String())
	}
	if len(store.grants) != 0 {
		t.Fatalf("cross-application grant was persisted: %+v", store.grants)
	}
	if out := request("app-a"); out.Code != http.StatusCreated || len(store.grants) != 1 {
		t.Fatalf("same-application grant status=%d body=%s grants=%+v", out.Code, out.Body.String(), store.grants)
	}
}

func TestBrowserCannotUseIdentityAccessCheckAsAuthorizationOracle(t *testing.T) {
	store := &memoryStore{principal: Principal{Type: PrincipalUser, ID: "alice", TenantID: "tenant-a", IsActive: true}}
	handler := NewModule(store, "identity-token").Handler()
	req := httptest.NewRequest(http.MethodPost, "/access/check", strings.NewReader(`{"scope":{"tenant_id":"tenant-a","department_id":"dept-a","application_id":"app-a","agent_instance_id":"agent-a"},"principal_type":"user","principal_id":"alice","action":"run"}`))
	setBrowserIdentityHeaders(req, store.principal, "dept-a", "app-a")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("browser access-check status=%d body=%s", out.Code, out.Body.String())
	}
}

func TestBrowserGrantExplainUsesIdentityDecisionAndExactApplicationScope(t *testing.T) {
	store := &memoryStore{
		principal: Principal{Type: PrincipalUser, ID: "alice", TenantID: "tenant-a", Roles: []string{"application_admin"}, IsActive: true},
		grants:    []Grant{{ID: "grant-a", TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentInstanceID: "install-a", SubjectType: PrincipalUser, SubjectID: "alice", Action: "run", Effect: "allow", Status: GrantActive, Revision: 1}},
	}
	handler := NewModule(store, "identity-token").Handler()
	request := func(applicationID string, roles []string) *httptest.ResponseRecorder {
		store.principal.Roles = roles
		body := `{"scope":{"tenant_id":"tenant-a","department_id":"dept-a","application_id":"` + applicationID + `","agent_instance_id":"install-a"},"principal_type":"user","principal_id":"alice","action":"run"}`
		req := httptest.NewRequest(http.MethodPost, "/grants:explain", strings.NewReader(body))
		setBrowserIdentityHeaders(req, store.principal, "dept-a", "app-a")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if out := request("app-a", []string{"application_admin"}); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"allowed":true`) {
		t.Fatalf("same-application explain status=%d body=%s", out.Code, out.Body.String())
	}
	if out := request("app-b", []string{"application_admin"}); out.Code != http.StatusForbidden {
		t.Fatalf("cross-application explain status=%d body=%s", out.Code, out.Body.String())
	}
	if out := request("app-a", []string{"operator"}); out.Code != http.StatusForbidden {
		t.Fatalf("unprivileged explain status=%d body=%s", out.Code, out.Body.String())
	}
}

func TestBrowserAgentAccessRequestsAreSelfScopedAndApprovalCreatesExactGrants(t *testing.T) {
	store := &memoryStore{
		tenant:      Tenant{ID: "tenant-a", Code: "tenant-a", Name: "Tenant A", Status: "active", Revision: 1},
		department:  Department{ID: "dept-a", TenantID: "tenant-a", Code: "compliance", Name: "Compliance", Status: "active", Revision: 1},
		application: Application{ID: "app-a", TenantID: "tenant-a", DepartmentID: "dept-a", Code: "business-app", Name: "Regulatory", Status: "active", Revision: 1},
		principals: []Principal{
			{Type: PrincipalUser, ID: "alice", TenantID: "tenant-a", IsActive: true},
			{Type: PrincipalUser, ID: "bob", TenantID: "tenant-a", IsActive: true},
			{Type: PrincipalUser, ID: "app-admin", TenantID: "tenant-a", Roles: []string{"application_admin"}, IsActive: true},
		},
	}
	module := NewModule(store, "internal-token")
	module.SetAgentInstallationResolver(staticAgentInstallationResolver{items: map[string]AgentInstallation{"install-check": {AgentID: "ticket-assistant"}}})
	handler := module.Handler()
	call := func(method, path, body, principal string, roles ...string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer internal-token")
		req.Header.Set("X-Browser-Module", "1")
		req.Header.Set("X-Tenant-ID", "tenant-a")
		req.Header.Set("X-Department-ID", "dept-a")
		req.Header.Set("X-Application-ID", "app-a")
		req.Header.Set("X-Principal-Type", string(PrincipalUser))
		req.Header.Set("X-Principal-ID", principal)
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	createBody := `{"agent_instance_id":"install-check","actions":["run","history.read"],"reason":"Need this agent for my reporting work"}`
	created := call(http.MethodPost, "/access-requests", createBody, "alice")
	if created.Code != http.StatusCreated {
		t.Fatalf("create request status=%d body=%s", created.Code, created.Body.String())
	}
	var request AgentAccessRequest
	if err := json.Unmarshal(created.Body.Bytes(), &request); err != nil {
		t.Fatal(err)
	}
	if request.SubjectID != "alice" || request.AgentID != "ticket-assistant" || request.AgentInstanceID != "install-check" || request.Status != AgentAccessRequestPending {
		t.Fatalf("request must use trusted subject and catalog identity: %+v", request)
	}
	if duplicate := call(http.MethodPost, "/access-requests", createBody, "alice"); duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate pending request status=%d body=%s", duplicate.Code, duplicate.Body.String())
	}
	if forged := call(http.MethodPost, "/access-requests", `{"agent_instance_id":"install-check","actions":["run"],"reason":"Need access for this work","subject_id":"bob"}`, "alice"); forged.Code != http.StatusBadRequest {
		t.Fatalf("caller-supplied subject must be rejected: status=%d body=%s", forged.Code, forged.Body.String())
	}
	if mine := call(http.MethodGet, "/access-requests?status=pending", "", "bob"); mine.Code != http.StatusOK || strings.Contains(mine.Body.String(), `"subject_id":"alice"`) {
		t.Fatalf("another user's request must not appear in self-service list: status=%d body=%s", mine.Code, mine.Body.String())
	}
	if adminList := call(http.MethodGet, "/access-requests?status=pending", "", "app-admin"); adminList.Code != http.StatusOK || !strings.Contains(adminList.Body.String(), `"subject_id":"alice"`) {
		t.Fatalf("application admin must see pending requests in current application: status=%d body=%s", adminList.Code, adminList.Body.String())
	}
	if forbidden := call(http.MethodPost, "/access-requests/"+request.ID+"/approve", `{"expected_revision":1,"comment":"approved"}`, "bob"); forbidden.Code != http.StatusForbidden {
		t.Fatalf("ordinary user must not approve access request: status=%d body=%s", forbidden.Code, forbidden.Body.String())
	}
	approved := call(http.MethodPost, "/access-requests/"+request.ID+"/approve", `{"expected_revision":1,"comment":"Approved for reporting duties"}`, "app-admin")
	if approved.Code != http.StatusOK {
		t.Fatalf("approve request status=%d body=%s", approved.Code, approved.Body.String())
	}
	if len(store.grants) != 2 {
		t.Fatalf("approval should produce one grant per requested action, got %d", len(store.grants))
	}
	for _, grant := range store.grants {
		if grant.TenantID != "tenant-a" || grant.DepartmentID != "dept-a" || grant.ApplicationID != "app-a" || grant.AgentInstanceID != "install-check" || grant.SubjectID != "alice" || grant.SubjectType != PrincipalUser || grant.Effect != "allow" || grant.Status != GrantActive {
			t.Fatalf("grant escaped exact request boundary: %+v", grant)
		}
	}
	if stale := call(http.MethodPost, "/access-requests/"+request.ID+"/approve", `{"expected_revision":1,"comment":"stale approval"}`, "app-admin"); stale.Code != http.StatusConflict {
		t.Fatalf("stale decision revision must conflict: status=%d body=%s", stale.Code, stale.Body.String())
	}
	if selfCreate := call(http.MethodPost, "/access-requests", createBody, "app-admin"); selfCreate.Code != http.StatusCreated {
		t.Fatalf("admin may also request access as a user: status=%d body=%s", selfCreate.Code, selfCreate.Body.String())
	} else {
		var ownRequest AgentAccessRequest
		if err := json.Unmarshal(selfCreate.Body.Bytes(), &ownRequest); err != nil {
			t.Fatal(err)
		}
		if selfReview := call(http.MethodPost, "/access-requests/"+ownRequest.ID+"/approve", `{"expected_revision":1,"comment":"self review"}`, "app-admin"); selfReview.Code != http.StatusForbidden {
			t.Fatalf("requester self-review must be forbidden: status=%d body=%s", selfReview.Code, selfReview.Body.String())
		}
	}
}

func TestBrowserAgentAccessRequestRejectsUnpublishedOrCrossApplicationInstallation(t *testing.T) {
	store := &memoryStore{
		tenant:      Tenant{ID: "tenant-a", Code: "tenant-a", Name: "Tenant A", Status: "active", Revision: 1},
		department:  Department{ID: "dept-a", TenantID: "tenant-a", Code: "compliance", Name: "Compliance", Status: "active", Revision: 1},
		application: Application{ID: "app-a", TenantID: "tenant-a", DepartmentID: "dept-a", Code: "business-app", Name: "Regulatory", Status: "active", Revision: 1},
		principals:  []Principal{{Type: PrincipalUser, ID: "alice", TenantID: "tenant-a", IsActive: true}},
	}
	module := NewModule(store, "internal-token")
	module.SetAgentInstallationResolver(staticAgentInstallationResolver{items: map[string]AgentInstallation{}})
	handler := module.Handler()
	call := func(applicationID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/access-requests", strings.NewReader(`{"agent_instance_id":"not-published","actions":["run"],"reason":"Need this agent for my reporting work"}`))
		req.Header.Set("Authorization", "Bearer internal-token")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Browser-Module", "1")
		req.Header.Set("X-Tenant-ID", "tenant-a")
		req.Header.Set("X-Department-ID", "dept-a")
		req.Header.Set("X-Application-ID", applicationID)
		req.Header.Set("X-Principal-Type", string(PrincipalUser))
		req.Header.Set("X-Principal-ID", "alice")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if response := call("app-a"); response.Code != http.StatusNotFound {
		t.Fatalf("unknown/unpublished installation must be hidden: status=%d body=%s", response.Code, response.Body.String())
	}
	if response := call("app-b"); response.Code != http.StatusNotFound {
		t.Fatalf("cross-application target must not resolve: status=%d body=%s", response.Code, response.Body.String())
	}
	if len(store.agentAccessRequests) != 0 {
		t.Fatalf("unavailable installation must not create request, got %d", len(store.agentAccessRequests))
	}
}
