package modelgovernance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func seedApprovedModel(t *testing.T, s *memoryStore) {
	t.Helper()
	p := Provider{ID: "provider-1", ProviderKey: "provider-one", DisplayName: "Provider One", Type: ProviderOnPrem, TrustZone: TrustLocal, EndpointRef: "service://model-provider", SecretRef: "secret://model/provider", Status: StatusDraft, Revision: 1}
	if err := s.CreateProvider(context.Background(), &p); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateProviderStatus(context.Background(), p.ID, 1, StatusApproved); err != nil {
		t.Fatal(err)
	}
	d := ModelDefinition{ID: "definition-1", ProviderID: p.ID, ModelKey: "model-one", Kind: ModelKindChat, DisplayName: "Model One", Capabilities: json.RawMessage(`{}`), ContextLimit: 4096, LifecycleStatus: StatusDraft, Revision: 1}
	if err := s.CreateDefinition(context.Background(), &d); err != nil {
		t.Fatal(err)
	}
	v := ModelVersion{ID: "version-1", DefinitionID: d.ID, SemanticVersion: "1.0.0", ProviderFingerprint: "fingerprint", Status: StatusDraft, Revision: 1}
	if err := s.CreateVersion(context.Background(), &v); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveVersion(context.Background(), v.ID, 1); err != nil {
		t.Fatal(err)
	}
}

func TestScopedModelHTTPUsesTrustedApplicationRatherThanGlobalTarget(t *testing.T) {
	s := newMemoryStore()
	seedApprovedModel(t, s)
	active := true
	m := moduleForTest(s, func(_ context.Context, _ Actor, action Action, target Scope) error {
		if !active || (action != ActionManageDeployment && action != ActionManagePolicy) || target != (Scope{TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a"}) {
			return ErrForbidden
		}
		return nil
	})
	body := `{"model_version_id":"version-1","environment":"staging","endpoint_ref":"service://model-serving","runtime_kind":"http","min_replicas":1,"max_replicas":3,"resource_profile":{"cpu":"1"},"capacity":{"max_concurrent_requests":40}}`
	w := browserRequest(m.Handler(), http.MethodPost, "/deployments", body, nil)
	if w.Code != http.StatusCreated {
		t.Fatal("scoped deployment was denied at global entry gate", w.Code, w.Body.String())
	}
	for _, path := range []string{"/deployments", "/access-policies"} {
		if w := browserRequest(m.Handler(), http.MethodGet, path, "", nil); w.Code != http.StatusOK {
			t.Fatal("scoped list denied", path, w.Code)
		}
	}
	for _, path := range []string{"/providers", "/models", "/prices"} {
		if w := browserRequest(m.Handler(), http.MethodGet, path, "", nil); w.Code != http.StatusForbidden {
			t.Fatal("scoped permission opened global catalog", path, w.Code)
		}
	}
	foreign := strings.Replace(body, `{"model_version_id"`, `{"application_id":"foreign-app","model_version_id"`, 1)
	if w := browserRequest(m.Handler(), http.MethodPost, "/deployments", foreign, nil); w.Code != http.StatusForbidden || len(s.deployments) != 1 {
		t.Fatal("body scope override created foreign deployment", w.Code, len(s.deployments))
	}
	active = false
	if w := browserRequest(m.Handler(), http.MethodPost, "/deployments", body, nil); w.Code != http.StatusForbidden || len(s.deployments) != 1 {
		t.Fatal("revocation did not prevent scoped write", w.Code, len(s.deployments))
	}
}

func TestScopedDeploymentRoutesEnforceScopeAndRevision(t *testing.T) {
	s := newMemoryStore()
	seedApprovedModel(t, s)
	m := moduleForTest(s, func(context.Context, Actor, Action, Scope) error { return nil })
	body := `{"model_version_id":"version-1","environment":"staging","endpoint_ref":"service://model-serving","runtime_kind":"http","min_replicas":1,"max_replicas":3,"resource_profile":{"cpu":"1"},"capacity":{"max_concurrent_requests":40}}`
	r := browserRequest(m.Handler(), http.MethodPost, "/deployments", body, nil)
	if r.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", r.Code, r.Body.String())
	}
	var d Deployment
	if err := json.Unmarshal(r.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.TenantID != "tenant-a" || d.DepartmentID != "department-a" || d.ApplicationID != "application-a" {
		t.Fatalf("blank deployment scope was not normalized to authenticated application: %+v", d)
	}
	r = browserRequest(m.Handler(), http.MethodGet, "/deployments/"+d.ID, "", map[string]string{"X-Tenant-ID": "tenant-b"})
	if r.Code != http.StatusNotFound {
		t.Fatalf("cross tenant get=%d %s", r.Code, r.Body.String())
	}
	// A browser administrator may create desired state but cannot self-report
	// observed runtime health as ready.
	r = browserRequest(m.Handler(), http.MethodPost, "/deployments/"+d.ID+"/health", `{"health_status":"ready","revision":1}`, nil)
	if r.Code != http.StatusForbidden || !strings.Contains(r.Body.String(), "SERVICE_IDENTITY_REQUIRED") {
		t.Fatalf("browser health update=%d %s", r.Code, r.Body.String())
	}
	r = serviceRequest(m.Handler(), http.MethodPost, "/deployments/"+d.ID+"/health", `{"health_status":"ready","revision":1}`, "tenant-a", "department-a", "application-a")
	if r.Code != http.StatusOK {
		t.Fatalf("trusted service health update=%d %s", r.Code, r.Body.String())
	}
	var observed map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &observed); err != nil || observed["observed_revision"] != float64(1) || observed["revision"] != float64(2) {
		t.Fatalf("trusted probe receipt did not preserve observed CAS revision: %s", r.Body.String())
	}
	r = serviceRequest(m.Handler(), http.MethodPost, "/deployments/"+d.ID+"/health", `{"health_status":"unavailable","revision":1}`, "tenant-a", "department-a", "application-a")
	if r.Code != http.StatusConflict {
		t.Fatalf("stale update=%d %s", r.Code, r.Body.String())
	}
	r = serviceRequest(m.Handler(), http.MethodPost, "/deployments/"+d.ID+"/health", `{"health_status":"degraded","revision":2}`, "tenant-b", "department-a", "application-a")
	if r.Code != http.StatusConflict {
		t.Fatalf("cross-tenant service health update=%d %s", r.Code, r.Body.String())
	}
	stillOwned, err := s.GetDeployment(context.Background(), Scope{TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a"}, d.ID)
	if err == nil && (stillOwned.ObservedRevision != 1 || stillOwned.Revision != 2 || stillOwned.HealthStatus != "ready") {
		t.Fatalf("stale or foreign health update changed trusted observation: %+v", stillOwned)
	}
	if err != nil || stillOwned.HealthStatus != "ready" || stillOwned.Revision != 2 {
		t.Fatalf("cross-tenant health update changed deployment: row=%+v err=%v", stillOwned, err)
	}
	crossAppDeployment := strings.Replace(body, `{"model_version_id"`, `{"application_id":"application-b","model_version_id"`, 1)
	r = browserRequest(m.Handler(), http.MethodPost, "/deployments", crossAppDeployment, nil)
	if r.Code != http.StatusForbidden || len(s.deployments) != 1 {
		t.Fatalf("cross app create=%d %s rows=%d", r.Code, r.Body.String(), len(s.deployments))
	}
	denied := moduleForTest(s, func(_ context.Context, _ Actor, action Action, _ Scope) error {
		if action == ActionManageDeployment {
			return ErrForbidden
		}
		return nil
	})
	r = browserRequest(denied.Handler(), http.MethodGet, "/deployments", "", nil)
	if r.Code != http.StatusForbidden {
		t.Fatalf("unauthorized deployment listing=%d %s", r.Code, r.Body.String())
	}
}

func TestScopedAccessPolicyCRUDAndEnforcementFailClosed(t *testing.T) {
	s := newMemoryStore()
	seedApprovedModel(t, s)
	m := moduleForTest(s, func(_ context.Context, actor Actor, action Action, target Scope) error {
		if action != ActionManagePolicy || target != actorScope(actor) {
			return ErrForbidden
		}
		return nil
	})
	body := `{"installation_id":"install-a","agent_version_id":"agent-v1","principal_id":"user-a","allow_local":true,"allow_private":false,"allow_external":false,"allowed_providers":["provider-1"],"allowed_models":["definition-1"]}`
	r := browserRequest(m.Handler(), http.MethodPost, "/access-policies", body, nil)
	if r.Code != http.StatusCreated {
		t.Fatalf("create policy=%d %s", r.Code, r.Body.String())
	}
	var p AccessPolicy
	if err := json.Unmarshal(r.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.TenantID != "tenant-a" || p.DepartmentID != "department-a" || p.ApplicationID != "application-a" {
		t.Fatalf("blank scope was not normalized to authenticated application: %+v", p)
	}
	r = browserRequest(m.Handler(), http.MethodPost, "/access-policies/"+p.ID+"/approve", `{"revision":1}`, nil)
	if r.Code != http.StatusOK {
		t.Fatalf("approve=%d %s", r.Code, r.Body.String())
	}
	r = browserRequest(m.Handler(), http.MethodPost, "/access-policies/"+p.ID+"/revoke", `{"revision":1}`, nil)
	if r.Code != http.StatusConflict {
		t.Fatalf("stale revoke=%d %s", r.Code, r.Body.String())
	}
	scope := ModelAccessScope{TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", InstallationID: "install-a", AgentVersionID: "agent-v1", PrincipalID: "user-a"}
	if err := m.EvaluateModelAccess(context.Background(), scope, "version-1"); err != nil {
		t.Fatalf("approved policy should allow: %v", err)
	}
	r = browserRequest(m.Handler(), http.MethodPost, "/access-policies/"+p.ID+"/revoke", `{"revision":2}`, nil)
	if r.Code != http.StatusOK {
		t.Fatalf("revoke=%d %s", r.Code, r.Body.String())
	}
	if err := m.EvaluateModelAccess(context.Background(), scope, "version-1"); err != ErrModelAccessDenied {
		t.Fatalf("revoked policy must deny, got %v", err)
	}
	crossAppPolicy := strings.Replace(body, `{"installation_id"`, `{"tenant_id":"tenant-a","department_id":"department-a","application_id":"application-b","installation_id"`, 1)
	r = browserRequest(m.Handler(), http.MethodPost, "/access-policies", crossAppPolicy, nil)
	if r.Code != http.StatusForbidden || len(s.policies) != 1 {
		t.Fatalf("cross-app policy=%d %s rows=%d", r.Code, r.Body.String(), len(s.policies))
	}
	r = browserRequest(m.Handler(), http.MethodGet, "/access-policies", "", map[string]string{"X-Tenant-ID": "tenant-b"})
	if r.Code != http.StatusOK || strings.Contains(r.Body.String(), p.ID) {
		t.Fatalf("cross-tenant policy listing=%d %s", r.Code, r.Body.String())
	}
	denied := moduleForTest(s, func(_ context.Context, _ Actor, action Action, _ Scope) error {
		if action == ActionManagePolicy {
			return ErrForbidden
		}
		return nil
	})
	r = browserRequest(denied.Handler(), http.MethodGet, "/access-policies", "", nil)
	if r.Code != http.StatusForbidden {
		t.Fatalf("unauthorized policy listing=%d %s", r.Code, r.Body.String())
	}
}

func serviceRequest(handler http.Handler, method, path, body, tenant, department, application string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer internal-token")
	req.Header.Set("X-Tenant-ID", tenant)
	req.Header.Set("X-Department-ID", department)
	req.Header.Set("X-Application-ID", application)
	req.Header.Set("X-Principal-Type", "service")
	req.Header.Set("X-Principal-ID", "deployment-controller")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func TestAccessPolicyDenyPreservingIntersectionAndExpiry(t *testing.T) {
	scope := ModelAccessScope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", InstallationID: "i", AgentVersionID: "v", PrincipalID: "u"}
	now := time.Now().UTC()
	p := AccessPolicy{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AllowLocal: true, AllowedProviders: []string{"p"}, AllowedModels: []string{"m"}, Status: PolicyApproved}
	if err := evaluateAccessPolicies([]AccessPolicy{p}, scope, "p", "m", TrustLocal, now); err != nil {
		t.Fatalf("expected allow: %v", err)
	}
	deny := p
	deny.AllowLocal = false
	if err := evaluateAccessPolicies([]AccessPolicy{p, deny}, scope, "p", "m", TrustLocal, now); err != ErrModelAccessDenied {
		t.Fatalf("intersection should deny: %v", err)
	}
	expired := p
	past := now.Add(-time.Second)
	expired.EffectiveUntil = &past
	if err := evaluateAccessPolicies([]AccessPolicy{expired}, scope, "p", "m", TrustLocal, now); err != ErrModelAccessDenied {
		t.Fatalf("expired policy should deny: %v", err)
	}
	if err := evaluateAccessPolicies(nil, scope, "p", "m", TrustLocal, now); err != ErrModelAccessDenied {
		t.Fatalf("no policy should deny: %v", err)
	}
}
