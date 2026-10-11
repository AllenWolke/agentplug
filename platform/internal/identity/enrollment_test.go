package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeEnrollmentStore struct {
	Store
	command         *EnrollmentCommand
	rateKeys        []RegistrationRateKey
	principalWrites int
	listScope       EnrollmentScope
	listItems       []Enrollment
	listTotal       int64
	identity        LocalIdentity
}

func (f *fakeEnrollmentStore) CheckEnrollmentRateLimit(_ context.Context, keys []RegistrationRateKey, _ time.Time) error {
	f.rateKeys = append([]RegistrationRateKey(nil), keys...)
	return nil
}
func (f *fakeEnrollmentStore) CreateEnrollment(_ context.Context, value EnrollmentCommand) error {
	f.command = &value
	return nil
}
func (f *fakeEnrollmentStore) GetEnrollmentByToken(_ context.Context, id, hash string) (Enrollment, error) {
	if f.command == nil || id != f.command.ID || hash != f.command.StatusTokenHash {
		return Enrollment{}, ErrEnrollmentNotFound
	}
	return enrollmentProjection(*f.command), nil
}
func (f *fakeEnrollmentStore) VerifyEnrollmentContact(_ context.Context, id, statusHash, codeHash string, now time.Time) (Enrollment, error) {
	if f.command == nil || id != f.command.ID || statusHash != f.command.StatusTokenHash {
		return Enrollment{}, ErrEnrollmentNotFound
	}
	if codeHash != f.command.VerifyTokenHash {
		return Enrollment{}, ErrVerificationRejected
	}
	return Enrollment{ID: id, Status: EnrollmentPending, Revision: f.command.Revision + 1, UpdatedAt: now}, nil
}
func (f *fakeEnrollmentStore) WithdrawEnrollment(context.Context, string, string, uint64, time.Time) (Enrollment, error) {
	return Enrollment{}, ErrEnrollmentConflict
}
func (f *fakeEnrollmentStore) ListEnrollments(_ context.Context, scope EnrollmentScope, _ string, _, _ int) ([]Enrollment, int64, error) {
	f.listScope = scope
	return f.listItems, f.listTotal, nil
}
func (f *fakeEnrollmentStore) GetEnrollment(_ context.Context, scope EnrollmentScope, id string) (Enrollment, error) {
	f.listScope = scope
	for _, item := range f.listItems {
		if item.ID == id {
			return item, nil
		}
	}
	return Enrollment{}, ErrEnrollmentNotFound
}
func (f *fakeEnrollmentStore) ApproveEnrollment(context.Context, EnrollmentScope, string, string, uint64, string, string, []EnrollmentGrant, time.Time) (Enrollment, error) {
	return Enrollment{}, ErrEnrollmentUnavailable
}
func (f *fakeEnrollmentStore) RejectEnrollment(context.Context, EnrollmentScope, string, string, uint64, string, string, time.Time) (Enrollment, error) {
	return Enrollment{}, ErrEnrollmentUnavailable
}
func (f *fakeEnrollmentStore) CreatePrincipal(context.Context, Principal) error {
	f.principalWrites++
	return nil
}
func (f *fakeEnrollmentStore) GetPrincipal(_ context.Context, typ PrincipalType, id string) (Principal, error) {
	if typ != PrincipalUser || id != "admin" {
		return Principal{}, ErrPrincipalNotFound
	}
	return Principal{Type: PrincipalUser, ID: id, TenantID: "tenant-config", Roles: []string{"application_admin"}, IsActive: true}, nil
}
func (f *fakeEnrollmentStore) VerifyEnrollmentCredentials(context.Context, string, string) (LocalIdentity, error) {
	return f.identity, nil
}
func (f *fakeEnrollmentStore) ValidateEnrollmentSession(context.Context, string, EnrollmentScope, uint64) (LocalIdentity, error) {
	return f.identity, nil
}

func enrollmentProjection(value EnrollmentCommand) Enrollment {
	return Enrollment{ID: value.ID, Username: value.Username, DisplayName: value.DisplayName, Contact: value.ContactMasked,
		TenantID: value.TenantID, DepartmentID: value.DepartmentID, ApplicationID: value.ApplicationID,
		Reason: value.Reason, RequestedAgentIDs: value.RequestedAgentIDs, Status: value.Status,
		Revision: value.Revision, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
}

type fakeEnrollmentSender struct{ contact, code string }

func (s *fakeEnrollmentSender) QueueEnrollmentVerification(_ context.Context, _ EnrollmentScope, _, contact, code string, _ time.Time) error {
	s.contact, s.code = contact, code
	return nil
}

func TestRegistrationUsesConfiguredScopeAndStoresOnlyHashes(t *testing.T) {
	store := &fakeEnrollmentStore{}
	module := NewModule(store, "gateway-secret")
	module.ConfigureEnrollment(EnrollmentConfig{
		Scope:      EnrollmentScope{TenantID: "tenant-config", DepartmentID: "dept-config", ApplicationID: "app-config"},
		InviteCode: "invite-secret", Environment: "development",
	})
	body := `{"username":"Alice.1","display_name":"Alice Example","contact":"alice@example.org","password":"long-password-123","invite_code":"invite-secret","reason":"Need access to complete assigned reviews","requested_agent_ids":["validation-agent"],"tenant_id":"attacker-tenant"}`
	req := httptest.NewRequest(http.MethodPost, "/registrations", strings.NewReader(body))
	req.Header.Set("X-Internal-Token", "gateway-secret")
	req.RemoteAddr = "192.0.2.44:1234"
	rec := httptest.NewRecorder()
	module.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("forged scope field should be rejected by strict decoding: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if store.command != nil || store.principalWrites != 0 {
		t.Fatal("invalid request must not create enrollment or principal")
	}

	body = `{"username":"Alice.1","display_name":"Alice Example","contact":"alice@example.org","password":"long-password-123","invite_code":"invite-secret","reason":"Need access to complete assigned reviews","requested_agent_ids":["validation-agent"]}`
	req = httptest.NewRequest(http.MethodPost, "/registrations", strings.NewReader(body))
	req.Header.Set("X-Internal-Token", "gateway-secret")
	req.RemoteAddr = "192.0.2.44:1234"
	rec = httptest.NewRecorder()
	module.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("registration status=%d body=%s", rec.Code, rec.Body.String())
	}
	if store.command == nil {
		t.Fatal("expected an enrollment command")
	}
	command := store.command
	if command.TenantID != "tenant-config" || command.DepartmentID != "dept-config" || command.ApplicationID != "app-config" {
		t.Fatalf("enrollment scope did not come from server config: %+v", command)
	}
	if command.PasswordHash == "long-password-123" || !strings.HasPrefix(command.PasswordHash, "$pbkdf2-sha256$") {
		t.Fatal("registration must store only a password hash")
	}
	if len(command.StatusTokenHash) != 64 || len(command.VerifyTokenHash) != 64 || command.StatusTokenHash == command.VerifyTokenHash {
		t.Fatal("status and contact verification tokens must be hashed independently")
	}
	if command.ContactHash == "alice@example.org" || command.ContactMasked != "a***@example.org" {
		t.Fatalf("contact should be hashed and masked, got hash=%q masked=%q", command.ContactHash, command.ContactMasked)
	}
	if command.Status != EnrollmentContactVerificationPending || command.Revision != 1 || store.principalWrites != 0 {
		t.Fatalf("registration must remain pending without a principal: status=%s revision=%d principalWrites=%d", command.Status, command.Revision, store.principalWrites)
	}
	var receipt EnrollmentRegistrationReceipt
	if err := json.Unmarshal(rec.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.StatusToken == "" || len(receipt.VerificationCode) != 6 || receipt.RegistrationID != command.ID {
		t.Fatalf("development receipt missing status token or OTP: %+v", receipt)
	}
	if command.VerifyTokenHash == enrollmentTokenHash(receipt.VerificationCode) {
		t.Fatal("low-entropy contact codes must not be stored as an unkeyed hash")
	}
	if len(store.rateKeys) != 3 || store.rateKeys[0].Value != "192.0.2.44" {
		t.Fatalf("expected server-derived IP/username/contact rate checks, got %+v", store.rateKeys)
	}
}

func TestRegistrationRequiresDeliveryOutsideDevelopment(t *testing.T) {
	store := &fakeEnrollmentStore{}
	module := NewModule(store, "gateway-secret")
	module.ConfigureEnrollment(EnrollmentConfig{Scope: EnrollmentScope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}, InviteCode: "invite", Environment: "production"})
	body := `{"username":"alice","display_name":"Alice Example","contact":"alice@example.org","password":"long-password-123","invite_code":"invite","reason":"Need access to complete assigned reviews"}`
	req := httptest.NewRequest(http.MethodPost, "/registrations", strings.NewReader(body))
	req.Header.Set("X-Internal-Token", "gateway-secret")
	rec := httptest.NewRecorder()
	module.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || store.command != nil {
		t.Fatalf("production registration without a sender must fail closed: status=%d command=%v", rec.Code, store.command)
	}
}

func TestRegistrationStatusRejectsQueryCapability(t *testing.T) {
	store := &fakeEnrollmentStore{command: &EnrollmentCommand{ID: "enr-1", StatusTokenHash: enrollmentTokenHash("status-secret")}}
	module := NewModule(store, "gateway-secret")
	module.ConfigureEnrollment(EnrollmentConfig{Scope: EnrollmentScope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}, Environment: "development"})
	req := httptest.NewRequest(http.MethodGet, "/registrations/enr-1/status?registration_token=status-secret", nil)
	req.Header.Set("X-Internal-Token", "gateway-secret")
	rec := httptest.NewRecorder()
	module.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status capability in URL must be rejected: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEnrollmentApplicantCannotReviewOwnRequest(t *testing.T) {
	store := &fakeEnrollmentStore{listItems: []Enrollment{{ID: "enr-1", Username: "admin", TenantID: "tenant-config", DepartmentID: "dept-config", ApplicationID: "app-config", RequestedAgentIDs: []string{"agent"}, Status: EnrollmentPending, Revision: 2}}}
	module := NewModule(store, "internal")
	module.ConfigureEnrollment(EnrollmentConfig{Scope: EnrollmentScope{TenantID: "tenant-config", DepartmentID: "dept-config", ApplicationID: "app-config"}})
	req := httptest.NewRequest(http.MethodPost, "/enrollments/enr-1/approve", strings.NewReader(`{"expected_revision":2,"comment":"self approval","grants":[{"agent_instance_id":"install-1","actions":["run"]}]}`))
	req.Header.Set("Authorization", "Bearer internal")
	req.Header.Set(browserModuleHeader, "1")
	req.Header.Set("X-Tenant-ID", "tenant-config")
	req.Header.Set("X-Department-ID", "dept-config")
	req.Header.Set("X-Application-ID", "app-config")
	req.Header.Set("X-Principal-ID", "admin")
	req.Header.Set("X-Principal-Type", string(PrincipalUser))
	rec := httptest.NewRecorder()
	module.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("applicant must not approve their own enrollment: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEnrollmentCredentialEndpointsRequireInternalToken(t *testing.T) {
	store := &fakeEnrollmentStore{identity: LocalIdentity{PrincipalID: "alice", Username: "alice", TenantID: "t", DepartmentID: "d", ApplicationID: "a", Roles: []string{"operator"}, AuthRevision: 1}}
	module := NewModule(store, "gateway-secret")
	body := `{"username":"alice","password":"secret"}`
	req := httptest.NewRequest(http.MethodPost, "/internal/credentials/verify", strings.NewReader(body))
	rec := httptest.NewRecorder()
	module.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing internal token status=%d body=%s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/internal/credentials/verify", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec = httptest.NewRecorder()
	module.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"auth_revision":1`)) {
		t.Fatalf("valid internal credential request status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if _, exists := response["password"]; exists {
		t.Fatal("credential response must not echo password")
	}
}

func TestPublicEnrollmentRoutesRequireGatewayProxyToken(t *testing.T) {
	module := NewModule(&fakeEnrollmentStore{}, "gateway-secret")
	for _, path := range []string{"/registration-agent-catalog", "/registrations"} {
		method := http.MethodGet
		if path == "/registrations" {
			method = http.MethodPost
		}
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		module.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("direct registration route %s must require gateway authentication: status=%d body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestEnrollmentAdminListUsesConfiguredScope(t *testing.T) {
	store := &fakeEnrollmentStore{listItems: []Enrollment{{ID: "enr-1", Username: "alice", Contact: "a***@example.org", RequestedAgentIDs: []string{"agent"}, Status: EnrollmentPending, Revision: 2}}, listTotal: 1}
	module := NewModule(store, "internal")
	module.ConfigureEnrollment(EnrollmentConfig{Scope: EnrollmentScope{TenantID: "tenant-config", DepartmentID: "dept-config", ApplicationID: "app-config"}})
	req := httptest.NewRequest(http.MethodGet, "/enrollments?status=pending_review&page=1&page_size=20", nil)
	req.Header.Set("Authorization", "Bearer internal")
	req.Header.Set(browserModuleHeader, "1")
	req.Header.Set("X-Tenant-ID", "tenant-config")
	req.Header.Set("X-Department-ID", "dept-config")
	req.Header.Set("X-Application-ID", "app-config")
	req.Header.Set("X-Principal-ID", "admin")
	req.Header.Set("X-Principal-Type", string(PrincipalUser))
	rec := httptest.NewRecorder()
	module.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin list status=%d body=%s", rec.Code, rec.Body.String())
	}
	if store.listScope != (EnrollmentScope{TenantID: "tenant-config", DepartmentID: "dept-config", ApplicationID: "app-config"}) {
		t.Fatalf("admin query scope did not use server config: %+v", store.listScope)
	}
	for _, field := range []string{`"items"`, `"total":1`, `"page":1`, `"page_size":20`, `"contact":"a***@example.org"`, `"requested_agent_ids"`} {
		if !bytes.Contains(rec.Body.Bytes(), []byte(field)) {
			t.Fatalf("response missing %s: %s", field, rec.Body.String())
		}
	}
}

func TestEnrollmentCredentialHashVerification(t *testing.T) {
	encoded, err := hashEnrollmentPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyEnrollmentPassword(encoded, "correct horse battery staple") {
		t.Fatal("expected correct password to validate")
	}
	if verifyEnrollmentPassword(encoded, "wrong password") {
		t.Fatal("wrong password must be rejected")
	}
}

func TestProductionEnrollmentCodeRequiresSecretHMACKey(t *testing.T) {
	if _, err := enrollmentVerificationCodeHash(&EnrollmentConfig{Environment: "production"}, "123456"); !errors.Is(err, ErrEnrollmentUnavailable) {
		t.Fatalf("production OTP hashing without a secret key must fail closed, got %v", err)
	}
	if _, err := enrollmentVerificationCodeHash(&EnrollmentConfig{Environment: "production", VerificationHMACKey: "fixture-hmac-0123456789abcdef0123456789abcdef"}, "123456"); err != nil {
		t.Fatalf("configured production HMAC key should hash the OTP: %v", err)
	}
}

type staticEnrollmentCatalog struct {
	scope EnrollmentScope
	items []EnrollmentAgent
}

func (c *staticEnrollmentCatalog) ListRequestableEnrollmentAgents(_ context.Context, scope EnrollmentScope) ([]EnrollmentAgent, error) {
	c.scope = scope
	return c.items, nil
}

func TestPublicEnrollmentCatalogUsesConfiguredScope(t *testing.T) {
	store := &fakeEnrollmentStore{}
	module := NewModule(store, "gateway-secret")
	catalog := &staticEnrollmentCatalog{items: []EnrollmentAgent{{AgentID: "validation", AgentInstanceID: "install-1", Name: "Validation", SemanticVersion: "1.0.0"}}}
	configScope := EnrollmentScope{TenantID: "tenant-config", DepartmentID: "dept-config", ApplicationID: "app-config"}
	module.ConfigureEnrollment(EnrollmentConfig{Scope: configScope, CatalogResolver: catalog})
	req := httptest.NewRequest(http.MethodGet, "/registration-agent-catalog?tenant_id=other", nil)
	req.Header.Set("X-Internal-Token", "gateway-secret")
	rec := httptest.NewRecorder()
	module.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || catalog.scope != configScope {
		t.Fatalf("catalog should be limited to configured scope: status=%d scope=%+v body=%s", rec.Code, catalog.scope, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"agent_instance_id":"install-1"`)) {
		t.Fatalf("catalog should expose the exact installation id: %s", rec.Body.String())
	}
}

var _ EnrollmentRepository = (*fakeEnrollmentStore)(nil)
var _ EnrollmentCredentials = (*fakeEnrollmentStore)(nil)
var _ EnrollmentCatalogResolver = (*staticEnrollmentCatalog)(nil)

func TestEnrollmentDirectConfigurationRejectsWeakHMACKeys(t *testing.T) {
	for _, environment := range []string{"production", "prod", " PRODUCTION ", "staging", ""} {
		for _, key := range []string{"short", strings.Repeat("k", 32), strings.Repeat("密", 11), "replace-0123456789abcdef0123456789abcdef"} {
			config := &EnrollmentConfig{Environment: environment, VerificationHMACKey: key}
			if hash, err := enrollmentVerificationCodeHash(config, "123456"); !errors.Is(err, ErrEnrollmentUnavailable) || hash != "" {
				t.Fatal("direct module configuration accepted weak HMAC key")
			}
		}
	}
	if _, err := enrollmentVerificationCodeHash(&EnrollmentConfig{Environment: "development"}, "123456"); err != nil {
		t.Fatal(err)
	}
}
