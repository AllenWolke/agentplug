package modelgovernance

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxBodyBytes = 1 << 20

type Module struct {
	store         Store
	internalToken string
	authorizer    Authorizer
	allowLocal    bool
	endpointCheck func(string, bool) error
}

func NewModule(store Store, internalToken string, authorizer Authorizer) *Module {
	return &Module{store: store, internalToken: strings.TrimSpace(internalToken), authorizer: authorizer, endpointCheck: ValidateEndpoint}
}

// SetAllowLocalEndpoints enables loopback/http endpoint references for local
// and private Providers. It never relaxes checks for external Providers.
func (m *Module) SetAllowLocalEndpoints(allow bool) { m.allowLocal = allow }

// SetEndpointValidator is primarily useful for deterministic security tests.
func (m *Module) SetEndpointValidator(validate func(string, bool) error) { m.endpointCheck = validate }

func (m *Module) Name() string { return "model-governance" }

func (m *Module) Start(ctx context.Context) error {
	if m.store == nil {
		return errors.New("model governance store is required")
	}
	// Schema is installed by the versioned migration command, never Start.
	// Schema由独立版本迁移命令安装，Start不得改库。
	return ctx.Err()
}

func (m *Module) Ready() error {
	if m.store == nil {
		return errors.New("model governance store is required")
	}
	if m.internalToken == "" {
		return errors.New("model governance internal token is required")
	}
	if m.authorizer == nil {
		return errors.New("model governance authorizer is required")
	}
	return nil
}

func (m *Module) Close(context.Context) error { return nil }

func (m *Module) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/providers", m.providers)
	mux.HandleFunc("/providers/", m.provider)
	mux.HandleFunc("/models", m.models)
	mux.HandleFunc("/models/", m.model)
	mux.HandleFunc("/prices", m.prices)
	mux.HandleFunc("/prices/", m.price)
	mux.HandleFunc("/deployments", m.deployments)
	mux.HandleFunc("/deployments/", m.deployment)
	mux.HandleFunc("/access-policies", m.accessPolicies)
	mux.HandleFunc("/access-policies/", m.accessPolicy)
	return mux
}

func (m *Module) providers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if _, ok := m.authorize(w, r, ActionRead); !ok {
			return
		}
		limit, ok := readLimit(w, r)
		if !ok {
			return
		}
		rows, err := m.store.ListProviders(r.Context(), limit)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusOK, map[string]any{"items": rows})
	case http.MethodPost:
		actor, ok := m.authorize(w, r, ActionCreate)
		if !ok {
			return
		}
		var in CreateProviderRequest
		if !m.decode(w, r, &in) {
			return
		}
		row, err := validateCreateProvider(in, actor, m.endpointCheck, m.allowLocal)
		if err != nil {
			m.storeError(w, err)
			return
		}
		row.ID, err = newID()
		if err != nil {
			m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "could not allocate provider id")
			return
		}
		if err = m.store.CreateProvider(r.Context(), &row); err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusCreated, row)
	default:
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	}
}

func (m *Module) provider(w http.ResponseWriter, r *http.Request) {
	parts := pathParts(r.URL.Path, "/providers/")
	if len(parts) == 0 || parts[0] == "" {
		m.error(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		if _, ok := m.authorize(w, r, ActionRead); !ok {
			return
		}
		row, err := m.store.GetProvider(r.Context(), parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusOK, row)
		return
	}
	if len(parts) != 2 || r.Method != http.MethodPost {
		m.error(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
		return
	}
	var action Action
	switch parts[1] {
	case "test":
		action = ActionTest
	case "approve":
		action = ActionApprove
	case "disable":
		action = ActionDisable
	default:
		m.error(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
		return
	}
	if _, ok := m.authorize(w, r, action); !ok {
		return
	}
	switch action {
	case ActionTest:
		var empty struct{}
		if !m.decode(w, r, &empty) {
			return
		}
		row, err := m.store.GetProvider(r.Context(), parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		result := ProviderTestResult{ProviderID: row.ID, CheckedAt: time.Now().UTC()}
		switch row.Status {
		case StatusDisabled:
			result.Reason = "provider is disabled"
		case StatusDraft, StatusApproved:
			if err = m.endpointCheck(row.EndpointRef, m.allowLocal && row.Type != ProviderExternalManaged); err != nil {
				result.Reason = err.Error()
			} else {
				result.Validated, result.Reason = true, "endpoint passed safety validation"
			}
		default:
			result.Reason = "provider has an unknown status"
		}
		m.json(w, http.StatusOK, result)
	case ActionApprove, ActionDisable:
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
		status := StatusApproved
		if action == ActionDisable {
			status = StatusDisabled
		}
		if err := m.store.UpdateProviderStatus(r.Context(), parts[0], in.Revision, status); err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusOK, map[string]any{"status": status, "revision": in.Revision + 1})
	}
}

func (m *Module) models(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if _, ok := m.authorize(w, r, ActionRead); !ok {
			return
		}
		limit, ok := readLimit(w, r)
		if !ok {
			return
		}
		rows, err := m.store.ListDefinitions(r.Context(), strings.TrimSpace(r.URL.Query().Get("provider_id")), limit)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusOK, map[string]any{"items": rows})
	case http.MethodPost:
		if _, ok := m.authorize(w, r, ActionCreate); !ok {
			return
		}
		var in CreateModelDefinitionRequest
		if !m.decode(w, r, &in) {
			return
		}
		row, err := validateCreateDefinition(in)
		if err != nil {
			m.storeError(w, err)
			return
		}
		provider, err := m.store.GetProvider(r.Context(), row.ProviderID)
		if err != nil {
			m.storeError(w, err)
			return
		}
		if provider.Status != StatusApproved {
			m.error(w, http.StatusConflict, "PROVIDER_NOT_APPROVED", "provider must be approved before model registration")
			return
		}
		row.ID, err = newID()
		if err != nil {
			m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "could not allocate model id")
			return
		}
		if err = m.store.CreateDefinition(r.Context(), &row); err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusCreated, row)
	default:
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	}
}

func (m *Module) model(w http.ResponseWriter, r *http.Request) {
	parts := pathParts(r.URL.Path, "/models/")
	if len(parts) == 0 || parts[0] == "" {
		m.error(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
		return
	}
	if len(parts) == 2 && parts[1] == "versions" {
		switch r.Method {
		case http.MethodGet:
			if _, ok := m.authorize(w, r, ActionRead); !ok {
				return
			}
			if _, err := m.store.GetDefinition(r.Context(), parts[0]); err != nil {
				m.storeError(w, err)
				return
			}
			limit, ok := readLimit(w, r)
			if !ok {
				return
			}
			rows, err := m.store.ListVersions(r.Context(), parts[0], limit)
			if err != nil {
				m.storeError(w, err)
				return
			}
			m.json(w, http.StatusOK, map[string]any{"items": rows})
		case http.MethodPost:
			if _, ok := m.authorize(w, r, ActionCreate); !ok {
				return
			}
			var in CreateModelVersionRequest
			if !m.decode(w, r, &in) {
				return
			}
			definition, err := m.store.GetDefinition(r.Context(), parts[0])
			if err != nil {
				m.storeError(w, err)
				return
			}
			provider, err := m.store.GetProvider(r.Context(), definition.ProviderID)
			if err != nil {
				m.storeError(w, err)
				return
			}
			if provider.Status != StatusApproved || definition.LifecycleStatus == StatusDisabled || definition.LifecycleStatus != StatusDraft {
				m.error(w, http.StatusConflict, "MODEL_NOT_WRITABLE", "model definition is not writable")
				return
			}
			row, err := validateCreateVersion(definition, provider, in)
			if err != nil {
				m.storeError(w, err)
				return
			}
			row.ID, err = newID()
			if err != nil {
				m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "could not allocate model version id")
				return
			}
			if err = m.store.CreateVersion(r.Context(), &row); err != nil {
				m.storeError(w, err)
				return
			}
			m.json(w, http.StatusCreated, row)
		default:
			m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		}
		return
	}
	if len(parts) == 4 && parts[1] == "versions" && parts[2] != "" && parts[3] == "approve" && r.Method == http.MethodPost {
		if _, ok := m.authorize(w, r, ActionApprove); !ok {
			return
		}
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
		if _, err := m.store.GetVersion(r.Context(), parts[0], parts[2]); err != nil {
			m.storeError(w, err)
			return
		}
		if err := m.store.ApproveVersion(r.Context(), parts[2], in.Revision); err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusOK, map[string]any{"status": StatusApproved, "revision": in.Revision + 1})
		return
	}
	m.error(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
}

func (m *Module) authorize(w http.ResponseWriter, r *http.Request, action Action) (Actor, bool) {
	if m.internalToken == "" {
		m.error(w, http.StatusUnauthorized, "UNAUTHENTICATED", "platform internal token is not configured")
		return Actor{}, false
	}
	provided := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if provided == "" {
		provided = strings.TrimSpace(r.Header.Get("X-Internal-Token"))
	}
	if len(provided) != len(m.internalToken) || subtle.ConstantTimeCompare([]byte(provided), []byte(m.internalToken)) != 1 {
		m.error(w, http.StatusUnauthorized, "UNAUTHENTICATED", "platform internal token is invalid")
		return Actor{}, false
	}
	if r.Header.Get("X-Browser-Module") != "1" {
		// Non-browser module calls have already passed the shared internal-token
		// check above. Preserve their explicitly supplied service scope so
		// trusted orchestration can report observed deployment health without
		// allowing a browser administrator to self-assert readiness.
		// 非浏览器模块调用已通过上方内部令牌校验；保留调用方传递的服务
		// Scope，供编排器上报 observed health；浏览器管理员不能自报 ready。
		return Actor{
			TenantID: strings.TrimSpace(r.Header.Get("X-Tenant-ID")), DepartmentID: strings.TrimSpace(r.Header.Get("X-Department-ID")),
			ApplicationID: strings.TrimSpace(r.Header.Get("X-Application-ID")), PrincipalType: strings.TrimSpace(r.Header.Get("X-Principal-Type")),
			PrincipalID: strings.TrimSpace(r.Header.Get("X-Principal-ID")),
		}, true
	}
	actor := Actor{TenantID: strings.TrimSpace(r.Header.Get("X-Tenant-ID")), DepartmentID: strings.TrimSpace(r.Header.Get("X-Department-ID")), ApplicationID: strings.TrimSpace(r.Header.Get("X-Application-ID")), PrincipalType: strings.TrimSpace(r.Header.Get("X-Principal-Type")), PrincipalID: strings.TrimSpace(r.Header.Get("X-Principal-ID")), Browser: true}
	if actor.TenantID == "" || actor.DepartmentID == "" || actor.ApplicationID == "" || actor.PrincipalType != "user" || actor.PrincipalID == "" || m.authorizer == nil {
		m.error(w, http.StatusForbidden, "FORBIDDEN", "trusted platform administrator identity is required")
		return Actor{}, false
	}
	target := Scope{}
	if action == ActionManageDeployment || action == ActionManagePolicy {
		// Deployment and access-policy routes operate in the gateway's current
		// application, not the global provider/model catalog.
		target = actorScope(actor)
	}
	if err := m.authorizer.AuthorizeModelGovernance(r.Context(), actor, action, target); err != nil {
		if errors.Is(err, ErrForbidden) {
			m.error(w, http.StatusForbidden, "FORBIDDEN", "model governance operation is not authorized")
		} else {
			m.error(w, http.StatusServiceUnavailable, "IDENTITY_UNAVAILABLE", "authorization state is unavailable")
		}
		return Actor{}, false
	}
	return actor, true
}

func readLimit(w http.ResponseWriter, r *http.Request) (int, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return 50, true
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		(&Module{}).error(w, http.StatusBadRequest, "INVALID_REQUEST", "limit must be a positive integer")
		return 0, false
	}
	return clampLimit(value), true
}

func pathParts(path, prefix string) []string {
	path = strings.TrimPrefix(path, prefix)
	if path == "" {
		return nil
	}
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil
		}
	}
	return parts
}

func (m *Module) decode(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.ContentLength > maxBodyBytes {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "request body exceeds the size limit")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "request body is invalid")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "request body must contain one JSON value")
		return false
	}
	return true
}

func (m *Module) storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "model governance request is invalid")
	case errors.Is(err, ErrInvalidSecretRef):
		m.error(w, http.StatusBadRequest, "INVALID_SECRET_REF", "secret_ref must be a managed reference")
	case errors.Is(err, ErrUnsafeEndpoint):
		m.error(w, http.StatusBadRequest, "UNSAFE_ENDPOINT", "provider endpoint failed safety validation")
	case errors.Is(err, ErrForbidden):
		m.error(w, http.StatusForbidden, "FORBIDDEN", "model governance operation is not authorized")
	case errors.Is(err, ErrModelAccessDenied):
		m.error(w, http.StatusForbidden, "MODEL_ACCESS_DENIED", "model access is denied by governance policy")
	case errors.Is(err, ErrNotFound):
		m.error(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
	case errors.Is(err, ErrRevisionConflict):
		m.error(w, http.StatusConflict, "REVISION_CONFLICT", "resource revision changed or state transition is invalid")
	case errors.Is(err, ErrPriceOverlap):
		m.error(w, http.StatusConflict, "PRICE_INTERVAL_OVERLAP", "effective interval overlaps another price version")
	case errors.Is(err, ErrAlreadyExists):
		m.error(w, http.StatusConflict, "ALREADY_EXISTS", "resource already exists")
	default:
		m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "model governance storage failed")
	}
}

func (m *Module) error(w http.ResponseWriter, status int, code, message string) {
	m.json(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func (m *Module) json(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func newID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:]), nil
}

var _ interface {
	Name() string
	Start(context.Context) error
	Handler() http.Handler
	Close(context.Context) error
} = (*Module)(nil)
