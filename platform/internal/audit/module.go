package audit

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type Module struct {
	store             Store
	internalToken     string
	canReadBrowser    func(context.Context, string, string, string, string) (bool, error)
	authorizeMetadata MetadataAuthorizer
	authorizeContent  ContentAuthorizer
}

func NewModule(store Store, internalToken string) *Module {
	return &Module{store: store, internalToken: strings.TrimSpace(internalToken)}
}

func (m *Module) Name() string { return "audit" }
func (m *Module) Start(ctx context.Context) error {
	if m.store == nil {
		return errors.New("audit store is required")
	}
	// Schema is installed by the versioned migration command, never Start.
	// Schema由独立版本迁移命令安装，Start不得改库。
	return ctx.Err()
}
func (m *Module) Ready() error {
	if m.store == nil {
		return errors.New("audit store is required")
	}
	return nil
}
func (m *Module) Close(context.Context) error { return nil }

// SetBrowserReader wires browser audit authorization to the platform Identity
// source of truth. Shared gateway credentials never imply a user's audit role.
// SetBrowserReader 将浏览器审计权限连接到平台 Identity 权威源；网关共享令牌不代表用户拥有审计角色。
func (m *Module) SetBrowserReader(check func(context.Context, string, string, string, string) (bool, error)) {
	if m != nil {
		m.canReadBrowser = check
	}
}

func (m *Module) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/events", m.events)
	mux.HandleFunc("/events/", m.content)
	mux.HandleFunc("/exports", m.export)
	mux.HandleFunc("/runtime-steps", m.runtimeSteps)
	return mux
}

func (m *Module) events(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(r) {
		m.error(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return
	}
	switch r.Method {
	case http.MethodPost:
		if r.Header.Get("X-Browser-Module") == "1" {
			m.error(w, http.StatusForbidden, "FORBIDDEN")
			return
		}
		var event Event
		if err := decode(r, &event); err != nil {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if err := m.store.Record(r.Context(), event); err != nil {
			status, code := http.StatusBadRequest, "INVALID_EVENT"
			if errors.Is(err, ErrConflict) {
				status, code = http.StatusConflict, "IDEMPOTENCY_CONFLICT"
			}
			m.error(w, status, code)
			return
		}
		m.json(w, http.StatusCreated, event)
	case http.MethodGet:
		if r.Header.Get("X-Browser-Module") == "1" && m.authorizeMetadata != nil {
			m.browserMetadata(w, r)
			return
		}
		if r.Header.Get("X-Browser-Module") == "1" {
			if r.Header.Get("X-Principal-Type") != "user" || r.Header.Get("X-Principal-ID") == "" || m.canReadBrowser == nil {
				m.error(w, http.StatusForbidden, "FORBIDDEN")
				return
			}
			allowed, err := m.canReadBrowser(r.Context(), r.Header.Get("X-Tenant-ID"), r.Header.Get("X-Department-ID"), r.Header.Get("X-Application-ID"), r.Header.Get("X-Principal-ID"))
			if err != nil {
				m.error(w, http.StatusServiceUnavailable, "IDENTITY_UNAVAILABLE")
				return
			}
			if !allowed {
				m.error(w, http.StatusForbidden, "FORBIDDEN")
				return
			}
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
		tenantID, departmentID, applicationID := r.Header.Get("X-Tenant-ID"), r.Header.Get("X-Department-ID"), r.Header.Get("X-Application-ID")
		var result Page
		var err error
		if taskID, traceID := strings.TrimSpace(r.URL.Query().Get("task_id")), strings.TrimSpace(r.URL.Query().Get("trace_id")); taskID != "" || traceID != "" {
			reader, ok := m.store.(FilteredReader)
			if !ok {
				m.error(w, http.StatusNotImplemented, "FILTERED_AUDIT_QUERY_UNAVAILABLE")
				return
			}
			result, err = reader.ListFiltered(r.Context(), tenantID, departmentID, applicationID, taskID, traceID, page, pageSize)
		} else {
			result, err = m.store.List(r.Context(), tenantID, departmentID, applicationID, page, pageSize)
		}
		if err != nil {
			if errors.Is(err, ErrInvalidEvent) {
				m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
				return
			}
			m.error(w, http.StatusInternalServerError, "AUDIT_QUERY_FAILED")
			return
		}
		if r.Header.Get("X-Browser-Module") == "1" {
			result.Items = append([]Event{}, result.Items...)
			for i := range result.Items {
				if !(MetadataScope{Type: "application", TenantID: tenantID, DepartmentID: departmentID, ApplicationID: applicationID}).contains(result.Items[i]) {
					m.error(w, http.StatusInternalServerError, "AUDIT_SCOPE_MISMATCH")
					return
				}
				result.Items[i].Summary = ""
			}
			result.MetadataOnly = true
			w.Header().Set("Cache-Control", "no-store")
		}
		m.json(w, http.StatusOK, result)
	default:
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
	}
}

func (m *Module) browserMetadata(w http.ResponseWriter, r *http.Request) {
	actor := sharedkernel.Scope{PrincipalType: r.Header.Get("X-Principal-Type"), PrincipalID: r.Header.Get("X-Principal-ID"), TenantID: r.Header.Get("X-Tenant-ID"), DepartmentID: r.Header.Get("X-Department-ID"), ApplicationID: r.Header.Get("X-Application-ID")}
	if actor.Validate() != nil || actor.PrincipalType != "user" {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	query := r.URL.Query()
	target := MetadataScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	if _, explicit := query["scope_type"]; explicit {
		target = MetadataScope{Type: query.Get("scope_type"), TenantID: query.Get("tenant_id"), DepartmentID: query.Get("department_id"), ApplicationID: query.Get("application_id")}
	} else if query.Has("tenant_id") || query.Has("department_id") || query.Has("application_id") {
		m.error(w, http.StatusBadRequest, "EXPLICIT_AUDIT_SCOPE_REQUIRED")
		return
	}
	if target.Validate() != nil {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if err := m.authorizeMetadata(r.Context(), actor, target); err != nil {
		if errors.Is(err, ErrMetadataForbidden) {
			m.error(w, http.StatusForbidden, "FORBIDDEN")
		} else {
			m.error(w, http.StatusServiceUnavailable, "IDENTITY_UNAVAILABLE")
		}
		return
	}
	page, _ := strconv.Atoi(query.Get("page"))
	size, _ := strconv.Atoi(query.Get("page_size"))
	for _, key := range []string{"page", "page_size"} {
		if raw := query.Get(key); raw != "" {
			if _, err := strconv.Atoi(raw); err != nil {
				m.error(w, http.StatusBadRequest, "INVALID_PAGINATION")
				return
			}
		}
	}
	request := MetadataQuery{Scope: target, TaskID: strings.TrimSpace(query.Get("task_id")), TraceID: strings.TrimSpace(query.Get("trace_id")), Page: page, PageSize: size}
	var result Page
	var err error
	if reader, ok := m.store.(MetadataReader); ok {
		result, err = reader.ListMetadata(r.Context(), request)
	} else if target.Type == "application" {
		if request.TaskID != "" || request.TraceID != "" {
			if reader, ok := m.store.(FilteredReader); ok {
				result, err = reader.ListFiltered(r.Context(), target.TenantID, target.DepartmentID, target.ApplicationID, request.TaskID, request.TraceID, page, size)
			} else {
				err = ErrInvalidEvent
			}
		} else {
			result, err = m.store.List(r.Context(), target.TenantID, target.DepartmentID, target.ApplicationID, page, size)
		}
	} else {
		m.error(w, http.StatusNotImplemented, "SCOPED_AUDIT_QUERY_UNAVAILABLE")
		return
	}
	if err != nil {
		if errors.Is(err, ErrInvalidEvent) {
			m.error(w, http.StatusBadRequest, "INVALID_SCOPE_OR_PAGINATION")
		} else {
			m.error(w, http.StatusInternalServerError, "AUDIT_QUERY_FAILED")
		}
		return
	}
	result.Items = append([]Event{}, result.Items...)
	for i := range result.Items {
		if !target.contains(result.Items[i]) {
			m.error(w, http.StatusInternalServerError, "AUDIT_SCOPE_MISMATCH")
			return
		}
		result.Items[i].Summary = ""
	}
	result.MetadataOnly = true
	w.Header().Set("Cache-Control", "no-store")
	m.json(w, http.StatusOK, result)
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
