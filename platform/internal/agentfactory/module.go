package agentfactory

import (
	"bytes"
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
)

const maxRequestBytes = 12 << 20 // supports an 8MiB binary artifact after base64 expansion

type Module struct {
	store         Store
	authorizer    Authorizer
	internalToken string
}

func NewModule(store Store, authorizer Authorizer, internalToken string) *Module {
	return &Module{store: store, authorizer: authorizer, internalToken: strings.TrimSpace(internalToken)}
}

func (m *Module) Name() string { return "agent-factory" }
func (m *Module) Start(ctx context.Context) error {
	if m == nil || m.store == nil {
		return errors.New("agent factory store is required")
	}
	if m.internalToken == "" {
		return errors.New("agent factory internal token is required")
	}
	// Schema is installed by the versioned migration command, never Start.
	// Schema由独立版本迁移命令安装，Start不得改库。
	return ctx.Err()
}
func (m *Module) Ready() error {
	if m == nil || m.store == nil || m.authorizer == nil || m.internalToken == "" {
		return errors.New("agent factory dependencies are not configured")
	}
	return nil
}
func (m *Module) Close(context.Context) error { return nil }

// Handler is mounted under the Platform module registry. Its dependencies are ports, so the same contract can be hosted remotely later.
// Handler 挂载在 Platform 模块注册表下。依赖均为端口，因此未来可用相同契约远程承载。
func (m *Module) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/templates", m.templates)
	mux.HandleFunc("/templates/", m.template)
	mux.HandleFunc("/mappings", m.mappings)
	mux.HandleFunc("/mappings/", m.mapping)
	return mux
}

func (m *Module) templates(w http.ResponseWriter, r *http.Request) {
	action := ActionRead
	if r.Method == http.MethodPost {
		action = ActionManage
	}
	scope, actor, ok := m.authorize(w, r, action)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		limit, valid := readLimit(r)
		if !valid {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		items, err := m.store.ListTemplates(r.Context(), scope, limit, r.URL.Query().Get("after"))
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var in CreateTemplateRequest
		if !m.decode(w, r, &in) {
			return
		}
		item, err := (Service{Store: m.store}).RegisterTemplate(r.Context(), scope, actor, in)
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusCreated, item)
	default:
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
	}
}

func (m *Module) template(w http.ResponseWriter, r *http.Request) {
	parts := pathParts(r.URL.Path, "/templates/")
	if len(parts) == 0 || !safeID(parts[0]) {
		m.writeError(w, http.StatusNotFound, "NOT_FOUND")
		return
	}
	action := ActionRead
	if len(parts) == 2 && parts[1] == "versions" && r.Method == http.MethodPost {
		action = ActionManage
	}
	scope, actor, ok := m.authorize(w, r, action)
	if !ok {
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		item, err := m.store.GetTemplate(r.Context(), scope, parts[0])
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, item)
		return
	}
	if len(parts) != 2 || parts[1] != "versions" {
		m.writeError(w, http.StatusNotFound, "NOT_FOUND")
		return
	}
	parent, err := m.store.GetTemplate(r.Context(), scope, parts[0])
	if err != nil {
		m.writeStoreError(w, err)
		return
	}
	if r.Method == http.MethodGet {
		limit, valid := readLimit(r)
		if !valid {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		items, e := m.store.ListTemplateVersions(r.Context(), scope, parent.ID, limit)
		if e != nil {
			m.writeStoreError(w, e)
			return
		}
		m.writeJSON(w, http.StatusOK, map[string]any{"items": items})
		return
	}
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	var in CreateTemplateVersionRequest
	if !m.decode(w, r, &in) {
		return
	}
	item, err := (Service{Store: m.store}).RegisterVersion(r.Context(), scope, actor, parts[0], in)
	if err != nil {
		m.writeStoreError(w, err)
		return
	}
	m.writeJSON(w, http.StatusCreated, item)
}

func (m *Module) mappings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		scope, _, ok := m.authorize(w, r, ActionRead)
		if !ok {
			return
		}
		limit, valid := readLimit(r)
		if !valid {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		items, err := m.store.ListMappings(r.Context(), scope, limit, r.URL.Query().Get("after"))
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
	scope, actor, ok := m.authorize(w, r, ActionManage)
	if !ok {
		return
	}
	var in CreateMappingRequest
	if !m.decode(w, r, &in) {
		return
	}
	item, err := (Service{Store: m.store}).CreateMapping(r.Context(), scope, actor, in)
	if err != nil {
		m.writeStoreError(w, err)
		return
	}
	m.writeJSON(w, http.StatusCreated, item)
}

func (m *Module) mapping(w http.ResponseWriter, r *http.Request) {
	parts := pathParts(r.URL.Path, "/mappings/")
	if len(parts) == 0 || !safeID(parts[0]) {
		m.writeError(w, http.StatusNotFound, "NOT_FOUND")
		return
	}
	action := ActionRead
	if len(parts) == 2 && parts[1] == "dry-run" {
		action = ActionManage
	}
	if len(parts) == 2 && parts[1] == "publish" {
		action = ActionPublish
	}
	scope, actor, ok := m.authorize(w, r, action)
	if !ok {
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		item, err := m.store.GetMapping(r.Context(), scope, parts[0])
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, item)
		return
	}
	if len(parts) == 2 && parts[1] == "evidence" && r.Method == http.MethodGet {
		limit, valid := readLimit(r)
		if !valid {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		items, err := (Service{Store: m.store}).ListEvidence(r.Context(), scope, parts[0], limit)
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, map[string]any{"items": items})
		return
	}
	if len(parts) != 2 {
		m.writeError(w, http.StatusNotFound, "NOT_FOUND")
		return
	}
	switch parts[1] {
	case "dry-run":
		if r.Method != http.MethodPost {
			m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		var in DryRunRequest
		if !m.decode(w, r, &in) {
			return
		}
		result, err := (Service{Store: m.store}).DryRun(r.Context(), scope, actor, parts[0], in)
		if err != nil {
			m.writeError(w, http.StatusUnprocessableEntity, "CONFORMANCE_FAILED")
			return
		}
		m.writeJSON(w, http.StatusOK, result)
	case "publish":
		if r.Method != http.MethodPost {
			m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		var body struct {
			Revision uint64 `json:"revision"`
		}
		if !m.decode(w, r, &body) {
			return
		}
		expected := body.Revision
		if raw := strings.TrimSpace(r.Header.Get("If-Match")); raw != "" {
			parsed, err := strconv.ParseUint(strings.Trim(raw, "\""), 10, 64)
			if err != nil || parsed == 0 || body.Revision != 0 && body.Revision != parsed {
				m.writeError(w, http.StatusBadRequest, "INVALID_REVISION")
				return
			}
			expected = parsed
		}
		item, err := (Service{Store: m.store}).PublishMapping(r.Context(), scope, parts[0], expected)
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, map[string]any{"status": item.Status, "revision": item.Revision})
	default:
		m.writeError(w, http.StatusNotFound, "NOT_FOUND")
	}
}

func (m *Module) authorize(w http.ResponseWriter, r *http.Request, action Action) (Scope, Actor, bool) {
	provided := strings.TrimSpace(r.Header.Get("X-Internal-Token"))
	if provided == "" {
		fields := strings.Fields(r.Header.Get("Authorization"))
		if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
			provided = fields[1]
		}
	}
	if m == nil || m.internalToken == "" || len(provided) != len(m.internalToken) || subtle.ConstantTimeCompare([]byte(provided), []byte(m.internalToken)) != 1 {
		m.writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return Scope{}, Actor{}, false
	}
	if r.Header.Get("X-Browser-Module") != "1" || strings.TrimSpace(r.Header.Get("X-Principal-Type")) != "user" {
		m.writeError(w, http.StatusUnauthorized, "BROWSER_IDENTITY_REQUIRED")
		return Scope{}, Actor{}, false
	}
	scope := Scope{TenantID: strings.TrimSpace(r.Header.Get("X-Tenant-ID")), DepartmentID: strings.TrimSpace(r.Header.Get("X-Department-ID")), ApplicationID: strings.TrimSpace(r.Header.Get("X-Application-ID"))}
	actor := Actor{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, PrincipalType: "user", PrincipalID: strings.TrimSpace(r.Header.Get("X-Principal-ID"))}
	if scope.Validate() != nil || actor.PrincipalID == "" {
		m.writeError(w, http.StatusUnauthorized, "BROWSER_IDENTITY_REQUIRED")
		return Scope{}, Actor{}, false
	}
	if m.authorizer == nil {
		m.writeError(w, http.StatusServiceUnavailable, "AUTHORIZATION_UNAVAILABLE")
		return Scope{}, Actor{}, false
	}
	if err := m.authorizer.AuthorizeAgentFactory(r.Context(), actor, action, scope); err != nil {
		if errors.Is(err, ErrForbidden) {
			m.writeError(w, http.StatusForbidden, "FORBIDDEN")
		} else {
			m.writeError(w, http.StatusServiceUnavailable, "AUTHORIZATION_UNAVAILABLE")
		}
		return Scope{}, Actor{}, false
	}
	return scope, actor, true
}

func (m *Module) decode(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.ContentLength > maxRequestBytes {
		m.writeError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE")
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil || len(body) > maxRequestBytes {
		m.writeError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(target) != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return false
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return false
	}
	return true
}

func (m *Module) writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrInvalidScope):
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
	case errors.Is(err, ErrNotFound):
		m.writeError(w, http.StatusNotFound, "NOT_FOUND")
	case errors.Is(err, ErrConflict):
		m.writeError(w, http.StatusConflict, "REVISION_CONFLICT")
	case errors.Is(err, ErrAlreadyExists):
		m.writeError(w, http.StatusConflict, "ALREADY_EXISTS")
	case errors.Is(err, ErrForbidden):
		m.writeError(w, http.StatusForbidden, "FORBIDDEN")
	case errors.Is(err, ErrConformanceNeeded):
		m.writeError(w, http.StatusConflict, "CONFORMANCE_REQUIRED")
	default:
		m.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
	}
}
func (m *Module) writeError(w http.ResponseWriter, status int, code string) {
	m.writeJSON(w, status, map[string]any{"error": map[string]string{"code": code}})
}
func (m *Module) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func readLimit(r *http.Request) (int, bool) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return 50, true
	}
	value, err := strconv.Atoi(raw)
	return clampLimit(value), err == nil && value > 0
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
func newID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("allocate agent factory id: %w", err)
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(bytes[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

var _ interface {
	Name() string
	Start(context.Context) error
	Ready() error
	Handler() http.Handler
	Close(context.Context) error
} = (*Module)(nil)
