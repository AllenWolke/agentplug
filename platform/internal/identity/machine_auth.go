package identity

// Machine client credentials and short-lived opaque access tokens are owned by
// Identity. The raw secrets are returned only at issuance and never persisted.
// Identity 模块负责机器凭证和短时不透明访问令牌；原始 Secret 仅在签发时返回，不落库。

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

const machineAccessTokenTTL = 5 * time.Minute

var (
	ErrMachineCredentialNotFound = errors.New("machine credential not found")
	ErrMachineCredentialsInvalid = errors.New("invalid machine credentials")
	ErrMachineCredentialConflict = errors.New("machine credential revision conflict")
	ErrMachineAccessDenied       = errors.New("machine access denied")
)

// MachineCredential contains only a one-way secret hash and bounded network
// restrictions. PrincipalID is also the OAuth client_id.
// MachineCredential 仅含单向 Secret 哈希和有界网络限制；PrincipalID 同时作为 OAuth client_id。
type MachineCredential struct {
	TenantID     string    `json:"tenant_id"`
	PrincipalID  string    `json:"client_id"`
	SecretHash   string    `json:"-"`
	NetworkCIDRs []string  `json:"network_cidrs"`
	Status       string    `json:"status"`
	Revision     uint64    `json:"revision"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// MachineAccessToken stores only the token hash. Every API call rechecks the
// credential revision, principal status, network and current grant.
// MachineAccessToken 仅保存令牌哈希；每次调用重新验证凭证版本、主体状态、网络和当前 Grant。
type MachineAccessToken struct {
	TokenHash          string
	TenantID           string
	PrincipalID        string
	DepartmentID       string
	ApplicationID      string
	AgentInstanceID    string
	Actions            []string
	NetworkCIDRs       []string
	CredentialRevision uint64
	ExpiresAt          time.Time
	CreatedAt          time.Time
}

// MachineAuthStore is a narrow persistence seam, separate from human session
// storage so it can later be replaced by an IAM service adapter.
// MachineAuthStore 是机器身份专用的窄持久化端口，可独立替换为 IAM 服务 Adapter。
type MachineAuthStore interface {
	CreateMachineCredential(context.Context, MachineCredential) error
	GetMachineCredential(context.Context, string, string) (MachineCredential, error)
	ListMachineCredentials(context.Context, string) ([]MachineCredential, error)
	RotateMachineCredential(context.Context, string, string, uint64, string, []string) (uint64, error)
	DisableMachineCredential(context.Context, string, string, uint64) (uint64, error)
	CreateMachineAccessToken(context.Context, MachineAccessToken) error
	GetMachineAccessToken(context.Context, string) (MachineAccessToken, error)
}

type MachineGrantScope struct {
	TenantID        string   `json:"tenant_id"`
	DepartmentID    string   `json:"department_id"`
	ApplicationID   string   `json:"application_id"`
	AgentInstanceID string   `json:"agent_instance_id"`
	Actions         []string `json:"actions"`
}

type MachineTokenIssueRequest struct {
	GrantType    string            `json:"grant_type"`
	TenantID     string            `json:"tenant_id"`
	ClientID     string            `json:"client_id"`
	ClientSecret string            `json:"client_secret"`
	Scope        MachineGrantScope `json:"scope"`
}

type MachineTokenIssueResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type MachineIdentity struct {
	Scope              sharedkernel.Scope
	AuthorizationEpoch uint64
	ExpiresAt          time.Time
	Actions            []string
}

func NewMachineSecret() (secret string, hash string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate machine secret: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(raw)
	return secret, digestMachineValue(secret), nil
}

func NewMachineAccessToken() (token string, hash string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate machine access token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, digestMachineValue(token), nil
}

func digestMachineValue(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func normalizeMachineCIDRs(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 32 {
		return nil, ErrInvalidResource
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, ErrInvalidResource
		}
		canonical := network.String()
		if _, exists := seen[canonical]; !exists {
			seen[canonical] = struct{}{}
			result = append(result, canonical)
		}
	}
	return result, nil
}

func machineSourceAllowed(remoteAddr string, cidrs []string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.Trim(strings.TrimSpace(remoteAddr), "[]")
	}
	ip := net.ParseIP(host)
	if ip == nil || len(cidrs) == 0 {
		return false
	}
	for _, raw := range cidrs {
		_, network, parseErr := net.ParseCIDR(raw)
		if parseErr == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func allowedMachineAction(action string) bool {
	switch action {
	case "run", "read", "events", "cancel", "resume":
		return true
	default:
		return false
	}
}

// ExchangeMachineToken authenticates a registered service principal and issues
// an opaque, five-minute token only for actions currently allowed by grants.
// ExchangeMachineToken 验证机器主体后，只为当前 Grant 已允许的动作签发五分钟不透明令牌。
func (m *Module) ExchangeMachineToken(ctx context.Context, request MachineTokenIssueRequest, remoteAddr string) (MachineTokenIssueResponse, error) {
	store, ok := m.store.(MachineAuthStore)
	if !ok || request.GrantType != "client_credentials" || strings.TrimSpace(request.TenantID) == "" ||
		strings.TrimSpace(request.ClientID) == "" || strings.TrimSpace(request.ClientSecret) == "" {
		return MachineTokenIssueResponse{}, ErrMachineCredentialsInvalid
	}
	credential, err := store.GetMachineCredential(ctx, request.TenantID, request.ClientID)
	if err != nil || credential.Status != "active" {
		return MachineTokenIssueResponse{}, ErrMachineCredentialsInvalid
	}
	providedHash := digestMachineValue(request.ClientSecret)
	if len(providedHash) != len(credential.SecretHash) || subtle.ConstantTimeCompare([]byte(providedHash), []byte(credential.SecretHash)) != 1 {
		return MachineTokenIssueResponse{}, ErrMachineCredentialsInvalid
	}
	if !machineSourceAllowed(remoteAddr, credential.NetworkCIDRs) {
		return MachineTokenIssueResponse{}, ErrMachineCredentialsInvalid
	}
	principal, err := m.store.GetPrincipal(ctx, PrincipalServicePrincipal, credential.PrincipalID)
	if err != nil || !principal.IsActive || principal.TenantID != credential.TenantID || len(principal.Roles) != 0 {
		return MachineTokenIssueResponse{}, ErrMachineCredentialsInvalid
	}
	scope := sharedkernel.Scope{TenantID: request.Scope.TenantID, DepartmentID: request.Scope.DepartmentID,
		ApplicationID: request.Scope.ApplicationID, AgentInstanceID: request.Scope.AgentInstanceID,
		PrincipalType: string(PrincipalServicePrincipal), PrincipalID: principal.ID}
	if scope.Validate() != nil || scope.TenantID != credential.TenantID || len(request.Scope.Actions) == 0 || len(request.Scope.Actions) > 5 {
		return MachineTokenIssueResponse{}, ErrMachineCredentialsInvalid
	}
	actions := make([]string, 0, len(request.Scope.Actions))
	seen := make(map[string]struct{}, len(request.Scope.Actions))
	for _, action := range request.Scope.Actions {
		action = strings.TrimSpace(action)
		if !allowedMachineAction(action) {
			return MachineTokenIssueResponse{}, ErrMachineCredentialsInvalid
		}
		if _, duplicate := seen[action]; duplicate {
			continue
		}
		decision, accessErr := checkMachinePermission(ctx, m.store, scope, action, nil)
		if accessErr != nil || !decision.Allowed {
			return MachineTokenIssueResponse{}, ErrMachineCredentialsInvalid
		}
		seen[action] = struct{}{}
		actions = append(actions, action)
	}
	token, tokenHash, err := NewMachineAccessToken()
	if err != nil {
		return MachineTokenIssueResponse{}, err
	}
	now := time.Now().UTC()
	if err := store.CreateMachineAccessToken(ctx, MachineAccessToken{TokenHash: tokenHash, TenantID: scope.TenantID,
		PrincipalID: principal.ID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
		AgentInstanceID: scope.AgentInstanceID, Actions: actions, NetworkCIDRs: credential.NetworkCIDRs,
		CredentialRevision: credential.Revision, ExpiresAt: now.Add(machineAccessTokenTTL), CreatedAt: now}); err != nil {
		return MachineTokenIssueResponse{}, err
	}
	return MachineTokenIssueResponse{AccessToken: token, TokenType: "Bearer", ExpiresIn: int(machineAccessTokenTTL.Seconds())}, nil
}

// AuthenticateMachineToken rechecks durable credential and grant state for
// every public API request; rotation, disable or grant revocation takes effect
// immediately, without waiting for the token's natural expiry.
// AuthenticateMachineToken 每次请求都重查凭证和 Grant；轮换、禁用或撤销授权即时生效。
func (m *Module) AuthenticateMachineToken(ctx context.Context, rawToken, remoteAddr, action string) (MachineIdentity, error) {
	store, ok := m.store.(MachineAuthStore)
	if !ok || strings.TrimSpace(rawToken) == "" || !allowedMachineAction(action) {
		return MachineIdentity{}, ErrMachineAccessDenied
	}
	token, err := store.GetMachineAccessToken(ctx, digestMachineValue(rawToken))
	if err != nil || !token.ExpiresAt.After(time.Now().UTC()) || !containsString(token.Actions, action) || !machineSourceAllowed(remoteAddr, token.NetworkCIDRs) {
		return MachineIdentity{}, ErrMachineAccessDenied
	}
	credential, err := store.GetMachineCredential(ctx, token.TenantID, token.PrincipalID)
	if err != nil || credential.Status != "active" || credential.Revision != token.CredentialRevision {
		return MachineIdentity{}, ErrMachineAccessDenied
	}
	principal, err := m.store.GetPrincipal(ctx, PrincipalServicePrincipal, token.PrincipalID)
	if err != nil || !principal.IsActive || principal.TenantID != token.TenantID || len(principal.Roles) != 0 {
		return MachineIdentity{}, ErrMachineAccessDenied
	}
	scope := sharedkernel.Scope{TenantID: token.TenantID, DepartmentID: token.DepartmentID, ApplicationID: token.ApplicationID,
		AgentInstanceID: token.AgentInstanceID, PrincipalType: string(PrincipalServicePrincipal), PrincipalID: token.PrincipalID}
	decision, err := checkMachinePermission(ctx, m.store, scope, action, nil)
	if err != nil || !decision.Allowed {
		return MachineIdentity{}, ErrMachineAccessDenied
	}
	return MachineIdentity{Scope: scope, AuthorizationEpoch: token.CredentialRevision, ExpiresAt: token.ExpiresAt, Actions: append([]string(nil), token.Actions...)}, nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

type machineCredentialRequest struct {
	PrincipalID  string   `json:"principal_id"`
	NetworkCIDRs []string `json:"network_cidrs"`
}

type rotateMachineCredentialRequest struct {
	ExpectedRevision uint64   `json:"expected_revision"`
	NetworkCIDRs     []string `json:"network_cidrs"`
}

type machineCredentialMutationResponse struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	NetworkCIDRs []string `json:"network_cidrs"`
	Status       string   `json:"status"`
	Revision     uint64   `json:"revision"`
}

func (m *Module) machineCredentials(w http.ResponseWriter, r *http.Request) {
	if !m.requireAuth(w, r) {
		return
	}
	store, ok := m.store.(MachineAuthStore)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "MACHINE_IDENTITY_UNAVAILABLE")
		return
	}
	if r.Method == http.MethodGet {
		actor, allowed := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin")
		if !allowed {
			return
		}
		if actor.Policy != nil {
			scoped, ok := m.store.(interface {
				ListPermissionMachineCredentials(context.Context, sharedkernel.Scope) ([]MachineCredential, error)
			})
			if !ok {
				m.error(w, http.StatusServiceUnavailable, "MACHINE_IDENTITY_UNAVAILABLE")
				return
			}
			items, err := scoped.ListPermissionMachineCredentials(r.Context(), actor.Scope)
			if err != nil {
				m.permissionError(w, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			m.json(w, http.StatusOK, items)
			return
		}
		scope, err := identityScopeFromRequest(r)
		if err != nil || !actor.canManage(scope.TenantID, "", "") {
			m.error(w, http.StatusForbidden, "FORBIDDEN")
			return
		}
		items, err := store.ListMachineCredentials(r.Context(), scope.TenantID)
		if err != nil {
			m.error(w, http.StatusServiceUnavailable, "MACHINE_IDENTITY_UNAVAILABLE")
			return
		}
		m.json(w, http.StatusOK, items)
		return
	}
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, allowed := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin")
	if !allowed {
		return
	}
	if actor.Policy != nil {
		m.error(w, http.StatusForbidden, "USE_WORKLOAD_PRINCIPAL_CREATION")
		return
	}
	scope, err := identityScopeFromRequest(r)
	if err != nil || !actor.canManage(scope.TenantID, "", "") {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	var request machineCredentialRequest
	if err := decode(r, &request); err != nil || strings.TrimSpace(request.PrincipalID) == "" {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	principal, err := m.store.GetPrincipal(r.Context(), PrincipalServicePrincipal, request.PrincipalID)
	if err != nil || !principal.IsActive || principal.TenantID != scope.TenantID || len(principal.Roles) != 0 {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	cidrs, err := normalizeMachineCIDRs(request.NetworkCIDRs)
	if err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_NETWORK_CIDRS")
		return
	}
	secret, secretHash, err := NewMachineSecret()
	if err != nil {
		m.error(w, http.StatusInternalServerError, "MACHINE_IDENTITY_UNAVAILABLE")
		return
	}
	credential := MachineCredential{TenantID: scope.TenantID, PrincipalID: principal.ID, SecretHash: secretHash,
		NetworkCIDRs: cidrs, Status: "active", Revision: 1}
	if err := store.CreateMachineCredential(r.Context(), credential); err != nil {
		if errors.Is(err, ErrMachineCredentialConflict) {
			m.error(w, http.StatusConflict, "CREDENTIAL_ALREADY_EXISTS")
			return
		}
		m.error(w, http.StatusServiceUnavailable, "MACHINE_IDENTITY_UNAVAILABLE")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	m.json(w, http.StatusCreated, machineCredentialMutationResponse{ClientID: principal.ID, ClientSecret: secret,
		NetworkCIDRs: cidrs, Status: "active", Revision: 1})
}

func (m *Module) machineCredential(w http.ResponseWriter, r *http.Request) {
	if !m.requireAuth(w, r) {
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
	baseScope, err := identityScopeFromRequest(r)
	if err != nil || actor.Policy == nil && !actor.canManage(baseScope.TenantID, "", "") {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	store, ok := m.store.(MachineAuthStore)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "MACHINE_IDENTITY_UNAVAILABLE")
		return
	}
	parts := strings.FieldsFunc(strings.Trim(strings.TrimPrefix(r.URL.Path, "/machine-credentials/"), "/"), func(r rune) bool { return r == '/' })
	if len(parts) != 2 || (parts[1] != "rotate" && parts[1] != "disable") {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	if _, err := m.store.GetPrincipal(r.Context(), PrincipalServicePrincipal, parts[0]); err != nil {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	credential, err := store.GetMachineCredential(r.Context(), baseScope.TenantID, parts[0])
	if err != nil {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	var request rotateMachineCredentialRequest
	if err := decode(r, &request); err != nil || request.ExpectedRevision == 0 {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if parts[1] == "rotate" {
		cidrs, err := normalizeMachineCIDRs(request.NetworkCIDRs)
		if err != nil {
			m.error(w, http.StatusBadRequest, "INVALID_NETWORK_CIDRS")
			return
		}
		secret, secretHash, err := NewMachineSecret()
		if err != nil {
			m.error(w, http.StatusInternalServerError, "MACHINE_IDENTITY_UNAVAILABLE")
			return
		}
		var revision uint64
		if actor.Policy != nil {
			scoped, ok := m.store.(interface {
				ChangePermissionMachineCredential(context.Context, sharedkernel.Scope, string, uint64, string, []string, bool) (uint64, error)
			})
			if !ok {
				m.error(w, http.StatusServiceUnavailable, "MACHINE_IDENTITY_UNAVAILABLE")
				return
			}
			revision, err = scoped.ChangePermissionMachineCredential(r.Context(), actor.Scope, parts[0], request.ExpectedRevision, secretHash, cidrs, false)
			if err != nil {
				m.permissionError(w, err)
				return
			}
		} else {
			revision, err = store.RotateMachineCredential(r.Context(), baseScope.TenantID, parts[0], request.ExpectedRevision, secretHash, cidrs)
		}
		if err != nil {
			if errors.Is(err, ErrMachineCredentialConflict) {
				m.error(w, http.StatusConflict, "REVISION_CONFLICT")
				return
			}
			// Log only the persistence error; never log the raw credential, secret hash,
			// access token, or CIDR list. / 仅记录持久化错误，绝不记录凭证、哈希、Token 或 CIDR。
			slog.Error("machine credential rotation persistence failed", "error", err)
			m.error(w, http.StatusServiceUnavailable, "MACHINE_IDENTITY_UNAVAILABLE")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		m.json(w, http.StatusOK, machineCredentialMutationResponse{ClientID: parts[0], ClientSecret: secret,
			NetworkCIDRs: cidrs, Status: "active", Revision: revision})
		return
	}
	var revision uint64
	if actor.Policy != nil {
		scoped, ok := m.store.(interface {
			ChangePermissionMachineCredential(context.Context, sharedkernel.Scope, string, uint64, string, []string, bool) (uint64, error)
		})
		if !ok {
			m.error(w, http.StatusServiceUnavailable, "MACHINE_IDENTITY_UNAVAILABLE")
			return
		}
		revision, err = scoped.ChangePermissionMachineCredential(r.Context(), actor.Scope, parts[0], request.ExpectedRevision, "", nil, true)
		if err != nil {
			m.permissionError(w, err)
			return
		}
	} else {
		revision, err = store.DisableMachineCredential(r.Context(), baseScope.TenantID, parts[0], request.ExpectedRevision)
	}
	if err != nil {
		if errors.Is(err, ErrMachineCredentialConflict) {
			m.error(w, http.StatusConflict, "REVISION_CONFLICT")
			return
		}
		slog.Error("machine credential disable persistence failed", "error", err)
		m.error(w, http.StatusServiceUnavailable, "MACHINE_IDENTITY_UNAVAILABLE")
		return
	}
	m.json(w, http.StatusOK, map[string]any{"client_id": credential.PrincipalID, "status": "disabled", "revision": revision})
}

func (m *Module) machineToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	var request MachineTokenIssueRequest
	if err := decode(r, &request); err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if clientID, clientSecret, ok := r.BasicAuth(); ok {
		request.ClientID, request.ClientSecret = clientID, clientSecret
	}
	response, err := m.ExchangeMachineToken(r.Context(), request, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, ErrMachineCredentialsInvalid) || errors.Is(err, ErrMachineAccessDenied) {
			m.error(w, http.StatusUnauthorized, "INVALID_CLIENT")
			return
		}
		m.error(w, http.StatusServiceUnavailable, "MACHINE_IDENTITY_UNAVAILABLE")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	m.json(w, http.StatusOK, response)
}

func marshalMachineActions(values []string) (string, error) {
	raw, err := json.Marshal(values)
	return string(raw), err
}
