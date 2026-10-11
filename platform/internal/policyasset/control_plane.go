package policyasset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/bootstrap"
)

type AssetType string

const (
	AssetModel     AssetType = "model"
	AssetPrompt    AssetType = "prompt"
	AssetTool      AssetType = "tool"
	AssetMemory    AssetType = "memory"
	AssetKnowledge AssetType = "knowledge"
	AssetRuntime   AssetType = "runtime"
)

type AssetStatus string

const (
	AssetDraft     AssetStatus = "draft"
	AssetPublished AssetStatus = "published"
)

type Action string

const (
	ActionRead    Action = "read"
	ActionCreate  Action = "create"
	ActionUpdate  Action = "update"
	ActionPublish Action = "publish"
)

var (
	ErrInvalidAsset    = errors.New("invalid policy asset")
	ErrAssetNotFound   = errors.New("policy asset not found")
	ErrAssetConflict   = errors.New("policy asset revision conflict")
	ErrForbidden       = errors.New("policy asset operation forbidden")
	ErrInvalidScope    = errors.New("invalid policy asset scope")
	ErrInvalidSnapshot = errors.New("invalid policy snapshot publication")
)

// Scope is the ownership boundary for all six policy asset families. Agent
// and version are mandatory so a published asset cannot be silently reused
// by another installation/version.
type Scope struct {
	TenantID       string `json:"tenant_id"`
	DepartmentID   string `json:"department_id"`
	ApplicationID  string `json:"application_id"`
	AgentID        string `json:"agent_id"`
	AgentVersionID string `json:"agent_version_id"`
}

func (s Scope) validate() error {
	for _, value := range []string{s.TenantID, s.DepartmentID, s.ApplicationID, s.AgentID, s.AgentVersionID} {
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) || len(value) > 128 || strings.ContainsAny(value, "\x00\r\n") {
			return ErrInvalidScope
		}
	}
	return nil
}

type Actor struct {
	TenantID      string
	DepartmentID  string
	ApplicationID string
	PrincipalType string
	PrincipalID   string
}

// Authorizer resolves the current browser principal and roles through the
// Identity boundary. Actor data comes only from trusted Gateway headers;
// Scope is the target resource boundary and is never accepted as authority.
type Authorizer interface {
	AuthorizePolicyAsset(context.Context, Actor, Action, Scope) error
}

// Asset type comes from the validated route or the actual asset being created.
// Snapshot publication deliberately continues through the separate Authorizer.
type TypedAssetAuthorizer interface {
	AuthorizeTypedPolicyAsset(context.Context, Actor, Action, Scope, AssetType) error
}

type Asset struct {
	ID        string          `json:"id"`
	Type      AssetType       `json:"type"`
	Scope     Scope           `json:"scope"`
	Revision  uint64          `json:"revision"`
	Status    AssetStatus     `json:"status"`
	Content   json.RawMessage `json:"content"`
	Hash      string          `json:"content_hash"`
	CreatedBy string          `json:"created_by,omitempty"`
	CreatedAt time.Time       `json:"created_at,omitempty"`
}

type AssetRef struct {
	ID       string `json:"id"`
	Revision uint64 `json:"revision"`
}

type PublishSnapshotRequest struct {
	Scope            Scope                  `json:"scope"`
	ExpectedRevision uint64                 `json:"expected_revision"`
	Assets           map[AssetType]AssetRef `json:"assets"`
	// Rule binds an approved deterministic bundle to the immutable publication.
	// Rule 将已审批确定性规则包绑定到不可变发布，不依赖开发启动引导。
	Rule RulePolicy `json:"rule,omitempty"`
}

type Store interface {
	EnsureSchema(context.Context) error
	Ping(context.Context) error
	CreateAsset(context.Context, Asset) error
	GetAsset(context.Context, Scope, AssetType, string, uint64) (Asset, error)
	ListAssets(context.Context, Scope, AssetType, int) ([]Asset, error)
	GetSnapshot(context.Context, Scope) (Snapshot, error)
	UpdateAsset(context.Context, Scope, AssetType, string, uint64, json.RawMessage) (Asset, error)
	PublishAsset(context.Context, Scope, AssetType, string, uint64) (Asset, error)
	PublishSnapshot(context.Context, PublishSnapshotRequest) (Snapshot, error)
}

type Module struct {
	store         Store
	authorizer    Authorizer
	internalToken string
}

func NewModule(store Store, authorizer Authorizer, internalToken string) *Module {
	return &Module{store: store, authorizer: authorizer, internalToken: strings.TrimSpace(internalToken)}
}

func (m *Module) Name() string { return "policyasset" }

func (m *Module) Start(ctx context.Context) error {
	if m == nil || m.store == nil {
		return errors.New("policy asset store is required")
	}
	if m.internalToken == "" {
		return errors.New("policy asset internal gateway token is required")
	}
	// The control plane uses the installed schema; deployment owns migrations.
	// 策略控制面只使用已安装Schema，迁移由部署阶段负责。
	return ctx.Err()
}

func (m *Module) Ready() error {
	return m.ReadyContext(context.Background())
}

func (m *Module) ReadyContext(ctx context.Context) error {
	if m == nil || m.store == nil {
		return errors.New("policy asset store is required")
	}
	if m.internalToken == "" {
		return errors.New("policy asset internal gateway token is required")
	}
	return bootstrap.ProbeDependency(ctx, m.store.Ping)
}

func (m *Module) Close(context.Context) error { return nil }

// Handler is mounted at /modules/policyasset. Management is browser-only;
// internal runtime resolution remains the separate SQLResolver contract.
func (m *Module) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/assets", m.assets)
	mux.HandleFunc("/assets/", m.asset)
	mux.HandleFunc("/snapshots/current", m.currentSnapshot)
	mux.HandleFunc("/snapshots/publish", m.publishSnapshot)
	return mux
}

func (m *Module) assets(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			ID      string          `json:"id"`
			Type    AssetType       `json:"type"`
			Scope   Scope           `json:"scope"`
			Content json.RawMessage `json:"content"`
		}
		if decodeJSON(r, &req) != nil || validateAssetContent(req.Type, req.Content) != nil || !validID(req.ID) {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if !m.authorize(w, r, ActionCreate, req.Scope, req.Type) {
			return
		}
		content, hash, err := canonicalContent(req.Type, req.Content)
		if err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		asset := Asset{ID: req.ID, Type: req.Type, Scope: req.Scope, Revision: 1, Status: AssetDraft, Content: content, Hash: hash, CreatedBy: strings.TrimSpace(r.Header.Get("X-Principal-ID"))}
		if err := m.store.CreateAsset(r.Context(), asset); err != nil {
			m.writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, asset)
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	scope, ok := scopeFromQuery(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	typ := AssetType(strings.TrimSpace(r.URL.Query().Get("type")))
	if typ != "" && !validAssetType(typ) {
		writeError(w, http.StatusBadRequest, "INVALID_ASSET_TYPE")
		return
	}
	referencesOnly := r.URL.Query().Get("view") == "snapshot-references"
	if referencesOnly {
		if typ != "" {
			writeError(w, http.StatusBadRequest, "INVALID_ASSET_TYPE")
			return
		}
		if !m.authorize(w, r, ActionRead, scope) {
			return
		}
	} else {
		if !m.authorize(w, r, ActionRead, scope, typ) {
			return
		}
		// An unfiltered list contains Prompt/Tool bodies as well. It cannot
		// bypass their typed permissions through the generic policy action.
		if typ == "" && (!m.authorize(w, r, ActionRead, scope, AssetPrompt) || !m.authorize(w, r, ActionRead, scope, AssetTool)) {
			return
		}
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			writeError(w, http.StatusBadRequest, "INVALID_LIMIT")
			return
		}
		limit = parsed
	}
	items, err := m.store.ListAssets(r.Context(), scope, typ, limit)
	if err != nil {
		m.writeStoreError(w, err)
		return
	}
	if referencesOnly {
		references := []map[string]any{}
		for _, item := range items {
			if item.Status == AssetPublished {
				references = append(references, map[string]any{"id": item.ID, "type": item.Type, "revision": item.Revision, "status": item.Status})
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": references})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (m *Module) asset(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/assets/"), "/"), "/")
	if len(parts) < 2 || len(parts) > 3 {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	typ, id := AssetType(parts[0]), parts[1]
	if !validAssetType(typ) || !validID(id) {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	if len(parts) == 3 {
		if parts[2] != "publish" || r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
			return
		}
		var req struct {
			Scope            Scope  `json:"scope"`
			ExpectedRevision uint64 `json:"expected_revision"`
		}
		if decodeJSON(r, &req) != nil || req.ExpectedRevision == 0 {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if !m.authorize(w, r, ActionPublish, req.Scope, typ) {
			return
		}
		asset, err := m.store.PublishAsset(r.Context(), req.Scope, typ, id, req.ExpectedRevision)
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, asset)
		return
	}
	switch r.Method {
	case http.MethodGet:
		scope, ok := scopeFromQuery(r)
		if !ok {
			writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
			return
		}
		if !m.authorize(w, r, ActionRead, scope, typ) {
			return
		}
		revision := uint64(0)
		if raw := r.URL.Query().Get("revision"); raw != "" {
			parsed, err := strconv.ParseUint(raw, 10, 64)
			if err != nil || parsed == 0 {
				writeError(w, http.StatusBadRequest, "INVALID_REVISION")
				return
			}
			revision = parsed
		}
		asset, err := m.store.GetAsset(r.Context(), scope, typ, id, revision)
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, asset)
	case http.MethodPut:
		var req struct {
			Scope            Scope           `json:"scope"`
			ExpectedRevision uint64          `json:"expected_revision"`
			Content          json.RawMessage `json:"content"`
		}
		if decodeJSON(r, &req) != nil || req.ExpectedRevision == 0 || validateAssetContent(typ, req.Content) != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if !m.authorize(w, r, ActionUpdate, req.Scope, typ) {
			return
		}
		asset, err := m.store.UpdateAsset(r.Context(), req.Scope, typ, id, req.ExpectedRevision, req.Content)
		if err != nil {
			m.writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, asset)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
	}
}

func (m *Module) publishSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	var req PublishSnapshotRequest
	if decodeJSON(r, &req) != nil || req.ExpectedRevision > 1_000_000_000 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if !m.authorize(w, r, ActionPublish, req.Scope) {
		return
	}
	snapshot, err := m.store.PublishSnapshot(r.Context(), req)
	if err != nil {
		m.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (m *Module) currentSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	scope, ok := scopeFromQuery(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if !m.authorize(w, r, ActionRead, scope) {
		return
	}
	snapshot, err := m.store.GetSnapshot(r.Context(), scope)
	if err != nil {
		m.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (m *Module) authorize(w http.ResponseWriter, r *http.Request, action Action, scope Scope, assetTypes ...AssetType) bool {
	if m == nil || m.internalToken == "" {
		writeError(w, http.StatusServiceUnavailable, "AUTHENTICATION_UNAVAILABLE")
		return false
	}
	providedToken := strings.TrimSpace(r.Header.Get("X-Internal-Token"))
	if providedToken == "" {
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			providedToken = parts[1]
		}
	}
	if len(providedToken) != len(m.internalToken) || subtle.ConstantTimeCompare([]byte(providedToken), []byte(m.internalToken)) != 1 {
		writeError(w, http.StatusUnauthorized, "INTERNAL_AUTHENTICATION_REQUIRED")
		return false
	}
	if r.Header.Get("X-Browser-Module") != "1" || strings.TrimSpace(r.Header.Get("X-Principal-Type")) != "user" || strings.TrimSpace(r.Header.Get("X-Principal-ID")) == "" {
		writeError(w, http.StatusUnauthorized, "BROWSER_IDENTITY_REQUIRED")
		return false
	}
	if err := scope.validate(); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return false
	}
	if m == nil || m.authorizer == nil {
		writeError(w, http.StatusServiceUnavailable, "AUTHORIZATION_UNAVAILABLE")
		return false
	}
	actor := Actor{
		TenantID:      strings.TrimSpace(r.Header.Get("X-Tenant-ID")),
		DepartmentID:  strings.TrimSpace(r.Header.Get("X-Department-ID")),
		ApplicationID: strings.TrimSpace(r.Header.Get("X-Application-ID")),
		PrincipalType: "user", PrincipalID: strings.TrimSpace(r.Header.Get("X-Principal-ID")),
	}
	if actor.TenantID == "" || actor.DepartmentID == "" || actor.ApplicationID == "" {
		writeError(w, http.StatusUnauthorized, "BROWSER_IDENTITY_REQUIRED")
		return false
	}
	var err error
	if len(assetTypes) > 0 {
		typed, ok := m.authorizer.(TypedAssetAuthorizer)
		if !ok {
			writeError(w, http.StatusServiceUnavailable, "AUTHORIZATION_UNAVAILABLE")
			return false
		}
		err = typed.AuthorizeTypedPolicyAsset(r.Context(), actor, action, scope, assetTypes[0])
	} else {
		err = m.authorizer.AuthorizePolicyAsset(r.Context(), actor, action, scope)
	}
	if err != nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN")
		return false
	}
	return true
}

func (m *Module) writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrAssetNotFound), errors.Is(err, ErrPolicyNotFound):
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
	case errors.Is(err, ErrInvalidAsset), errors.Is(err, ErrInvalidScope), errors.Is(err, ErrInvalidSnapshot):
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
	case errors.Is(err, ErrAssetConflict):
		writeError(w, http.StatusConflict, "REVISION_CONFLICT")
	case errors.Is(err, ErrForbidden):
		writeError(w, http.StatusForbidden, "FORBIDDEN")
	default:
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
	}
}

func scopeFromQuery(r *http.Request) (Scope, bool) {
	s := Scope{TenantID: r.URL.Query().Get("tenant_id"), DepartmentID: r.URL.Query().Get("department_id"), ApplicationID: r.URL.Query().Get("application_id"), AgentID: r.URL.Query().Get("agent_id"), AgentVersionID: r.URL.Query().Get("agent_version_id")}
	return s, s.validate() == nil
}

func validID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	// Asset IDs are exact, portable ASCII keys shared by publication,
	// routing and SDK references. Scope columns remain UTF-8; neither
	// asset identifiers nor their unique constraints use truncated prefixes.
	// 资产 ID 是发布、路由与 SDK 共用的精确 ASCII 键；作用域保留 UTF-8，
	// 不以截断前缀代替完整标识或唯一性。
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == ':' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func validAssetType(t AssetType) bool {
	switch t {
	case AssetModel, AssetPrompt, AssetTool, AssetMemory, AssetKnowledge, AssetRuntime:
		return true
	default:
		return false
	}
}

func decodeJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request contains trailing JSON")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code}})
}

func sameScope(a, b Scope) bool { return a == b }

func canonicalContent(t AssetType, raw json.RawMessage) (json.RawMessage, string, error) {
	if err := validateAssetContent(t, raw); err != nil {
		return nil, "", err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, "", ErrInvalidAsset
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, "", ErrInvalidAsset
	}
	sum := sha256.Sum256(canonical)
	return canonical, hex.EncodeToString(sum[:]), nil
}

func validateAsset(asset Asset) error {
	if !validID(asset.ID) || !validAssetType(asset.Type) || asset.Scope.validate() != nil || asset.Revision == 0 || asset.Status != AssetDraft && asset.Status != AssetPublished {
		return ErrInvalidAsset
	}
	content, hash, err := canonicalContent(asset.Type, asset.Content)
	if err != nil {
		return err
	}
	if !bytes.Equal(content, asset.Content) || asset.Hash != "" && asset.Hash != hash {
		return ErrInvalidAsset
	}
	return nil
}

func validateAssetContent(t AssetType, raw json.RawMessage) error {
	if !validAssetType(t) || len(raw) == 0 || len(raw) > 128*1024 {
		return ErrInvalidAsset
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	switch t {
	case AssetModel:
		var policy ModelPolicy
		if decoder.Decode(&policy) != nil || strings.TrimSpace(policy.Provider) == "" || strings.TrimSpace(policy.Model) == "" || policy.MaxTokens < 1 || policy.BudgetCents < 0 || policy.InputMicrosPer1KTokens < 0 || policy.OutputMicrosPer1KTokens < 0 || math.IsNaN(policy.Temperature) || math.IsInf(policy.Temperature, 0) || policy.Temperature < 0 || policy.Temperature > 2 {
			return ErrInvalidAsset
		}
		if policy.ValidateEmbeddingTarget() != nil || policy.ValidateReasoningMode() != nil || policy.ValidateInputLimit() != nil {
			return ErrInvalidAsset
		}
	case AssetPrompt:
		var policy PromptPolicy
		if decoder.Decode(&policy) != nil || strings.TrimSpace(policy.TemplateHash) == "" || strings.TrimSpace(policy.Template) == "" {
			return ErrInvalidAsset
		}
	case AssetTool:
		var policy ToolPolicy
		if decoder.Decode(&policy) != nil || policy.AllowedTools == nil || hasEmpty(policy.AllowedTools) || hasEmpty(policy.RequireConfirmation) || policy.ValidateFunctions() != nil {
			return ErrInvalidAsset
		}
	case AssetMemory:
		var policy MemoryPolicy
		if decoder.Decode(&policy) != nil || policy.MaxEntries < 1 || policy.WorkingTTLSeconds < 0 || policy.SessionTTLSeconds < 0 || policy.TaskTTLSeconds < 0 {
			return ErrInvalidAsset
		}
	case AssetKnowledge:
		var policy KnowledgePolicy
		if decoder.Decode(&policy) != nil || policy.AllowedScopes == nil || hasEmpty(policy.AllowedScopes) || policy.ValidateDocuments() != nil {
			return ErrInvalidAsset
		}
	case AssetRuntime:
		var policy RuntimePolicy
		if decoder.Decode(&policy) != nil || policy.MaxAttempts < 1 || policy.TaskTimeoutSeconds < 1 || policy.LeaseSeconds < 1 || policy.CancelGraceSeconds < 0 || policy.ValidateContext() != nil {
			return ErrInvalidAsset
		}
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidAsset
	}
	return nil
}

func hasEmpty(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}

func snapshotFromAssets(req PublishSnapshotRequest, assets map[AssetType]Asset) (Snapshot, error) {
	if err := req.Scope.validate(); err != nil || len(req.Assets) != 6 {
		return Snapshot{}, ErrInvalidSnapshot
	}
	for _, t := range []AssetType{AssetModel, AssetPrompt, AssetTool, AssetMemory, AssetKnowledge, AssetRuntime} {
		if _, ok := req.Assets[t]; !ok {
			return Snapshot{}, ErrInvalidSnapshot
		}
	}
	if len(assets) != 6 {
		return Snapshot{}, ErrInvalidSnapshot
	}
	if req.Rule.Version != "" || req.Rule.Checksum != "" {
		digest, err := hex.DecodeString(req.Rule.Checksum)
		if strings.TrimSpace(req.Rule.Version) == "" || req.Rule.Version != strings.TrimSpace(req.Rule.Version) || len(req.Rule.Version) > 128 || err != nil || len(digest) != 32 || req.Rule.Checksum != strings.ToLower(req.Rule.Checksum) {
			return Snapshot{}, ErrInvalidSnapshot
		}
	}
	var snapshot Snapshot
	snapshot.Rule = req.Rule
	snapshot.RuleBundleVersion, snapshot.RuleBundleChecksum = req.Rule.Version, req.Rule.Checksum
	for t, asset := range assets {
		if !sameScope(asset.Scope, req.Scope) || asset.Status != AssetPublished {
			return Snapshot{}, ErrInvalidSnapshot
		}
		switch t {
		case AssetModel:
			snapshot.ModelProfileID = asset.ID
			if json.Unmarshal(asset.Content, &snapshot.Model) != nil {
				return Snapshot{}, ErrInvalidAsset
			}
		case AssetPrompt:
			snapshot.PromptVersionID = asset.ID
			if json.Unmarshal(asset.Content, &snapshot.Prompt) != nil {
				return Snapshot{}, ErrInvalidAsset
			}
		case AssetTool:
			snapshot.ToolPolicyID = asset.ID
			if json.Unmarshal(asset.Content, &snapshot.Tool) != nil {
				return Snapshot{}, ErrInvalidAsset
			}
		case AssetMemory:
			snapshot.MemoryPolicyID = asset.ID
			if json.Unmarshal(asset.Content, &snapshot.Memory) != nil {
				return Snapshot{}, ErrInvalidAsset
			}
		case AssetKnowledge:
			snapshot.KnowledgePolicyID = asset.ID
			if json.Unmarshal(asset.Content, &snapshot.Knowledge) != nil {
				return Snapshot{}, ErrInvalidAsset
			}
		case AssetRuntime:
			snapshot.RuntimePolicyID = asset.ID
			if json.Unmarshal(asset.Content, &snapshot.Runtime) != nil {
				return Snapshot{}, ErrInvalidAsset
			}
		default:
			return Snapshot{}, ErrInvalidSnapshot
		}
	}
	return snapshot, nil
}

var _ bootstrap.Module = (*Module)(nil)
var _ bootstrap.ReadyModule = (*Module)(nil)
