package conversation

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// Module exposes the conversation product boundary.  Authentication remains
// deliberately narrow here; public identity extraction can later be replaced
// by the platform IAM adapter without changing the Store or domain contract.
// Module 暴露会话产品边界；这里保持窄认证边界，未来可替换为平台 IAM Adapter，
// 不改变 Store 与领域契约。
type Module struct {
	store           Store
	internalToken   string
	allowManaged    bool
	starter         RunStarter
	replay          RunReplayResolver
	progress        RunProgressResolver
	binding         RuntimeBindingResolver
	policy          RunPolicyResolver
	modelSelections policyasset.ModelSelectionStore
	signer          ContextTokenSigner
	principalRoles  func(context.Context, Scope) ([]string, error)
	access          AccessControl
	erasureEnabled  bool
	erasureCancel   context.CancelFunc
	erasureDone     chan struct{}
}

func NewModule(store Store, internalToken string, allowManaged bool) *Module {
	return &Module{store: store, internalToken: strings.TrimSpace(internalToken), allowManaged: allowManaged}
}

// SetRunStarter wires the runtime through a Port; the conversation module
// remains usable without a scheduler in unit tests and read-only deployments.
// SetRunStarter 通过 Port 接入 Runtime；无调度器时仍可用于只读/单测部署。
func (m *Module) SetRunStarter(starter RunStarter) { m.starter = starter }

// SetRuntimeBindingResolver supplies trusted Agent/version targets. Keeping it
// as a Port allows a remote catalog or deployment controller to replace the
// static bootstrap map later without exposing endpoint selection to browsers.
// SetRuntimeBindingResolver 注入可信 Agent/版本目标；通过 Port 保留后续替换为
// 远程 Catalog/部署控制器的条件，浏览器永远不能自行选择 endpoint。
func (m *Module) SetRuntimeBindingResolver(resolver RuntimeBindingResolver) { m.binding = resolver }

// SetRunPolicyResolver supplies the authoritative immutable policy snapshot
// for browser-created runs. / SetRunPolicyResolver 注入浏览器 Run 所需的权威
// 不可变策略快照解析器。
func (m *Module) SetRunPolicyResolver(resolver RunPolicyResolver) { m.policy = resolver }

func (m *Module) SetModelSelectionStore(store policyasset.ModelSelectionStore) {
	m.modelSelections = store
}

// SetContextTokenSigner enables the browser-to-runtime command adapter. A
// missing signer keeps the module usable for machine callers that already send
// a complete signed contract, but browser requests fail closed rather than
// receiving an unsigned execution envelope.
// SetContextTokenSigner 启用浏览器到 Runtime 的命令适配；未配置时仍允许已带
// 完整签名信封的机器调用，浏览器请求不会被转换成未签名执行信封。
func (m *Module) SetContextTokenSigner(signer ContextTokenSigner) { m.signer = signer }

// SetPrincipalRoleResolver connects privileged browser operations to the
// platform-owned Identity source of truth. Caller-supplied role headers are
// never accepted. / SetPrincipalRoleResolver 将受保护的浏览器操作连接到平台
// Identity 权威事实源，绝不接受调用方自报的角色头。
func (m *Module) SetPrincipalRoleResolver(resolve func(context.Context, Scope) ([]string, error)) {
	m.principalRoles = resolve
}

func (m *Module) Name() string { return "conversation" }

func (m *Module) Start(ctx context.Context) error {
	if m.store == nil {
		return errors.New("conversation store is required")
	}
	// Schema is installed by the versioned migration command, never Start.
	// Schema由独立版本迁移命令安装，Start不得改库。
	return m.startErasureWorker(ctx)
}

func (m *Module) Ready() error {
	return m.ReadyContext(context.Background())
}

func (m *Module) ReadyContext(ctx context.Context) error {
	if m.store == nil {
		return errors.New("conversation store is required")
	}
	return bootstrap.ProbeDependency(ctx, m.store.Ping)
}

func (m *Module) Close(ctx context.Context) error { return m.stopErasureWorker(ctx) }

func (m *Module) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/sessions", m.sessions)
	mux.HandleFunc("/sessions/", m.session)
	mux.HandleFunc("/managed-search", m.managedSearch)
	mux.HandleFunc("/shares/", m.share)
	mux.HandleFunc("/exports", m.exports)
	mux.HandleFunc("/exports/", m.export)
	mux.HandleFunc("/deletion-requests", m.deletionRequests)
	mux.HandleFunc("/deletion-requests/", m.deletionRequest)
	mux.HandleFunc("/retention-policy", m.retentionPolicy)
	mux.HandleFunc("/legal-holds", m.legalHolds)
	mux.HandleFunc("/legal-holds/", m.legalHold)
	return mux
}

// managedSearch replaces the retired Backend global-search endpoint. The
// tenant boundary comes from the authenticated Identity Principal: a
// platform_admin is confined to its own tenant, while system_admin/admin may
// search globally. Browser-supplied tenant filters can narrow access but can
// never widen it.
// managedSearch 替代已退役 Backend 的全局搜索入口。租户边界取自可信 Identity：
// platform_admin 仅能查本租户，system_admin/admin 可全局查询；浏览器过滤条件只能
// 缩小权限，不能扩大权限。
func (m *Module) managedSearch(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	scope, err := scopeFromRequest(r)
	if err != nil || scope.PrincipalType != "user" {
		m.writeError(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	if m.access != nil {
		plan, err := m.access.ReadPlan(r.Context(), scope)
		if err != nil {
			m.storeError(w, err)
			return
		}
		if !plan.Legacy {
			if tenant := r.URL.Query().Get("tenant_id"); tenant != "" && tenant != scope.TenantID {
				m.writeError(w, http.StatusForbidden, "FORBIDDEN")
				return
			}
			if app := r.URL.Query().Get("application_id"); app != "" && app != scope.ApplicationID {
				m.writeError(w, http.StatusForbidden, "FORBIDDEN")
				return
			}
			query := Query{Kind: r.URL.Query().Get("kind"), View: "managed", Text: r.URL.Query().Get("q")}
			query.Page, _ = strconv.Atoi(r.URL.Query().Get("page"))
			query.PageSize, _ = strconv.Atoi(r.URL.Query().Get("page_size"))
			reader, ok := m.store.(AuthorizedHistoryReader)
			if !ok {
				m.writeError(w, http.StatusServiceUnavailable, "HISTORY_READER_UNAVAILABLE")
				return
			}
			result, err := reader.ListAuthorized(r.Context(), scope, query, plan)
			if err != nil {
				m.storeError(w, err)
				return
			}
			result.Items, err = m.projectPermissions(r.Context(), scope, result.Items)
			if err != nil {
				m.storeError(w, err)
				return
			}
			m.writeJSON(w, http.StatusOK, result)
			return
		}
	}
	if m.principalRoles == nil {
		m.writeError(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	roles, err := m.principalRoles(r.Context(), scope)
	if err != nil {
		m.writeError(w, http.StatusServiceUnavailable, "IDENTITY_UNAVAILABLE")
		return
	}
	global := hasConversationRole(roles, "system_admin", "admin")
	tenantAdmin := hasConversationRole(roles, "platform_admin")
	if !global && !tenantAdmin {
		m.writeError(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	query := ManagedSearchQuery{
		Kind:          strings.TrimSpace(r.URL.Query().Get("kind")),
		Text:          strings.TrimSpace(r.URL.Query().Get("q")),
		TenantID:      strings.TrimSpace(r.URL.Query().Get("tenant_id")),
		ApplicationID: strings.TrimSpace(r.URL.Query().Get("application_id")),
	}
	query.Page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	query.PageSize, _ = strconv.Atoi(r.URL.Query().Get("page_size"))
	if tenantAdmin {
		if query.TenantID != "" && query.TenantID != scope.TenantID {
			m.writeError(w, http.StatusForbidden, "FORBIDDEN")
			return
		}
		query.TenantID = scope.TenantID
	}
	query, err = normalizeManagedSearchQuery(query)
	if err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_QUERY")
		return
	}
	reader, ok := m.store.(ManagedSearchReader)
	if !ok {
		m.writeError(w, http.StatusServiceUnavailable, "MANAGED_SEARCH_UNAVAILABLE")
		return
	}
	result, err := reader.SearchManaged(r.Context(), query)
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.writeJSON(w, http.StatusOK, result)
}

func normalizeManagedSearchQuery(query ManagedSearchQuery) (ManagedSearchQuery, error) {
	if query.Kind == "" {
		query.Kind = "qa"
	}
	if query.Kind != "qa" && query.Kind != "check" || len(query.Text) > 256 || len(query.TenantID) > 128 || len(query.ApplicationID) > 128 {
		return ManagedSearchQuery{}, ErrInvalidQuery
	}
	if query.Page < 1 {
		query.Page = 1
	}
	if query.PageSize < 1 {
		query.PageSize = 20
	}
	if query.PageSize > 100 {
		query.PageSize = 100
	}
	return query, nil
}

func hasConversationRole(roles []string, allowed ...string) bool {
	for _, role := range roles {
		for _, candidate := range allowed {
			if strings.TrimSpace(role) == candidate {
				return true
			}
		}
	}
	return false
}

func (m *Module) sessions(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(w, r) {
		return
	}
	scope, err := scopeFromRequest(r)
	if err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if r.Method == http.MethodPost {
		var session Session
		if err := decode(r, &session); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if m.binding != nil {
			binding, err := m.binding.Resolve(r.Context(), scope, session.AgentID, session.AgentVersionID)
			if errors.Is(err, ErrForbidden) {
				m.storeError(w, ErrForbidden)
				return
			}
			if err != nil || binding.InstallationID == "" || binding.AgentVersionID != "" && binding.AgentVersionID != session.AgentVersionID {
				m.writeError(w, http.StatusConflict, "RUNTIME_BINDING_UNAVAILABLE")
				return
			}
			if session.InstallationID != "" && session.InstallationID != binding.InstallationID {
				m.writeError(w, http.StatusBadRequest, "RUNTIME_BINDING_MISMATCH")
				return
			}
			session.InstallationID = binding.InstallationID
		} else if session.InstallationID != "" || r.Header.Get("X-Browser-Module") == "1" {
			// Without a trusted resolver, a caller cannot create authoritative
			// installation provenance by supplying a field in the request.
			m.writeError(w, http.StatusServiceUnavailable, "RUNTIME_BINDING_UNAVAILABLE")
			return
		}
		session.TenantID, session.DepartmentID, session.ApplicationID = scope.TenantID, scope.DepartmentID, scope.ApplicationID
		session.PrincipalType, session.OwnerID = scope.PrincipalType, scope.PrincipalID
		// The initial projection has no messages. Client counters cannot select
		// between a new run and continuation authorization.
		session.MessageCount = 0
		if m.access != nil {
			resource := SessionResource{ID: session.ID, OwnerID: scope.PrincipalID, PrincipalType: scope.PrincipalType, InstallationID: session.InstallationID, AgentID: session.AgentID, AgentVersionID: session.AgentVersionID}
			if err := m.access.Authorize(r.Context(), scope, resource, "run"); err != nil {
				m.storeError(w, err)
				return
			}
		}
		if err := m.store.CreateSession(r.Context(), scope, session); err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusCreated, session)
		return
	}
	if r.Method != http.MethodGet {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	query := Query{Kind: r.URL.Query().Get("kind"), View: r.URL.Query().Get("view"), Text: r.URL.Query().Get("text")}
	query.Page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	query.PageSize, _ = strconv.Atoi(r.URL.Query().Get("page_size"))
	if m.access != nil {
		plan, err := m.access.ReadPlan(r.Context(), scope)
		if err != nil {
			m.storeError(w, err)
			return
		}
		if !plan.Legacy {
			reader, ok := m.store.(AuthorizedHistoryReader)
			if !ok {
				m.writeError(w, http.StatusServiceUnavailable, "HISTORY_READER_UNAVAILABLE")
				return
			}
			result, err := reader.ListAuthorized(r.Context(), scope, query, plan)
			if err != nil {
				m.storeError(w, err)
				return
			}
			result.Items, err = m.projectPermissions(r.Context(), scope, result.Items)
			if err != nil {
				m.storeError(w, err)
				return
			}
			m.writeJSON(w, http.StatusOK, result)
			return
		}
	}
	page, err := (&AccessPolicy{AllowManaged: m.allowManaged}).Normalize(scope, query)
	if err != nil {
		m.storeError(w, err)
		return
	}
	result, err := m.store.List(r.Context(), scope, page)
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.writeJSON(w, http.StatusOK, result)
}

func (m *Module) session(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(w, r) {
		return
	}
	scope, err := scopeFromRequest(r)
	if err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/sessions/"), "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	id := parts[0]
	if action := sessionRouteAction(parts, r.Method); action != "" && action != "run-or-continue" {
		scope, err = m.authorizeSession(r.Context(), scope, id, action)
		if err != nil {
			m.storeError(w, err)
			return
		}
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		item, err := m.store.Detail(r.Context(), scope, id)
		if err != nil {
			m.storeError(w, err)
			return
		}
		items, err := m.projectPermissions(r.Context(), scope, []Summary{item})
		if err != nil {
			m.storeError(w, err)
			return
		}
		item = items[0]
		if m.progress != nil {
			item.RunProgress, err = m.progress.ResolveRunProgress(r.Context(), scope, item)
			if err != nil {
				// Preserve authorized history during an execution read outage.
				item.RunProgress = nil
				item.RunProgressUnavailable = true
			}
		}
		m.writeJSON(w, http.StatusOK, item)
		return
	}
	if len(parts) == 2 && parts[1] == "resume" && r.Method == http.MethodPost {
		item, err := m.store.Resume(r.Context(), scope, id)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, item)
		return
	}
	if len(parts) == 2 && parts[1] == "runs" && r.Method == http.MethodPost {
		if m.starter == nil {
			m.writeError(w, http.StatusNotImplemented, "RUNTIME_NOT_AVAILABLE")
			return
		}
		var request RunStartRequest
		if err := decode(r, &request); err != nil || strings.TrimSpace(request.RunID) == "" || strings.TrimSpace(request.IdempotencyKey) == "" || request.ModelSelection.Validate() != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if len(request.Request) == 0 {
			request.Request = json.RawMessage(`{}`)
		}
		routingTaskInput := append(json.RawMessage(nil), request.Request...)
		// Check the current resource grant before loading or comparing an
		// accepted command, so revoked callers cannot probe its business input.
		if _, err := m.authorizeSession(r.Context(), scope, id, "run"); err != nil {
			m.storeError(w, err)
			return
		}
		if m.replay != nil && r.Header.Get("X-Browser-Module") == "1" && scope.PrincipalType == "user" {
			matched, replayErr := m.replay.MatchRunReplay(r.Context(), scope, id, request)
			if replayErr != nil {
				m.storeError(w, replayErr)
				return
			}
			if matched {
				if _, err := m.authorizeSession(r.Context(), scope, id, "run"); err != nil {
					m.storeError(w, err)
					return
				}
				// Only acknowledge an existing receipt. No new projection, signature,
				// creation or dispatch is performed, even if its status changed.
				m.writeJSON(w, http.StatusAccepted, map[string]any{"run_id": request.RunID, "session_id": id})
				return
			}
		}
		scope, err = m.authorizeSession(r.Context(), scope, id, "run-or-continue")
		if err != nil {
			m.storeError(w, err)
			return
		}
		item, err := m.store.Detail(r.Context(), scope, id)
		if err != nil {
			m.storeError(w, err)
			return
		}
		inputSchemaURI := ""
		if m.binding != nil {
			binding, resolveErr := m.binding.Resolve(r.Context(), scope, item.AgentID, item.AgentVersionID)
			if errors.Is(resolveErr, ErrForbidden) {
				m.storeError(w, ErrForbidden)
				return
			}
			if resolveErr != nil {
				m.writeError(w, http.StatusConflict, "RUNTIME_BINDING_UNAVAILABLE")
				return
			}
			if item.InstallationID == "" {
				m.writeError(w, http.StatusConflict, "SESSION_INSTALLATION_UNVERIFIED")
				return
			}
			if item.InstallationID != binding.InstallationID {
				m.writeError(w, http.StatusConflict, "SESSION_INSTALLATION_CHANGED")
				return
			}
			// A browser may omit binding fields, but if it sends any value it must
			// exactly match the trusted resolver; this prevents endpoint/instance
			// substitution through the same-origin gateway.
			if (request.AgentEndpoint != "" && request.AgentEndpoint != binding.AgentEndpoint) ||
				(request.AgentInstanceID != "" && request.AgentInstanceID != binding.AgentInstanceID) ||
				(request.InstallationID != "" && request.InstallationID != binding.InstallationID) ||
				(request.AuthorizationEpoch != 0 && request.AuthorizationEpoch != binding.AuthorizationEpoch) {
				m.writeError(w, http.StatusBadRequest, "RUNTIME_BINDING_MISMATCH")
				return
			}
			request.AgentEndpoint = binding.AgentEndpoint
			request.AgentInstanceID = binding.AgentInstanceID
			request.InstallationID = binding.InstallationID
			request.AuthorizationEpoch = binding.AuthorizationEpoch
			inputSchemaURI = binding.InputSchemaURI
		}
		if strings.TrimSpace(request.AgentEndpoint) == "" || strings.TrimSpace(request.AgentInstanceID) == "" || strings.TrimSpace(request.InstallationID) == "" || request.AuthorizationEpoch == 0 {
			m.writeError(w, http.StatusBadRequest, "INVALID_RUNTIME_BINDING")
			return
		}
		traceID := request.TraceID
		if traceID == "" {
			traceID = scope.TraceID
		}
		runScope := sharedkernel.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: request.AgentInstanceID, AgentID: item.AgentID, PrincipalID: scope.PrincipalID, PrincipalType: scope.PrincipalType, InstallationID: request.InstallationID, AgentVersionID: item.AgentVersionID, SessionID: id, RunID: request.RunID, AuthorizationEpoch: request.AuthorizationEpoch, TraceID: traceID}
		// Browser/gateway request IDs are not necessarily W3C trace IDs. Only
		// preserve a canonical 32-character hexadecimal trace; derive one from
		// the durable Run ID for missing or malformed values.
		// 浏览器/网关请求 ID 未必是 W3C Trace ID。仅保留规范的 32 位十六进制值；
		// 缺失或格式错误时从持久化 Run ID 派生稳定 Trace ID。
		if !validTraceID(runScope.TraceID) {
			runScope.TraceID = NewContextTraceID(runScope.RunID)
		}
		if err := runScope.ValidateTrusted(); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_RUNTIME_SCOPE")
			return
		}
		var input map[string]any
		if err := json.Unmarshal(request.Request, &input); err != nil || input == nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		_, isV2Envelope := input["protocol_version"]
		if m.signer != nil && !isV2Envelope {
			if m.policy == nil {
				m.writeError(w, http.StatusServiceUnavailable, "POLICY_SNAPSHOT_UNAVAILABLE")
				return
			}
			policy, policyErr := m.policy.ResolveAgentPolicy(r.Context(), runScope, item.AgentVersionID)
			if policyErr != nil || policy == nil {
				m.writeError(w, http.StatusServiceUnavailable, "POLICY_SNAPSHOT_UNAVAILABLE")
				return
			}
			// The published version is the authority. Discard any policy fields
			// supplied by the browser, including an apparently valid but stale hash.
			// 已发布版本才是策略权威；浏览器提交的策略字段全部覆盖，避免伪造或过期快照。
			input["policy_snapshot"] = policy
			request.Request, err = json.Marshal(input)
			if err != nil {
				m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
				return
			}
		}
		fingerprint, fingerprintErr := RunCommandSelectionFingerprint(runScope, request.IdempotencyKey, request.Request, request.ModelSelection)
		if fingerprintErr != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if request.Fingerprint != "" && subtle.ConstantTimeCompare([]byte(request.Fingerprint), []byte(fingerprint)) != 1 {
			m.writeError(w, http.StatusBadRequest, "IDEMPOTENCY_FINGERPRINT_MISMATCH")
			return
		}
		// Fingerprint the authenticated scope, resolved Agent binding and
		// canonical business request on the server. Browser callers intentionally
		// do not need to know a private runtime hashing contract, and cannot force
		// two different payloads to share an idempotency identity.
		// 指纹由服务端根据可信主体、解析后的 Agent 绑定和规范化业务请求生成；
		// 浏览器无需了解运行时私有哈希契约，也不能让不同请求复用同一幂等身份。
		request.Fingerprint = fingerprint
		if m.signer != nil {
			if !isV2Envelope {
				// Use the immutable published manifest, never infer a schema version
				// from the Agent ID or accept a browser-selected schema.
				if !strings.HasPrefix(inputSchemaURI, "schema://") || strings.TrimSpace(inputSchemaURI) != inputSchemaURI {
					m.writeError(w, http.StatusServiceUnavailable, "INPUT_SCHEMA_UNAVAILABLE")
					return
				}
				executeRequest := contract.ExecuteRequest{
					ProtocolVersion: contract.ProtocolVersion,
					Scope: contract.ScopeKey{
						TenantID: runScope.TenantID, DepartmentID: runScope.DepartmentID, ApplicationID: runScope.ApplicationID,
						AgentInstanceID: runScope.AgentInstanceID, AgentID: runScope.AgentID, AgentVersionID: runScope.AgentVersionID,
						PrincipalType: runScope.PrincipalType, PrincipalID: runScope.PrincipalID, SessionID: runScope.SessionID,
						RunID: runScope.RunID, AuthorizationEpoch: runScope.AuthorizationEpoch, TraceID: runScope.TraceID,
						InstallationID: runScope.InstallationID,
					},
					Operation: "run", IdempotencyKey: request.IdempotencyKey,
					InputSchema: inputSchemaURI, Input: input,
				}
				token, signErr := m.signer.Sign(r.Context(), runScope, executeRequest)
				if signErr != nil {
					m.writeError(w, http.StatusServiceUnavailable, "CONTEXT_SIGNING_UNAVAILABLE")
					return
				}
				executeRequest.ContextToken = token
				request.Request, err = json.Marshal(executeRequest)
				if err != nil {
					m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
					return
				}
			} else {
				// Already-signed machine envelopes are validated by the runtime; the
				// browser-to-runtime signer never re-signs caller-controlled claims.
				// 已签名机器信封交由 Runtime 校验；中台不会替调用方重新签发其声明。
				if len(request.Request) == 0 {
					m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
					return
				}
			}
		}
		var runID string
		// The preference is platform-owned durable metadata; business input and the
		// signed execution v2 wire contract remain compatible with existing Agents.
		if request.ModelSelection.EffectiveMode() == "automatic" && (isV2Envelope || m.modelSelections == nil || m.policy == nil) {
			m.writeError(w, http.StatusConflict, "MODEL_ROUTING_UNAVAILABLE")
			return
		}
		if m.modelSelections != nil && !isV2Envelope && m.policy != nil {
			var published policyasset.ModelPolicy
			policy, valid := input["policy_snapshot"].(map[string]any)
			raw, marshalErr := json.Marshal(policy["model"])
			policyHash, hashOK := policy["content_hash"].(string)
			if !valid || !hashOK || marshalErr != nil || json.Unmarshal(raw, &published) != nil ||
				(request.ModelSelection.EffectiveMode() == "automatic" && (published.Routing == nil || published.ValidateRouting() != nil)) {
				m.writeError(w, http.StatusConflict, "MODEL_ROUTING_UNAVAILABLE")
				return
			}
			binding := policyasset.ModelSelectionBinding{Selection: request.ModelSelection, PolicySHA256: policyHash, CommandFingerprint: request.Fingerprint}
			if binding.Selection.EffectiveMode() == "automatic" {
				var taskErr error
				binding, taskErr = policyasset.BindRoutingTask(binding, routingTaskInput, *published.Routing)
				if taskErr != nil {
					m.writeError(w, http.StatusBadRequest, "INVALID_ROUTING_TASK")
					return
				}
			}
			if err := m.modelSelections.BindModelSelection(r.Context(), runScope, binding); err != nil {
				m.writeError(w, http.StatusConflict, "MODEL_SELECTION_BINDING_FAILED")
				return
			}
		}
		if starter, ok := m.starter.(RunMessageStarter); ok {
			runID, err = starter.StartRunWithMessage(r.Context(), runScope, request.RunID, request.IdempotencyKey, request.Fingerprint, request.AgentEndpoint, request.Request, request.MessageID)
		} else {
			runID, err = m.starter.StartRun(r.Context(), runScope, request.RunID, request.IdempotencyKey, request.Fingerprint, request.AgentEndpoint, request.Request)
		}
		if err != nil {
			m.writeError(w, http.StatusConflict, "RUN_START_FAILED")
			return
		}
		m.writeJSON(w, http.StatusAccepted, map[string]any{"run_id": runID, "session_id": id})
		return
	}
	if len(parts) == 2 && parts[1] == "messages" && r.Method == http.MethodGet {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
		page, size = normalizeMessagePage(page, size)
		items, total, err := m.store.ListMessages(r.Context(), scope, id, page, size)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, MessagePage{Items: items, Total: total, Page: page, PageSize: size})
		return
	}
	if len(parts) == 2 && parts[1] == "messages" && r.Method == http.MethodPost {
		var message Message
		if err := decode(r, &message); err != nil || (message.SessionID != "" && message.SessionID != id) {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if m.access != nil && scope.PrincipalType == "user" && message.Role != "user" {
			m.writeError(w, http.StatusBadRequest, "INVALID_MESSAGE_ROLE")
			return
		}
		// The authorized route owns the session identity; reject substitutions.
		// 已鉴权路由确定会话身份；请求体可省略，但不能替换成另一会话。
		message.SessionID = id
		if err := m.store.AppendMessage(r.Context(), scope, message); err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusCreated, message)
		return
	}
	if len(parts) == 4 && parts[1] == "messages" && parts[3] == "regenerate" && r.Method == http.MethodPost {
		regenerator, ok := m.store.(RegenerationStore)
		if !ok {
			m.writeError(w, http.StatusNotImplemented, "REGENERATION_NOT_AVAILABLE")
			return
		}
		var request struct {
			VersionMode string `json:"version_mode"`
		}
		if err := decode(r, &request); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		item, err := regenerator.Regenerate(r.Context(), scope, id, parts[2], request.VersionMode)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusAccepted, item)
		return
	}
	if len(parts) == 4 && parts[1] == "messages" && parts[2] != "" && parts[3] == "revisions" {
		if revisions, ok := m.store.(RevisionStore); ok {
			if r.Method == http.MethodGet {
				items, err := revisions.ListRevisions(r.Context(), scope, id, parts[2])
				if err != nil {
					m.storeError(w, err)
					return
				}
				m.writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
				return
			}
			if r.Method == http.MethodPost {
				var request struct {
					Content      string `json:"content"`
					Reason       string `json:"reason"`
					BaseRevision uint64 `json:"base_revision"`
				}
				if err := decode(r, &request); err != nil {
					m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
					return
				}
				item, err := revisions.ReviseMessage(r.Context(), scope, id, parts[2], request.Content, request.Reason, request.BaseRevision)
				if err != nil {
					m.storeError(w, err)
					return
				}
				m.writeJSON(w, http.StatusCreated, item)
				return
			}
		}
	}
	if len(parts) == 2 && parts[1] == "shares" && r.Method == http.MethodPost {
		governance, ok := m.governance()
		if !ok {
			m.writeError(w, http.StatusNotImplemented, "GOVERNANCE_NOT_AVAILABLE")
			return
		}
		var request ShareRequest
		if err := decode(r, &request); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		request.SessionID = id
		item, err := governance.CreateShare(r.Context(), scope, request)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusCreated, item)
		return
	}
	m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
}

func (m *Module) governance() (GovernanceStore, bool) {
	store, ok := m.store.(GovernanceStore)
	return store, ok
}

func (m *Module) share(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/shares/"), "/"), "/")
	if len(parts) == 1 && r.Method == http.MethodGet {
		// A capability token is the sole authority for this deliberately public,
		// read-only view. No caller-supplied tenant/principal header is trusted.
		// 能力令牌是此公开只读视图的唯一授权；不信任调用方提交的租户/主体头。
		if !validShareToken(parts[0]) {
			m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
			return
		}
		reader, ok := m.store.(PublicShareReader)
		if !ok {
			m.writeError(w, http.StatusServiceUnavailable, "SHARE_READER_UNAVAILABLE")
			return
		}
		page, pageSize, valid := publicSharePagination(r)
		if !valid {
			m.writeError(w, http.StatusBadRequest, "INVALID_PAGINATION")
			return
		}
		item, err := reader.ReadPublicShare(r.Context(), parts[0], page, pageSize)
		if err != nil {
			m.storeError(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store, private")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		m.writeJSON(w, http.StatusOK, item)
		return
	}
	if !m.authorized(w, r) {
		return
	}
	governance, ok := m.governance()
	if !ok {
		m.writeError(w, http.StatusServiceUnavailable, "GOVERNANCE_UNAVAILABLE")
		return
	}
	scope, err := scopeFromRequest(r)
	if err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if len(parts) == 2 && parts[1] == "revoke" && r.Method == http.MethodPost {
		item, err := governance.RevokeShare(r.Context(), scope, parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, item)
		return
	}
	m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
}

func publicSharePagination(r *http.Request) (int, int, bool) {
	page, pageSize := 1, 100
	if raw := strings.TrimSpace(r.URL.Query().Get("page")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100000 {
			return 0, 0, false
		}
		page = parsed
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("page_size")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return 0, 0, false
		}
		pageSize = parsed
	}
	return page, pageSize, true
}

func runFingerprint(scope sharedkernel.Scope, idempotencyKey string, requestJSON []byte) (string, error) {
	var canonicalRequest any
	decoder := json.NewDecoder(strings.NewReader(string(requestJSON)))
	decoder.UseNumber()
	if err := decoder.Decode(&canonicalRequest); err != nil {
		return "", err
	}
	if canonicalRequest == nil {
		return "", errors.New("run request must not be null")
	}
	material, err := json.Marshal(struct {
		TenantID           string `json:"tenant_id"`
		DepartmentID       string `json:"department_id"`
		ApplicationID      string `json:"application_id"`
		PrincipalType      string `json:"principal_type"`
		PrincipalID        string `json:"principal_id"`
		AgentInstanceID    string `json:"agent_instance_id"`
		AgentID            string `json:"agent_id"`
		AgentVersionID     string `json:"agent_version_id"`
		InstallationID     string `json:"installation_id"`
		AuthorizationEpoch uint64 `json:"authorization_epoch"`
		SessionID          string `json:"session_id"`
		RunID              string `json:"run_id"`
		IdempotencyKey     string `json:"idempotency_key"`
		Request            any    `json:"request"`
	}{
		TenantID: scope.TenantID, DepartmentID: scope.DepartmentID,
		ApplicationID: scope.ApplicationID, PrincipalType: scope.PrincipalType,
		PrincipalID: scope.PrincipalID, AgentInstanceID: scope.AgentInstanceID,
		AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
		InstallationID: scope.InstallationID, AuthorizationEpoch: scope.AuthorizationEpoch,
		SessionID: scope.SessionID, RunID: scope.RunID,
		IdempotencyKey: idempotencyKey, Request: canonicalRequest,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(material)
	return hex.EncodeToString(digest[:]), nil
}

func (m *Module) exports(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(w, r) {
		return
	}
	governance, ok := m.governance()
	if !ok {
		m.writeError(w, http.StatusNotImplemented, "GOVERNANCE_NOT_AVAILABLE")
		return
	}
	scope, err := scopeFromRequest(r)
	if err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	var request ExportRequest
	if err := decode(r, &request); err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if len(request.SessionIDs) != 1 {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if _, err := m.authorizeSession(r.Context(), scope, request.SessionIDs[0], "history.export"); err != nil {
		m.storeError(w, err)
		return
	}
	item, err := governance.CreateExport(r.Context(), scope, request)
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.writeJSON(w, http.StatusCreated, item)
}

func (m *Module) export(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(w, r) {
		return
	}
	governance, ok := m.governance()
	if !ok {
		m.writeError(w, http.StatusNotImplemented, "GOVERNANCE_NOT_AVAILABLE")
		return
	}
	scope, err := scopeFromRequest(r)
	if err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/exports/"), "/"), "/")
	if len(parts) == 1 && r.Method == http.MethodGet {
		if m.access != nil {
			reader, ok := m.store.(AuthorizedHistoryReader)
			if !ok {
				m.writeError(w, http.StatusServiceUnavailable, "HISTORY_READER_UNAVAILABLE")
				return
			}
			sessionID, err := reader.GetExportSessionID(r.Context(), scope, parts[0])
			if err != nil {
				m.storeError(w, err)
				return
			}
			if _, err := m.authorizeSession(r.Context(), scope, sessionID, "history.export"); err != nil {
				m.storeError(w, err)
				return
			}
		}
		item, err := governance.GetExport(r.Context(), scope, parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, item)
		return
	}
	if len(parts) == 2 && parts[1] == "approve" && r.Method == http.MethodPost {
		item, err := governance.ApproveExport(r.Context(), scope, parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, item)
		return
	}
	m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
}

func (m *Module) deletionRequests(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(w, r) {
		return
	}
	governance, ok := m.governance()
	if !ok {
		m.writeError(w, http.StatusNotImplemented, "GOVERNANCE_NOT_AVAILABLE")
		return
	}
	scope, err := scopeFromRequest(r)
	if err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if r.Method == http.MethodPost {
		var request DeleteRequest
		if err := decode(r, &request); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if len(request.SessionIDs) != 1 {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if _, err := m.authorizeSession(r.Context(), scope, request.SessionIDs[0], "history.delete.request"); err != nil {
			m.storeError(w, err)
			return
		}
		item, err := governance.RequestDeletion(r.Context(), scope, request)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusCreated, item)
		return
	}
	if r.Method == http.MethodGet {
		if scope.PrincipalType == "user" {
			plan, err := m.deletionPlan(r.Context(), scope)
			if err != nil {
				m.storeError(w, err)
				return
			}
			if !plan.Legacy {
				manager, ok := m.store.(AuthorizedDeletionStore)
				if !ok {
					m.writeError(w, http.StatusServiceUnavailable, "DELETION_MANAGEMENT_UNAVAILABLE")
					return
				}
				page, _ := strconv.Atoi(r.URL.Query().Get("page"))
				size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
				items, total, err := manager.ListDeletionRequestsAuthorized(r.Context(), scope, page, size, plan)
				if err != nil {
					m.storeError(w, err)
					return
				}
				current, err := m.deletionPlan(r.Context(), scope)
				if err != nil || !reflect.DeepEqual(plan, current) {
					m.writeError(w, http.StatusForbidden, "FORBIDDEN")
					return
				}
				m.writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": maxPage(page), "page_size": maxSize(size)})
				return
			}
			if !m.requireDeletionAdmin(w, r, scope) {
				return
			}
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
		var items []DeletionRequest
		var total int64
		if scope.PrincipalType == "user" {
			manager, ok := m.store.(DeletionManagementStore)
			if !ok {
				m.writeError(w, http.StatusServiceUnavailable, "DELETION_MANAGEMENT_UNAVAILABLE")
				return
			}
			items, total, err = manager.ListDeletionRequestsForManagement(r.Context(), scope, page, size)
		} else {
			items, total, err = governance.ListDeletionRequests(r.Context(), scope, page, size)
		}
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": maxPage(page), "page_size": maxSize(size)})
		return
	}
	m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
}

func (m *Module) deletionRequest(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(w, r) {
		return
	}
	governance, ok := m.governance()
	if !ok {
		m.writeError(w, http.StatusNotImplemented, "GOVERNANCE_NOT_AVAILABLE")
		return
	}
	scope, err := scopeFromRequest(r)
	if err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/deletion-requests/"), "/"), "/")
	if len(parts) == 2 && parts[1] == "approve" && r.Method == http.MethodPost {
		var item DeletionRequest
		if scope.PrincipalType == "user" {
			plan, planErr := m.deletionPlan(r.Context(), scope)
			if planErr != nil {
				m.storeError(w, planErr)
				return
			}
			if !plan.Legacy {
				manager, ok := m.store.(AuthorizedDeletionStore)
				if !ok {
					m.writeError(w, http.StatusServiceUnavailable, "DELETION_MANAGEMENT_UNAVAILABLE")
					return
				}
				item, err = manager.ApproveDeletionAuthorized(r.Context(), scope, parts[0], func(ctx context.Context, resource SessionResource) error {
					return m.access.Authorize(ctx, scope, resource, "business.review")
				})
				if err != nil {
					m.storeError(w, err)
					return
				}
				m.writeJSON(w, http.StatusOK, item)
				return
			}
			if !m.requireDeletionAdmin(w, r, scope) {
				return
			}
			manager, ok := m.store.(DeletionManagementStore)
			if !ok {
				m.writeError(w, http.StatusServiceUnavailable, "DELETION_MANAGEMENT_UNAVAILABLE")
				return
			}
			item, err = manager.ApproveDeletionByUser(r.Context(), scope, parts[0])
		} else {
			item, err = governance.ApproveDeletion(r.Context(), scope, parts[0])
		}
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, item)
		return
	}
	m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
}

func (m *Module) requireDeletionAdmin(w http.ResponseWriter, r *http.Request, scope Scope) bool {
	if scope.PrincipalType != "user" || m.principalRoles == nil {
		m.writeError(w, http.StatusForbidden, "FORBIDDEN")
		return false
	}
	roles, err := m.principalRoles(r.Context(), scope)
	if err != nil {
		m.writeError(w, http.StatusForbidden, "FORBIDDEN")
		return false
	}
	for _, role := range roles {
		switch strings.TrimSpace(role) {
		case "system_admin", "admin", "platform_admin", "department_admin", "application_admin":
			return true
		}
	}
	m.writeError(w, http.StatusForbidden, "FORBIDDEN")
	return false
}

func (m *Module) retentionStore() (RetentionStore, bool) {
	store, ok := m.store.(RetentionStore)
	return store, ok
}

// retentionPolicy exposes an explicit service-principal governance boundary.
// retentionPolicy 显式要求服务身份，避免普通用户改变清理窗口。
func (m *Module) retentionPolicy(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(w, r) {
		return
	}
	store, ok := m.retentionStore()
	if !ok {
		m.writeError(w, http.StatusNotImplemented, "RETENTION_NOT_AVAILABLE")
		return
	}
	scope, err := scopeFromRequest(r)
	if err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if r.Method == http.MethodGet {
		kind := r.URL.Query().Get("kind")
		item, err := store.GetRetentionPolicy(r.Context(), scope, kind)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, item)
		return
	}
	if r.Method == http.MethodPut {
		var item RetentionPolicy
		if err := decode(r, &item); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		item, err = store.PutRetentionPolicy(r.Context(), scope, item)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, item)
		return
	}
	if r.Method == http.MethodPost && r.URL.Query().Get("op") == "sweep" {
		var request struct {
			Before time.Time `json:"before"`
			Limit  int       `json:"limit"`
		}
		if err := decode(r, &request); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if request.Before.IsZero() {
			request.Before = time.Now().UTC()
		}
		result, err := store.SweepExpired(r.Context(), scope, request.Before, request.Limit)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, result)
		return
	}
	m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
}

func (m *Module) legalHolds(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(w, r) {
		return
	}
	store, ok := m.retentionStore()
	if !ok {
		m.writeError(w, http.StatusNotImplemented, "LEGAL_HOLD_NOT_AVAILABLE")
		return
	}
	scope, err := scopeFromRequest(r)
	if err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if r.Method == http.MethodPost {
		var request LegalHoldRequest
		if err := decode(r, &request); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		item, err := store.PlaceLegalHold(r.Context(), scope, request)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusCreated, item)
		return
	}
	if r.Method == http.MethodGet {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
		items, total, err := store.ListLegalHolds(r.Context(), scope, page, size)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": maxPage(page), "page_size": maxSize(size)})
		return
	}
	m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
}

func (m *Module) legalHold(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(w, r) {
		return
	}
	store, ok := m.retentionStore()
	if !ok {
		m.writeError(w, http.StatusNotImplemented, "LEGAL_HOLD_NOT_AVAILABLE")
		return
	}
	scope, err := scopeFromRequest(r)
	if err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/legal-holds/"), "/"), "/")
	if len(parts) == 2 && parts[1] == "release" && r.Method == http.MethodPost {
		item, err := store.ReleaseLegalHold(r.Context(), scope, parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, item)
		return
	}
	m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
}

func maxPage(value int) int {
	if value < 1 {
		return 1
	}
	return value
}

func maxSize(value int) int {
	if value < 1 {
		return 20
	}
	if value > 100 {
		return 100
	}
	return value
}

func normalizeMessagePage(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return page, size
}

func (m *Module) authorized(w http.ResponseWriter, r *http.Request) bool {
	if m.internalToken == "" {
		return true
	}
	value := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if value == "" {
		value = strings.TrimSpace(r.Header.Get("X-Internal-Token"))
	}
	if len(value) != len(m.internalToken) || subtle.ConstantTimeCompare([]byte(value), []byte(m.internalToken)) != 1 {
		m.writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return false
	}
	return true
}

func scopeFromRequest(r *http.Request) (Scope, error) {
	scope := Scope{TenantID: strings.TrimSpace(r.Header.Get("X-Tenant-ID")), DepartmentID: strings.TrimSpace(r.Header.Get("X-Department-ID")), ApplicationID: strings.TrimSpace(r.Header.Get("X-Application-ID")), PrincipalType: strings.TrimSpace(r.Header.Get("X-Principal-Type")), PrincipalID: strings.TrimSpace(r.Header.Get("X-Principal-ID")), TraceID: strings.TrimSpace(r.Header.Get("X-Trace-ID"))}
	if scope.PrincipalType == "" {
		scope.PrincipalType = "user"
	}
	if scope.TraceID == "" {
		scope.TraceID = "conversation-module"
	}
	if err := scope.Validate(); err != nil {
		return Scope{}, err
	}
	return scope, nil
}

func validTraceID(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
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

func (m *Module) storeError(w http.ResponseWriter, err error) {
	status, code := http.StatusInternalServerError, "INTERNAL_ERROR"
	switch {
	case errors.Is(err, ErrDeletionRecorderUnavailable):
		status, code = http.StatusServiceUnavailable, "DELETION_AUDIT_UNAVAILABLE"
	case errors.Is(err, ErrNotFound):
		status, code = http.StatusNotFound, "RESOURCE_NOT_FOUND"
	case errors.Is(err, ErrForbidden):
		status, code = http.StatusForbidden, "FORBIDDEN"
	case errors.Is(err, ErrInvalidQuery):
		status, code = http.StatusBadRequest, "SCHEMA_VALIDATION_FAILED"
	case errors.Is(err, ErrRevisionConflict):
		status, code = http.StatusConflict, "REVISION_CONFLICT"
	case errors.Is(err, ErrRunReplayConflict):
		status, code = http.StatusConflict, "IDEMPOTENCY_CONFLICT"
	case errors.Is(err, ErrLegalHold):
		status, code = http.StatusConflict, "LEGAL_HOLD_ACTIVE"
	case errors.Is(err, ErrRetentionPolicy):
		status, code = http.StatusBadRequest, "INVALID_RETENTION_POLICY"
	case errors.Is(err, ErrExportTooLarge):
		status, code = http.StatusRequestEntityTooLarge, "EXPORT_TOO_LARGE"
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
