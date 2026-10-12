// Package capability exposes the platform-owned capability gateway used by
// independently deployed Agents.  It is deliberately a narrow compatibility
// boundary: policy/authentication stays in the platform and providers remain
// replaceable behind this module.
// capability 包提供平台所有的能力网关兼容边界：认证与策略在平台内完成，
// 模型、知识和工具实现通过窄接口替换，避免 Agent 复制基础设施。
package capability

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/modelcapacity"
	"github.com/lexagent/platform/internal/modelgateway"
	modelgovernance "github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

const maxBody = 1 << 20

type Module struct {
	internalToken   string
	signingSecret   string
	publicKey       ed25519.PublicKey
	issuer          string
	audience        string
	mu              sync.Mutex
	memoryStore     MemoryStore
	stateStore      CheckpointStore
	skills          *SkillRegistry
	agentRouter     *agentcoordination.Router
	skillControl    *SkillControlPlane
	knowledge       KnowledgeProvider
	policy          policyasset.Resolver
	modelStore      ModelInvocationStore
	modelAccess     modelgateway.AccessResolver
	modelGateway    modelgateway.Port
	developmentMock bool
	modelPrices     interface {
		ResolvePrice(context.Context, string, time.Time) (modelgovernance.PriceVersion, error)
	}
	modelBudgets              usagecost.ModelBudgetStore
	modelCapacity             modelcapacity.CapacityProvider
	toolStore                 ToolInvocationStore
	usageRecorder             usagecost.Recorder
	tools                     ToolProvider
	toolConfirmation          *ToolConfirmationVerifier
	toolConfirmationAuthority ToolConfirmationAuthority
	toolApprovalControl       *ToolApprovalControl
	notifications             NotificationToolPort
	liveAuthority             LiveExecutionAuthority
	billingCancel             context.CancelFunc
	billingDone               chan struct{}
	billingStats              BillingWorkerStats
	toolCancel                context.CancelFunc
	toolDone                  chan struct{}
	stateCancel               context.CancelFunc
	stateDone                 chan struct{}
	toolStats                 BillingWorkerStats
	billingControl            modelgovernance.Authorizer
}

// SetUsageRecorder wires the durable usage/cost ledger without making the
// capability gateway own its tables. A remote Usage service can implement the
// same recorder contract when the platform is split into services.
func (m *Module) SetUsageRecorder(recorder usagecost.Recorder) {
	m.usageRecorder = recorder
}

// 开发模式的 mock 在平台内执行，不视为外部厂商；其他环境默认拒绝。
func (m *Module) EnableDevelopmentMock(environment string) {
	m.developmentMock = environment == "development"
}

// SetGovernedModelInvocation connects the signed policy snapshot to approved
// Model Version resolution and the replaceable Model Gateway invocation port.
// When either dependency is configured, both become mandatory for generation;
// the deterministic test fallback is never used as an implicit substitute.
func (m *Module) SetGovernedModelInvocation(access modelgateway.AccessResolver, gateway modelgateway.Port) {
	m.modelAccess = access
	m.modelGateway = gateway
}

// SetModelBilling wires approved effective prices and the atomic usage/budget
// ledger used for real governed model calls. The existing Recorder remains
// available for deterministic local fallback paths.
func (m *Module) SetModelBilling(prices interface {
	ResolvePrice(context.Context, string, time.Time) (modelgovernance.PriceVersion, error)
}, budgets usagecost.ModelBudgetStore) {
	m.modelPrices = prices
	m.modelBudgets = budgets
}

// SetModelCapacity installs the shared deployment-capacity lease adapter.
// Local-model execution fails closed when a ready deployment or capacity
// provider is not available.
func (m *Module) SetModelCapacity(provider modelcapacity.CapacityProvider) {
	m.modelCapacity = provider
}

// NotificationToolPort is the capability boundary for durable notification
// requests. The platform composition root adapts it to the Notification
// Outbox; accepting a request must never be reported as delivered.
// NotificationToolPort 是通知工具的持久化边界；由平台组合根适配到通知 Outbox，
// 受理请求不能被谎报为已送达。
type NotificationToolPort interface {
	Enqueue(context.Context, NotificationToolCommand) (NotificationToolReceipt, error)
}

type NotificationToolCommand struct {
	Scope       sharedkernel.Scope
	ToolName    string
	CallID      string
	Fingerprint string
	EventID     string
	RecipientID string
	Title       string
	Text        string
}

type NotificationToolReceipt struct {
	EventID string
	Status  string
}

type memoryEntry struct {
	Value     map[string]any
	ExpiresAt time.Time
}

// MemoryStore is the platform-owned persistence boundary for working/session
// memory. Implementations may be in-process for unit tests or SQL/Redis for a
// deployed modular monolith; Agents only see the HTTP capability contract.
// MemoryStore 是平台所有的记忆持久化边界；单测可用内存实现，部署可替换为
// SQL/Redis，Agent 不感知底层存储。
type MemoryStore interface {
	Load(context.Context, string) (memoryEntry, bool, error)
	Save(context.Context, string, memoryEntry, int) error
}

type memoryMapStore struct {
	mu     sync.Mutex
	values map[string]memoryEntry
}

func newMemoryMapStore() *memoryMapStore {
	return &memoryMapStore{values: make(map[string]memoryEntry)}
}

func (s *memoryMapStore) Load(_ context.Context, key string) (memoryEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.values[key]
	if !ok {
		return memoryEntry{}, false, nil
	}
	if !entry.ExpiresAt.IsZero() && !time.Now().Before(entry.ExpiresAt) {
		delete(s.values, key)
		return memoryEntry{}, false, nil
	}
	return memoryEntry{Value: cloneMemoryValue(entry.Value), ExpiresAt: entry.ExpiresAt}, true, nil
}

func (s *memoryMapStore) Save(ctx context.Context, key string, entry memoryEntry, maxEntries int) error {
	return s.SaveAuthorized(ctx, key, entry, maxEntries, nil)
}

func (s *memoryMapStore) SaveAuthorized(ctx context.Context, key string, entry memoryEntry, maxEntries int, check func(context.Context) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if check != nil {
		if err := check(ctx); err != nil {
			return errors.Join(errMemoryWriteDenied, err)
		}
	}
	now := time.Now()
	count := 0
	for existingKey, existing := range s.values {
		if !existing.ExpiresAt.IsZero() && !now.Before(existing.ExpiresAt) {
			delete(s.values, existingKey)
			continue
		}
		if strings.HasPrefix(existingKey, memoryScopePrefix(key)) {
			count++
		}
	}
	if maxEntries > 0 {
		_, exists := s.values[key]
		if !exists && count >= maxEntries {
			return errMemoryLimitExceeded
		}
	}
	s.values[key] = memoryEntry{Value: cloneMemoryValue(entry.Value), ExpiresAt: entry.ExpiresAt}
	return nil
}

var errMemoryLimitExceeded = errors.New("memory policy max_entries exceeded")

// KnowledgeProvider is the platform-owned knowledge boundary. Agents only
// send a governed query; credentials and provider-specific HTTP details stay
// inside this module.
// KnowledgeProvider 是平台所有的知识边界；Agent 只提交受治理查询，凭证和
// Provider 相关 HTTP 细节留在本模块内。
type KnowledgeProvider interface {
	Search(context.Context, harnessContext, knowledgeQuery) (map[string]any, error)
}

type knowledgeQuery struct {
	Query             string
	Answer            bool
	SkillContext      string
	Scope             string
	TopK              int
	AsOf              string
	CacheMode         string
	Documents         []policyasset.KnowledgeDocumentBinding
	GovernedDocuments bool
	Policy            policyasset.Snapshot
	ModelCall         KnowledgeModelCall
	ModelCheck        KnowledgeModelCheck
}

func firstString(values map[string]any, key, fallback string) string {
	if value := stringValue(values[key]); value != "" {
		return value
	}
	return fallback
}

func stringValue(v any) string {
	switch value := v.(type) {
	case string:
		return value
	case float64:
		return strconv.FormatInt(int64(value), 10)
	case json.Number:
		return value.String()
	default:
		return ""
	}
}

func numberValue(v any) float64 {
	if value, ok := v.(json.Number); ok {
		number, _ := value.Float64()
		return number
	}
	if value, ok := v.(float64); ok {
		return value
	}
	return 0
}

func NewModule(token, signingSecret string, publicKey ed25519.PublicKey, issuer, audience string) *Module {
	return &Module{internalToken: token, signingSecret: signingSecret, publicKey: publicKey,
		issuer: issuer, audience: audience, memoryStore: newMemoryMapStore(),
		modelStore: newMemoryModelInvocationStore(), toolStore: newMemoryToolInvocationStore(), tools: builtinToolProvider{}}
}

// NewModuleWithKnowledge keeps the deterministic provider as the default test
// implementation while allowing production to inject platform-owned storage.
// NewModuleWithKnowledge 保持确定性 Provider 作为默认测试实现，同时允许生产
// 进程注入自主知识存储。
func NewModuleWithKnowledge(token, signingSecret string, publicKey ed25519.PublicKey, issuer, audience string, provider KnowledgeProvider) *Module {
	m := NewModule(token, signingSecret, publicKey, issuer, audience)
	m.knowledge = provider
	return m
}

// NewModuleWithKnowledgeAndPolicies enables the production policy snapshot
// resolver while retaining the deterministic provider constructor for tests.
// NewModuleWithKnowledgeAndPolicies 在保持测试 Fixture 构造器不变的同时，
// 为生产能力网关启用控制面策略快照 Resolver。
func NewModuleWithKnowledgeAndPolicies(token, signingSecret string, publicKey ed25519.PublicKey, issuer, audience string, provider KnowledgeProvider, resolver policyasset.Resolver) *Module {
	m := NewModuleWithKnowledge(token, signingSecret, publicKey, issuer, audience, provider)
	m.policy = resolver
	return m
}

// NewModuleWithKnowledgePoliciesAndMemory injects a durable platform memory
// implementation without changing the Agent-facing capability contract.
// NewModuleWithKnowledgePoliciesAndMemory 注入持久化记忆实现，同时不改变 Agent
// 对外能力契约，便于单实例先用 SQL、后续切 Redis/远程服务。
func NewModuleWithKnowledgePoliciesAndMemory(token, signingSecret string, publicKey ed25519.PublicKey, issuer, audience string, provider KnowledgeProvider, resolver policyasset.Resolver, memory MemoryStore) *Module {
	m := NewModuleWithKnowledgeAndPolicies(token, signingSecret, publicKey, issuer, audience, provider, resolver)
	if memory != nil {
		m.memoryStore = memory
	}
	return m
}

// NewModuleWithGovernance injects durable model invocation accounting. Keeping
// this as a constructor option preserves fast unit fixtures and makes the
// future remote usage service a drop-in replacement.
func NewModuleWithGovernance(token, signingSecret string, publicKey ed25519.PublicKey, issuer, audience string, provider KnowledgeProvider, resolver policyasset.Resolver, memory MemoryStore, modelStore ModelInvocationStore) *Module {
	return NewModuleWithGovernanceAndToolLedger(token, signingSecret, publicKey, issuer, audience, provider, resolver, memory, modelStore, nil)
}

// NewModuleWithGovernanceAndToolLedger injects both model and side-effect
// ledgers. Keeping each behind a Port allows a future Usage/Tool service to
// replace the SQL implementation without changing Agent code.
// NewModuleWithGovernanceAndToolLedger 同时注入模型调用账本与副作用账本，
// 通过 Port 保持后续拆分 Usage/Tool Service 时的替换边界。
func NewModuleWithGovernanceAndToolLedger(token, signingSecret string, publicKey ed25519.PublicKey, issuer, audience string, provider KnowledgeProvider, resolver policyasset.Resolver, memory MemoryStore, modelStore ModelInvocationStore, toolStore ToolInvocationStore) *Module {
	m := NewModuleWithKnowledgePoliciesAndMemory(token, signingSecret, publicKey, issuer, audience, provider, resolver, memory)
	if modelStore != nil {
		m.modelStore = modelStore
	}
	if toolStore != nil {
		m.toolStore = toolStore
	}
	return m
}

func (m *Module) SetNotificationToolPort(port NotificationToolPort) {
	m.notifications = port
}

func (m *Module) Name() string { return "capability" }
func (m *Module) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("module context is required")
	}
	if m.liveAuthority != nil && len(m.publicKey) != ed25519.PublicKeySize {
		return errors.New("live execution authority requires a verification key")
	}
	if m.publicKey != nil && m.liveAuthority == nil {
		return errors.New("live execution authority is required")
	}
	if m.toolStore != nil {
		if _, ok := m.toolStore.(ToolRecoveryStore); !ok {
			return errors.New("tool recovery store is required")
		}
	}
	if m.modelBudgets != nil {
		if _, ok := m.modelStore.(ModelBillingRecoveryStore); !ok {
			return errors.New("billing recovery store is required")
		}
		m.mu.Lock()
		if m.billingCancel == nil {
			workerCtx, cancel := context.WithCancel(ctx)
			m.billingCancel, m.billingDone = cancel, make(chan struct{})
			go m.billingLoop(workerCtx, m.billingDone)
		}
		m.mu.Unlock()
	}
	if m.toolStore != nil {
		m.mu.Lock()
		if m.toolCancel == nil {
			workerCtx, cancel := context.WithCancel(ctx)
			m.toolCancel, m.toolDone = cancel, make(chan struct{})
			go m.toolRecoveryLoop(workerCtx, m.toolDone)
		}
		m.mu.Unlock()
	}
	if store, ok := m.stateStore.(CheckpointMaintenanceStore); ok {
		m.mu.Lock()
		if m.stateCancel == nil {
			workerCtx, cancel := context.WithCancel(ctx)
			m.stateCancel, m.stateDone = cancel, make(chan struct{})
			go checkpointMaintenanceLoop(workerCtx, m.stateDone, store)
		}
		m.mu.Unlock()
	}
	return nil
}
func (m *Module) Close(ctx context.Context) error {
	m.mu.Lock()
	cancel, done := m.billingCancel, m.billingDone
	toolCancel, toolDone := m.toolCancel, m.toolDone
	stateCancel, stateDone := m.stateCancel, m.stateDone
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if toolCancel != nil {
		toolCancel()
	}
	if stateCancel != nil {
		stateCancel()
	}
	for _, wait := range []chan struct{}{done, toolDone, stateDone} {
		if wait == nil {
			continue
		}
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

type harnessContext struct {
	TenantID             string `json:"tenant_id"`
	DepartmentID         string `json:"department_id"`
	ApplicationID        string `json:"application_id"`
	AgentID              string `json:"agent_id"`
	AgentInstanceID      string `json:"agent_instance_id"`
	PrincipalType        string `json:"principal_type"`
	InstallationID       string `json:"installation_id"`
	AgentVersionID       string `json:"agent_version_id"`
	ActorID              string `json:"actor_id"`
	RequestID            string `json:"request_id"`
	TraceID              string `json:"trace_id"`
	TaskID               string `json:"task_id"`
	ParentRunID          string `json:"parent_run_id"`
	ThreadID             string `json:"thread_id"`
	SessionID            string `json:"session_id"`
	KnowledgeScope       string `json:"knowledge_scope"`
	IdempotencyKey       string `json:"idempotency_key"`
	ModelProfileID       string `json:"model_profile_id"`
	PromptVersionID      string `json:"prompt_version_id"`
	MemoryPolicyID       string `json:"memory_policy_id"`
	ToolPolicyID         string `json:"tool_policy_id"`
	KnowledgePolicyID    string `json:"knowledge_policy_id"`
	RuntimePolicyID      string `json:"runtime_policy_id"`
	RuleBundleVersion    string `json:"rule_bundle_version"`
	RuleBundleChecksum   string `json:"rule_bundle_checksum"`
	PlatformContextToken string `json:"platform_context_token"`
	AuthorizationEpoch   uint64 `json:"authorization_epoch"`
}

type envelope struct {
	ToolApproval   *ToolConfirmationClaims  `json:"-"`
	ResourceAccess CapabilityResourceAccess `json:"-"`
	Context        harnessContext           `json:"context"`
	Input          json.RawMessage          `json:"input"`
	Policy         policyasset.Snapshot     `json:"-"`
}
type response struct {
	Code      int    `json:"code"`
	Message   string `json:"message"`
	ErrorCode string `json:"error_code,omitempty"`
	Data      any    `json:"data,omitempty"`
	TraceID   string `json:"trace_id,omitempty"`
}

func (m *Module) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/billing/metrics", m.billingMetrics)
	mux.HandleFunc("/billing/reconciliations", m.billingAdmin)
	mux.HandleFunc("/internal/permission/check", m.permission)
	mux.HandleFunc("/internal/model/generate", m.generate)
	mux.HandleFunc("/internal/model/embed", m.embed)
	mux.HandleFunc("/internal/prompt/resolve", m.resolvePrompt)
	mux.HandleFunc("/internal/knowledge/search", m.search)
	mux.HandleFunc("/internal/knowledge/answer", m.search)
	mux.HandleFunc("/internal/knowledge/answer/recovery", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			m.error(w, 405, "METHOD_NOT_ALLOWED", "POST required", "")
			return
		}
		m.search(w, r.WithContext(context.WithValue(r.Context(), knowledgeRecoveryOnlyKey{}, true)))
	})
	mux.HandleFunc("/internal/knowledge/replay", m.replay)
	mux.HandleFunc("/internal/memory/access", m.memory)
	mux.HandleFunc("/internal/state/checkpoint", m.checkpoint)
	mux.HandleFunc("/internal/tool/invoke", m.tool)
	mux.HandleFunc("/internal/tool/receipt", m.toolReceipt)
	mux.HandleFunc("/internal/model/receipt", m.modelReceipt)
	mux.HandleFunc("/internal/model/embed/receipt", m.modelReceipt)
	mux.HandleFunc("/tool-approvals/", m.toolApprovalHTTP)
	mux.HandleFunc("/internal/context/renew", m.renewContext)
	mux.HandleFunc("/internal/context/events/check", m.checkEventRead)
	mux.HandleFunc("/internal/context/prepare", m.prepareContext)
	mux.HandleFunc("/internal/runtime/harness-policy", m.harnessPolicy)
	mux.HandleFunc("/internal/skill/load", m.loadSkill)
	mux.HandleFunc("/internal/agent/route", m.routeAgents)
	mux.HandleFunc("/internal/agent/prepare", m.routeAgents)
	mux.HandleFunc("/internal/agent/admit", m.routeAgents)
	mux.HandleFunc("/internal/agent/child", m.routeAgents)
	mux.HandleFunc("/internal/agent/cancel", m.routeAgents)
	mux.HandleFunc("/internal/agent/gather", m.routeAgents)
	mux.HandleFunc("/internal/agent/admission-state", m.routeAgents)
	mux.HandleFunc("/skills/", m.skillControlHTTP)
	return mux
}

// InternalHandler is kept separate from the public module tree so the
// bootstrap can bind it only to the private listener.
func (m *Module) InternalHandler() http.Handler {
	handler := m.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/tool-approvals/") || strings.HasPrefix(r.URL.Path, "/skills/") {
			m.error(w, 403, "HUMAN_CONTROL_PLANE_ONLY", "approval is not available on the Agent internal listener", "")
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func (m *Module) authorize(w http.ResponseWriter, r *http.Request) (envelope, bool) {
	return m.authorizeWithExpiry(w, r, false)
}

func (m *Module) authorizeWithExpiry(w http.ResponseWriter, r *http.Request, allowExpired bool) (envelope, bool) {
	if r.Method != http.MethodPost || m.internalToken == "" || !hmac.Equal([]byte(m.internalToken), []byte(strings.TrimSpace(r.Header.Get("X-Internal-Token")))) {
		m.error(w, http.StatusUnauthorized, "UNAUTHENTICATED", "invalid internal credential", "")
		return envelope{}, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		m.error(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "request body exceeds limit", "")
		return envelope{}, false
	}
	if m.signingSecret != "" {
		supplied := strings.TrimPrefix(strings.TrimSpace(r.Header.Get("X-Context-Signature")), "sha256=")
		mac := hmac.New(sha256.New, []byte(m.signingSecret))
		_, _ = mac.Write(requestSignaturePayload(r.Method, r.URL.RequestURI(), body))
		if supplied == "" || !hmac.Equal([]byte(supplied), []byte(fmt.Sprintf("%x", mac.Sum(nil)))) {
			m.error(w, http.StatusUnauthorized, "INVALID_SIGNATURE", "invalid request signature", "")
			return envelope{}, false
		}
	}
	var op envelope
	if err := json.Unmarshal(body, &op); err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid capability envelope", "")
		return envelope{}, false
	}
	if err := m.validateContextWithExpiry(r, op.Context, allowExpired); err != nil {
		m.error(w, http.StatusForbidden, "CAPABILITY_DENIED", err.Error(), op.Context.TraceID)
		return envelope{}, false
	}
	policy, err := m.validatePolicy(r.Context(), op.Context)
	if err != nil {
		m.error(w, http.StatusForbidden, "POLICY_DENIED", err.Error(), op.Context.TraceID)
		return envelope{}, false
	}
	op.Policy = policy
	if m.publicKey != nil {
		op.ResourceAccess, err = resourceAccessForRoute(r.URL.Path, op)
		if err != nil {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid capability resource input", op.Context.TraceID)
			return envelope{}, false
		}
		if err := m.validateLiveAuthority(r.Context(), op); err != nil {
			m.error(w, http.StatusForbidden, "CAPABILITY_DENIED", "current execution authorization denied", op.Context.TraceID)
			return envelope{}, false
		}
		if err := m.authenticateWorkload(r, op); err != nil {
			m.error(w, http.StatusForbidden, "WORKLOAD_AUTHENTICATION_DENIED", "current workload credential denied", op.Context.TraceID)
			return envelope{}, false
		}
		retainWorkloadProof(r, op)
	}
	return op, true
}

func (m *Module) validatePolicy(ctx context.Context, c harnessContext) (policyasset.Snapshot, error) {
	if m.policy == nil {
		return policyasset.Snapshot{}, nil
	}
	requested := policyasset.SnapshotFromContext(map[string]string{
		"model_profile_id":     c.ModelProfileID,
		"prompt_version_id":    c.PromptVersionID,
		"tool_policy_id":       c.ToolPolicyID,
		"memory_policy_id":     c.MemoryPolicyID,
		"knowledge_policy_id":  c.KnowledgePolicyID,
		"runtime_policy_id":    c.RuntimePolicyID,
		"rule_bundle_version":  c.RuleBundleVersion,
		"rule_bundle_checksum": c.RuleBundleChecksum,
	})
	if err := requested.ValidateIDs(); err != nil {
		return policyasset.Snapshot{}, errors.New("six policy identifiers are required")
	}
	snapshot, err := m.policy.Resolve(ctx, sharedkernel.Scope{
		TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID,
		AgentID: c.AgentID, AgentVersionID: c.AgentVersionID, PrincipalID: c.ActorID,
		PrincipalType: c.PrincipalType, AgentInstanceID: c.AgentInstanceID,
		InstallationID: c.InstallationID, SessionID: c.SessionID, RunID: c.TaskID,
		TraceID: c.TraceID, AuthorizationEpoch: c.AuthorizationEpoch,
	}, c.AgentVersionID)
	if err != nil {
		return policyasset.Snapshot{}, errors.New("policy snapshot unavailable")
	}
	if !snapshot.SameIDs(requested) || !snapshot.SameRuleBinding(requested) {
		return policyasset.Snapshot{}, errors.New("requested policy snapshot is not authorized")
	}
	return snapshot, nil
}

func (m *Module) validateContext(r *http.Request, c harnessContext) error {
	return m.validateContextWithExpiry(r, c, false)
}

func (m *Module) validateContextWithExpiry(r *http.Request, c harnessContext, allowExpired bool) error {
	if m.liveAuthority != nil && len(m.publicKey) != ed25519.PublicKeySize {
		return errors.New("platform verification key unavailable")
	}
	for name, value := range map[string]string{"tenant": c.TenantID, "department": c.DepartmentID, "application": c.ApplicationID, "agent": c.AgentID, "agent_instance": c.AgentInstanceID, "version": c.AgentVersionID, "principal_type": c.PrincipalType, "actor": c.ActorID, "trace": c.TraceID, "task": c.TaskID} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("missing capability scope: %s", name)
		}
	}
	if c.PrincipalType != "user" && c.PrincipalType != "service_principal" {
		return errors.New("invalid principal type")
	}
	if c.PlatformContextToken == "" || strings.TrimSpace(r.Header.Get("X-Platform-Context")) != "Bearer "+c.PlatformContextToken {
		return errors.New("platform context mismatch")
	}
	if m.publicKey != nil {
		if err := verifyTokenWithExpiry(m.publicKey, m.issuer, m.audience, c, allowExpired); err != nil {
			return err
		}
	}
	return nil
}

func verifyToken(key ed25519.PublicKey, issuer, audience string, c harnessContext) error {
	return verifyTokenWithExpiry(key, issuer, audience, c, false)
}

func verifyTokenWithExpiry(key ed25519.PublicKey, issuer, audience string, c harnessContext, allowExpired bool) error {
	parts := strings.Split(c.PlatformContextToken, ".")
	if len(parts) != 3 {
		return errors.New("invalid platform context token")
	}
	decode := func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
	h, err := decode(parts[0])
	if err != nil {
		return errors.New("invalid platform context header")
	}
	var header map[string]any
	if json.Unmarshal(h, &header) != nil || header["alg"] != "EdDSA" {
		return errors.New("invalid platform context algorithm")
	}
	p, err := decode(parts[1])
	if err != nil {
		return errors.New("invalid platform context claims")
	}
	var claims map[string]any
	if json.Unmarshal(p, &claims) != nil {
		return errors.New("invalid platform context claims")
	}
	s, err := decode(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), s) {
		return errors.New("invalid platform context signature")
	}
	checks := map[string]string{"iss": issuer, "aud": audience, "subject_type": c.PrincipalType, "sub": c.ActorID, "tenant_id": c.TenantID, "department_id": c.DepartmentID, "application_id": c.ApplicationID, "agent_instance_id": c.AgentInstanceID,
		"installation_id": c.InstallationID, "agent_id": c.AgentID, "agent_version_id": c.AgentVersionID, "run_id": c.TaskID, "session_id": c.SessionID, "trace_id": c.TraceID}
	// A non-empty parent is a signed billing lineage. An ordinary Run must not
	// silently accept an unexpected parent claim or a forged request field.
	// 父 Run 是签名的计费血缘；普通 Run 不接受伪造的父 Run 字段。
	if c.ParentRunID != "" {
		checks["parent_run_id"] = c.ParentRunID
	} else if parent, ok := claims["parent_run_id"]; ok && parent != "" {
		return errors.New("unexpected platform parent run claim")
	}
	for k, expected := range checks {
		if actual, ok := claims[k].(string); !ok || actual != expected {
			return fmt.Errorf("platform context claim mismatch: %s", k)
		}
	}
	if epoch, ok := claims["authorization_epoch"].(float64); !ok || c.AuthorizationEpoch == 0 || epoch != float64(c.AuthorizationEpoch) {
		return errors.New("platform context authorization epoch mismatch")
	}
	now := float64(time.Now().Unix())
	iat, iok := claims["iat"].(float64)
	exp, eok := claims["exp"].(float64)
	if !iok || !eok || iat > now+30 || (!allowExpired && exp <= now) || exp <= iat || exp-iat > 300 {
		return errors.New("platform context expired")
	}
	return nil
}

func (m *Module) permission(w http.ResponseWriter, r *http.Request) {
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(op.Input, &in) != nil || in.Name == "" {
		m.error(w, 400, "INVALID_REQUEST", "capability name is required", op.Context.TraceID)
		return
	}
	if !op.Policy.AllowsTool(in.Name) {
		m.error(w, http.StatusForbidden, "CAPABILITY_DENIED", "tool is not allowed by the published policy", op.Context.TraceID)
		return
	}
	allowed := isNotificationTool(in.Name) || m.tools != nil && m.tools.Supports(in.Name)
	if !allowed {
		m.error(w, 403, "CAPABILITY_DENIED", "capability is not allowed by policy", op.Context.TraceID)
		return
	}
	if isNotificationTool(in.Name) && m.notifications == nil {
		m.error(w, http.StatusServiceUnavailable, "CAPABILITY_UNAVAILABLE", "notification outbox is unavailable", op.Context.TraceID)
		return
	}
	if in.Name == notifySelfToolName && op.Context.PrincipalType != "user" {
		m.error(w, http.StatusForbidden, "NOTIFICATION_RECIPIENT_DENIED", "notify.self requires a human principal", op.Context.TraceID)
		return
	}
	m.ok(w, map[string]bool{"allowed": true}, op.Context.TraceID)
}

func (m *Module) generate(w http.ResponseWriter, r *http.Request) {
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	m.generateAuthorized(w, r, op)
}

func (m *Module) generateAuthorized(w http.ResponseWriter, r *http.Request, op envelope) {
	var in struct {
		Texts              []string                     `json:"texts"`
		EmbeddingPurpose   string                       `json:"input_purpose,omitempty"`
		Messages           []modelgateway.Message       `json:"messages"`
		FunctionNames      []string                     `json:"function_names"`
		SkillBindings      map[string]SkillModelBinding `json:"skill_bindings"`
		PromptTemplateHash string                       `json:"prompt_template_hash"`
		IdempotencyKey     string                       `json:"idempotency_key"`
		Temperature        float64                      `json:"temperature"`
		MaxTokens          int                          `json:"max_tokens"`
	}
	embeddingCall := r.URL.Path == "/internal/model/embed"

	if embeddingCall {
		selectedPolicy, err := op.Policy.Model.ForEmbedding()
		if err != nil {
			m.error(w, http.StatusForbidden, "MODEL_SELECTION_MISMATCH", "published embedding target is incomplete", op.Context.TraceID)
			return
		}
		op.Policy.Model = selectedPolicy
	}
	if json.Unmarshal(op.Input, &in) != nil {
		m.error(w, 400, "INVALID_REQUEST", "invalid model input", op.Context.TraceID)
		return
	}
	if in.EmbeddingPurpose != "" && (!embeddingCall || (in.EmbeddingPurpose != "query" && in.EmbeddingPurpose != "document")) {
		m.error(w, 400, "INVALID_REQUEST", "invalid embedding input purpose", op.Context.TraceID)
		return
	}
	if !validSkillModelBindings(in.SkillBindings) || embeddingCall && len(in.SkillBindings) > 0 {
		m.error(w, 400, "INVALID_REQUEST", "invalid skill dependencies", op.Context.TraceID)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), skillModelBindingsKey{}, in.SkillBindings))
	if !m.currentCapability(w, r, op) {
		return
	}
	if embeddingCall {
		if len(in.FunctionNames) > 0 {
			m.error(w, 400, "INVALID_REQUEST", "embedding cannot request functions", op.Context.TraceID)
			return
		}
		if len(in.Texts) == 0 || len(in.Texts) > 128 {
			m.error(w, 400, "INVALID_REQUEST", "embedding requires 1 to 128 texts", op.Context.TraceID)
			return
		}
		in.Messages = nil
		bytes := 0
		for _, text := range in.Texts {
			bytes += len(text)
			if strings.TrimSpace(text) == "" || bytes > 1024*1024 {
				m.error(w, 400, "INVALID_REQUEST", "embedding text batch is invalid or too large", op.Context.TraceID)
				return
			}
			in.Messages = append(in.Messages, modelgateway.Message{Role: "user", Content: text})
		}
		// Embedding has no generation prompt or output tokens. Reserve one
		// output token conservatively through the existing common budget port.
		in.PromptTemplateHash = op.Policy.Prompt.TemplateHash
		in.MaxTokens = 1
		in.Temperature = 0
	}
	if len(in.Messages) == 0 {
		m.error(w, 400, "INVALID_REQUEST", "messages are required", op.Context.TraceID)
		return
	}
	if op.Policy.Prompt.TemplateHash != "" && in.PromptTemplateHash != op.Policy.Prompt.TemplateHash {
		log.Printf("prompt version denied: requested=%q published=%q agent=%q version=%q", in.PromptTemplateHash, op.Policy.Prompt.TemplateHash, op.Context.AgentID, op.Context.AgentVersionID)
		m.error(w, http.StatusForbidden, "PROMPT_VERSION_DENIED", "prompt template does not match the published policy", op.Context.TraceID)
		return
	}
	if in.MaxTokens < 0 || op.Policy.Model.MaxTokens > 0 && in.MaxTokens > op.Policy.Model.MaxTokens {
		m.error(w, http.StatusBadRequest, "MODEL_LIMIT_EXCEEDED", "requested token limit exceeds the published model policy", op.Context.TraceID)
		return
	}
	if in.MaxTokens == 0 {
		in.MaxTokens = op.Policy.Model.MaxTokens
	}
	if in.Temperature < 0 || in.Temperature > 2 {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "temperature must be between 0 and 2", op.Context.TraceID)
		return
	}
	if !embeddingCall && modelgateway.ValidateFunctionRequest(op.Policy.Tool, in.FunctionNames, in.Messages) != nil {
		m.error(w, 403, "FUNCTION_POLICY_DENIED", "function definitions or tool transcript violate published policy", op.Context.TraceID)
		return
	}
	budgetMessages := modelBudgetMessages(in.Messages, op.Policy.Tool, in.FunctionNames)
	if !embeddingCall && validateModelContextLimit(op.Policy.Model, in.Messages, op.Policy.Tool, in.FunctionNames) != nil {
		m.error(w, http.StatusBadRequest, "CONTEXT_LIMIT_EXCEEDED", "model input exceeds the published input token limit", op.Context.TraceID)
		return
	}
	provider := strings.ToLower(strings.TrimSpace(op.Policy.Model.Provider))
	if provider == "" {
		provider = "local"
	}
	governanceConfigured := m.modelAccess != nil || m.modelGateway != nil
	if len(in.FunctionNames) > 0 && !governanceConfigured {
		m.error(w, 503, "FUNCTION_PROVIDER_UNAVAILABLE", "function calling requires a governed provider", op.Context.TraceID)
		return
	}
	if !governanceConfigured && provider == "mock" && !m.developmentMock {
		m.error(w, http.StatusForbidden, "DEVELOPMENT_MODEL_DENIED", "mock model requires explicit development mode", op.Context.TraceID)
		return
	}
	if !governanceConfigured && !op.Policy.Model.AllowExternal && provider != "local" && provider != "platform" && !(provider == "mock" && m.developmentMock) {
		m.error(w, http.StatusForbidden, "EXTERNAL_MODEL_DENIED", "external model provider is disabled by policy", op.Context.TraceID)
		return
	}
	var selectedModel modelgateway.Selection
	var modelScope sharedkernel.Scope
	if governanceConfigured {
		if embeddingCall {
			if _, ok := m.modelGateway.(modelgateway.UsageEmbeddingPort); !ok {
				m.error(w, 503, "MODEL_GOVERNANCE_UNAVAILABLE", "usage-bearing embedding provider required", op.Context.TraceID)
				return
			}
		}
		if m.modelAccess == nil || m.modelGateway == nil || strings.TrimSpace(op.Policy.Model.ModelVersionID) == "" {
			m.error(w, http.StatusServiceUnavailable, "MODEL_GOVERNANCE_UNAVAILABLE", "approved model selection is not configured", op.Context.TraceID)
			return
		}
		modelScope = sharedkernel.Scope{TenantID: op.Context.TenantID, DepartmentID: op.Context.DepartmentID, ApplicationID: op.Context.ApplicationID, AgentInstanceID: op.Context.AgentInstanceID, AgentID: op.Context.AgentID, PrincipalID: op.Context.ActorID, PrincipalType: op.Context.PrincipalType, InstallationID: op.Context.InstallationID, AgentVersionID: op.Context.AgentVersionID, SessionID: op.Context.SessionID, RunID: op.Context.TaskID, ParentRunID: op.Context.ParentRunID, AuthorizationEpoch: op.Context.AuthorizationEpoch, TraceID: op.Context.TraceID}
		if modelScope.RunID == "" {
			modelScope.RunID = op.Context.RequestID
		}
		resolvedModel, resolveErr := m.modelAccess.ResolveModel(r.Context(), modelScope, op.Policy.Model.ModelVersionID)
		if resolveErr != nil {
			if errors.Is(resolveErr, modelgovernance.ErrModelAccessDenied) || errors.Is(resolveErr, modelgovernance.ErrNotFound) || errors.Is(resolveErr, modelgovernance.ErrForbidden) {
				m.error(w, http.StatusForbidden, "MODEL_ACCESS_DENIED", "model version is not approved or is not allowed for this execution scope", op.Context.TraceID)
			} else {
				m.error(w, http.StatusServiceUnavailable, "MODEL_GOVERNANCE_UNAVAILABLE", "model authorization service is unavailable", op.Context.TraceID)
			}
			return
		}
		selectedModel = resolvedModel
		if selectedModel.ModelVersionID != op.Policy.Model.ModelVersionID || selectedModel.ProviderID == "" || selectedModel.ProviderKey == "" || selectedModel.ModelID == "" || selectedModel.ModelKey == "" ||
			!sameModelSelection(provider, op.Policy.Model.Model, selectedModel) {
			m.error(w, http.StatusForbidden, "MODEL_SELECTION_MISMATCH", "published model selection does not match the approved catalog version", op.Context.TraceID)
			return
		}
		if selectedModel.TrustZone == modelgovernance.TrustExternal && !op.Policy.Model.AllowExternal {
			m.error(w, http.StatusForbidden, "EXTERNAL_MODEL_DENIED", "external model provider is disabled by policy", op.Context.TraceID)
			return
		}
	}
	if in.IdempotencyKey == "" {
		in.IdempotencyKey = op.Context.IdempotencyKey
	}
	if in.IdempotencyKey == "" {
		in.IdempotencyKey = op.Context.RequestID + ":model.generate"
		if embeddingCall {
			in.IdempotencyKey = op.Context.RequestID + ":model.embed"
		}
	}
	fingerprint, _ := modelCommandFingerprint(in.Messages, in.Temperature, in.MaxTokens, in.PromptTemplateHash, op.Policy.Model, in.FunctionNames, embeddingCall, in.SkillBindings)
	if embeddingCall {
		fingerprint = modelPurposeFingerprint(fingerprint, in.EmbeddingPurpose)
	}
	scopeHash := capabilityScopeHash(op.Context)
	estimatedCost := estimateModelCost(budgetMessages)
	var budgetReservation *usagecost.ModelBudgetReservation
	var approvedPrice modelgovernance.PriceVersion
	var modelAttemptToken string
	if m.modelStore != nil {
		invocationBudget, invocationEstimate := op.Policy.Model.BudgetCents, estimatedCost
		if governanceConfigured {
			// ModelBudgetStore is authoritative for governed calls. Keep this
			// invocation record for request idempotency without charging its legacy
			// cent-based counter a second time.
			invocationBudget, invocationEstimate = 0, 0
		}
		var replayed ModelInvocation
		var replay bool
		var err error
		if governanceConfigured {
			preparations, ok := m.modelStore.(ModelPreparationStore)
			if !ok {
				m.error(w, http.StatusServiceUnavailable, "MODEL_BILLING_UNAVAILABLE", "durable preparation store required", op.Context.TraceID)
				return
			}
			replayed, replay, err = preparations.ReserveGoverned(r.Context(), scopeHash, in.IdempotencyKey, fingerprint)
			modelAttemptToken = replayed.AttemptToken
		} else {
			replayed, replay, err = m.modelStore.Reserve(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, invocationBudget, invocationEstimate)
		}
		if err != nil {
			switch {
			case errors.Is(err, ErrModelInvocationConflict):
				m.error(w, http.StatusConflict, "MODEL_IDEMPOTENCY_CONFLICT", "model idempotency key was reused with different input", op.Context.TraceID)
			case errors.Is(err, ErrModelInvocationReconciliationNeeded):
				m.error(w, http.StatusConflict, "MODEL_RECONCILIATION_REQUIRED", "provider outcome requires billing reconciliation", op.Context.TraceID)
			case errors.Is(err, ErrModelInvocationPending):
				m.error(w, http.StatusConflict, "MODEL_INVOCATION_IN_PROGRESS", "model invocation is still running", op.Context.TraceID)
			case errors.Is(err, ErrModelBudgetExceeded):
				m.error(w, http.StatusPaymentRequired, "MODEL_BUDGET_EXCEEDED", "model budget exceeded", op.Context.TraceID)
			default:
				logLedgerFailure("model_reserve", err)
				m.error(w, http.StatusBadGateway, "MODEL_LEDGER_UNAVAILABLE", "model invocation ledger unavailable", op.Context.TraceID)
			}
			return
		}
		if replay {
			if !governanceConfigured && m.recordUsage(r.Context(), op.Context, op.Policy.Model, replayed.Response, in.IdempotencyKey) != nil {
				m.error(w, http.StatusBadGateway, "USAGE_LEDGER_UNAVAILABLE", "usage ledger unavailable", op.Context.TraceID)
				return
			}
			m.currentModelResult(w, r, op, replayed.Response)
			return
		}
	}
	if governanceConfigured {
		_, budgetReconciliationSupported := m.modelBudgets.(usagecost.ModelBudgetReconciliationStore)
		_, invocationReconciliationSupported := m.modelStore.(ModelInvocationReconciliationStore)
		_, billingRecoverySupported := m.modelStore.(ModelBillingRecoveryStore)
		_, sendLifecycleSupported := m.modelStore.(ModelSendLifecycleStore)
		_, noChargeReleaseSupported := m.modelBudgets.(usagecost.ModelBudgetManualReleaseStore)
		if m.modelStore == nil || m.modelPrices == nil || m.modelBudgets == nil || !budgetReconciliationSupported || !invocationReconciliationSupported || !billingRecoverySupported || !sendLifecycleSupported || !noChargeReleaseSupported {
			m.failModelInvocation(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, op.Context.TraceID, modelAttemptToken)
			m.error(w, http.StatusServiceUnavailable, "MODEL_BILLING_UNAVAILABLE", "approved pricing, budget settlement and reconciliation stores are required", op.Context.TraceID)
			return
		}
		pricedAt := time.Now().UTC()
		var err error
		approvedPrice, err = m.modelPrices.ResolvePrice(r.Context(), selectedModel.ModelVersionID, pricedAt)
		if err != nil || !validRuntimeModelPrice(approvedPrice, selectedModel.ModelVersionID, pricedAt) {
			m.failModelInvocation(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, op.Context.TraceID, modelAttemptToken)
			m.error(w, http.StatusServiceUnavailable, "MODEL_PRICE_UNAVAILABLE", "no valid approved effective USD model price is available", op.Context.TraceID)
			return
		}
		requestID, idErr := newModelBudgetAttemptID()
		if idErr != nil {
			m.failModelInvocation(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, op.Context.TraceID, modelAttemptToken)
			m.error(w, http.StatusServiceUnavailable, "MODEL_BILLING_UNAVAILABLE", "model budget reservation could not be created", op.Context.TraceID)
			return
		}
		budgetRequest, reserveErr := buildModelBudgetRequest(op.Context, budgetMessages, in.MaxTokens, op.Policy.Model.BudgetCents, approvedPrice, fingerprint, requestID, pricedAt, op.Policy.Runtime.LeaseSeconds)
		if binding, required := m.modelBudgets.(usagecost.ModelBudgetExecutionBindingStore); reserveErr == nil && required && binding.RequiresExecutionBinding() {
			var budgetCtx context.Context
			budgetCtx, reserveErr = m.bindModelBudgetAdmission(r, op, budgetRequest, budgetMessages, in.MaxTokens)
			if reserveErr == nil {
				r = r.WithContext(budgetCtx)
			}
		}
		if reserveErr == nil {
			var reservation usagecost.ModelBudgetReservation
			reservation, reserveErr = reserveModelBudgetAdmission(r.Context(), m.modelBudgets, budgetRequest)
			if reserveErr == nil {
				budgetReservation = &reservation
			}
		}
		if reserveErr != nil {
			m.failModelInvocation(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, op.Context.TraceID, modelAttemptToken)
			switch {
			case errors.Is(reserveErr, usagecost.ErrBudgetExceeded):
				m.error(w, http.StatusPaymentRequired, "MODEL_BUDGET_EXCEEDED", "model budget exceeded", op.Context.TraceID)
			case budgetAdmissionDeferred(reserveErr):
				logLedgerFailure("model_budget_admission", reserveErr)
				m.error(w, http.StatusServiceUnavailable, "MODEL_BUDGET_ADMISSION_DEFERRED", "model budget admission is waiting for a live ancestor lock", op.Context.TraceID)
			default:
				logLedgerFailure("model_budget_admission", reserveErr)
				m.error(w, http.StatusBadGateway, "MODEL_BUDGET_UNAVAILABLE", "model budget ledger unavailable", op.Context.TraceID)
			}
			return
		}
	}
	var capacityLease *modelcapacity.Lease
	if governanceConfigured && selectedModel.TrustZone == modelgovernance.TrustLocal {
		if m.modelCapacity == nil || selectedModel.DeploymentID == "" || selectedModel.CapacityUnits <= 0 {
			recoveryOwned := false
			if budgetReservation != nil {
				recoveryOwned = m.releaseUnsentAdmission(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, *budgetReservation, op.Context.TraceID, modelAttemptToken)
			}
			if !recoveryOwned {
				m.failModelInvocation(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, op.Context.TraceID, modelAttemptToken)
			}
			m.error(w, http.StatusServiceUnavailable, "MODEL_CAPACITY_UNAVAILABLE", "a ready managed local model deployment and capacity provider are required", op.Context.TraceID)
			return
		}
		lease, capacityErr := m.modelCapacity.AcquireCapacity(r.Context(), modelcapacity.Request{
			Scope: modelScope, DeploymentID: selectedModel.DeploymentID, Units: 1,
			Owner: op.Context.ActorID, RequestID: in.IdempotencyKey, TTL: 2 * time.Minute,
		})
		if capacityErr != nil {
			recoveryOwned := false
			if budgetReservation != nil {
				recoveryOwned = m.releaseUnsentAdmission(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, *budgetReservation, op.Context.TraceID, modelAttemptToken)
			}
			if !recoveryOwned {
				m.failModelInvocation(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, op.Context.TraceID, modelAttemptToken)
			}
			if errors.Is(capacityErr, modelcapacity.ErrExceeded) {
				m.error(w, http.StatusTooManyRequests, "MODEL_CAPACITY_EXCEEDED", "managed local model deployment is at capacity", op.Context.TraceID)
			} else {
				log.Printf("model capacity admission unavailable trace=%q deployment_configured=true error_type=%T", op.Context.TraceID, capacityErr)
				m.error(w, http.StatusServiceUnavailable, "MODEL_CAPACITY_UNAVAILABLE", "managed local model capacity is unavailable", op.Context.TraceID)
			}
			return
		}
		capacityLease = &lease
	}
	user := in.Messages[len(in.Messages)-1].Content
	var text, resultModel string
	usage := map[string]int{}
	result := map[string]any{}
	var embeddingVectors [][]float32
	var incomplete bool
	if governanceConfigured {
		messages := in.Messages
		// Persist and retain before sending. RPC cancellation is not proof of no charge.
		// 请求发送前持久化且保留预算，RPC 取消不等于厂商未计费。
		modelSendDeadline := time.Now().UTC().Add(2 * time.Minute)
		if err := m.prepareModelSend(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, *budgetReservation, modelSendDeadline, modelAttemptToken); err != nil {
			m.error(w, http.StatusServiceUnavailable, "MODEL_SEND_PERSISTENCE_FAILED", "model request was not sent because recovery persistence failed", op.Context.TraceID)
			return
		}
		// Use the persisted attempt's absolute cutoff, not a fresh timeout after a pause.
		// 使用已持久化尝试的绝对截止时间，进程暂停后不能重新获得发送窗口。
		// Do not send after an already observed caller cancellation. Once sending
		// starts, retain this bounded attempt to collect its billable receipt;
		// caller cancellation still prevents disclosure and any subsequent call.
		if r.Context().Err() != nil {
			if err := m.abortUnsentModel(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, *budgetReservation, modelAttemptToken); err != nil {
				m.error(w, http.StatusBadGateway, "MODEL_RECONCILIATION_REQUIRED", "unsent request accounting requires recovery", op.Context.TraceID)
				return
			}
			m.error(w, http.StatusRequestTimeout, "MODEL_CALL_CANCELLED", "model request cancelled before sending", op.Context.TraceID)
			return
		}
		if err := m.checkCurrentCapability(r, op); err != nil {
			if abortErr := m.abortUnsentModel(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, *budgetReservation, modelAttemptToken); abortErr != nil {
				m.error(w, 502, "MODEL_RECONCILIATION_REQUIRED", "unsent request accounting requires recovery", op.Context.TraceID)
				return
			}
			if capacityLease != nil {
				_ = m.modelCapacity.ReleaseCapacity(r.Context(), *capacityLease)
			}
			m.error(w, 403, "CAPABILITY_DENIED", "current execution authorization denied before model send", op.Context.TraceID)
			return
		}
		providerCtx, stopProvider := context.WithDeadline(context.WithoutCancel(r.Context()), modelSendDeadline.Add(-time.Minute))
		if providerCtx.Err() != nil {
			stopProvider()
			m.error(w, http.StatusBadGateway, "MODEL_RECONCILIATION_REQUIRED", "model send window expired; provider was not invoked", op.Context.TraceID)
			return
		}
		var invocation modelgateway.GenerateResult
		var invokeErr error
		if embeddingCall {
			var embedded modelgateway.EmbeddingResult
			embeddingContext, purposeErr := modelgateway.WithEmbeddingPurpose(providerCtx, in.EmbeddingPurpose)
			if purposeErr != nil {
				invokeErr = purposeErr
			} else {
				embedded, invokeErr = m.modelGateway.(modelgateway.UsageEmbeddingPort).EmbedWithUsage(embeddingContext, modelScope, op.Policy, in.Texts)
			}
			embeddingVectors = embedded.Vectors
			invocation.InputTokens = embedded.InputTokens
		} else {
			invocation, invokeErr = m.modelGateway.Generate(providerCtx, modelScope, op.Policy, modelgateway.GenerateRequest{Prompt: user, Model: selectedModel.ModelKey, ModelVersionID: selectedModel.ModelVersionID, ProviderID: selectedModel.ProviderID, ModelID: selectedModel.ModelID, Messages: messages, Temperature: in.Temperature, MaxTokens: in.MaxTokens, FunctionNames: in.FunctionNames})
		}
		stopProvider()
		if capacityLease != nil && (invokeErr == nil || definitelyNoModelCharge(invokeErr)) {
			if releaseErr := m.modelCapacity.ReleaseCapacity(r.Context(), *capacityLease); releaseErr != nil {
				// A failed release remains bounded by the SQL lease TTL; do not discard
				// a known billable result or hide it behind a capacity cleanup error.
				log.Printf("model capacity lease release deferred to expiry trace=%q error_type=%T", op.Context.TraceID, releaseErr)
			}
		} else if capacityLease != nil {
			// The provider outcome is uncertain. Keep capacity reserved until lease
			// expiry so a timed-out remote call cannot be immediately oversold.
			log.Printf("model capacity lease retained for uncertain outcome trace=%q", op.Context.TraceID)
		}
		if invokeErr != nil {
			log.Printf("model provider failure run_id=%q embedding=%t error_kind=%s", modelScope.RunID, embeddingCall, modelProviderErrorKind(invokeErr))
			if definitelyNoModelCharge(invokeErr) {
				if err := m.abortUnsentModel(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, *budgetReservation, modelAttemptToken); err != nil {
					m.error(w, http.StatusBadGateway, "MODEL_RECONCILIATION_REQUIRED", "unsent request accounting could not be finalized", op.Context.TraceID)
					return
				}
				m.error(w, http.StatusBadGateway, "MODEL_PROVIDER_FAILED", "governed model invocation failed", op.Context.TraceID)
			} else {
				m.markModelReconciliation(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, *budgetReservation, nil, 0, op.Context.TraceID, modelAttemptToken)
				m.error(w, http.StatusBadGateway, "MODEL_RECONCILIATION_REQUIRED", "provider outcome is uncertain and requires billing reconciliation", op.Context.TraceID)
			}
			return
		}
		if !embeddingCall && strings.TrimSpace(invocation.Text) == "" && len(invocation.ToolCalls) == 0 && !invocation.Incomplete || embeddingCall && !validEmbeddingVectors(embeddingVectors, len(in.Texts)) || invocation.InputTokens < 0 || invocation.OutputTokens < 0 {
			m.markModelReconciliation(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, *budgetReservation, nil, 0, op.Context.TraceID, modelAttemptToken)
			m.error(w, http.StatusBadGateway, "MODEL_RECONCILIATION_REQUIRED", "provider returned an invalid billable result", op.Context.TraceID)
			return
		}
		text, resultModel = invocation.Text, selectedModel.ModelKey
		incomplete = !embeddingCall && invocation.Incomplete
		usage = map[string]int{"input_tokens": invocation.InputTokens, "output_tokens": invocation.OutputTokens}
		result = map[string]any{"provider_id": selectedModel.ProviderID, "model_id": selectedModel.ModelID, "model_version_id": selectedModel.ModelVersionID}
		if len(invocation.ToolCalls) > 0 {
			result["tool_calls"], result["completion_status"] = invocation.ToolCalls, "tool_calls"
			bindings := map[string]string{}
			for _, call := range invocation.ToolCalls {
				tool, err := op.Policy.Tool.ValidateFunctionArguments(call.Function.Name, json.RawMessage(call.Function.Arguments))
				if err != nil {
					continue
				}
				bindings[call.Function.Name] = tool
			}
			result["function_bindings"] = bindings
		}
		if invocation.FinishReason != "" {
			result["finish_reason"] = invocation.FinishReason
		}
	} else {
		text = `{"diagnosis":"三段证据已核对，建议复核源端与报表端快照","suggestion":"补齐快照并转人工复核"}`
		if marker := "<untrusted_evidence_json>"; strings.Contains(user, marker) {
			raw := strings.SplitN(strings.SplitN(user, marker, 2)[1], "</untrusted_evidence_json>", 2)[0]
			var items []struct {
				Content string `json:"content"`
			}
			if json.Unmarshal([]byte(raw), &items) == nil && len(items) > 0 && strings.TrimSpace(items[0].Content) != "" {
				text = items[0].Content
			}
		}
		resultModel = op.Policy.Model.Model
		if resultModel == "" {
			resultModel = "platform-local-deterministic-v1"
		}
		usage = map[string]int{"input_tokens": len(user)/4 + 1, "output_tokens": len(text)/4 + 1}
	}
	result["text"], result["model"], result["usage"] = text, resultModel, usage
	if incomplete {
		result["completion_status"] = "incomplete"
		if _, exists := result["finish_reason"]; !exists {
			result["finish_reason"] = "length"
		}
	}
	if embeddingCall {
		delete(result, "text")
		result["vectors"] = embeddingVectors
	}
	if governanceConfigured {
		attachModelUsageStepID(result, governedModelUsageScope(op.Context), in.IdempotencyKey)
	}
	usage = result["usage"].(map[string]int)
	costCents := int64(usage["input_tokens"]+usage["output_tokens"]+99) / 100
	if !governanceConfigured && op.Policy.Model.BudgetCents > 0 && costCents > op.Policy.Model.BudgetCents {
		m.error(w, http.StatusPaymentRequired, "MODEL_BUDGET_EXCEEDED", "model budget exceeded", op.Context.TraceID)
		return
	}
	if governanceConfigured {
		actualCostMicros, costErr := approvedModelCost(approvedPrice, int64(usage["input_tokens"]), int64(usage["output_tokens"]))
		if costErr != nil {
			m.markModelReconciliation(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, *budgetReservation, result, 0, op.Context.TraceID, modelAttemptToken)
			m.error(w, http.StatusBadGateway, "MODEL_RECONCILIATION_REQUIRED", "provider result is known but its approved cost could not be calculated", op.Context.TraceID)
			return
		}
		result["billing"] = map[string]any{"price_version_id": approvedPrice.ID, "currency": approvedPrice.Currency, "cost_micros": actualCostMicros}
		costCents = ceilModelCostCents(actualCostMicros)
		event, eventErr := buildModelUsageEvent(op.Context, selectedModel, usage["input_tokens"], usage["output_tokens"], actualCostMicros, in.IdempotencyKey)
		if eventErr != nil {
			m.markModelReconciliation(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, *budgetReservation, result, costCents, op.Context.TraceID, modelAttemptToken)
			m.error(w, http.StatusBadGateway, "MODEL_RECONCILIATION_REQUIRED", "provider result is known but usage scope could not be recorded", op.Context.TraceID)
			return
		}
		if event.StepID != nil {
			result["step_id"] = *event.StepID
		}
		if err := m.markModelReconciliation(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, *budgetReservation, result, costCents, op.Context.TraceID, modelAttemptToken, event); err != nil {
			m.error(w, http.StatusBadGateway, "MODEL_RECONCILIATION_REQUIRED", "provider result requires durable billing recovery", op.Context.TraceID)
			return
		}
		_, settleErr := m.modelBudgets.Settle(r.Context(), *budgetReservation, event, approvedPrice.ID)
		if settleErr != nil {
			log.Printf("model result requires billing reconciliation trace=%q error_type=%T", op.Context.TraceID, settleErr)
			m.error(w, http.StatusBadGateway, "MODEL_RECONCILIATION_REQUIRED", "provider result is known but usage settlement failed", op.Context.TraceID)
			return
		}
	}
	if !governanceConfigured {
		attachModelUsageStepID(result, legacyModelUsageScope(op.Context), in.IdempotencyKey)
	}
	if m.modelStore != nil {
		if err := m.modelStore.Complete(r.Context(), scopeHash, in.IdempotencyKey, fingerprint, result, costCents); err != nil {
			if governanceConfigured {
				log.Printf("settled model result requires invocation reconciliation trace=%q error_type=%T", op.Context.TraceID, err)
				m.error(w, http.StatusBadGateway, "MODEL_RECONCILIATION_REQUIRED", "usage was settled but invocation replay record requires reconciliation", op.Context.TraceID)
				return
			}
			m.error(w, http.StatusBadGateway, "MODEL_LEDGER_UNAVAILABLE", "model invocation ledger unavailable", op.Context.TraceID)
			return
		}
	}
	if !governanceConfigured && m.recordUsage(r.Context(), op.Context, op.Policy.Model, result, in.IdempotencyKey) != nil {
		m.error(w, http.StatusBadGateway, "USAGE_LEDGER_UNAVAILABLE", "usage ledger unavailable", op.Context.TraceID)
		return
	}
	m.currentModelResult(w, r, op, result)
}

func (m *Module) recordUsage(ctx context.Context, h harnessContext, pricing policyasset.ModelPolicy, result map[string]any, idempotencyKey string) error {
	if m.usageRecorder == nil {
		return nil
	}
	usage, ok := result["usage"].(map[string]int)
	if !ok {
		if raw, exists := result["usage"].(map[string]any); exists {
			usage = make(map[string]int, len(raw))
			for key, value := range raw {
				switch item := value.(type) {
				case int:
					usage[key] = item
				case float64:
					usage[key] = int(item)
				default:
					return errors.New("invalid model usage response")
				}
			}
			ok = true
		}
	}
	if !ok {
		return errors.New("model usage is missing")
	}
	// The deterministic local provider and the governed provider share the
	// same signed parent-Run billing attribution for Evaluation cases.
	// 确定性本地模型与受治理模型均按签名父评测 Run 归集用量。
	usageScope := legacyModelUsageScope(h)
	if usageScope.RunID == "" || usageScope.TenantID == "" || usageScope.DepartmentID == "" || usageScope.ApplicationID == "" || usageScope.AgentID == "" || usageScope.AgentVersionID == "" {
		return errors.New("model usage scope is incomplete")
	}
	provider := pricing.Provider
	if provider == "" {
		provider = "local"
	}
	inputTokens, inputOK := usage["input_tokens"]
	outputTokens, outputOK := usage["output_tokens"]
	if !inputOK || !outputOK || inputTokens < 0 || outputTokens < 0 {
		return errors.New("model usage token counts are invalid")
	}
	stepID, err := modelUsageStepIDFromResult(result, usageScope, idempotencyKey)
	if err != nil {
		return err
	}
	keyBytes := sha256.Sum256([]byte(h.TenantID + "|" + h.ApplicationID + "|" + usageScope.RunID + "|" + idempotencyKey))
	costMicros, err := pricedModelCost(pricing, int64(inputTokens), int64(outputTokens))
	if err != nil {
		return err
	}
	event := usagecost.Event{ID: "model-" + fmt.Sprintf("%x", keyBytes[:]), StepID: stepID, Scope: usageScope, Provider: provider, Model: "", InputTokens: int64(inputTokens), OutputTokens: int64(outputTokens), CostMicros: costMicros}
	if model, ok := result["model"].(string); ok {
		event.Model = model
	}
	if event.Model == "" {
		event.Model = "platform-local-deterministic-v1"
	}
	_, err = m.usageRecorder.Apply(ctx, event)
	if err != nil {
		logLedgerFailure("usage_record", err)
	}
	return err
}

func sameModelSelection(policyProvider, policyModel string, selected modelgateway.Selection) bool {
	providerMatches := policyProvider == selected.ProviderKey || policyProvider == strings.ToLower(selected.ProviderKey) || policyProvider == selected.ProviderID
	modelMatches := policyModel == selected.ModelKey || policyModel == selected.ModelID
	return providerMatches && modelMatches
}

func (m *Module) failModelInvocation(ctx context.Context, scopeHash, key, fingerprint, traceID, attemptToken string) {
	if attemptToken != "" {
		store, ok := m.modelStore.(ModelPreparationStore)
		if !ok {
			return
		}
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := store.FailPreparation(writeCtx, scopeHash, key, fingerprint, attemptToken); err != nil {
			log.Printf("model preparation terminal state unavailable trace=%q error_type=%T", traceID, err)
		}
		return
	}
	store, ok := m.modelStore.(ModelInvocationFailureStore)
	if !ok {
		return
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := store.Fail(writeCtx, scopeHash, key, fingerprint); err != nil {
		log.Printf("model invocation terminal state unavailable trace=%q error_type=%T", traceID, err)
	}
}

// pricedModelCost uses the immutable ModelPolicy snapshot rather than a
// hard-coded token price. The zero-price local provider remains supported for
// offline deterministic development; external providers must publish both
// rates so budget and reconciliation cannot silently undercharge.
// 价格由不可变模型策略快照计算，禁止硬编码；本地确定性 Provider 可为零价，
// 外部 Provider 必须声明双向费率，避免预算与对账静默少计费。
func pricedModelCost(policy policyasset.ModelPolicy, inputTokens, outputTokens int64) (int64, error) {
	if inputTokens < 0 || outputTokens < 0 || policy.InputMicrosPer1KTokens < 0 || policy.OutputMicrosPer1KTokens < 0 {
		return 0, errors.New("model pricing is invalid")
	}
	if policy.AllowExternal && (policy.InputMicrosPer1KTokens == 0 || policy.OutputMicrosPer1KTokens == 0) {
		return 0, errors.New("external model pricing is required")
	}
	inputCost := (inputTokens*policy.InputMicrosPer1KTokens + 999) / 1000
	outputCost := (outputTokens*policy.OutputMicrosPer1KTokens + 999) / 1000
	if inputCost > int64(^uint64(0)>>1)-outputCost {
		return 0, errors.New("model pricing overflows")
	}
	return inputCost + outputCost, nil
}

func capabilityScopeHash(c harnessContext) string {
	raw, _ := json.Marshal([]string{c.TenantID, c.DepartmentID, c.ApplicationID, c.AgentID, c.AgentInstanceID, c.PrincipalType, c.ActorID, c.InstallationID, c.AgentVersionID, c.SessionID})
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func estimateModelCost(messages []struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}) int64 {
	if len(messages) == 0 {
		return 1
	}
	content := messages[len(messages)-1].Content
	// The deterministic provider and external adapters use token usage in the
	// same ledger. Reserve a conservative one-cent minimum before execution.
	// 估算值用于原子预算预占，宁可保守拒绝，也不能执行后才发现超预算。
	inputTokens := len(content)/4 + 1
	outputTokens := 32
	return int64((inputTokens + outputTokens + 99) / 100)
}

func (m *Module) resolvePrompt(w http.ResponseWriter, r *http.Request) {
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(op.Policy.Prompt.Template) == "" {
		m.error(w, http.StatusNotFound, "PROMPT_NOT_FOUND", "published prompt template is unavailable", op.Context.TraceID)
		return
	}
	m.currentResult(w, r, op, map[string]any{"prompt_version_id": op.Context.PromptVersionID, "template_hash": op.Policy.Prompt.TemplateHash, "template": op.Policy.Prompt.Template})
}

func (m *Module) embed(w http.ResponseWriter, r *http.Request) {
	if m.modelAccess != nil || m.modelGateway != nil {
		m.generate(w, r)
		return
	}
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	var in struct {
		Texts []string `json:"texts"`
	}
	if json.Unmarshal(op.Input, &in) != nil || len(in.Texts) == 0 {
		m.error(w, 400, "INVALID_REQUEST", "texts are required", op.Context.TraceID)
		return
	}
	vectors := make([][]float32, len(in.Texts))
	for i, text := range in.Texts {
		v := make([]float32, 8)
		for j := range v {
			v[j] = float32((runeSum(text)+j)%101) / 100
		}
		vectors[i] = v
	}
	m.currentResult(w, r, op, map[string]any{"vectors": vectors, "model": "platform-local-embedding-v1"})
}
func runeSum(s string) int {
	n := 0
	for _, r := range s {
		n += int(r)
	}
	return n
}

func (m *Module) search(w http.ResponseWriter, r *http.Request) {
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	var in struct {
		Query         string                       `json:"query"`
		Scope         string                       `json:"knowledge_scope"`
		TopK          int                          `json:"top_k"`
		AsOf          string                       `json:"as_of"`
		CacheMode     string                       `json:"cache_mode"`
		SourceIDs     []string                     `json:"source_ids,omitempty"`
		SkillBindings map[string]SkillModelBinding `json:"skill_bindings"`
		SkillRequests []knowledgeSkillSelection    `json:"skill_requests"`
	}
	if json.Unmarshal(op.Input, &in) != nil || strings.TrimSpace(in.Query) == "" {
		m.error(w, 400, "INVALID_REQUEST", "query is required", op.Context.TraceID)
		return
	}
	if in.CacheMode != "" && in.CacheMode != "use" && in.CacheMode != "cold" && in.CacheMode != "bypass" {
		m.error(w, 400, "INVALID_CACHE_MODE", "cache_mode must be use, cold or bypass", op.Context.TraceID)
		return
	}
	if !op.Policy.AllowsKnowledgeScope(in.Scope) {
		m.error(w, http.StatusForbidden, "KNOWLEDGE_SCOPE_DENIED", "knowledge scope is not allowed by the published policy", op.Context.TraceID)
		return
	}
	if in.TopK < 0 || in.TopK > 100 {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "top_k must be between 0 and 100", op.Context.TraceID)
		return
	}
	if in.TopK == 0 {
		in.TopK = 5
	}
	plan, err := m.knowledgeDocumentPlan(r, op, in.Scope)
	if err != nil || !plan.Legacy && len(plan.Documents) == 0 {
		m.error(w, http.StatusForbidden, "KNOWLEDGE_DOCUMENTS_DENIED", "no authorized knowledge documents", op.Context.TraceID)
		return
	}
	plan, err = selectKnowledgeSources(plan, in.SourceIDs)
	if err != nil {
		m.error(w, http.StatusForbidden, "KNOWLEDGE_SOURCES_DENIED", "selected sources are not currently authorized", op.Context.TraceID)
		return
	}
	answer := r.URL.Path == "/internal/knowledge/answer" || r.URL.Path == "/internal/knowledge/answer/recovery"
	if answer && (plan.Legacy || m.knowledge == nil) {
		m.error(w, http.StatusServiceUnavailable, "KNOWLEDGE_ANSWER_UNAVAILABLE", "governed knowledge answer dependencies are required", op.Context.TraceID)
		return
	}
	var skillContext string
	if len(in.SkillBindings) > 0 || len(in.SkillRequests) > 0 {
		if !answer || !validSkillModelBindings(in.SkillBindings) {
			m.error(w, 400, "INVALID_REQUEST", "valid skill dependencies require knowledge answer", op.Context.TraceID)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), skillModelBindingsKey{}, in.SkillBindings))
		if !m.currentCapability(w, r, op) {
			return
		}
		skillContext, err = m.knowledgeSkillContext(r, op, in.SkillBindings, in.SkillRequests)
		if err != nil {
			m.error(w, 403, "SKILL_DENIED", "knowledge skill dependencies unavailable", op.Context.TraceID)
			return
		}
	}
	if m.knowledge != nil {
		searchCtx, stopSearch := context.WithCancel(r.Context())
		defer stopSearch()
		result, err := m.knowledge.Search(searchCtx, op.Context, knowledgeQuery{Query: strings.TrimSpace(in.Query), Answer: answer, SkillContext: skillContext, Scope: in.Scope, TopK: in.TopK, AsOf: in.AsOf, CacheMode: in.CacheMode, Documents: plan.Documents, GovernedDocuments: !plan.Legacy, Policy: op.Policy, ModelCall: m.knowledgeModelCall(r, op, searchCtx), ModelCheck: m.knowledgeModelCheck(r, op, searchCtx)})
		if err != nil {
			if errors.Is(err, errKnowledgeDocumentAuthority) {
				m.error(w, http.StatusForbidden, "KNOWLEDGE_DOCUMENTS_DENIED", "knowledge source authorization failed", op.Context.TraceID)
				return
			}
			var modelError *KnowledgeModelError
			if errors.As(err, &modelError) {
				m.error(w, modelError.Status, modelError.Code, "governed knowledge model stage failed", op.Context.TraceID)
				return
			}
			log.Printf("knowledge provider unavailable trace=%q provider=governed-rag error_type=%T", op.Context.TraceID, err)
			m.error(w, http.StatusBadGateway, "KNOWLEDGE_PROVIDER_UNAVAILABLE", "knowledge provider unavailable", op.Context.TraceID)
			return
		}
		if answer {
			m.knowledgeAnswerResult(w, r, op, in.Scope, in.TopK, result)
		} else {
			m.knowledgeResult(w, r, op, in.Scope, in.TopK, result)
		}
		return
	}
	refs := []map[string]any{{"doc_id": "platform-guide", "clause_or_chunk_id": "capability-boundary", "title": "平台公共能力说明", "content": "业务 Agent 通过 SDK 调用平台公共能力，平台统一验证身份、权限与执行上下文。", "effective_date": "2026-01-01", "status": "effective", "kb_version": "guide-v1", "source": "platform_knowledge"}}
	if in.TopK > 0 && in.TopK < len(refs) {
		refs = refs[:in.TopK]
	}
	for _, ref := range refs {
		ref["provider_knowledge_base_id"] = "builtin"
		ref["provider_document_id"] = ref["doc_id"]
	}
	m.knowledgeResult(w, r, op, in.Scope, in.TopK, map[string]any{"references": refs, "retrieved_sources": []string{"platform_knowledge"}, "failed_sources": []string{}, "partial_degraded": false, "request_id": op.Context.RequestID})
}
func (m *Module) replay(w http.ResponseWriter, r *http.Request) {
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	m.currentResult(w, r, op, map[string]any{"references": []any{}, "retrieved_sources": []string{}, "failed_sources": []string{}, "partial_degraded": false, "request_id": op.Context.RequestID})
}

// memory exposes the platform-owned working/session memory contract.  The key
// is always scoped by the full execution identity, so two users or two Agent
// instances can never observe each other's values.  The in-process map is a
// deterministic single-instance implementation; the interface is deliberately
// request-shaped so it can be moved to Redis/SQL without changing Agents.
// memory 提供平台所有的工作/会话记忆契约。键由完整运行身份组成，确保不同用户
// 或不同 Agent 实例无法互相读取；当前使用进程内 Map 实现单实例语义，接口保持
// 请求边界不变，后续可无感迁移到 Redis/SQL。
func (m *Module) memory(w http.ResponseWriter, r *http.Request) {
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	var in struct {
		Operation string         `json:"operation"`
		Namespace string         `json:"namespace"`
		Key       string         `json:"key"`
		Value     map[string]any `json:"value"`
	}
	if err := json.Unmarshal(op.Input, &in); err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid memory request", op.Context.TraceID)
		return
	}
	in.Operation = strings.ToLower(strings.TrimSpace(in.Operation))
	in.Namespace = strings.TrimSpace(in.Namespace)
	in.Key = strings.TrimSpace(in.Key)
	if (in.Operation != "load" && in.Operation != "save") || in.Namespace == "" || in.Key == "" {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "memory operation, namespace and key are required", op.Context.TraceID)
		return
	}
	base := strings.Join([]string{
		op.Context.TenantID,
		op.Context.DepartmentID,
		op.Context.ApplicationID,
		op.Context.AgentID,
		op.Context.AgentInstanceID,
		op.Context.ActorID,
		op.Context.SessionID,
		in.Namespace,
	}, "\x00")
	scopeKey := base + "\x00" + in.Key
	if m.memoryStore == nil {
		m.error(w, http.StatusServiceUnavailable, "MEMORY_UNAVAILABLE", "memory store is unavailable", op.Context.TraceID)
		return
	}
	if in.Operation == "load" {
		entry, exists, err := m.memoryStore.Load(r.Context(), scopeKey)
		if err != nil {
			m.error(w, http.StatusBadGateway, "MEMORY_STORE_UNAVAILABLE", "memory store unavailable", op.Context.TraceID)
			return
		}
		if !exists {
			m.currentResult(w, r, op, map[string]any{"value": nil})
			return
		}
		m.currentResult(w, r, op, map[string]any{"value": cloneMemoryValue(entry.Value), "expires_in_seconds": int(time.Until(entry.ExpiresAt).Seconds())})
		return
	}
	if in.Value == nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "memory value is required", op.Context.TraceID)
		return
	}
	ttl := op.Policy.Memory.WorkingTTLSeconds
	if ttl <= 0 {
		ttl = op.Policy.Memory.TaskTTLSeconds
	}
	if ttl <= 0 {
		m.error(w, http.StatusForbidden, "MEMORY_POLICY_DENIED", "memory policy does not allow a positive TTL", op.Context.TraceID)
		return
	}
	if !m.currentCapability(w, r, op) {
		return
	}
	entry := memoryEntry{Value: cloneMemoryValue(in.Value), ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second)}
	if m.publicKey != nil {
		// The gateway already verified this command. Carry its exact signed
		// generation into the local effect transaction, not merely the
		// temporary context used by the preceding permission check.
		ctx, err := m.skillExecutionContext(r, op)
		if err != nil {
			m.error(w, http.StatusForbidden, "MEMORY_EXECUTION_SCOPE_DENIED", "trusted memory execution binding required", op.Context.TraceID)
			return
		}
		bound, ok := ctx.Value(skillRuntimeContextKey{}).(skillRuntimeContext)
		if !ok {
			m.error(w, http.StatusForbidden, "MEMORY_EXECUTION_SCOPE_DENIED", "trusted memory execution binding required", op.Context.TraceID)
			return
		}
		r = r.WithContext(context.WithValue(ctx, runtimeBudgetContextKey{}, bound))
	}
	mutationBytes, _ := json.Marshal([]any{in.Namespace, in.Key, in.Value})
	mutationHash := sha256.Sum256(mutationBytes)
	mutationContext := context.WithValue(r.Context(), memoryMutationKey{}, memoryMutation{Scope: scopeFromHarness(op.Context), CallID: op.Context.RequestID, Fingerprint: hex.EncodeToString(mutationHash[:])})
	var saveErr error
	if m.publicKey != nil {
		store, ok := m.memoryStore.(AuthorizedMemoryStore)
		if !ok {
			saveErr = errMemoryContinuityUnavailable
		} else {
			saveErr = store.SaveAuthorized(mutationContext, scopeKey, entry, op.Policy.Memory.MaxEntries, func(ctx context.Context) error {
				return m.checkCurrentCapability(r.WithContext(ctx), op)
			})
		}
	} else {
		saveErr = m.memoryStore.Save(mutationContext, scopeKey, entry, op.Policy.Memory.MaxEntries)
	}
	if err := saveErr; err != nil {
		if errors.Is(err, errMemoryWriteDenied) {
			m.error(w, http.StatusForbidden, "CAPABILITY_DENIED", "current execution authorization denied", op.Context.TraceID)
			return
		}
		if errors.Is(err, errMemoryContinuityUnavailable) {
			m.error(w, http.StatusServiceUnavailable, "MEMORY_CONTINUITY_UNAVAILABLE", "memory write continuity unavailable", op.Context.TraceID)
			return
		}
		if errors.Is(err, errMemoryLimitExceeded) {
			m.error(w, http.StatusConflict, "MEMORY_LIMIT_EXCEEDED", err.Error(), op.Context.TraceID)
			return
		}
		m.error(w, http.StatusBadGateway, "MEMORY_STORE_UNAVAILABLE", "memory store unavailable", op.Context.TraceID)
		return
	}
	m.currentResult(w, r, op, map[string]any{"saved": true, "expires_in_seconds": ttl})
}

func memoryScopePrefix(key string) string {
	index := strings.LastIndex(key, "\x00")
	if index < 0 {
		return key
	}
	return key[:index+1]
}

func cloneMemoryValue(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var clone map[string]any
	if json.Unmarshal(raw, &clone) != nil {
		return nil
	}
	return clone
}

func (m *Module) tool(w http.ResponseWriter, r *http.Request) {
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	var in struct {
		Name              string         `json:"name"`
		CallID            string         `json:"call_id"`
		Payload           map[string]any `json:"payload"`
		ConfirmationToken string         `json:"confirmation_token"`
	}
	decoder := json.NewDecoder(bytes.NewReader(op.Input))
	decoder.UseNumber()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF || in.Name == "" || len(in.Name) > 128 || len(in.CallID) > 128 || len(in.ConfirmationToken) > 8192 {
		m.error(w, 400, "INVALID_REQUEST", "tool name is required", op.Context.TraceID)
		return
	}
	if !op.Policy.AllowsTool(in.Name) {
		m.error(w, http.StatusForbidden, "CAPABILITY_DENIED", "tool is not allowed by the published policy", op.Context.TraceID)
		return
	}
	explicitCallID := in.CallID != ""
	if in.CallID == "" {
		in.CallID = op.Context.IdempotencyKey
	}
	if in.CallID == "" {
		in.CallID = op.Context.RequestID + ":tool:" + in.Name
	}
	descriptor, registered := m.RuntimeToolDescriptor(in.Name)
	if !registered {
		m.error(w, 403, "RUNTIME_REGISTRATION_DENIED", "registered runtime descriptor required", op.Context.TraceID)
		return
	}
	if descriptor.Risk != "read_only" && !explicitCallID {
		m.error(w, 400, "RUNTIME_IDEMPOTENCY_REQUIRED", "explicit call_id required for writable operations", op.Context.TraceID)
		return
	}
	// Validate availability and input before creating any invocation record.
	// 在写账本前校验依赖和输入；拒绝请求不遗留 running 记录。
	switch in.Name {
	case sendNotificationToolName:
		if _, _, _, err := notificationToolFields(in.Payload); err != nil {
			m.error(w, 400, "INVALID_NOTIFICATION", "invalid notification fields", op.Context.TraceID)
			return
		}
		if m.notifications == nil {
			m.error(w, 503, "NOTIFICATION_UNAVAILABLE", "notification outbox is unavailable", op.Context.TraceID)
			return
		}
	case notifySelfToolName:
		if _, _, err := selfNotificationFields(scopeFromHarness(op.Context), in.Payload); err != nil {
			if op.Context.PrincipalType != "user" {
				m.error(w, http.StatusForbidden, "NOTIFICATION_RECIPIENT_DENIED", "notify.self requires a human principal", op.Context.TraceID)
			} else {
				m.error(w, 400, "INVALID_NOTIFICATION", "notify.self accepts only title and text within their size limits", op.Context.TraceID)
			}
			return
		}
		if m.notifications == nil {
			m.error(w, 503, "NOTIFICATION_UNAVAILABLE", "notification outbox is unavailable", op.Context.TraceID)
			return
		}
	default:
		if m.tools == nil || !m.tools.Supports(in.Name) {
			m.error(w, 403, "CAPABILITY_DENIED", "tool is not implemented by platform", op.Context.TraceID)
			return
		}
	}
	fingerprint, fingerprintErr := ToolCommandFingerprint(in.Name, in.Payload)
	if fingerprintErr != nil {
		m.error(w, 400, "INVALID_REQUEST", "tool input cannot be encoded", op.Context.TraceID)
		return
	}
	if !isNotificationTool(in.Name) {
		if preflight, supported := m.tools.(runtimeToolPreflight); supported {
			if preflight.ValidateToolCommand(ToolCommand{Scope: scopeFromHarness(op.Context), Name: in.Name, CallID: in.CallID, Payload: in.Payload}) != nil {
				m.error(w, 400, "RUNTIME_INPUT_DENIED", "registered runtime input rejected", op.Context.TraceID)
				return
			}
		}
	}
	scopeHash := toolScopeHash(op.Context)
	if m.runtimeConfirmationRequired(op.Policy.Tool.RequireConfirmation, in.Name) {
		if m.checkToolConfirmation(r.Context(), in.ConfirmationToken, scopeFromHarness(op.Context), op.Policy.Hash, in.Name, in.CallID, fingerprint) != nil {
			m.error(w, http.StatusForbidden, "TOOL_CONFIRMATION_REQUIRED", "valid operation-bound confirmation is required", op.Context.TraceID)
			return
		}
		body, _ := base64.RawURLEncoding.Strict().DecodeString(strings.Split(in.ConfirmationToken, ".")[0])
		var claims ToolConfirmationClaims
		if json.Unmarshal(body, &claims) != nil {
			m.error(w, 403, "TOOL_CONFIRMATION_REQUIRED", "valid operation-bound confirmation is required", op.Context.TraceID)
			return
		}
		op.ToolApproval = &claims
	}
	if op.ToolApproval != nil {
		r = r.WithContext(context.WithValue(r.Context(), runtimeExecutionAuthorizationKey{}, runtimeExecutionAuthorization{PolicyHash: op.Policy.Hash, Approval: *op.ToolApproval}))
	}
	leaseStore, supported := m.toolStore.(ToolExecutionLeaseStore)
	if !supported {
		m.error(w, 503, "TOOL_LEASE_UNAVAILABLE", "tool execution lease store unavailable", op.Context.TraceID)
		return
	}
	renewalStore, supported := m.toolStore.(ToolLeaseRenewalStore)
	if !supported {
		m.error(w, 503, "TOOL_LEASE_UNAVAILABLE", "tool renewal store unavailable", op.Context.TraceID)
		return
	}
	var toolLease ToolExecutionLease
	receiptQuery := ToolReceiptQuery{Scope: scopeFromHarness(op.Context), CallID: in.CallID, Name: in.Name, Fingerprint: fingerprint}
	receiptQuery.RuntimeAudit = &ToolRuntimeAuditBinding{Descriptor: descriptor, PolicyHash: op.Policy.Hash}
	if op.ToolApproval != nil {
		digest := sha256.Sum256([]byte(op.ToolApproval.ApprovalID))
		receiptQuery.RuntimeAudit.ApprovalDigest = fmt.Sprintf("%x", digest)
	}
	r = r.WithContext(context.WithValue(r.Context(), toolReceiptContextKey{}, receiptQuery))
	if guarded, ok := m.toolStore.(runtimeBudgetAdmissionStore); ok && guarded.RequiresExecutionAdmission() {
		ctx, err := m.skillExecutionContext(r, op)
		if err != nil {
			m.error(w, 403, "RUNTIME_BUDGET_SCOPE_DENIED", "trusted runtime budget binding required", op.Context.TraceID)
			return
		}
		bound, ok := ctx.Value(skillRuntimeContextKey{}).(skillRuntimeContext)
		if !ok {
			m.error(w, 403, "RUNTIME_BUDGET_SCOPE_DENIED", "trusted runtime budget binding required", op.Context.TraceID)
			return
		}
		r = r.WithContext(context.WithValue(ctx, runtimeBudgetContextKey{}, bound))
	}
	toolTimeout := time.Duration(descriptor.TimeoutSeconds) * time.Second
	if seconds := op.Policy.Runtime.TaskTimeoutSeconds; seconds > 0 && time.Duration(seconds)*time.Second < toolTimeout {
		toolTimeout = time.Duration(seconds) * time.Second
	}
	toolLeaseTTL := 30 * time.Second
	if seconds := op.Policy.Runtime.LeaseSeconds; seconds > 0 && seconds <= 600 {
		toolLeaseTTL = time.Duration(seconds) * time.Second
	}
	if op.Policy.Runtime.TaskTimeoutSeconds >= 570 || op.Policy.Runtime.LeaseSeconds > 600 {
		m.error(w, 403, "RUNTIME_POLICY_INVALID", "tool runtime policy exceeds supported bounds", op.Context.TraceID)
		return
	}
	{
		replayed, replay, err := leaseStore.AcquireTool(r.Context(), scopeHash, in.CallID, fingerprint, "capability-http", toolLeaseTTL)
		if err != nil {
			if errors.Is(err, ErrToolResultUnknown) || errors.Is(err, ErrToolInvocationPending) {
				recoverCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
				result, found, recoverErr := m.restoreBusinessTool(recoverCtx, ToolReceiptQuery{Scope: scopeFromHarness(op.Context), CallID: in.CallID, Name: in.Name, Fingerprint: fingerprint})
				cancel()
				if recoverErr != nil {
					m.error(w, 503, "TOOL_RECEIPT_UNAVAILABLE", "tool commit receipt could not be verified", op.Context.TraceID)
					return
				}
				if found {
					m.toolObservedResult(w, r, op, in.Name, in.CallID, result)
					return
				}
			}
			switch {
			case errors.Is(err, ErrToolResultUnknown):
				m.toolObservedFailure(w, r, op, in.Name, in.CallID, nil, http.StatusConflict, "TOOL_RESULT_UNKNOWN", err)
			case errors.Is(err, ErrToolInvocationConflict):
				m.error(w, http.StatusConflict, "TOOL_IDEMPOTENCY_CONFLICT", "tool call ID was reused with different input", op.Context.TraceID)
			case errors.Is(err, ErrToolInvocationPending):
				m.error(w, http.StatusConflict, "TOOL_INVOCATION_IN_PROGRESS", "tool invocation is still running", op.Context.TraceID)
			default:
				m.error(w, http.StatusBadGateway, "TOOL_LEDGER_UNAVAILABLE", "tool invocation ledger unavailable", op.Context.TraceID)
			}
			return
		}
		if replay {
			m.toolObservedResult(w, r, op, in.Name, in.CallID, replayed.Result)
			return
		}
		toolLease = replayed.Lease
	}
	if err := leaseStore.BeginTool(r.Context(), toolLease); err != nil {
		if errors.Is(err, usagecost.ErrBudgetExceeded) {
			m.failTool(context.WithValue(r.Context(), toolLeaseContextKey{}, toolLease), scopeHash, in.CallID, fingerprint, "MODEL_BUDGET_EXCEEDED")
			m.error(w, http.StatusPaymentRequired, "MODEL_BUDGET_EXCEEDED", "run budget exhausted before tool execution", op.Context.TraceID)
			return
		}
		m.error(w, 409, "TOOL_LEASE_LOST", "tool execution lease is no longer valid", op.Context.TraceID)
		return
	}
	toolStarted := time.Now().UTC()
	// A tool deadline limits downstream work, not the caller's authorization
	// check. Keep the live caller context for bounded failure disclosure.
	callerRequest := r
	toolCtx, stopTool := context.WithTimeout(r.Context(), toolTimeout)
	defer stopTool()
	watch := m.watchToolLease(toolCtx, stopTool, toolLease, toolLeaseTTL, op, renewalStore)
	defer watch.finish()
	r = r.WithContext(context.WithValue(toolCtx, toolLeaseContextKey{}, toolLease))
	observeFailure := func(status int, code string, cause error) {
		// Lost leases cannot be bypassed by switching back to the caller context.
		if !watch.finish() {
			m.error(w, http.StatusForbidden, "CAPABILITY_DENIED", "tool execution authority ended; result unavailable", op.Context.TraceID)
			return
		}
		checkCtx, cancel := context.WithTimeout(callerRequest.Context(), 2*time.Second)
		defer cancel()
		m.toolObservedFailure(w, callerRequest.WithContext(checkCtx), op, in.Name, in.CallID, &toolStarted, status, code, cause)
	}
	var out map[string]any
	switch in.Name {
	case sendNotificationToolName, notifySelfToolName:
		scope := scopeFromHarness(op.Context)
		var recipientID, title, text string
		var inputErr error
		if in.Name == notifySelfToolName {
			title, text, inputErr = selfNotificationFields(scope, in.Payload)
			recipientID = scope.PrincipalID
		} else {
			recipientID, title, text, inputErr = notificationToolFields(in.Payload)
		}
		if inputErr != nil {
			m.failTool(r.Context(), scopeHash, in.CallID, fingerprint, "invalid notification request")
			if in.Name == notifySelfToolName && scope.PrincipalType != "user" {
				m.error(w, http.StatusForbidden, "NOTIFICATION_RECIPIENT_DENIED", "notify.self requires a human principal", op.Context.TraceID)
			} else if in.Name == notifySelfToolName {
				m.error(w, http.StatusBadRequest, "INVALID_NOTIFICATION", "notify.self accepts only title and text within their size limits", op.Context.TraceID)
			} else {
				m.error(w, http.StatusBadRequest, "INVALID_NOTIFICATION", "receiver_id, title and text are required within their size limits", op.Context.TraceID)
			}
			return
		}
		if m.notifications == nil {
			m.failTool(r.Context(), scopeHash, in.CallID, fingerprint, "notification outbox unavailable")
			m.error(w, http.StatusServiceUnavailable, "NOTIFICATION_UNAVAILABLE", "notification outbox is unavailable", op.Context.TraceID)
			return
		}
		digest := sha256.Sum256([]byte(scopeHash + "\x00" + in.CallID))
		receipt, enqueueErr := m.notifications.Enqueue(r.Context(), NotificationToolCommand{
			Scope: scopeFromHarness(op.Context), EventID: "agent-tool-" + fmt.Sprintf("%x", digest),
			ToolName: in.Name, CallID: in.CallID, Fingerprint: fingerprint,
			RecipientID: recipientID, Title: title, Text: text,
		})
		if enqueueErr != nil || strings.TrimSpace(receipt.EventID) == "" || strings.TrimSpace(receipt.Status) == "" {
			m.recordToolError(r.Context(), scopeHash, in.CallID, fingerprint, enqueueErr)
			if enqueueErr == nil {
				enqueueErr = errors.New("notification receipt missing")
			}
			observeFailure(http.StatusServiceUnavailable, "NOTIFICATION_ENQUEUE_FAILED", enqueueErr)
			return
		}
		out = map[string]any{
			"message_id": receipt.EventID, "delivery_status": receipt.Status,
			"accepted": true, "delivered": false,
		}
	default:
		provided, err := m.tools.Invoke(r.Context(), ToolCommand{Scope: scopeFromHarness(op.Context), Name: in.Name, CallID: in.CallID, Payload: in.Payload})
		if err != nil {
			m.recordToolError(r.Context(), scopeHash, in.CallID, fingerprint, err)
			observeFailure(http.StatusBadGateway, "TOOL_PROVIDER_FAILED", err)
			return
		}
		out = provided
	}
	observation, safeOutput := newToolObservation(scopeFromHarness(op.Context), in.Name, in.CallID, &toolStarted, "succeeded", "completed", "", out)
	if descriptor.ExecutionType == "code" {
		// The sealed Code adapter supplies the verified outcome, including known
		// failed/timeout results. Do not overwrite it with a success envelope.
		verified, err := toolObservationResponse(scopeFromHarness(op.Context), in.Name, in.CallID, out)
		if err != nil || out["_runtime_receipt_version"] != observationVersion {
			m.recordToolError(r.Context(), scopeHash, in.CallID, fingerprint, errors.New("invalid code observation"))
			observeFailure(502, "CODE_OBSERVATION_INVALID", errors.New("invalid code observation"))
			return
		}
		observation = verified["observation"].(runtimeObservation)
		safeOutput = verified["data"].(map[string]any)
	}
	observation.AuthorizationEpoch = op.Context.AuthorizationEpoch
	observation.ExecutionType = toolExecutionType(m.tools, in.Name)
	observation.PolicySnapshotHash = op.Policy.Hash
	observation.PermissionScope = toolPermissionScope(in.Name)
	storedOutput := storedToolObservation(observation, safeOutput)

	{
		watchOK := watch.finish()
		var authorityErr error
		if m.liveAuthority != nil {
			checkCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			authorityErr = m.validateLiveAuthority(checkCtx, op)
			cancel()
		}
		if !watchOK || r.Context().Err() != nil || authorityErr != nil {
			cause := errors.New("tool execution stopped")
			if err := r.Context().Err(); err != nil {
				cause = err
			}
			m.recordToolError(r.Context(), scopeHash, in.CallID, fingerprint, cause)
			observeFailure(409, "TOOL_EXECUTION_STOPPED", cause)
			return
		}
		if err := leaseStore.FinishTool(r.Context(), toolLease, storedOutput); err != nil {
			observeFailure(http.StatusBadGateway, "TOOL_LEDGER_UNAVAILABLE", err)
			return
		}
	}
	logRuntimeObservation(observation)
	m.toolObservedResult(w, r, op, in.Name, in.CallID, storedOutput)
}

func notificationToolFields(payload map[string]any) (recipientID, title, text string, err error) {
	if recipientID, err = notificationTextField(payload, "receiver_id", 128); err != nil {
		return "", "", "", err
	}
	if title, err = notificationTextField(payload, "title", 256); err != nil {
		return "", "", "", err
	}
	if text, err = notificationTextField(payload, "text", 4096); err != nil {
		return "", "", "", err
	}
	return recipientID, title, text, nil
}

func (m *Module) failTool(ctx context.Context, scopeHash, callID, fingerprint, reason string) {
	if lease, ok := ctx.Value(toolLeaseContextKey{}).(ToolExecutionLease); ok {
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		store, supported := m.toolStore.(ToolExecutionLeaseStore)
		if !supported || store.RejectTool(writeCtx, lease) != nil {
			log.Print("tool rejection lease update failed code=TOOL_LEASE_WRITE_FAILED")
		}
		return
	}
	if store, ok := m.toolStore.(toolInvocationFailureStore); ok {
		if err := store.Fail(ctx, scopeHash, callID, fingerprint, reason); err != nil {
			log.Print("tool failure ledger update failed code=TOOL_LEDGER_WRITE_FAILED")
		}
	}
}

func (m *Module) recordToolError(ctx context.Context, scope, id, fp string, cause error) {
	// Generic downstream errors cannot prove rollback, including commit timeouts.
	// 普通下游错误不能证明事务回滚，尤其是提交超时；不得盲目重试。
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if errors.Is(cause, ErrToolNotSubmitted) {
		m.failTool(writeCtx, scope, id, fp, "TOOL_NOT_SUBMITTED")
		return
	}
	if lease, ok := ctx.Value(toolLeaseContextKey{}).(ToolExecutionLease); ok {
		store, supported := m.toolStore.(ToolExecutionLeaseStore)
		if !supported || store.UnknownTool(writeCtx, lease) != nil {
			log.Print("tool unknown-result lease update failed code=TOOL_LEASE_WRITE_FAILED")
		}
		return
	}
	if store, ok := m.toolStore.(toolInvocationUnknownStore); ok {
		if err := store.MarkUnknown(writeCtx, scope, id, fp); err != nil {
			log.Print("tool unknown-result persistence failed code=TOOL_LEDGER_WRITE_FAILED")
		}
	} else {
		log.Print("tool unknown-result store unavailable code=TOOL_LEDGER_PORT_MISSING")
	}
}

func toolScopeHash(c harnessContext) string {
	return ToolReceiptScopeHash(scopeFromHarness(c))
}

func scopeFromHarness(c harnessContext) sharedkernel.Scope {
	return sharedkernel.Scope{
		TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID,
		AgentID: c.AgentID, AgentInstanceID: c.AgentInstanceID, PrincipalType: c.PrincipalType,
		InstallationID: c.InstallationID, AgentVersionID: c.AgentVersionID, PrincipalID: c.ActorID,
		SessionID: c.SessionID, RunID: c.TaskID, ParentRunID: c.ParentRunID, AuthorizationEpoch: c.AuthorizationEpoch, TraceID: c.TraceID,
	}
}

func (m *Module) ok(w http.ResponseWriter, data any, trace string) {
	m.write(w, http.StatusOK, response{Code: 0, Message: "ok", Data: data, TraceID: trace})
}
func (m *Module) error(w http.ResponseWriter, status int, code, message, trace string) {
	m.write(w, status, response{Code: 1, ErrorCode: code, Message: message, TraceID: trace})
}
func (m *Module) write(w http.ResponseWriter, status int, out response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(out)
}

var _ interface {
	Name() string
	Start(context.Context) error
	Handler() http.Handler
	Close(context.Context) error
} = (*Module)(nil)
