// Package execution exposes the platform-owned Run boundary.
// execution 包只负责运行元数据和事件的模块化组合，不承载 Agent 业务图。
package execution

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/policyasset"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/telemetry"
)

// Module is a local platform module. It deliberately depends on the runtime
// domain store through a narrow HTTP boundary, so a DB/remote adapter can be
// substituted without changing Agent code.
// Module 是本地平台模块；通过窄 HTTP 边界暴露运行域，后续可替换 DB/远程 Adapter。
type Module struct {
	store                    Repository
	internalToken            string
	dispatcher               *Dispatcher
	conversation             ConversationRecorder
	taskRecorder             TaskRecorder
	machineAuth              MachineAuthenticator
	machineTarget            MachineTargetResolver
	machinePolicy            MachineRunPolicyResolver
	machineSigner            MachineRunContextSigner
	modelSelections          policyasset.ModelSelectionStore
	modelRoutingSummary      policyasset.ModelRoutingSummaryReader
	authorizationEpoch       func(context.Context, sharedkernel.Scope, string) (uint64, error)
	reviewAuthorizer         func(context.Context, sharedkernel.Scope, string, string) error
	reviewAudit              func(context.Context, sharedkernel.Scope, string, string) error
	browserRunAuthorizer     BrowserRunAuthorizer
	eventReadAuthority       func(context.Context, sharedkernel.Scope, string) error
	pinnedRunTarget          func(context.Context, sharedkernel.Scope, string) error
	synchronousRunAuthorizer func(context.Context, sharedkernel.Scope, string, contract.ExecuteRequest) error
	synchronousRunAbortCheck func(context.Context, sharedkernel.Scope) (bool, error)
	closeStore               bool
	cancellationWorker       *cancellationWorkerLifecycle
	recoveryHolds            sharedkernel.RecoveryHolds
	recoveryHoldsConfigured  bool
}

var ErrReviewPermissionDenied = errors.New("business review permission denied")

func (m *Module) SetModelSelectionStore(store policyasset.ModelSelectionStore) {
	m.modelSelections = store
}

func (m *Module) SetModelRoutingSummaryReader(reader policyasset.ModelRoutingSummaryReader) {
	m.modelRoutingSummary = reader
}

// MachineAccess is the verified scope returned by the Identity boundary.
// MachineAccess 是 Identity 边界验证后返回的机器主体作用域。
type MachineAccess struct {
	Scope              sharedkernel.Scope
	AuthorizationEpoch uint64
}

// MachineAuthenticator and MachineTargetResolver are module ports. Execution
// does not import Identity or Catalog persistence implementations.
// MachineAuthenticator 和 MachineTargetResolver 是模块端口；Execution 不依赖 Identity/Catalog 的存储实现。
type MachineAuthenticator interface {
	AuthenticateMachine(context.Context, string, string, string) (MachineAccess, error)
	AuthorizeMachineRun(context.Context, string, string, string, sharedkernel.Scope, string) error
}

type MachineAgentTarget struct {
	AgentID        string
	InstallationID string
	VersionID      string
	InputSchemaURI string
	Endpoint       string
	Revision       uint64
}

type MachineTargetResolver interface {
	ResolveMachineTarget(context.Context, sharedkernel.Scope) (MachineAgentTarget, error)
}

// MachineRunPolicyResolver and MachineRunContextSigner keep machine Run
// preparation behind replaceable module ports. External systems submit only
// business input; the platform resolves the immutable policy snapshot and
// signs the trusted execution envelope before dispatch.
// MachineRunPolicyResolver 与 MachineRunContextSigner 是可替换的模块端口。外部系统只提交业务输入；
// 平台负责解析不可变策略快照，并在调度前签署可信执行信封。
type MachineRunPolicyResolver interface {
	ResolveAgentPolicy(context.Context, sharedkernel.Scope, string) (map[string]any, error)
}

type MachineRunContextSigner interface {
	Sign(context.Context, sharedkernel.Scope, contract.ExecuteRequest) (string, error)
}

// ConversationRecorder is an optional projection boundary.  Execution only
// publishes the trusted Run scope and request bytes; it never knows the
// conversation schema or storage implementation.
// ConversationRecorder 是可选的历史投影边界；Execution 只发布可信 Scope 和
// 请求字节，不感知会话表或存储实现。
type ConversationRecorder interface {
	RecordRun(context.Context, sharedkernel.Scope, []byte) error
}

type ConversationMessageRecorder interface {
	RecordRunWithMessage(context.Context, sharedkernel.Scope, []byte, string) error
}

// ConversationResultRecorder is an optional second projection hook for the
// Agent response. Keeping it separate preserves compatibility with read-only
// adapters while allowing the platform-owned history to display the durable
// assistant answer after a dispatcher run completes.
// ConversationResultRecorder 是可选的 Agent 响应投影端口；与输入投影分离，
// 不破坏只读 Adapter，同时让平台历史能展示 Dispatcher 完成后的答案。
type ConversationResultRecorder interface {
	RecordRunResult(context.Context, sharedkernel.Scope, string, map[string]any) error
}

// TaskRecorder projects an accepted Agent Run into a business read model
// without importing business tables into the execution module.
// TaskRecorder 将已接受的 Agent Run 投影到业务读取模型，Execution 不依赖业务表。
type TaskRecorder interface {
	RecordRunTask(context.Context, sharedkernel.Scope) error
}

// TaskRecorderWithRequest is an optional richer projection port. The runtime
// keeps the signed request opaque, while a product module may extract bounded
// explicit versioned business metadata for its read model.
// TaskRecorderWithRequest 是可选的丰富投影端口：Runtime 保持签名请求透明，
// 产品模块可提取显式声明的有界业务元数据。
type TaskRecorderWithRequest interface {
	RecordRunTaskWithRequest(context.Context, sharedkernel.Scope, []byte) error
}

func NewModule(internalToken string) *Module {
	return NewModuleWithRepository(internalToken, platformruntime.NewStore())
}

// NewModuleWithRepository allows the same HTTP module to use an in-process
// repository in tests or a persistent SQL repository in deployment.
// NewModuleWithRepository 让测试使用进程内仓储、部署使用持久化 SQL 仓储。
func NewModuleWithRepository(internalToken string, repository Repository) *Module {
	return &Module{store: repository, internalToken: internalToken, closeStore: true}
}

// NewModuleWithSharedRepository is used by the modular-monolith bootstrap
// when the repository is backed by the process-wide SQL pool. The bootstrap
// owns closing that pool; execution still owns run semantics and dispatcher
// shutdown. A remote repository can continue using NewModuleWithRepository.
func NewModuleWithSharedRepository(internalToken string, repository Repository) *Module {
	return &Module{store: repository, internalToken: internalToken, closeStore: false}
}

// NewModuleWithDispatcher enables the platform-owned asynchronous Agent
// dispatcher.  The dispatcher is optional so the pure runtime module remains
// usable in unit tests and in deployments that deliberately use an external
// scheduler.
// NewModuleWithDispatcher 启用平台内置异步 Agent 调度器；保持可选，便于单测及
// 由外部调度器接管的部署复用同一运行模块。
func NewModuleWithDispatcher(internalToken string, repository Repository, dispatcher *Dispatcher) *Module {
	return &Module{store: repository, internalToken: internalToken, dispatcher: dispatcher, closeStore: true}
}

// NewModuleWithDispatcherAndSharedRepository is the production local adapter
// constructor. SQL pool shutdown remains centralized in bootstrap while the
// Dispatcher is drained by the execution module.
func NewModuleWithDispatcherAndSharedRepository(internalToken string, repository Repository, dispatcher *Dispatcher) *Module {
	return &Module{store: repository, internalToken: internalToken, dispatcher: dispatcher, closeStore: false}
}

// SetConversationRecorder wires the optional product-history projection after
// shared modules are constructed.  It is a Port setter so a remote adapter can
// replace the SQL implementation without changing the runtime module.
// SetConversationRecorder 在模块组装后接入可选历史投影，保持远程替换边界。
func (m *Module) SetConversationRecorder(recorder ConversationRecorder) {
	m.conversation = recorder
	if m.dispatcher != nil {
		m.dispatcher.conversation = recorder
		if resultRecorder, ok := recorder.(ConversationResultRecorder); ok {
			m.dispatcher.SetResultRecorder(resultRecorder)
		}
	}
}

func (m *Module) SetTaskRecorder(recorder TaskRecorder) {
	m.taskRecorder = recorder
	if m.dispatcher != nil {
		m.dispatcher.taskRecorder = recorder
	}
}

func (m *Module) SetMachineAccessPorts(authenticator MachineAuthenticator, resolver MachineTargetResolver) {
	m.machineAuth = authenticator
	m.machineTarget = resolver
}

// SetMachineRunPolicyResolver wires the published policy authority for public
// client-credentials Run requests.
// SetMachineRunPolicyResolver 注入公共机器 Run 使用的已发布策略权威。
func (m *Module) SetMachineRunPolicyResolver(policy MachineRunPolicyResolver) {
	m.machinePolicy = policy
}

// SetMachineRunContextSigner wires the platform-owned signing key adapter.
// SetMachineRunContextSigner 注入由平台持有私钥的签名 Adapter。
func (m *Module) SetMachineRunContextSigner(signer MachineRunContextSigner) { m.machineSigner = signer }

func (m *Module) SetAuthorizationEpochResolver(resolve func(context.Context, sharedkernel.Scope, string) (uint64, error)) {
	m.authorizationEpoch = resolve
}

// SetReviewAuthorizer injects the current identity authority for human review.
// SetReviewAuthorizer 注入实时身份权威；浏览器不能自行声明审核角色。
func (m *Module) SetReviewAuthorizer(authorize func(context.Context, sharedkernel.Scope, string) error) {
	if authorize == nil {
		m.reviewAuthorizer = nil
		return
	}
	m.reviewAuthorizer = func(ctx context.Context, scope sharedkernel.Scope, reviewerID, _ string) error {
		if authorize(ctx, scope, reviewerID) != nil {
			return ErrReviewPermissionDenied
		}
		return nil
	}
}

// SetReviewPermissionAuthorizer distinguishes draft content from approving a
// business decision. Production composition must check the exact resource and
// object data scope for each action, including idempotent decision replays.
func (m *Module) SetReviewPermissionAuthorizer(authorize func(context.Context, sharedkernel.Scope, string, string) error) {
	m.reviewAuthorizer = authorize
}

// SetReviewAuditRecorder records authorized draft reads and decisions without
// storing the question, answer or evidence in the audit payload.
// SetReviewAuditRecorder 只记录审核动作，不把问题、答案或证据写入审计摘要。
func (m *Module) SetReviewAuditRecorder(record func(context.Context, sharedkernel.Scope, string, string) error) {
	m.reviewAudit = record
}

func (m *Module) SetDispatchSecurity(signer MachineRunContextSigner, authorize func(context.Context, sharedkernel.Scope) error) {
	if m.dispatcher != nil {
		m.dispatcher.SetSecurity(signer, authorize)
	}
}

// SetSynchronousRunAuthorizer installs the pre-persistence and result-read authority check for
// the governed synchronous product port. Parented synchronous Runs are denied
// when this verifier is absent; request fields alone never select an authority.
func (m *Module) SetSynchronousRunAuthorizer(authorize func(context.Context, sharedkernel.Scope, string, contract.ExecuteRequest) error) {
	if m != nil {
		m.synchronousRunAuthorizer = authorize
	}
}

// SetSynchronousRunAbortCheck distinguishes an explicitly aborted product Run
// from a worker shutdown, so reconnecting readers reuse the same durable child.
func (m *Module) SetSynchronousRunAbortCheck(check func(context.Context, sharedkernel.Scope) (bool, error)) {
	if m != nil {
		m.synchronousRunAbortCheck = check
	}
}

// SetApprovedResumeResolver installs the platform-only committed-approval
// recheck/re-sign port. The resolved token exists only in the dispatch request.
func (m *Module) SetApprovedResumeResolver(resolve func(context.Context, sharedkernel.Scope, json.RawMessage) (map[string]any, error)) {
	if m.dispatcher != nil {
		m.dispatcher.approvedResume = resolve
	}
}

// SetApprovedResumeRenewalResolver installs the platform-only recheck/re-sign
// port used by a live resumed generation. Unlike dispatch, renewal may resolve
// the immutable checkpoint revision referenced by the durable approval after
// the Harness head has advanced.
func (m *Module) SetApprovedResumeRenewalResolver(resolve func(context.Context, sharedkernel.Scope, json.RawMessage) (map[string]any, error)) {
	if m.dispatcher != nil {
		m.dispatcher.approvedResumeRenewal = resolve
	}
}

// SetRecoveryCheckpointReader installs a read-only public State reference port.
// Its values are transient inspection data, never durable recovery commands.
func (m *Module) SetRecoveryCheckpointReader(read func(context.Context, sharedkernel.Scope, contract.RecoveryCheckpointReference) (map[string]any, error)) {
	if m.dispatcher != nil {
		m.dispatcher.recoveryCheckpoint = read
	}
}

// SetRecoveryRenewalCheckpointReader installs the private historical reference
// reader used only after live Run/lease/body-hash validation. Dispatch and
// public State reads keep using the exact-current-head reader above.
func (m *Module) SetRecoveryRenewalCheckpointReader(read func(context.Context, sharedkernel.Scope, contract.RecoveryCheckpointReference) (map[string]any, error)) {
	if m.dispatcher != nil {
		m.dispatcher.recoveryCheckpointRenewal = read
	}
}

// SetCoordinatedReconciler installs the composition-owned stop-only hook before
// startup. It runs before cancellation confirmation and accepted-run discovery.
func (m *Module) SetCoordinatedReconciler(reconcile func(context.Context, int) error) {
	if m.dispatcher != nil {
		m.dispatcher.coordinatedReconcile = reconcile
	}
}

func (m *Module) SetCoordinatedGuard(check func(context.Context, sharedkernel.Scope) error) {
	if m.dispatcher != nil {
		m.dispatcher.coordinatedGuard = check
	}
}

func (m *Module) ConfigureDelegationCapacity(childWorkers int) error {
	if m == nil || m.dispatcher == nil {
		return errors.New("delegation dispatcher unavailable")
	}
	return m.dispatcher.ConfigureDelegationCapacity(childWorkers)
}

// SetStopQuiescence wires the platform model ledger barrier, independently of
// user business grants. A stopped graph can still have unsettled provider calls.
func (m *Module) SetStopQuiescence(check func(context.Context, sharedkernel.Scope) error) {
	if m.dispatcher != nil {
		m.dispatcher.stopQuiescence = check
	}
}

func (m *Module) SetStopEvidenceVerifier(verifier StopEvidenceVerifier) {
	if m.dispatcher != nil {
		m.dispatcher.stopEvidence = verifier
	}
}

// StartRun implements the conversation module's narrow RunStarter port.  It
// deliberately shares the exact repository create/projection/dispatch path
// used by the execution HTTP contract, so a browser command cannot create a
// second, less-governed execution path.
// StartRun 实现 Conversation 的窄 RunStarter 端口；复用 HTTP 合同相同的
// repository 创建、投影和派发路径，避免浏览器命令绕过治理。
func (m *Module) StartRun(ctx context.Context, scope sharedkernel.Scope, runID, idempotencyKey, fingerprint, agentEndpoint string, requestJSON []byte) (string, error) {
	return m.startRun(ctx, scope, runID, idempotencyKey, fingerprint, agentEndpoint, requestJSON, "")
}

// StartRunWithMessage is the browser conversation command variant. The
// runtime still owns the Run and events; messageID only avoids duplicating the
// user message already persisted by the conversation module.
func (m *Module) StartRunWithMessage(ctx context.Context, scope sharedkernel.Scope, runID, idempotencyKey, fingerprint, agentEndpoint string, requestJSON []byte, messageID string) (string, error) {
	return m.startRun(ctx, scope, runID, idempotencyKey, fingerprint, agentEndpoint, requestJSON, messageID)
}

func (m *Module) startRun(ctx context.Context, scope sharedkernel.Scope, runID, idempotencyKey, fingerprint, agentEndpoint string, requestJSON []byte, messageID string) (string, error) {
	if m.store == nil {
		return "", errors.New("execution repository is required")
	}
	if err := scope.ValidateTrusted(); err != nil || strings.TrimSpace(runID) == "" || scope.RunID != runID || strings.TrimSpace(idempotencyKey) == "" || strings.TrimSpace(agentEndpoint) == "" {
		return "", errors.New("invalid runtime start scope")
	}
	result, err := m.store.Create(platformruntime.CreateRequest{MessageID: messageID, ID: runID, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: idempotencyKey, Fingerprint: fingerprint, TraceContext: telemetry.Capture(ctx), RequestJSON: append([]byte(nil), requestJSON...), AgentEndpoint: agentEndpoint})
	if err != nil {
		return "", err
	}
	m.projectCreated(ctx, result.Run.ID)
	if m.dispatcher != nil {
		m.dispatcher.Enqueue(result.Run)
	}
	return result.Run.ID, nil
}

// Repository is the minimal runtime persistence boundary. It is intentionally
// smaller than the runtime domain so Local/SQL/remote adapters can evolve
// independently without leaking a database client into handlers.
// Repository 是最小运行持久化边界，避免 Handler 直接依赖数据库客户端。
type Repository interface {
	Create(platformruntime.CreateRequest) (platformruntime.CreateResult, error)
	Get(string) (platformruntime.Run, error)
	Transition(string, platformruntime.Status, platformruntime.Status, uint64) (platformruntime.Run, error)
	TransitionLeased(string, platformruntime.Status, platformruntime.Status, uint64, string) (platformruntime.Run, error)
	FinalizeLeased(string, platformruntime.Status, uint64, string, map[string]any, map[string]any) (platformruntime.Run, error)
	PendingOutcomes(int) ([]platformruntime.Outcome, error)
	PendingOutcomesAfter(string, int) ([]platformruntime.Outcome, error)
	GetOutcome(string) (platformruntime.Outcome, error)
	AcknowledgeOutcome(string, uint64) error
	PendingCreations(int) ([]platformruntime.CreationProjection, error)
	PendingCreationsAfter(string, int) ([]platformruntime.CreationProjection, error)
	GetCreation(string) (platformruntime.CreationProjection, error)
	AcknowledgeCreation(string, string) error
	RecordDispatchCommand(platformruntime.DispatchCommand, string) error
	GetDispatchCommand(string) (platformruntime.DispatchCommand, error)
	// Cancel atomically performs the terminal transition and appends the
	// cancellation events in the same repository transaction.
	// Cancel 在同一个仓储事务中完成终态迁移和取消事件追加。
	Cancel(string, uint64) (platformruntime.Run, error)
	PrepareResume(string, []byte) (platformruntime.Run, error)
	Events(string, uint64) ([]platformruntime.Event, error)
	AppendEvent(string, string, map[string]any) (platformruntime.Event, error)
	AcquireLease(string, string, time.Time, time.Duration) (platformruntime.Run, error)
	Heartbeat(string, string, uint64, time.Time, time.Duration) (platformruntime.Run, error)
	CheckSessionLease(platformruntime.Run, time.Time) error
}

func (m *Module) Name() string { return "execution" }

func (m *Module) Start(ctx context.Context) error {
	if m.cancellationWorker != nil {
		if err := m.cancellationWorker.start(ctx); err != nil {
			return err
		}
	}
	if m.dispatcher != nil {
		m.dispatcher.Start(ctx)
	}
	return nil
}

func (m *Module) Close(ctx context.Context) error {
	if m.cancellationWorker != nil {
		if err := m.cancellationWorker.close(ctx); err != nil {
			return err
		}
	}
	if m.dispatcher != nil {
		if err := m.dispatcher.Close(ctx); err != nil {
			return err
		}
	}
	if m.closeStore {
		if closer, ok := m.store.(interface{ Close() error }); ok {
			return closer.Close()
		}
	}
	return nil
}

// Handler exposes the internal Local Run Provider contract. The path is
// mounted below /modules/execution by ModuleRegistry.
// Handler 暴露内部 Local Run Provider 契约，由 ModuleRegistry 挂载到模块路径下。
func (m *Module) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/platform/runs", m.create)
	mux.HandleFunc("/platform/runs/", m.run)
	mux.HandleFunc("/agent-runs", m.machineRuns)
	mux.HandleFunc("/agent-runs/", m.machineRun)
	return mux
}

type scopeDTO struct {
	TenantID           string `json:"tenant_id"`
	DepartmentID       string `json:"department_id"`
	ApplicationID      string `json:"application_id"`
	AgentInstanceID    string `json:"agent_instance_id"`
	AgentID            string `json:"agent_id"`
	PrincipalID        string `json:"principal_id"`
	PrincipalType      string `json:"principal_type"`
	InstallationID     string `json:"installation_id"`
	AgentVersionID     string `json:"agent_version_id"`
	SessionID          string `json:"session_id"`
	RunID              string `json:"run_id"`
	ParentRunID        string `json:"parent_run_id,omitempty"`
	AuthorizationEpoch uint64 `json:"authorization_epoch"`
	TraceID            string `json:"trace_id"`
}

func (s scopeDTO) domain() sharedkernel.Scope {
	return sharedkernel.Scope{
		TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID,
		AgentInstanceID: s.AgentInstanceID, AgentID: s.AgentID, PrincipalID: s.PrincipalID,
		PrincipalType: s.PrincipalType, InstallationID: s.InstallationID, AgentVersionID: s.AgentVersionID,
		SessionID: s.SessionID, RunID: s.RunID, ParentRunID: s.ParentRunID, AuthorizationEpoch: s.AuthorizationEpoch, TraceID: s.TraceID,
	}
}

func scopeFromDomain(s sharedkernel.Scope) scopeDTO {
	return scopeDTO{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID,
		AgentInstanceID: s.AgentInstanceID, AgentID: s.AgentID, PrincipalID: s.PrincipalID, PrincipalType: s.PrincipalType,
		InstallationID: s.InstallationID, AgentVersionID: s.AgentVersionID, SessionID: s.SessionID, RunID: s.RunID,
		AuthorizationEpoch: s.AuthorizationEpoch, TraceID: s.TraceID, ParentRunID: s.ParentRunID}
}

type createRequest struct {
	RunID          string          `json:"run_id"`
	Scope          scopeDTO        `json:"scope"`
	AgentVersionID string          `json:"agent_version_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	Fingerprint    string          `json:"fingerprint"`
	Request        json.RawMessage `json:"request,omitempty"`
	AgentEndpoint  string          `json:"agent_endpoint,omitempty"`
}

type transitionRequest struct {
	Scope            scopeDTO `json:"scope"`
	From             string   `json:"from"`
	To               string   `json:"to"`
	ExpectedRevision uint64   `json:"expected_revision"`
}

type eventRequest struct {
	Scope     scopeDTO       `json:"scope"`
	AfterSeq  uint64         `json:"after_seq"`
	EventType string         `json:"event_type"`
	Payload   map[string]any `json:"payload"`
}

type leaseRequest struct {
	Scope            scopeDTO `json:"scope"`
	LeaseToken       string   `json:"lease_token"`
	ExpectedRevision uint64   `json:"expected_revision"`
	TTLSeconds       int      `json:"ttl_seconds"`
}

type cancelRequest struct {
	Scope            scopeDTO `json:"scope"`
	ExpectedRevision uint64   `json:"expected_revision"`
}

type runResponse struct {
	ModelRouting   *policyasset.RunModelRoutingSummary `json:"model_routing,omitempty"`
	RunID          string                              `json:"run_id"`
	Status         string                              `json:"status"`
	Revision       uint64                              `json:"revision"`
	AgentVersionID string                              `json:"agent_version_id"`
	Scope          scopeDTO                            `json:"scope"`
	Replayed       bool                                `json:"replayed,omitempty"`
	Cancellation   *CancellationProjection             `json:"cancellation,omitempty"`
}

type eventResponse struct {
	RunID      string         `json:"run_id"`
	Seq        uint64         `json:"seq"`
	Type       string         `json:"event_type"`
	Payload    map[string]any `json:"payload"`
	OccurredAt string         `json:"occurred_at"`
}

func (m *Module) create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !m.authorized(r) {
		m.writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return
	}
	if r.Header.Get("X-Browser-Module") != "" {
		m.writeError(w, http.StatusForbidden, "USE_CONVERSATION_RUN_COMMAND")
		return
	}
	var request createRequest
	if err := decodeJSON(r, &request); err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := request.Scope.domain().ValidateTrusted(); err != nil || request.Scope.RunID != request.RunID {
		m.writeError(w, http.StatusBadRequest, "SCHEMA_VALIDATION_FAILED")
		return
	}
	result, err := m.store.Create(platformruntime.CreateRequest{
		ID: request.RunID, Scope: request.Scope.domain(), AgentVersionID: request.AgentVersionID,
		IdempotencyKey: request.IdempotencyKey, Fingerprint: request.Fingerprint,
		TraceContext: telemetry.Capture(r.Context()), RequestJSON: append([]byte(nil), request.Request...), AgentEndpoint: request.AgentEndpoint,
	})
	if err != nil {
		m.writeRuntimeError(w, err)
		return
	}
	m.writeJSON(w, http.StatusOK, runResponseFrom(result.Run, result.Replayed))
	m.projectCreated(r.Context(), result.Run.ID)
	if m.dispatcher != nil {
		m.dispatcher.Enqueue(result.Run)
	}
}

func (m *Module) run(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(r) {
		m.writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/platform/runs/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	runID := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		run, err := m.store.Get(runID)
		if err != nil {
			m.writeRuntimeError(w, err)
			return
		}
		if r.Header.Get("X-Browser-Module") == "1" {
			if err := m.checkBrowserRunAccess(r, run.Scope, "history.read"); err != nil {
				m.writeBrowserRunPermissionError(w, err)
				return
			}
		} else if !scopeHeadersMatch(r, run.Scope) {
			m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
			return
		}
		m.writeCancellationAwareRun(w, r, http.StatusOK, run, false)
		return
	}
	if len(parts) != 2 {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	if r.Header.Get("X-Browser-Module") != "" && (parts[1] == "transition" || parts[1] == "lease" || parts[1] == "events" && r.Method != http.MethodGet) {
		m.writeError(w, http.StatusForbidden, "INTERNAL_RUN_COMMAND")
		return
	}
	switch parts[1] {
	case "agent-events":
		m.agentEvents(w, r, runID)
	case "event-capability":
		m.eventCapability(w, r, runID)
	case "authorization-renewal":
		m.renewWaitingAuthorization(w, r, runID)
	case "transition":
		m.transition(w, r, runID)
	case "resume":
		if r.Header.Get("X-Browser-Module") == "1" {
			m.resumeBrowser(w, r, runID)
		} else {
			m.resume(w, r, runID)
		}
	case "review":
		m.reviewBrowser(w, r, runID)
	case "cancel":
		if r.Header.Get("X-Browser-Module") == "1" {
			m.cancelBrowser(w, r, runID)
		} else {
			m.cancel(w, r, runID)
		}
	case "events":
		if r.Method == http.MethodGet {
			m.eventsSSE(w, r, runID)
		} else {
			m.events(w, r, runID)
		}
	case "lease":
		m.lease(w, r, runID)
	default:
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
	}
}

// cancel persists intent before the signed stop command; terminal cancellation
// and session release require a remote stop acknowledgment.
// cancel 先保存意图；签名停止命令获得确认后才写终态并释放会话锁。
func (m *Module) cancel(w http.ResponseWriter, r *http.Request, runID string) {
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "INVALID_REQUEST")
		return
	}
	var request cancelRequest
	if err := decodeJSON(r, &request); err != nil || request.Scope.RunID != runID || request.Scope.domain().ValidateTrusted() != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	run, err := m.store.Get(runID)
	if err != nil || !sameScope(run.Scope, request.Scope.domain()) {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	if run.Status == platformruntime.StatusCancelled {
		m.writeCancellationAwareRun(w, r, http.StatusOK, run, true)
		return
	}
	if run.Status == platformruntime.StatusSucceeded || run.Status == platformruntime.StatusFailed {
		m.writeRuntimeError(w, platformruntime.ErrInvalidTransition)
		return
	}
	expected := request.ExpectedRevision
	updated, err := m.requestCancellation(r.Context(), run, expected)
	if err != nil {
		m.writeRuntimeError(w, err)
		return
	}
	// 202 exposes durable intent, never a fabricated successful stop.
	// 202 仅表示意图已保存，不代表业务图已经停止。
	status := http.StatusOK
	if updated.Status == platformruntime.StatusCancelling {
		status = http.StatusAccepted
	}
	m.writeCancellationAwareRun(w, r, status, updated, false)
}

// cancelBrowser is the browser-gateway variant. The gateway authenticates the
// user and supplies only tenant/application/principal headers; the module
// resolves the complete Scope from the durable Run before changing state.
// cancelBrowser 面向浏览器网关，仅信任网关派生的主体字段，再从持久化 Run
// 解析完整 Scope，避免浏览器伪造 Agent/安装实例信息。
func (m *Module) cancelBrowser(w http.ResponseWriter, r *http.Request, runID string) {
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	// Browsers do not supply a revision. Claim/heartbeat can change the server's
	// read before BeginCancellation commits. Only a confirmed CAS conflict is
	// retried, with fresh authorization; no business or provider call is replayed.
	for attempt := 0; attempt < 3; attempt++ {
		run, err := m.store.Get(runID)
		if err != nil {
			m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
			return
		}
		if err := m.checkBrowserRunAccess(r, run.Scope, "cancel"); err != nil {
			m.writeBrowserRunPermissionError(w, err)
			return
		}
		updated, err := m.requestCancellation(r.Context(), run, run.Revision)
		if err != nil {
			if errors.Is(err, platformruntime.ErrRevisionConflict) && attempt < 2 && r.Context().Err() == nil {
				continue
			}
			m.writeRuntimeError(w, err)
			return
		}
		status := http.StatusOK
		if updated.Status == platformruntime.StatusCancelling {
			status = http.StatusAccepted
		}
		m.writeCancellationAwareRun(w, r, status, updated, false)
		return
	}
}

type resumeRequest struct {
	Scope scopeDTO       `json:"scope"`
	Input map[string]any `json:"input"`
}

type browserReviewRequest struct {
	Decision string `json:"decision"`
	Comment  string `json:"comment"`
}

// reviewBrowser returns only a bounded decision snapshot to an authorized
// reviewer; the full owner conversation and signing token stay private.
// reviewBrowser 仅向有权审核人返回有界审阅快照，不开放发起人完整会话或签名令牌。
func (m *Module) reviewBrowser(w http.ResponseWriter, r *http.Request, runID string) {
	if r.Method != http.MethodGet || r.Header.Get("X-Browser-Module") != "1" {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	run, outcome, reviewerID, status, code := m.browserReviewContext(r, runID)
	if status != 0 {
		m.writeError(w, status, code)
		return
	}
	if m.reviewAudit == nil || m.reviewAudit(r.Context(), run.Scope, reviewerID, humanReviewAction("read")) != nil {
		m.writeError(w, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE")
		return
	}
	var draft struct {
		Review *ReviewPreview `json:"review"`
	}
	if len(outcome.OutputJSON) > 1<<20 || json.Unmarshal(outcome.OutputJSON, &draft) != nil || draft.Review == nil || draft.Review.Validate() != nil {
		m.writeError(w, http.StatusServiceUnavailable, "REVIEW_SNAPSHOT_INVALID")
		return
	}
	m.writeJSON(w, http.StatusOK, map[string]any{"run_id": run.ID, "revision": run.Revision, "agent_id": run.Scope.AgentID, "review": draft.Review, "status": "waiting_review"})

}

// browserReviewContext checks the current Run, interrupt and live reviewer
// identity before either a draft read or a decision is permitted.
// browserReviewContext 在读草稿或提交决定前统一核验Run、中断与实时审核身份。
func (m *Module) browserReviewContext(r *http.Request, runID string) (platformruntime.Run, platformruntime.Outcome, string, int, string) {
	run, err := m.store.Get(runID)
	if err != nil || r.Header.Get("X-Tenant-ID") != run.Scope.TenantID || r.Header.Get("X-Department-ID") != run.Scope.DepartmentID || r.Header.Get("X-Application-ID") != run.Scope.ApplicationID || r.Header.Get("X-Principal-Type") != "user" {
		return platformruntime.Run{}, platformruntime.Outcome{}, "", http.StatusNotFound, "RESOURCE_NOT_FOUND"
	}
	reviewerID := strings.TrimSpace(r.Header.Get("X-Principal-ID"))
	action := "business.content.read"
	if r.Method == http.MethodPost {
		action = "business.review"
	}
	if reviewerID == "" || reviewerID == run.Scope.PrincipalID || m.reviewAuthorizer == nil {
		return platformruntime.Run{}, platformruntime.Outcome{}, "", http.StatusForbidden, "REVIEW_FORBIDDEN"
	}
	if err := m.reviewAuthorizer(r.Context(), run.Scope, reviewerID, action); err != nil {
		if errors.Is(err, ErrReviewPermissionDenied) {
			return platformruntime.Run{}, platformruntime.Outcome{}, "", http.StatusForbidden, "REVIEW_FORBIDDEN"
		}
		return platformruntime.Run{}, platformruntime.Outcome{}, "", http.StatusServiceUnavailable, "AUTHORIZATION_UNAVAILABLE"
	}
	if run.Status != platformruntime.StatusWaiting {
		return platformruntime.Run{}, platformruntime.Outcome{}, "", http.StatusConflict, "INVALID_TRANSITION"
	}
	outcome, err := m.store.GetOutcome(runID)
	if err != nil || outcome.Revision != run.Revision || outcome.EventType != "waiting" {
		return platformruntime.Run{}, platformruntime.Outcome{}, "", http.StatusConflict, "REVIEW_NOT_WAITING"
	}
	var waitingOutput struct {
		Stage string `json:"stage"`
	}
	if err := json.Unmarshal(outcome.OutputJSON, &waitingOutput); err != nil || waitingOutput.Stage != "waiting_review" {
		return platformruntime.Run{}, platformruntime.Outcome{}, "", http.StatusConflict, "REVIEW_NOT_WAITING"
	}
	return run, outcome, reviewerID, 0, ""
}

// resumeBrowser binds a human decision to the durable Run and authenticated
// browser principal. The browser never supplies a trusted execution Scope.
// resumeBrowser 将人工决定绑定到持久化 Run 与网关认证的主体，浏览器不提供可信 Scope。
func (m *Module) resumeBrowser(w http.ResponseWriter, r *http.Request, runID string) {
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	var request browserReviewRequest
	if err := decodeJSON(r, &request); err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	request.Decision = strings.TrimSpace(request.Decision)
	request.Comment = strings.TrimSpace(request.Comment)
	if (request.Decision != "approve" && request.Decision != "reject" && request.Decision != "request_changes") || len(request.Comment) > 2000 || ((request.Decision == "reject" || request.Decision == "request_changes") && request.Comment == "") {
		m.writeError(w, http.StatusBadRequest, "INVALID_REVIEW_DECISION")
		return
	}
	run, _, reviewerID, status, code := m.browserReviewContext(r, runID)
	if status != 0 {
		// A retry after a committed decision must not enqueue the graph again.
		// 已提交决定的重试只回放 Run；不得再次入队消费 LangGraph interrupt。
		if status == http.StatusConflict && code == "INVALID_TRANSITION" {
			current, err := m.store.Get(runID)
			reviewer := strings.TrimSpace(r.Header.Get("X-Principal-ID"))
			if err == nil && reviewer != "" && reviewer != current.Scope.PrincipalID &&
				r.Header.Get("X-Tenant-ID") == current.Scope.TenantID && r.Header.Get("X-Department-ID") == current.Scope.DepartmentID && r.Header.Get("X-Application-ID") == current.Scope.ApplicationID && r.Header.Get("X-Principal-Type") == "user" &&
				m.reviewAuthorizer != nil && m.reviewAuthorizer(r.Context(), current.Scope, reviewer, "business.review") == nil {
				input, marshalErr := json.Marshal(map[string]string{"decision": request.Decision, "comment": request.Comment, "reviewer_id": reviewer})
				if marshalErr == nil && bytes.Equal(current.ResumeInputJSON, input) {
					if m.reviewAudit == nil || m.reviewAudit(r.Context(), current.Scope, reviewer, humanReviewAction("decision_replay")) != nil {
						m.writeError(w, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE")
						return
					}
					m.writeJSON(w, http.StatusOK, runResponseFrom(current, true))
					return
				}
			}
		}
		m.writeError(w, status, code)
		return
	}
	input, err := json.Marshal(map[string]string{"decision": request.Decision, "comment": request.Comment, "reviewer_id": reviewerID})
	if err != nil {
		m.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}
	// request_changes can return to waiting. An identical decision is still a
	// replay of the prior command, not permission to consume the next interrupt.
	// 补材料会再次进入 waiting；相同决定仍是旧命令重放，不能消费下一次中断。
	if len(run.ResumeInputJSON) > 0 && bytes.Equal(run.ResumeInputJSON, input) {
		if m.reviewAudit == nil || m.reviewAudit(r.Context(), run.Scope, reviewerID, humanReviewAction("decision_replay")) != nil {
			m.writeError(w, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE")
			return
		}
		m.writeJSON(w, http.StatusOK, runResponseFrom(run, true))
		return
	}
	if m.reviewAudit == nil || m.reviewAudit(r.Context(), run.Scope, reviewerID, humanReviewAction("decision_attempt")) != nil {
		m.writeError(w, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE")
		return
	}
	updated, err := m.store.PrepareResume(runID, input)
	if err != nil {
		// Two authorized retries may race after both observed waiting. The
		// database transition remains single-writer; only replay identical input.
		// 两个重试可能同时看到 waiting；数据库仍由单写者迁移，仅回放相同输入。
		if current, getErr := m.store.Get(runID); getErr == nil && len(current.ResumeInputJSON) > 0 && bytes.Equal(current.ResumeInputJSON, input) {
			m.writeJSON(w, http.StatusOK, runResponseFrom(current, true))
			return
		}
		m.writeRuntimeError(w, err)
		return
	}
	m.writeJSON(w, http.StatusOK, runResponseFrom(updated, false))
	if m.dispatcher != nil {
		m.dispatcher.Enqueue(updated)
	}
}

// resume stores the approval input before enqueueing a new dispatch attempt.
// The database transition and input update are one repository operation, so a
// crash between HTTP acknowledgement and worker execution remains recoverable.
// resume 在重新派发前持久化审核输入；状态迁移与输入更新是同一仓储操作，
// 即使 HTTP 响应后进程崩溃，重启对账仍能恢复。
func (m *Module) resume(w http.ResponseWriter, r *http.Request, runID string) {
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "INVALID_REQUEST")
		return
	}
	var request resumeRequest
	if err := decodeJSON(r, &request); err != nil || request.Scope.RunID != runID || request.Scope.domain().ValidateTrusted() != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	run, err := m.store.Get(runID)
	if err != nil || !sameScope(run.Scope, request.Scope.domain()) {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	input, err := json.Marshal(request.Input)
	if err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if len(run.ResumeInputJSON) > 0 && bytes.Equal(run.ResumeInputJSON, input) {
		// Same signed/internal command is an idempotent replay, not a new resume.
		// 同一内部恢复命令只回放现有状态，不重复执行 Agent。
		m.writeJSON(w, http.StatusOK, runResponseFrom(run, true))
		return
	}
	updated, err := m.store.PrepareResume(runID, input)
	if err != nil {
		if current, getErr := m.store.Get(runID); getErr == nil && len(current.ResumeInputJSON) > 0 && bytes.Equal(current.ResumeInputJSON, input) {
			m.writeJSON(w, http.StatusOK, runResponseFrom(current, true))
			return
		}
		m.writeRuntimeError(w, err)
		return
	}
	m.writeJSON(w, http.StatusOK, runResponseFrom(updated, false))
	if m.dispatcher != nil {
		m.dispatcher.Enqueue(updated)
	}
}

// eventsSSE is the platform-owned resumable event stream. It starts at the
// caller's after_seq cursor and reads durable events, so reconnecting after a
// process restart cannot lose already committed events.
func (m *Module) eventsSSE(w http.ResponseWriter, r *http.Request, runID string) {
	// An omitted cursor starts at zero; malformed explicit cursors fail closed.
	// 未提供游标时从零开始；显式非法游标仍拒绝。
	var afterSeq uint64
	if raw := r.URL.Query().Get("after_seq"); raw != "" {
		var err error
		afterSeq, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
	}
	run, err := m.store.Get(runID)
	matched := scopeHeadersMatch(r, run.Scope)
	if r.Header.Get("X-Browser-Module") == "1" {
		if err != nil {
			m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
			return
		}
		if authErr := m.checkBrowserRunAccess(r, run.Scope, "history.read"); authErr != nil {
			m.writeBrowserRunPermissionError(w, authErr)
			return
		}
		matched = true
	}
	if err != nil || !matched {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	if err := checkMachineStreamAccess(r.Context()); err != nil {
		m.writeError(w, http.StatusUnauthorized, "MACHINE_ACCESS_DENIED")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	_, ok := w.(http.Flusher)
	if !ok {
		m.writeError(w, http.StatusInternalServerError, "STREAM_UNAVAILABLE")
		return
	}
	cursor := afterSeq
	controller := http.NewResponseController(w)
	streamError := func(code string) {
		// Only stable codes reach the client; database details remain private.
		// 客户端仅接收稳定错误码，不暴露数据库或请求内容。
		if _, err := fmt.Fprintf(w, "event: stream_error\ndata: {\"code\":%q}\n\n", code); err == nil {
			_ = controller.Flush()
		}
	}
	checkStreamPermission := func() bool {
		if err := checkMachineStreamAccess(r.Context()); err != nil {
			streamError("MACHINE_ACCESS_DENIED")
			return false
		}
		if r.Header.Get("X-Browser-Module") != "1" {
			return true
		}
		if err := m.checkBrowserRunAccess(r, run.Scope, "history.read"); err != nil {
			code := "AUTHORIZATION_UNAVAILABLE"
			if errors.Is(err, ErrBrowserSessionInvalid) {
				code = "SESSION_INVALID"
			} else if errors.Is(err, ErrRunPermissionDenied) {
				code = "PERMISSION_DENIED"
			}
			streamError(code)
			return false
		}
		return true
	}
	for {
		if r.Context().Err() != nil {
			return
		}
		if !checkStreamPermission() {
			return
		}
		var events []platformruntime.Event
		var listErr error
		if store, ok := m.store.(interface {
			EventsContext(context.Context, string, uint64) ([]platformruntime.Event, error)
		}); ok {
			queryCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			events, listErr = store.EventsContext(queryCtx, runID, cursor)
			cancel()
		} else {
			events, listErr = m.store.Events(runID, cursor)
		}
		if listErr != nil {
			streamError("EVENT_STORE_UNAVAILABLE")
			return
		}
		for _, event := range events {
			if !checkStreamPermission() {
				return
			}
			payload, err := json.Marshal(event.Payload)
			if err != nil {
				streamError("EVENT_PAYLOAD_INVALID")
				return
			}
			if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
				return
			}
			if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.Seq, event.Type, payload); err != nil {
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
			cursor = event.Seq
			// A historical interrupt is not terminal after a later Resume. Replay
			// must continue to the current command's final event; only a Run that
			// is still waiting ends the owner stream at this point.
			// 历史 waiting 在后续 Resume 后不再是当前终点；重放必须继续读到新命令终态。
			if event.Type == "waiting" {
				latest, getErr := m.store.Get(runID)
				if getErr != nil {
					streamError("EVENT_STORE_UNAVAILABLE")
					return
				}
				if latest.Status == platformruntime.StatusWaiting {
					return
				}
			}
			if event.Type == "task_completed" || event.Type == "task_failed" || event.Type == "task_cancelled" {
				return
			}
		}
		if len(events) == 256 {
			continue
		}
		// Terminal replay at/after the final cursor must end instead of polling.
		// 终态且已读尽游标必须结束，不再无限轮询。
		latest, getErr := m.store.Get(runID)
		if getErr != nil {
			streamError("EVENT_STORE_UNAVAILABLE")
			return
		}
		if latest.Status == platformruntime.StatusSucceeded || latest.Status == platformruntime.StatusFailed || latest.Status == platformruntime.StatusCancelled {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (m *Module) lease(w http.ResponseWriter, r *http.Request, runID string) {
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "INVALID_REQUEST")
		return
	}
	var request leaseRequest
	if err := decodeJSON(r, &request); err != nil || request.Scope.RunID != runID || request.Scope.domain().ValidateTrusted() != nil || request.LeaseToken == "" || request.TTLSeconds < 1 || request.TTLSeconds > 3600 {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	run, err := m.store.Get(runID)
	if err != nil || !sameScope(run.Scope, request.Scope.domain()) {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	var updated platformruntime.Run
	if request.ExpectedRevision == 0 {
		updated, err = m.store.AcquireLease(runID, request.LeaseToken, time.Now().UTC(), time.Duration(request.TTLSeconds)*time.Second)
	} else {
		updated, err = m.store.Heartbeat(runID, request.LeaseToken, request.ExpectedRevision, time.Now().UTC(), time.Duration(request.TTLSeconds)*time.Second)
	}
	if err != nil {
		m.writeRuntimeError(w, err)
		return
	}
	m.writeJSON(w, http.StatusOK, runResponseFrom(updated, false))
}

func (m *Module) transition(w http.ResponseWriter, r *http.Request, runID string) {
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "INVALID_REQUEST")
		return
	}
	var request transitionRequest
	if err := decodeJSON(r, &request); err != nil || request.Scope.RunID != runID || request.Scope.domain().ValidateTrusted() != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	run, err := m.store.Get(runID)
	if err != nil || !sameScope(run.Scope, request.Scope.domain()) {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	updated, err := m.store.Transition(runID, platformruntime.Status(request.From), platformruntime.Status(request.To), request.ExpectedRevision)
	if err != nil {
		m.writeRuntimeError(w, err)
		return
	}
	m.writeJSON(w, http.StatusOK, runResponseFrom(updated, false))
}

func (m *Module) events(w http.ResponseWriter, r *http.Request, runID string) {
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "INVALID_REQUEST")
		return
	}
	var request eventRequest
	if err := decodeJSON(r, &request); err != nil || request.Scope.RunID != runID || request.Scope.domain().ValidateTrusted() != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	run, err := m.store.Get(runID)
	if err != nil || !sameScope(run.Scope, request.Scope.domain()) {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	if request.EventType != "" {
		event, appendErr := m.store.AppendEvent(runID, request.EventType, request.Payload)
		if appendErr != nil {
			m.writeRuntimeError(w, appendErr)
			return
		}
		m.writeJSON(w, http.StatusOK, eventResponse{RunID: runID, Seq: event.Seq, Type: event.Type, Payload: event.Payload, OccurredAt: event.OccurredAt.UTC().Format("2006-01-02T15:04:05.999999Z07:00")})
		return
	}
	events, err := m.store.Events(runID, request.AfterSeq)
	if err != nil {
		m.writeRuntimeError(w, err)
		return
	}
	result := make([]eventResponse, 0, len(events))
	for _, event := range events {
		result = append(result, eventResponse{RunID: runID, Seq: event.Seq, Type: event.Type, Payload: event.Payload, OccurredAt: event.OccurredAt.UTC().Format("2006-01-02T15:04:05.999999Z07:00")})
	}
	m.writeJSON(w, http.StatusOK, result)
}

func (m *Module) authorized(r *http.Request) bool {
	if m.internalToken == "" {
		return true
	}
	value := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if value == "" {
		value = strings.TrimSpace(r.Header.Get("X-Internal-Token"))
	}
	if len(value) != len(m.internalToken) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(value), []byte(m.internalToken)) == 1
}

func decodeJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple json values")
		}
		return err
	}
	return nil
}

func sameScope(left, right sharedkernel.Scope) bool {
	return left.TenantID == right.TenantID && left.DepartmentID == right.DepartmentID && left.ApplicationID == right.ApplicationID && left.AgentInstanceID == right.AgentInstanceID && left.AgentID == right.AgentID && left.PrincipalID == right.PrincipalID && left.PrincipalType == right.PrincipalType && left.InstallationID == right.InstallationID && left.AgentVersionID == right.AgentVersionID && left.SessionID == right.SessionID && left.RunID == right.RunID && left.ParentRunID == right.ParentRunID && left.AuthorizationEpoch == right.AuthorizationEpoch && left.TraceID == right.TraceID
}

func scopeHeadersMatch(r *http.Request, scope sharedkernel.Scope) bool {
	return r.Header.Get("X-Tenant-ID") == scope.TenantID &&
		r.Header.Get("X-Department-ID") == scope.DepartmentID &&
		r.Header.Get("X-Application-ID") == scope.ApplicationID &&
		r.Header.Get("X-Agent-Instance-ID") == scope.AgentInstanceID &&
		r.Header.Get("X-Agent-ID") == scope.AgentID &&
		r.Header.Get("X-Principal-ID") == scope.PrincipalID &&
		r.Header.Get("X-Principal-Type") == scope.PrincipalType &&
		r.Header.Get("X-Installation-ID") == scope.InstallationID &&
		r.Header.Get("X-Agent-Version-ID") == scope.AgentVersionID &&
		r.Header.Get("X-Session-ID") == scope.SessionID &&
		r.Header.Get("X-Authorization-Epoch") == fmt.Sprintf("%d", scope.AuthorizationEpoch) &&
		r.Header.Get("X-Trace-ID") == scope.TraceID
}

func runResponseFrom(run platformruntime.Run, replayed bool) runResponse {
	return runResponse{RunID: run.ID, Status: string(run.Status), Revision: run.Revision, AgentVersionID: run.AgentVersionID, Scope: scopeFromDomain(run.Scope), Replayed: replayed}
}

func (m *Module) writeRuntimeError(w http.ResponseWriter, err error) {
	// Keep the public error stable while retaining the server-side cause for
	// diagnosing transient SQL/transport failures during concurrent Runs.
	// 对外保持稳定错误码，同时保留服务端根因，便于排查并发 Run 的 SQL/传输故障。
	if err != nil {
		log.Printf("execution request failed: %T: %v", err, err)
	}
	status := http.StatusInternalServerError
	code := "INTERNAL_ERROR"
	switch {
	case errors.Is(err, platformruntime.ErrRunNotFound):
		status, code = http.StatusNotFound, "RESOURCE_NOT_FOUND"
	case errors.Is(err, platformruntime.ErrIdempotencyConflict):
		status, code = http.StatusConflict, "IDEMPOTENCY_CONFLICT"
	case errors.Is(err, platformruntime.ErrRevisionConflict), errors.Is(err, platformruntime.ErrLeaseConflict):
		status, code = http.StatusConflict, "REVISION_CONFLICT"
	case errors.Is(err, platformruntime.ErrInvalidTransition):
		status, code = http.StatusConflict, "INVALID_TRANSITION"
	case errors.Is(err, sharedkernel.ErrInvalidScope):
		status, code = http.StatusBadRequest, "SCHEMA_VALIDATION_FAILED"
	}
	m.writeError(w, status, code)
}

func (m *Module) writeError(w http.ResponseWriter, status int, code string) {
	m.writeJSON(w, status, map[string]any{"error": map[string]any{"code": code}})
}

func (m *Module) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}

var _ interface {
	Name() string
	Start(context.Context) error
	Handler() http.Handler
	Close(context.Context) error
} = (*Module)(nil)
