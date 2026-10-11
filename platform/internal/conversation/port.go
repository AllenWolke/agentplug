package conversation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/sharedkernel"
)

var (
	ErrInvalidQuery     = errors.New("invalid conversation query")
	ErrForbidden        = errors.New("conversation access forbidden")
	ErrNotFound         = errors.New("conversation not found")
	ErrRevisionConflict = errors.New("conversation revision conflict")
	ErrLegalHold        = errors.New("conversation is under legal hold")
	ErrRetentionPolicy  = errors.New("invalid retention policy")
	ErrRuntimeBinding   = errors.New("conversation runtime binding unavailable")
	ErrExportTooLarge   = errors.New("conversation export exceeds payload limit")
)

// Scope is copied from the trusted platform context; callers must not supply
// tenant/application values through free-form filters. / Scope 来自可信平台
// 上下文，调用方不能通过任意过滤器伪造租户或应用范围。
type Scope struct {
	TenantID, DepartmentID, ApplicationID string
	PrincipalType, PrincipalID            string
	TraceID                               string
	// Set only by the Module after authorizing actual session metadata.
	// PrincipalID remains the caller, including for audit and new objects.
	historyOwnerID string
}

func (s Scope) historyOwner() string {
	if s.historyOwnerID != "" {
		return s.historyOwnerID
	}
	return s.PrincipalID
}

func (s Scope) Validate() error {
	if s.TenantID == "" || s.DepartmentID == "" || s.ApplicationID == "" || s.PrincipalID == "" {
		return ErrInvalidQuery
	}
	if s.PrincipalType != "user" && s.PrincipalType != "service_principal" {
		return ErrInvalidQuery
	}
	return nil
}

func ScopeFromContract(scope contract.ScopeKey) Scope {
	return Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, TraceID: scope.TraceID}
}

type Query struct {
	Kind, View, Text string
	Page, PageSize   int
	// OwnerID is only honored by an explicitly authorized managed view. The
	// normal user view always overwrites it with the trusted principal.
	OwnerID string
}

// ManagedSearchQuery is an explicitly privileged, bounded search over the
// platform-owned conversation projection. Tenant/application filters are
// resolved and constrained by the Module from the trusted Identity principal;
// callers must never use this DTO as an authorization source.
// ManagedSearchQuery 是平台受管会话检索的有界查询条件。租户/应用过滤器由 Module
// 根据可信 Identity 主体解析并约束，调用方不能把该 DTO 当作授权来源。
type ManagedSearchQuery struct {
	Kind, Text, TenantID, ApplicationID string
	Page, PageSize                      int
}

// ManagedSearchReader is an optional store capability for privileged
// platform search. Keeping it separate from ordinary HistoryReader prevents
// the user-facing history API from accidentally acquiring cross-owner reads.
// ManagedSearchReader 是平台特权检索的可选存储能力；与普通历史读取分离，避免
// 用户历史 API 意外获得跨用户读取能力。
type ManagedSearchReader interface {
	SearchManaged(context.Context, ManagedSearchQuery) (Page, error)
}

func (q Query) Normalize() (Query, error) {
	q.Kind = strings.TrimSpace(q.Kind)
	q.View = strings.TrimSpace(q.View)
	q.Text = strings.TrimSpace(q.Text)
	if q.Kind != "" && q.Kind != "qa" && q.Kind != "check" {
		return Query{}, ErrInvalidQuery
	}
	if q.View == "" {
		q.View = "mine"
	}
	if q.View != "mine" && q.View != "managed" {
		return Query{}, ErrInvalidQuery
	}
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PageSize < 1 {
		q.PageSize = 20
	}
	if q.PageSize > 100 {
		q.PageSize = 100
	}
	return q, nil
}

type Summary struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	AgentID        string          `json:"agent_id"`
	AgentVersionID string          `json:"agent_version_id"`
	InstallationID string          `json:"installation_id,omitempty"`
	Title          string          `json:"title"`
	Preview        string          `json:"preview"`
	OwnerID        string          `json:"owner_id"`
	Status         string          `json:"status"`
	MessageCount   int             `json:"message_count"`
	CanContinue    bool            `json:"can_continue"`
	Permissions    map[string]bool `json:"permissions,omitempty"`
}

// Message is the platform-owned conversation message projection.  Agent
// graphs may keep richer checkpoint state, but product history is queried from
// this stable projection so it can later move behind a remote service.
// Message 是平台拥有的会话消息投影；Agent 图可以保存更丰富的 Checkpoint，
// 但产品历史只从这个稳定投影读取，未来可整体迁移到远程服务。
type Message struct {
	ID             string `json:"id"`
	SessionID      string `json:"session_id"`
	Role           string `json:"role"`
	Content        string `json:"content"`
	IntentCode     string `json:"intent_code,omitempty"`
	KnowledgeScope string `json:"knowledge_scope,omitempty"`
	// Metadata keeps bounded Agent answer projections (references, grounding,
	// intent and degradation flags) without making this module depend on a
	// concrete Agent schema. / Metadata 保存有界的 Agent 回答投影，避免会话
	// 模块依赖某个 Agent 的具体结构。
	Metadata   map[string]any `json:"metadata,omitempty"`
	RevisionNo uint64         `json:"revision_no,omitempty"`
	Edited     bool           `json:"edited,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
}

// Session is the durable product-facing history record.  Scope columns are
// deliberately part of the primary query contract to prevent ID-only access.
// Session 是持久化的产品历史记录；作用域字段明确进入查询契约，禁止仅凭 ID 访问。
type Session struct {
	Summary
	TenantID      string    `json:"tenant_id"`
	DepartmentID  string    `json:"department_id"`
	ApplicationID string    `json:"application_id"`
	PrincipalType string    `json:"principal_type"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Revision      uint64    `json:"revision"`
}

type Page struct {
	Items []Summary `json:"items"`
	Total int64     `json:"total"`
	Page  int       `json:"page"`
	Size  int       `json:"page_size"`
}

type MessagePage struct {
	Items    []Message `json:"items"`
	Total    int64     `json:"total"`
	Page     int       `json:"page"`
	PageSize int       `json:"page_size"`
}

// HistoryReader is the persistence adapter implemented by the existing
// Backend GORM service during migration. / HistoryReader 是迁移期由现有
// Backend GORM Service 实现的持久化 Port，平台领域不依赖 GORM。
type HistoryReader interface {
	List(context.Context, Scope, Query) (Page, error)
	Detail(context.Context, Scope, string) (Summary, error)
	Resume(context.Context, Scope, string) (Summary, error)
}

// Store extends the migration Port with the write operations owned by the
// conversation module.  Other modules must publish a command or event rather
// than writing these tables directly.
// Store 在迁移 Port 上增加会话模块拥有的写操作；其他模块必须发布命令或事件，
// 不能直接写这些表。
type Store interface {
	HistoryReader
	EnsureSchema(context.Context) error
	Ping(context.Context) error
	CreateSession(context.Context, Scope, Session) error
	AppendMessage(context.Context, Scope, Message) error
	ListMessages(context.Context, Scope, string, int, int) ([]Message, int64, error)
}

// GovernanceStore contains the product operations that are intentionally
// separate from the basic history reader.  Keeping this as an optional port
// lets older adapters continue to serve read-only history while the modular
// store rolls out share/export/deletion governance.
// GovernanceStore 将分享、导出和删除审批作为独立 Port，便于旧只读适配器
// 渐进接入，同时不让 HTTP Handler 依赖数据库实现。
type GovernanceStore interface {
	CreateShare(context.Context, Scope, ShareRequest) (Share, error)
	RevokeShare(context.Context, Scope, string) (Share, error)
	CreateExport(context.Context, Scope, ExportRequest) (Export, error)
	GetExport(context.Context, Scope, string) (Export, error)
	ApproveExport(context.Context, Scope, string) (Export, error)
	RequestDeletion(context.Context, Scope, DeleteRequest) (DeletionRequest, error)
	ListDeletionRequests(context.Context, Scope, int, int) ([]DeletionRequest, int64, error)
	ApproveDeletion(context.Context, Scope, string) (DeletionRequest, error)
}

// PublicShareReader resolves a short-lived capability token without requiring
// an authenticated user scope. Implementations must store only a token hash,
// enforce expiry/revocation in the query, and return a reduced read-only view.
// PublicShareReader 通过短期能力令牌读取只读分享；实现必须只保存令牌哈希，
// 在查询中强制检查过期/撤销，并且仅返回裁剪后的只读视图。
type PublicShareReader interface {
	ReadPublicShare(context.Context, string, int, int) (SharedConversation, error)
}

// DeletionManagementStore is an optional browser-admin extension. The Module
// resolves an active scoped administrator before these methods run; SQL still
// constrains every operation to the complete application scope.
// DeletionManagementStore 是可选的浏览器管理员扩展。Module 调用前会解析有效且
// 作用域匹配的管理员；SQL 仍按完整应用作用域约束操作。
type DeletionManagementStore interface {
	ListDeletionRequestsForManagement(context.Context, Scope, int, int) ([]DeletionRequest, int64, error)
	ApproveDeletionByUser(context.Context, Scope, string) (DeletionRequest, error)
}

// RetentionStore is the governance port for retention and legal hold.  It is
// deliberately separate from Store/GovernanceStore so a remote governance
// service can replace the SQL adapter without changing conversation commands.
// RetentionStore 是留存与法律保全治理端口，独立于会话读写端口，未来可替换为
// 远程治理服务而不改变会话命令契约。
type RetentionStore interface {
	GetRetentionPolicy(context.Context, Scope, string) (RetentionPolicy, error)
	PutRetentionPolicy(context.Context, Scope, RetentionPolicy) (RetentionPolicy, error)
	PlaceLegalHold(context.Context, Scope, LegalHoldRequest) (LegalHold, error)
	ListLegalHolds(context.Context, Scope, int, int) ([]LegalHold, int64, error)
	ReleaseLegalHold(context.Context, Scope, string) (LegalHold, error)
	SweepExpired(context.Context, Scope, time.Time, int) (RetentionSweep, error)
}

// RevisionStore owns immutable message revisions.  The current message row
// remains the read model while every edit is appended to this store, allowing
// audit/export workers to replay the complete history without legacy tables.
// RevisionStore 负责不可变消息修订；当前消息行仍是读模型，编辑只追加修订，
// 便于审计/导出 Worker 重放完整历史且不依赖旧表。
type RevisionStore interface {
	ListRevisions(context.Context, Scope, string, string) ([]Revision, error)
	ReviseMessage(context.Context, Scope, string, string, string, string, uint64) (Revision, error)
}

// RegenerationStore records a replay request and its independent branch
// session.  It is deliberately optional at the HTTP boundary so a remote
// adapter can implement the command without coupling the module to SQL.
// RegenerationStore 记录重执行请求及独立分支会话；HTTP 边界保持可选，便于
// 后续替换为远程 Adapter，而不把模块绑定到 SQL 实现。
type RegenerationStore interface {
	Regenerate(context.Context, Scope, string, string, string) (Regeneration, error)
}

// RunStarter is the narrow boundary used by the conversation product to
// submit a user turn to the platform runtime.  It carries only stable IDs and
// serialized input, so the concrete scheduler can later be remote.
// RunStarter 是会话产品提交用户轮次到平台 Runtime 的窄边界；只携带稳定 ID 与
// 序列化输入，后续可替换为远程调度服务。
type RunStarter interface {
	StartRun(context.Context, sharedkernel.Scope, string, string, string, string, []byte) (string, error)
}

// RunMessageStarter is an optional extension used when the product boundary
// appends the user message before dispatching the Run. It lets the runtime
// projection reuse that exact message instead of appending a second copy.
// RunMessageStarter 用于会话边界先追加用户消息再派发 Run 的场景，确保运行
// 投影复用同一 message_id，不重复追加用户问题。
type RunMessageStarter interface {
	StartRunWithMessage(context.Context, sharedkernel.Scope, string, string, string, string, []byte, string) (string, error)
}

// RuntimeBinding is the platform-owned target resolved from an immutable
// Agent/version binding. Browser callers must not choose the endpoint or
// installation; the resolver supplies those values from trusted deployment
// configuration or a future catalog adapter.
// RuntimeBinding 是平台根据不可变 Agent/版本绑定解析出的目标。浏览器不能自行
// 选择 endpoint 或 installation；这些值由可信部署配置或未来 Catalog Adapter 提供。
type RuntimeBinding struct {
	AgentEndpoint      string
	AgentInstanceID    string
	InstallationID     string
	AgentVersionID     string
	InputSchemaURI     string
	AuthorizationEpoch uint64
}

// RuntimeBindingResolver keeps the conversation module independent from
// environment variables and deployment-specific catalog storage.
// RuntimeBindingResolver 让会话模块不依赖环境变量或具体部署目录存储。
type RuntimeBindingResolver interface {
	Resolve(context.Context, Scope, string, string) (RuntimeBinding, error)
}

// RunPolicyResolver resolves the published immutable policy by trusted scope
// and the session's pinned Agent version. Browser-provided policy data is
// never authoritative. / RunPolicyResolver 只按可信作用域和会话固定版本解析
// 已发布策略；浏览器提交的策略数据不作为权威来源。
type RunPolicyResolver interface {
	ResolveAgentPolicy(context.Context, sharedkernel.Scope, string) (map[string]any, error)
}

// ContextTokenSigner lets the platform turn an authenticated browser command
// into a signed Agent Execution v2 envelope. The private key stays in the
// platform process/Secret mount and is never accepted from the browser.
// ContextTokenSigner 让中台把已认证浏览器命令转换为签名的 Agent v2 信封；私钥
// 只存在中台进程/Secret 挂载中，绝不接受浏览器提交；签名动作与信封中的
// invoke/run 操作严格一致。
type ContextTokenSigner interface {
	Sign(context.Context, sharedkernel.Scope, contract.ExecuteRequest) (string, error)
}

type Ed25519ContextTokenSigner struct {
	PrivateKey ed25519.PrivateKey
	Issuer     string
	Audience   string
	TTL        time.Duration
	// Clock is injected only by deterministic expiry tests; production uses UTC now.
	// Clock 仅供确定性过期测试注入；生产默认使用当前 UTC 时间。
	Clock func() time.Time
}

func (s Ed25519ContextTokenSigner) Sign(ctx context.Context, scope sharedkernel.Scope, request contract.ExecuteRequest) (string, error) {
	if len(s.PrivateKey) != ed25519.PrivateKeySize || strings.TrimSpace(s.Issuer) == "" || strings.TrimSpace(s.Audience) == "" {
		return "", errors.New("invalid context token signer")
	}
	if err := scope.ValidateTrusted(); err != nil {
		return "", fmt.Errorf("invalid signing scope: %w", err)
	}
	if request.ContextToken != "" || (request.Operation != "run" && request.Operation != "invoke" && request.Operation != "resume" && request.Operation != "cancel") || request.Scope.TenantID != scope.TenantID ||
		request.Scope.DepartmentID != scope.DepartmentID || request.Scope.ApplicationID != scope.ApplicationID ||
		request.Scope.AgentInstanceID != scope.AgentInstanceID || request.Scope.InstallationID != scope.InstallationID ||
		request.Scope.AgentID != scope.AgentID || request.Scope.AgentVersionID != scope.AgentVersionID ||
		request.Scope.PrincipalType != scope.PrincipalType || request.Scope.PrincipalID != scope.PrincipalID ||
		request.Scope.SessionID != scope.SessionID || request.Scope.RunID != scope.RunID ||
		request.Scope.ParentRunID != scope.ParentRunID ||
		request.Scope.AuthorizationEpoch != scope.AuthorizationEpoch || request.Scope.TraceID != scope.TraceID {
		return "", errors.New("execution envelope does not match signing scope")
	}
	policy, ok := request.Input["policy_snapshot"].(map[string]any)
	if !ok {
		return "", errors.New("immutable policy snapshot is missing")
	}
	policyHash, ok := policy["content_hash"].(string)
	if !ok || len(policyHash) != 64 {
		return "", errors.New("immutable policy hash is invalid")
	}
	bodyHash, err := contract.CanonicalExecuteBodyHash(request)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if s.Clock != nil {
		now = s.Clock().UTC()
	}
	ttl := s.TTL
	if ttl <= 0 || ttl > 5*time.Minute {
		ttl = 2 * time.Minute
	}
	encode := func(value any) string {
		raw, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := encode(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	claimValues := map[string]any{
		"iss": s.Issuer, "aud": s.Audience, "subject_type": scope.PrincipalType,
		"sub": scope.PrincipalID, "tenant_id": scope.TenantID,
		"application_id": scope.ApplicationID, "agent_instance_id": scope.AgentInstanceID,
		"department_id": scope.DepartmentID, "agent_id": scope.AgentID, "agent_version_id": scope.AgentVersionID,
		"run_id": scope.RunID, "session_id": scope.SessionID, "trace_id": scope.TraceID,
		"installation_id":     scope.InstallationID,
		"authorization_epoch": scope.AuthorizationEpoch, "policy_snapshot_hash": policyHash,
		"body_hash": bodyHash, "actions": []string{request.Operation},
		"iat": now.Unix(), "exp": now.Add(ttl).Unix(),
	}
	if scope.ParentRunID != "" {
		claimValues["parent_run_id"] = scope.ParentRunID
	}
	if lease, ok := sharedkernel.ExecutionLeaseFromContext(ctx); ok {
		claimValues["execution_revision"] = lease.Revision
		claimValues["lease_token_hash"] = lease.TokenHash
	}
	claims := encode(claimValues)
	input := header + "." + claims
	signed := ed25519.Sign(s.PrivateKey, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(signed), nil
}

// NewContextTraceID is deterministic per run and valid for the v2 trace
// contract, while avoiding user-controlled header values in the signed body.
func NewContextTraceID(runID string) string {
	if strings.TrimSpace(runID) == "" {
		return ""
	}
	hash := sha256.Sum256([]byte("conversation:" + runID))
	// W3C Trace Context uses 16-byte (32 hexadecimal character) trace IDs.
	// W3C Trace Context 的 Trace ID 为 16 字节（32 位十六进制字符）。
	return hex.EncodeToString(hash[:16])
}

// StaticRuntimeBindingResolver is the single-process bootstrap adapter. It is
// intentionally replaceable by a catalog/remote resolver in multi-instance
// or microservice deployments.
// StaticRuntimeBindingResolver 是单进程引导适配器；多实例或微服务部署时可替换
// 为 Catalog/远程 Resolver，而不改变会话 HTTP 契约。
type StaticRuntimeBindingResolver map[string]RuntimeBinding

func (r StaticRuntimeBindingResolver) Resolve(_ context.Context, _ Scope, agentID, versionID string) (RuntimeBinding, error) {
	binding, ok := r[agentID]
	if !ok || strings.TrimSpace(binding.AgentEndpoint) == "" || strings.TrimSpace(binding.AgentInstanceID) == "" || strings.TrimSpace(binding.InstallationID) == "" {
		return RuntimeBinding{}, ErrRuntimeBinding
	}
	if binding.AgentVersionID != "" && versionID != "" && binding.AgentVersionID != versionID {
		return RuntimeBinding{}, ErrRuntimeBinding
	}
	if binding.AuthorizationEpoch == 0 {
		binding.AuthorizationEpoch = 1
	}
	return binding, nil
}

type RunStartRequest struct {
	RunID              string          `json:"run_id"`
	IdempotencyKey     string          `json:"idempotency_key"`
	MessageID          string          `json:"message_id,omitempty"`
	Fingerprint        string          `json:"fingerprint"`
	AgentEndpoint      string          `json:"agent_endpoint"`
	AgentInstanceID    string          `json:"agent_instance_id"`
	InstallationID     string          `json:"installation_id"`
	AuthorizationEpoch uint64          `json:"authorization_epoch"`
	TraceID            string          `json:"trace_id"`
	Request            json.RawMessage `json:"request"`
}

type Regeneration struct {
	ID              string `json:"id"`
	SessionID       string `json:"session_id"`
	MessageID       string `json:"message_id"`
	BranchSessionID string `json:"branch_session_id"`
	VersionMode     string `json:"version_mode"`
	Status          string `json:"status"`
}

type Revision struct {
	ID         string    `json:"id"`
	SessionID  string    `json:"session_id"`
	MessageID  string    `json:"message_id"`
	Role       string    `json:"role"`
	Content    string    `json:"content"`
	Reason     string    `json:"reason,omitempty"`
	RevisionNo uint64    `json:"revision_no"`
	IsCurrent  bool      `json:"is_current"`
	CreatedAt  time.Time `json:"created_at"`
}

// AccessPolicy centralizes ownership and scope checks for history, export and
// deletion operations. / AccessPolicy 统一历史、导出和删除的归属与范围检查。
type AccessPolicy struct{ AllowManaged bool }

func (p AccessPolicy) Normalize(scope Scope, query Query) (Query, error) {
	if err := scope.Validate(); err != nil {
		return Query{}, err
	}
	query, err := query.Normalize()
	if err != nil {
		return Query{}, err
	}
	if query.View == "managed" && !p.AllowManaged {
		return Query{}, ErrForbidden
	}
	if query.View == "mine" {
		query.OwnerID = scope.PrincipalID
	}
	return query, nil
}

func (p AccessPolicy) CanAccess(scope Scope, summary Summary) bool {
	if summary.ID == "" || summary.OwnerID == "" || scope.Validate() != nil {
		return false
	}
	if summary.OwnerID == scope.PrincipalID {
		return true
	}
	return p.AllowManaged
}

type Share struct {
	ID          string    `json:"id"`
	Token       string    `json:"token,omitempty"`
	SessionID   string    `json:"session_id"`
	OwnerID     string    `json:"owner_id"`
	Status      string    `json:"status"`
	ExpiresAt   time.Time `json:"expires_at"`
	IncludeRefs bool      `json:"include_refs"`
	CreatedAt   time.Time `json:"created_at"`
}

// SharedConversation is deliberately smaller than the authenticated history
// response: it never exposes owner/scope identifiers, continuation controls,
// or internal message metadata.
// SharedConversation 刻意小于已认证历史响应：不暴露所有者/作用域标识、
// 继续执行控制或内部消息元数据。
type SharedConversation struct {
	SessionID         string          `json:"session_id"`
	Kind              string          `json:"kind"`
	Title             string          `json:"title"`
	ExpiresAt         time.Time       `json:"expires_at"`
	TotalMessages     int64           `json:"total_messages"`
	Page              int             `json:"page"`
	PageSize          int             `json:"page_size"`
	IncludeReferences bool            `json:"include_references"`
	Messages          []SharedMessage `json:"messages"`
}

type SharedMessage struct {
	Role       string    `json:"role"`
	Content    string    `json:"content"`
	CreatedAt  time.Time `json:"created_at"`
	References []any     `json:"references,omitempty"`
}

type ExportRequest struct {
	SessionIDs []string `json:"session_ids"`
}

type Export struct {
	ID          string    `json:"id"`
	SessionID   string    `json:"session_id"`
	OwnerID     string    `json:"owner_id"`
	Status      string    `json:"status"`
	PayloadJSON string    `json:"payload_json,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ApprovedAt  time.Time `json:"approved_at,omitempty"`
}

type DeleteRequest struct {
	SessionIDs []string `json:"session_ids"`
	Reason     string   `json:"reason"`
}

type DeletionRequest struct {
	ID          string    `json:"id"`
	SessionID   string    `json:"session_id"`
	OwnerID     string    `json:"owner_id"`
	Reason      string    `json:"reason"`
	Status      string    `json:"status"`
	RequestedAt time.Time `json:"requested_at"`
	ApprovedAt  time.Time `json:"approved_at,omitempty"`
}
type ShareRequest struct {
	SessionID   string `json:"session_id"`
	TTLSeconds  int64  `json:"ttl_seconds"`
	IncludeRefs bool   `json:"include_refs"`
}

type RetentionPolicy struct {
	ID            string    `json:"id"`
	Kind          string    `json:"kind"`
	RetentionDays int       `json:"retention_days"`
	Enabled       bool      `json:"enabled"`
	Revision      uint64    `json:"revision"`
	UpdatedBy     string    `json:"updated_by"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type LegalHoldRequest struct {
	SessionID string `json:"session_id"`
	Reason    string `json:"reason"`
}

type LegalHold struct {
	ID         string     `json:"id"`
	SessionID  string     `json:"session_id"`
	Reason     string     `json:"reason"`
	Status     string     `json:"status"`
	PlacedBy   string     `json:"placed_by"`
	ReleasedBy string     `json:"released_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ReleasedAt *time.Time `json:"released_at,omitempty"`
}

type RetentionSweep struct {
	Scanned  int `json:"scanned"`
	Disposed int `json:"disposed"`
	Held     int `json:"held"`
}
