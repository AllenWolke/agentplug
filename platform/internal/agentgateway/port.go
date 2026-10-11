package agentgateway

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/lexagent/platform/internal/contract"
)

var (
	ErrInvalidTarget   = errors.New("invalid agent gateway target")
	ErrTargetMismatch  = errors.New("agent target does not match request scope")
	ErrInvalidResponse = errors.New("agent gateway returned an invalid response")
	ErrNoAdapter       = errors.New("agent gateway adapter is not configured")
)

// Target is a published Agent installation endpoint. The Gateway never
// resolves an endpoint from an untrusted request body. / Target 是控制面发布的
// Agent 安装实例端点，Gateway 不从不可信请求体解析端点。
type Target struct {
	InstallationID string
	AgentID        string
	AgentVersionID string
	Endpoint       string
	Transport      string
	Revision       uint64
	ManifestHash   string
}

func (t Target) Validate() error {
	if t.InstallationID == "" || t.AgentID == "" || t.AgentVersionID == "" || t.Revision == 0 || t.ManifestHash == "" {
		return ErrInvalidTarget
	}
	if t.Transport == "local" {
		return nil
	}
	if t.Transport != "http" && t.Transport != "https" && t.Transport != "grpc" && t.Transport != "grpcs" {
		return fmt.Errorf("%w: unsupported transport", ErrInvalidTarget)
	}
	u, err := url.Parse(t.Endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !transportSchemeMatches(t.Transport, u.Scheme) {
		return ErrInvalidTarget
	}
	return nil
}

// Catalog stores a protocol family (http/grpc), while the registered endpoint
// may opt into TLS (https/grpcs). Only matching family pairs are valid.
// Catalog 保存协议族（http/grpc），登记端点可选择 TLS（https/grpcs）；只允许同族组合。
func transportSchemeMatches(transport, scheme string) bool {
	switch transport {
	case "http", "https":
		return scheme == "http" || scheme == "https"
	case "grpc", "grpcs":
		return scheme == "grpc" || scheme == "grpcs"
	default:
		return false
	}
}

func validateScope(target Target, request contract.ExecuteRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	installationID := request.Scope.InstallationID
	if installationID == "" {
		// Legacy fixtures predate the explicit installation field; production
		// protocol payloads always carry it. / 旧夹具尚未带显式安装字段，生产
		// 协议请求必须带 installation_id。
		installationID = request.Scope.AgentInstanceID
	}
	if installationID != target.InstallationID || request.Scope.AgentID != target.AgentID || request.Scope.AgentVersionID != target.AgentVersionID {
		return ErrTargetMismatch
	}
	return nil
}

func validateResponse(response contract.ExecuteResponse) error {
	if response.ProtocolVersion != contract.ProtocolVersion || response.RunID == "" || response.Status == "" {
		return ErrInvalidResponse
	}
	return nil
}

// EventStream is deliberately transport-neutral so HTTP SSE and gRPC streams
// have identical lifecycle semantics. / EventStream 统一 HTTP SSE 与 gRPC
// 的生命周期语义，避免领域模块感知具体传输。
type EventStream struct {
	Events <-chan contract.ExecutionEvent
	Errors <-chan error
	Close  func() error
}

// Transport is implemented by HTTP/gRPC/sidecar adapters outside the Agent
// domain. / Transport 由 HTTP/gRPC/sidecar Adapter 实现，领域不依赖语言框架。
type Transport interface {
	Invoke(context.Context, Target, contract.ExecuteRequest) (contract.ExecuteResponse, error)
	Run(context.Context, Target, contract.ExecuteRequest) (contract.ExecuteResponse, error)
	Resume(context.Context, Target, contract.ExecuteRequest) (contract.ExecuteResponse, error)
	Cancel(context.Context, Target, contract.ExecuteRequest) (contract.ExecuteResponse, error)
	Events(context.Context, Target, contract.EventRequest) (EventStream, error)
}

// LocalHandler is the in-process seam used by the modular monolith. The
// handler owns Agent business logic; it must not own platform authorization or
// persistence. / LocalHandler 是单体内 Local Adapter 接缝：业务由 Agent
// 持有，平台仍负责授权、Run 状态和持久化。
type LocalHandler interface {
	Execute(context.Context, string, contract.ExecuteRequest) (contract.ExecuteResponse, error)
	Events(context.Context, contract.EventRequest) (EventStream, error)
}

type LocalAdapter struct{ Handler LocalHandler }

func (a LocalAdapter) call(ctx context.Context, target Target, operation string, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	if a.Handler == nil {
		return contract.ExecuteResponse{}, ErrNoAdapter
	}
	if target.Transport != "local" {
		return contract.ExecuteResponse{}, ErrInvalidTarget
	}
	if err := validateScope(target, request); err != nil {
		return contract.ExecuteResponse{}, err
	}
	response, err := a.Handler.Execute(ctx, operation, request)
	if err != nil {
		return contract.ExecuteResponse{}, err
	}
	if err := validateResponse(response); err != nil {
		return contract.ExecuteResponse{}, err
	}
	return response, nil
}

func (a LocalAdapter) Invoke(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return a.call(ctx, target, "invoke", request)
}
func (a LocalAdapter) Run(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return a.call(ctx, target, "run", request)
}
func (a LocalAdapter) Resume(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return a.call(ctx, target, "resume", request)
}
func (a LocalAdapter) Cancel(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return a.call(ctx, target, "cancel", request)
}
func (a LocalAdapter) Events(ctx context.Context, target Target, request contract.EventRequest) (EventStream, error) {
	if a.Handler == nil {
		return EventStream{}, ErrNoAdapter
	}
	if target.Transport != "local" || request.ProtocolVersion != contract.ProtocolVersion || request.ContextToken == "" {
		return EventStream{}, ErrInvalidTarget
	}
	if err := request.Scope.Validate(); err != nil {
		return EventStream{}, err
	}
	if request.Scope.AgentInstanceID != target.InstallationID || request.Scope.AgentID != target.AgentID || request.Scope.AgentVersionID != target.AgentVersionID {
		return EventStream{}, ErrTargetMismatch
	}
	return a.Handler.Events(ctx, request)
}

// RemoteAdapter adds request validation and bounded deadlines around a real
// HTTP/gRPC transport. / RemoteAdapter 在真实 HTTP/gRPC Transport 外统一执行
// 请求校验与超时边界，未来拆成微服务时保持相同语义。
type RemoteAdapter struct {
	Transport Transport
	Timeout   time.Duration
}

func (a RemoteAdapter) call(ctx context.Context, target Target, operation string, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	if a.Transport == nil {
		return contract.ExecuteResponse{}, ErrNoAdapter
	}
	if target.Transport == "local" {
		return contract.ExecuteResponse{}, ErrInvalidTarget
	}
	if err := target.Validate(); err != nil {
		return contract.ExecuteResponse{}, err
	}
	if err := validateScope(target, request); err != nil {
		return contract.ExecuteResponse{}, err
	}
	callCtx := ctx
	if a.Timeout > 0 {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, a.Timeout)
		defer cancel()
	}
	var (
		response contract.ExecuteResponse
		err      error
	)
	switch operation {
	case "invoke":
		response, err = a.Transport.Invoke(callCtx, target, request)
	case "run":
		response, err = a.Transport.Run(callCtx, target, request)
	case "resume":
		response, err = a.Transport.Resume(callCtx, target, request)
	case "cancel":
		response, err = a.Transport.Cancel(callCtx, target, request)
	default:
		return contract.ExecuteResponse{}, fmt.Errorf("%w: operation", contract.ErrSchemaValidation)
	}
	if err != nil {
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			return contract.ExecuteResponse{}, context.DeadlineExceeded
		}
		return contract.ExecuteResponse{}, err
	}
	// A third-party transport may return after its own context handling is
	// complete. Never expose a late success after the platform deadline.
	// 第三方 Transport 可能忽略 context 并晚返回；平台超时后不得泄露迟到成功。
	if deadlineErr := callCtx.Err(); deadlineErr != nil {
		return contract.ExecuteResponse{}, deadlineErr
	}
	if err := validateResponse(response); err != nil {
		return contract.ExecuteResponse{}, err
	}
	return response, nil
}

func (a RemoteAdapter) Invoke(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return a.call(ctx, target, "invoke", request)
}
func (a RemoteAdapter) Run(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return a.call(ctx, target, "run", request)
}
func (a RemoteAdapter) Resume(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return a.call(ctx, target, "resume", request)
}
func (a RemoteAdapter) Cancel(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return a.call(ctx, target, "cancel", request)
}
func (a RemoteAdapter) Events(ctx context.Context, target Target, request contract.EventRequest) (EventStream, error) {
	if a.Transport == nil {
		return EventStream{}, ErrNoAdapter
	}
	if target.Transport == "local" {
		return EventStream{}, ErrInvalidTarget
	}
	if err := target.Validate(); err != nil {
		return EventStream{}, err
	}
	installationID := request.Scope.InstallationID
	if installationID == "" {
		installationID = request.Scope.AgentInstanceID
	}
	if request.ProtocolVersion != contract.ProtocolVersion || request.ContextToken == "" || installationID != target.InstallationID || request.Scope.AgentID != target.AgentID || request.Scope.AgentVersionID != target.AgentVersionID {
		return EventStream{}, ErrTargetMismatch
	}
	if err := request.Scope.Validate(); err != nil {
		return EventStream{}, err
	}
	return a.Transport.Events(ctx, target, request)
}

var _ Transport = LocalAdapter{}
var _ Transport = RemoteAdapter{}
