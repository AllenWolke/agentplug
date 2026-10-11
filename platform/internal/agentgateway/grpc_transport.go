package agentgateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	executionv2 "github.com/lexagent/platform/internal/agentgateway/proto"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/telemetry"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	grpcServiceName            = "lexagent.execution.v2.AgentExecutionService"
	maxSignedResumeInputBytes  = 128 << 10
	defaultGRPCMessageSize     = 8 << 20
	grpcResumeDispatchMetadata = "x-platform-resume-dispatch"
	grpcResumeInputMetadata    = "x-platform-resume-input"
)

var (
	// ErrGRPCInvalidResponse indicates that an Agent returned a protobuf
	// response that does not satisfy the platform execution contract.
	// ErrGRPCInvalidResponse 表示 Agent 返回的 protobuf 响应违反平台执行契约。
	ErrGRPCInvalidResponse = errors.New("agent gRPC transport returned an invalid response")
	// Transport status is not a completed application failure: an invocation
	// may have run before its acknowledgement was lost. Never wrap this as an
	// AppError which would authorize a second execution dispatch.
	ErrGRPCTransportUncertain = errors.New("agent gRPC execution outcome is uncertain")
	// ErrGRPCInputEncoding indicates that a JSON-compatible Agent input could
	// not be normalized into the canonical Protobuf Struct representation.
	// ErrGRPCInputEncoding 表示 Agent JSON 输入无法规范化为标准 Protobuf Struct。
	ErrGRPCInputEncoding = errors.New("agent gRPC transport could not encode execution input")
	// ErrGRPCEventProtocol indicates that the server-streaming RPC returned an
	// invalid event envelope, sequence, or timestamp.
	// ErrGRPCEventProtocol 表示服务端流返回非法事件包、序号或时间戳。
	ErrGRPCEventProtocol = errors.New("agent gRPC transport returned an invalid event stream")
	// ErrGRPCServicePath is returned for a registered endpoint that attempts to
	// select a service other than the canonical protobuf service.
	// ErrGRPCServicePath 表示注册端点试图选择非 canonical protobuf 服务。
	ErrGRPCServicePath = errors.New("agent gRPC endpoint contains an invalid service path")
)

// GRPCTransport is the standard Protobuf wire implementation of
// contracts/proto/agent_execution_v2.proto. It deliberately uses generated
// stubs instead of a private JSON codec so Go, Python, Java, and other
// protobuf-capable Agents share one service name and binary wire contract.
// GRPCTransport 是 contracts/proto/agent_execution_v2.proto 的标准 Protobuf
// 传输实现；使用生成 Stub，确保 Go、Python、Java 等 Agent 共用服务名和二进制协议。
type GRPCTransport struct {
	// Dialer is injectable for in-memory tests and service-mesh integrations.
	// Dialer 可注入 bufconn 测试连接或服务网格连接。
	Dialer func(context.Context, Target) (*grpc.ClientConn, error)
	// TLSConfig is cloned before use. It supports custom roots and mTLS client
	// certificates; grpcs always uses at least TLS 1.2.
	// TLSConfig 使用前复制，可配置自定义信任根和 mTLS 客户端证书；grpcs 最低使用 TLS 1.2。
	TLSConfig *tls.Config
	// MaxRecvMsgSize bounds each protobuf response/event message.
	// MaxRecvMsgSize 限制单条 protobuf 响应/事件消息的大小。
	MaxRecvMsgSize int
}

func (t GRPCTransport) Invoke(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return t.execute(ctx, target, "invoke", request)
}

func (t GRPCTransport) Run(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return t.execute(ctx, target, "run", request)
}

func (t GRPCTransport) Resume(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return t.execute(ctx, target, "resume", request)
}

func (t GRPCTransport) Cancel(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return t.execute(ctx, target, "cancel", request)
}

func (t GRPCTransport) execute(ctx context.Context, target Target, operation string, request contract.ExecuteRequest) (returned contract.ExecuteResponse, returnedErr error) {
	ctx, span := telemetry.Start(ctx, "platform.agent.grpc", trace.SpanKindClient)
	defer span.End()
	defer func() {
		if returnedErr != nil {
			telemetry.Failed(span, "AGENT_TRANSPORT_FAILED")
		}
	}()
	if target.Transport != "grpc" && target.Transport != "grpcs" {
		return contract.ExecuteResponse{}, ErrInvalidTarget
	}
	if err := target.Validate(); err != nil {
		return contract.ExecuteResponse{}, err
	}
	if err := validateScope(target, request); err != nil {
		return contract.ExecuteResponse{}, err
	}
	if _, err := grpcServicePath(target); err != nil {
		return contract.ExecuteResponse{}, err
	}
	conn, closeConn, err := t.connection(ctx, target)
	if err != nil {
		return contract.ExecuteResponse{}, err
	}
	if closeConn {
		defer conn.Close()
	}
	callCtx, err := grpcOutgoingContext(ctx, request.ContextToken, request.ResumeInput)
	if err != nil {
		return contract.ExecuteResponse{}, err
	}
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(callCtx, carrier)
	if parent := carrier["traceparent"]; parent != "" {
		callCtx = metadata.AppendToOutgoingContext(callCtx, "traceparent", parent)
	}
	if state := carrier["tracestate"]; state != "" {
		callCtx = metadata.AppendToOutgoingContext(callCtx, "tracestate", state)
	}
	protoRequest, err := toProtoExecuteRequest(request)
	if err != nil {
		return contract.ExecuteResponse{}, err
	}
	client := executionv2.NewAgentExecutionServiceClient(conn)
	var response *executionv2.ExecuteResponse
	switch operation {
	case "invoke":
		response, err = client.Invoke(callCtx, protoRequest)
	case "run":
		response, err = client.Run(callCtx, protoRequest)
	case "resume":
		response, err = client.Resume(callCtx, protoRequest)
	case "cancel":
		response, err = client.Cancel(callCtx, protoRequest)
	default:
		return contract.ExecuteResponse{}, fmt.Errorf("unsupported gRPC operation")
	}
	if err != nil {
		return contract.ExecuteResponse{}, mapGRPCError(err)
	}
	return fromProtoExecuteResponse(response)
}

func (t GRPCTransport) Events(ctx context.Context, target Target, request contract.EventRequest) (EventStream, error) {
	if target.Transport != "grpc" && target.Transport != "grpcs" {
		return EventStream{}, ErrInvalidTarget
	}
	if err := target.Validate(); err != nil {
		return EventStream{}, err
	}
	if err := request.Validate(); err != nil {
		return EventStream{}, err
	}
	if _, err := grpcServicePath(target); err != nil {
		return EventStream{}, err
	}
	installationID := request.Scope.InstallationID
	if installationID == "" {
		installationID = request.Scope.AgentInstanceID
	}
	if installationID != target.InstallationID || request.Scope.AgentID != target.AgentID || request.Scope.AgentVersionID != target.AgentVersionID {
		return EventStream{}, ErrTargetMismatch
	}
	conn, closeConn, err := t.connection(ctx, target)
	if err != nil {
		return EventStream{}, err
	}
	callCtx := grpcOutgoingAuthContext(ctx, request.ContextToken)
	protoRequest := &executionv2.EventRequest{
		ProtocolVersion:    request.ProtocolVersion,
		ContextToken:       request.ContextToken,
		Scope:              toProtoScope(request.Scope),
		AfterSeq:           request.AfterSeq,
		PolicySnapshotHash: request.PolicySnapshotHash,
	}
	stream, err := executionv2.NewAgentExecutionServiceClient(conn).Events(callCtx, protoRequest)
	if err != nil {
		if closeConn {
			_ = conn.Close()
		}
		return EventStream{}, mapGRPCError(err)
	}
	streamCtx, cancel := context.WithCancel(ctx)
	events := make(chan contract.ExecutionEvent)
	errorsCh := make(chan error, 1)
	go receiveGRPCEvents(streamCtx, stream, request.Scope.RunID, request.AfterSeq, events, errorsCh, cancel, conn, closeConn)
	return EventStream{
		Events: events,
		Errors: errorsCh,
		Close: func() error {
			cancel()
			if closeConn {
				return conn.Close()
			}
			return nil
		},
	}, nil
}

func receiveGRPCEvents(ctx context.Context, stream executionv2.AgentExecutionService_EventsClient, runID string, afterSeq uint64, events chan<- contract.ExecutionEvent, errorsCh chan<- error, cancel context.CancelFunc, conn *grpc.ClientConn, closeConn bool) {
	defer close(events)
	defer close(errorsCh)
	defer cancel()
	if closeConn {
		defer conn.Close()
	}
	previous := afterSeq
	for {
		item, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			if (errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled) && ctx.Err() != nil {
				return
			}
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil {
				errorsCh <- ctx.Err()
				return
			}
			errorsCh <- mapGRPCError(err)
			return
		}
		event, err := fromProtoExecutionEvent(item)
		if err != nil || event.RunID != runID || event.Seq <= previous {
			errorsCh <- ErrGRPCEventProtocol
			return
		}
		previous = event.Seq
		select {
		case events <- event:
		case <-ctx.Done():
			return
		}
	}
}

func (t GRPCTransport) connection(ctx context.Context, target Target) (*grpc.ClientConn, bool, error) {
	if t.Dialer != nil {
		conn, err := t.Dialer(ctx, target)
		return conn, false, err
	}
	u, err := url.Parse(target.Endpoint)
	if err != nil || u.Host == "" {
		return nil, false, ErrInvalidTarget
	}
	options := []grpc.DialOption{grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(t.maxRecvMsgSize()), grpc.MaxCallSendMsgSize(defaultGRPCMessageSize))}
	if u.Scheme == "grpcs" {
		config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		if t.TLSConfig != nil {
			config = t.TLSConfig.Clone()
			if config.MinVersion == 0 {
				config.MinVersion = tls.VersionTLS12
			}
			if config.ServerName == "" {
				config.ServerName = u.Hostname()
			}
		}
		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	} else {
		options = append(options, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	// grpc.NewClient delays network access until the first RPC. Keeping endpoint
	// resolution here preserves the gateway's testable Dialer seam.
	// grpc.NewClient 延迟到首次 RPC 才访问网络，保留可测试的 Dialer 接缝。
	conn, err := grpc.NewClient(u.Host, options...)
	if err != nil {
		return nil, false, err
	}
	return conn, true, nil
}

func grpcServicePath(target Target) (string, error) {
	u, err := url.Parse(target.Endpoint)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", ErrGRPCServicePath
	}
	service := strings.Trim(u.EscapedPath(), "/")
	if service != "" && service != grpcServiceName {
		return "", ErrGRPCServicePath
	}
	return grpcServiceName, nil
}

func grpcOutgoingAuthContext(ctx context.Context, token string) context.Context {
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set("authorization", "Bearer "+token)
	return metadata.NewOutgoingContext(ctx, md)
}

func grpcOutgoingContext(ctx context.Context, token string, resumeInput map[string]any) (context.Context, error) {
	ctx = grpcOutgoingAuthContext(ctx, token)
	if resumeInput == nil {
		return ctx, nil
	}
	raw, err := json.Marshal(resumeInput)
	if err != nil {
		return nil, fmt.Errorf("encode gRPC resume metadata: %w", err)
	}
	if len(raw) == 0 || len(raw) > maxSignedResumeInputBytes {
		return nil, fmt.Errorf("gRPC signed resume input exceeds size limit")
	}
	// Validate size only; resume data is a signed Protobuf field, not metadata.
	// 此处只验证大小；恢复决策必须在签名 Proto 正文中传递。
	return ctx, nil
}

func (t GRPCTransport) maxRecvMsgSize() int {
	if t.MaxRecvMsgSize > 0 {
		return t.MaxRecvMsgSize
	}
	return defaultGRPCMessageSize
}

func toProtoScope(scope contract.ScopeKey) *executionv2.ScopeKey {
	return &executionv2.ScopeKey{
		TenantId: scope.TenantID, DepartmentId: scope.DepartmentID, ApplicationId: scope.ApplicationID,
		AgentInstanceId: scope.AgentInstanceID, AgentId: scope.AgentID, AgentVersionId: scope.AgentVersionID,
		PrincipalType: scope.PrincipalType, PrincipalId: scope.PrincipalID, SessionId: scope.SessionID,
		RunId: scope.RunID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceId: scope.TraceID,
		ParentRunId: scope.ParentRunID, DelegationDepth: scope.DelegationDepth, InstallationId: scope.InstallationID,
	}
}

func toProtoExecuteRequest(request contract.ExecuteRequest) (*executionv2.ExecuteRequest, error) {
	// Normalize typed Go structs, json.Number, and other JSON-compatible values
	// through the same JSON boundary used by HTTP persistence/signing before
	// constructing Protobuf Struct. This keeps direct gRPC dispatch equivalent
	// to the browser Run path, which naturally crosses JSON serialization.
	// 将 Go 结构体、json.Number 等 JSON 兼容值先经过与 HTTP 持久化/签名相同的
	// JSON 边界规范化，再构造 Protobuf Struct，使直接 gRPC 调度与浏览器 Run 一致。
	rawInput, err := json.Marshal(request.Input)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal JSON input", ErrGRPCInputEncoding)
	}
	var normalizedInput map[string]any
	if err := json.Unmarshal(rawInput, &normalizedInput); err != nil || normalizedInput == nil {
		return nil, fmt.Errorf("%w: normalize JSON object", ErrGRPCInputEncoding)
	}
	input, err := structpb.NewStruct(normalizedInput)
	if err != nil {
		return nil, fmt.Errorf("%w: build Protobuf Struct", ErrGRPCInputEncoding)
	}
	var resumeInput *structpb.Struct
	if request.ResumeInput != nil {
		resumeInput, err = structpb.NewStruct(request.ResumeInput)
		if err != nil {
			return nil, fmt.Errorf("%w: resume input", ErrGRPCInputEncoding)
		}
	}
	return &executionv2.ExecuteRequest{
		ProtocolVersion: request.ProtocolVersion, ContextToken: request.ContextToken, Scope: toProtoScope(request.Scope),
		Operation: request.Operation, IdempotencyKey: request.IdempotencyKey, InputSchema: request.InputSchema, Input: input, ResumeInput: resumeInput,
	}, nil
}

func fromProtoExecuteResponse(response *executionv2.ExecuteResponse) (contract.ExecuteResponse, error) {
	if response == nil || response.ProtocolVersion != contract.ProtocolVersion || response.RunId == "" || response.Status == "" {
		return contract.ExecuteResponse{}, ErrGRPCInvalidResponse
	}
	if (response.Handoff != nil || response.AgentGroupHandoff != nil) && response.Status != "waiting" ||
		(response.Handoff != nil && response.AgentGroupHandoff != nil) {
		return contract.ExecuteResponse{}, ErrGRPCInvalidResponse
	}
	if response.Error != nil {
		if response.Status != "failed" || response.Error.Code == "" || response.Error.Message == "" {
			return contract.ExecuteResponse{}, ErrGRPCInvalidResponse
		}
		appErr := contract.AppError{
			Code: response.Error.Code, Message: response.Error.Message, Retryable: response.Error.Retryable,
			Details: structToMap(response.Error.Details),
		}
		failed := contract.ExecuteResponse{
			ProtocolVersion: response.ProtocolVersion, RunID: response.RunId, Status: response.Status,
			OutputSchema: response.OutputSchema, Output: structToMap(response.Output), Error: &appErr,
		}
		completed, err := NewCompletedExecutionFailure(failed)
		if err != nil {
			return contract.ExecuteResponse{}, ErrGRPCInvalidResponse
		}
		return failed, completed
	}
	if response.Status == "failed" {
		return contract.ExecuteResponse{}, ErrGRPCInvalidResponse
	}
	var handoff *contract.HandlerHandoff
	if value := response.Handoff; value != nil {
		handoff = &contract.HandlerHandoff{
			Version: value.Version, RunID: value.RunId, ExecutionRevision: value.ExecutionRevision,
			BodyHash: value.BodyHash, LeaseTokenHash: value.LeaseTokenHash, InputFingerprint: value.InputFingerprint,
			OriginOperation: value.OriginOperation, HarnessKey: value.HarnessKey, ToolName: value.ToolName, CallID: value.CallId,
			LastEventSeq: value.LastEventSeq,
		}
	}
	var groupHandoff *contract.AgentGroupHandoff
	if value := response.AgentGroupHandoff; value != nil {
		if value.Checkpoint == nil {
			return contract.ExecuteResponse{}, ErrGRPCInvalidResponse
		}
		cp := value.Checkpoint
		expiresAt, err := time.Parse(time.RFC3339Nano, cp.ExpiresAt)
		if err != nil {
			return contract.ExecuteResponse{}, ErrGRPCInvalidResponse
		}
		checkpoint := contract.RecoveryCheckpointReference{
			StateKey: cp.StateKey, Revision: cp.Revision, SchemaID: cp.SchemaId,
			ContentHash: cp.ContentHash, ExecutionRevision: cp.ExecutionRevision, ExpiresAt: expiresAt,
		}
		if checkpoint.Validate(value.ExecutionRevision) != nil || value.RunId != response.RunId {
			return contract.ExecuteResponse{}, ErrGRPCInvalidResponse
		}
		groupHandoff = &contract.AgentGroupHandoff{
			Version: value.Version, RunID: value.RunId, ExecutionRevision: value.ExecutionRevision,
			BodyHash: value.BodyHash, LeaseTokenHash: value.LeaseTokenHash, InputFingerprint: value.InputFingerprint,
			OriginOperation: value.OriginOperation, GroupKey: value.GroupKey, OperationKey: value.OperationKey,
			LastEventSeq: value.LastEventSeq, Checkpoint: checkpoint, ChildKeys: append([]string(nil), value.ChildKeys...),
		}
	}
	return contract.ExecuteResponse{
		ProtocolVersion: response.ProtocolVersion, RunID: response.RunId, Status: response.Status,
		OutputSchema: response.OutputSchema, Output: structToMap(response.Output), Handoff: handoff, AgentGroupHandoff: groupHandoff,
	}, nil
}

func fromProtoExecutionEvent(item *executionv2.ExecutionEvent) (contract.ExecutionEvent, error) {
	if item == nil || item.RunId == "" || item.Seq == 0 || item.Seq > contract.MaxAgentEventSequence || item.EventType == "" || item.Payload == nil || item.OccurredAt == nil || item.OccurredAt.CheckValid() != nil {
		return contract.ExecutionEvent{}, ErrGRPCEventProtocol
	}
	return contract.ExecutionEvent{
		RunID: item.RunId, Seq: item.Seq, EventType: item.EventType,
		OccurredAt: item.OccurredAt.AsTime().UTC(), Payload: item.Payload.AsMap(),
	}, nil
}

func structToMap(value *structpb.Struct) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value.AsMap()
}

func mapGRPCError(err error) error {
	if err == nil {
		return nil
	}
	var appErr contract.AppError
	if errors.As(err, &appErr) {
		return err
	}
	switch status.Code(err) {
	case codes.DeadlineExceeded:
		return fmt.Errorf("%w: %w", ErrGRPCTransportUncertain, context.DeadlineExceeded)
	case codes.Unavailable, codes.ResourceExhausted:
		return ErrGRPCTransportUncertain
	case codes.Canceled:
		return context.Canceled
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.Unauthenticated:
		// A status rejection still carries no validated terminal Run envelope.
		// Only fromProtoExecuteResponse may supply an application outcome.
		return ErrGRPCTransportUncertain
	default:
		return fmt.Errorf("agent gRPC call failed: %w", err)
	}
}

// Compile-time conformance keeps the gRPC adapter at the transport boundary.
// 编译期断言保证 gRPC Adapter 只依赖传输边界。
var _ Transport = GRPCTransport{}

// Used by event test servers and optional Agent implementations when mapping
// domain events to the canonical protobuf contract.
// 供事件测试服务及 Agent 实现将领域事件映射到 canonical protobuf 契约。
func toProtoExecutionEvent(event contract.ExecutionEvent) (*executionv2.ExecutionEvent, error) {
	if event.Seq == 0 || event.Seq > contract.MaxAgentEventSequence {
		return nil, ErrGRPCEventProtocol
	}
	payload, err := structpb.NewStruct(event.Payload)
	if err != nil {
		return nil, err
	}
	if event.OccurredAt.IsZero() {
		return nil, ErrGRPCEventProtocol
	}
	return &executionv2.ExecutionEvent{RunId: event.RunID, Seq: event.Seq, EventType: event.EventType, OccurredAt: timestamppb.New(event.OccurredAt.UTC()), Payload: payload}, nil
}
