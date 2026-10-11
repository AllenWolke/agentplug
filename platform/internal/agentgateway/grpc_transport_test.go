package agentgateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	executionv2 "github.com/lexagent/platform/internal/agentgateway/proto"
	"github.com/lexagent/platform/internal/contract"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const testGRPCRunID = "grpc-run-1"

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer strings.Builder
}

func (b *synchronizedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(value)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func grpcTestScope() contract.ScopeKey {
	return contract.ScopeKey{
		TenantID: "tenant", DepartmentID: "department", ApplicationID: "application",
		AgentInstanceID: "installation", InstallationID: "installation", AgentID: "agent",
		AgentVersionID: "version", PrincipalType: "user", PrincipalID: "user", SessionID: "session",
		RunID: testGRPCRunID, AuthorizationEpoch: 1, TraceID: strings.Repeat("a", 32),
	}
}

func grpcTestExecuteRequest(operation string) contract.ExecuteRequest {
	return contract.ExecuteRequest{
		ProtocolVersion: contract.ProtocolVersion,
		ContextToken:    "0123456789012345678901234567890123456789",
		Scope:           grpcTestScope(),
		Operation:       operation,
		IdempotencyKey:  "grpc-idempotency-key",
		InputSchema:     "schema://agent/input/v1",
		Input:           map[string]any{"question": "hello"},
	}
}

func grpcTestEventRequest() contract.EventRequest {
	return contract.EventRequest{
		ProtocolVersion: contract.ProtocolVersion,
		ContextToken:    "0123456789012345678901234567890123456789",
		Scope:           grpcTestScope(), AfterSeq: 0, PolicySnapshotHash: strings.Repeat("b", 64),
	}
}

type grpcTransportTestService struct {
	executionv2.UnimplementedAgentExecutionServiceServer
	mu           sync.Mutex
	metadata     map[string]metadata.MD
	requests     map[string]*executionv2.ExecuteRequest
	eventRequest *executionv2.EventRequest
}

func newGRPCTransportTestService() *grpcTransportTestService {
	return &grpcTransportTestService{metadata: make(map[string]metadata.MD), requests: make(map[string]*executionv2.ExecuteRequest)}
}

func (s *grpcTransportTestService) record(ctx context.Context, name string, request *executionv2.ExecuteRequest) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.metadata[name] = md.Copy()
	s.requests[name] = request
}

func (s *grpcTransportTestService) response(ctx context.Context, name string, request *executionv2.ExecuteRequest) (*executionv2.ExecuteResponse, error) {
	s.record(ctx, name, request)
	if failure, ok := request.Input.AsMap()["fixture_failure"].(string); ok {
		return &executionv2.ExecuteResponse{
			ProtocolVersion: contract.ProtocolVersion, RunId: request.Scope.RunId, Status: "failed",
			Error: &executionv2.AppError{Code: failure, Message: "fixed safe failure", Retryable: failure == "CAPABILITY_UNAVAILABLE"},
		}, nil
	}
	return &executionv2.ExecuteResponse{
		ProtocolVersion: contract.ProtocolVersion,
		RunId:           request.Scope.RunId,
		Status:          "succeeded",
		OutputSchema:    "schema://agent/output/v1",
		Output:          mustProtoStruct(map[string]any{"operation": request.Operation, "question": request.Input.AsMap()["question"]}),
	}, nil
}

func (s *grpcTransportTestService) Invoke(ctx context.Context, request *executionv2.ExecuteRequest) (*executionv2.ExecuteResponse, error) {
	return s.response(ctx, "invoke", request)
}

func TestGRPCTransportPreservesDomainPolicyAndUpstreamClassification(t *testing.T) {
	dialer, _ := startGRPCTransportTestServer(t)
	transport := GRPCTransport{Dialer: dialer}
	for _, code := range []string{"RULE_BUNDLE_INVALID", "POLICY_DENIED", "UNSUPPORTED_REPORT_TYPE", "CAPABILITY_UNAVAILABLE"} {
		t.Run(code, func(t *testing.T) {
			request := grpcTestExecuteRequest("invoke")
			request.Input = map[string]any{"fixture_failure": code}
			response, err := transport.Invoke(context.Background(), grpcTestTarget(), request)
			var typed contract.AppError
			var completed CompletedExecutionFailure
			if !errors.As(err, &typed) || typed.Code != code || typed.Retryable != (code == "CAPABILITY_UNAVAILABLE") ||
				!errors.As(err, &completed) || completed.Response.RunID != request.Scope.RunID ||
				completed.Response.ProtocolVersion != contract.ProtocolVersion || completed.Response.Status != "failed" ||
				response.RunID != request.Scope.RunID || response.Status != "failed" {
				t.Fatalf("gRPC classification lost: response=%+v error=%v", response, err)
			}
		})
	}
}
func (s *grpcTransportTestService) Run(ctx context.Context, request *executionv2.ExecuteRequest) (*executionv2.ExecuteResponse, error) {
	return s.response(ctx, "run", request)
}
func (s *grpcTransportTestService) Resume(ctx context.Context, request *executionv2.ExecuteRequest) (*executionv2.ExecuteResponse, error) {
	return s.response(ctx, "resume", request)
}
func (s *grpcTransportTestService) Cancel(ctx context.Context, request *executionv2.ExecuteRequest) (*executionv2.ExecuteResponse, error) {
	return s.response(ctx, "cancel", request)
}
func (s *grpcTransportTestService) Events(request *executionv2.EventRequest, stream executionv2.AgentExecutionService_EventsServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	s.mu.Lock()
	s.metadata["events"] = md.Copy()
	s.eventRequest = request
	s.mu.Unlock()
	for seq, eventType := range []string{"started", "task_completed"} {
		if err := stream.Send(&executionv2.ExecutionEvent{
			RunId: request.Scope.RunId, Seq: uint64(seq + 1), EventType: eventType,
			OccurredAt: timestamppb.New(time.Date(2026, 9, 25, 1, 2, seq, 0, time.UTC)),
			Payload:    mustProtoStruct(map[string]any{"seq": seq + 1}),
		}); err != nil {
			return err
		}
	}
	return nil
}

func mustProtoStruct(value map[string]any) *structpb.Struct {
	result, err := structpb.NewStruct(value)
	if err != nil {
		panic(err)
	}
	return result
}

func startGRPCTransportTestServer(t *testing.T) (func(context.Context, Target) (*grpc.ClientConn, error), *grpcTransportTestService) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	service := newGRPCTransportTestService()
	executionv2.RegisterAgentExecutionServiceServer(server, service)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	dialer := func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }
	return func(ctx context.Context, _ Target) (*grpc.ClientConn, error) {
		return grpc.NewClient(
			"passthrough:///grpc-test",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1<<20), grpc.MaxCallSendMsgSize(1<<20)),
		)
	}, service
}

func grpcTestTarget() Target {
	return Target{
		InstallationID: "installation", AgentID: "agent", AgentVersionID: "version",
		Endpoint: "grpc://bufnet/" + grpcServiceName, Transport: "grpc", Revision: 1, ManifestHash: "sha256:grpc-test",
	}
}

func TestGRPCTransportUsesCanonicalProtobufServiceAndAuth(t *testing.T) {
	dialer, service := startGRPCTransportTestServer(t)
	transport := GRPCTransport{Dialer: dialer}
	target := grpcTestTarget()
	for _, operation := range []string{"invoke", "run", "resume", "cancel"} {
		request := grpcTestExecuteRequest(operation)
		if operation == "resume" {
			request.ResumeInput = map[string]any{"decision": "approve"}
		}
		var response contract.ExecuteResponse
		var err error
		switch operation {
		case "invoke":
			response, err = transport.Invoke(context.Background(), target, request)
		case "run":
			response, err = transport.Run(context.Background(), target, request)
		case "resume":
			response, err = transport.Resume(context.Background(), target, request)
		case "cancel":
			response, err = transport.Cancel(context.Background(), target, request)
		}
		if err != nil {
			t.Fatalf("%s returned error: %v", operation, err)
		}
		if response.ProtocolVersion != contract.ProtocolVersion || response.RunID != testGRPCRunID || response.Status != "succeeded" || response.Output["operation"] != operation {
			t.Fatalf("unexpected %s response: %+v", operation, response)
		}
	}

	service.mu.Lock()
	defer service.mu.Unlock()
	for _, operation := range []string{"invoke", "run", "resume", "cancel"} {
		if service.requests[operation] == nil {
			t.Fatalf("canonical protobuf server did not receive %s RPC", operation)
		}
		if got := service.metadata[operation].Get("authorization"); len(got) != 1 || got[0] != "Bearer "+grpcTestExecuteRequest(operation).ContextToken {
			t.Fatalf("%s authorization metadata = %#v", operation, got)
		}
	}
	if got := service.metadata["resume"].Get(grpcResumeDispatchMetadata); len(got) != 0 {
		t.Fatalf("resume dispatch metadata = %#v", got)
	}
	if got := service.metadata["resume"].Get(grpcResumeInputMetadata); len(got) != 0 {
		t.Fatalf("resume input metadata = %#v", got)
	}
	if service.requests["resume"].ResumeInput.AsMap()["decision"] != "approve" {
		t.Fatal("signed resume body lost its decision")
	}
	if got := service.metadata["run"].Get(grpcResumeDispatchMetadata); len(got) != 0 {
		t.Fatalf("non-resume request received privileged resume metadata: %#v", got)
	}
}

func TestToProtoExecuteRequestNormalizesJSONCompatiblePolicyValues(t *testing.T) {
	type modelPolicy struct {
		Provider  string `json:"provider"`
		MaxTokens int    `json:"max_tokens"`
	}
	request := grpcTestExecuteRequest("invoke")
	request.Input["policy_snapshot"] = map[string]any{
		"model":       modelPolicy{Provider: "local", MaxTokens: 128},
		"temperature": json.Number("0.25"),
	}

	protoRequest, err := toProtoExecuteRequest(request)
	if err != nil {
		t.Fatalf("JSON-compatible policy snapshot could not be encoded: %v", err)
	}
	policy := protoRequest.Input.AsMap()["policy_snapshot"].(map[string]any)
	model := policy["model"].(map[string]any)
	if model["provider"] != "local" || model["max_tokens"] != float64(128) || policy["temperature"] != float64(0.25) {
		t.Fatalf("policy snapshot was not preserved at the JSON boundary: %#v", policy)
	}

	request.Input["unsupported"] = make(chan int)
	if _, err := toProtoExecuteRequest(request); !errors.Is(err, ErrGRPCInputEncoding) {
		t.Fatalf("non-JSON input error = %v, want ErrGRPCInputEncoding", err)
	}
}

func TestGRPCTransportEventsUseCanonicalProtobufAndAuth(t *testing.T) {
	dialer, service := startGRPCTransportTestServer(t)
	transport := GRPCTransport{Dialer: dialer}
	stream, err := transport.Events(context.Background(), grpcTestTarget(), grpcTestEventRequest())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	var got []contract.ExecutionEvent
	for event := range stream.Events {
		got = append(got, event)
	}
	if len(got) != 2 || got[0].Seq != 1 || got[1].EventType != "task_completed" || got[0].OccurredAt.IsZero() {
		t.Fatalf("unexpected events: %+v", got)
	}
	if err, ok := <-stream.Errors; ok && err != nil {
		t.Fatalf("event stream error: %v", err)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.eventRequest == nil || service.eventRequest.Scope.RunId != testGRPCRunID {
		t.Fatalf("canonical Events RPC request was not received: %+v", service.eventRequest)
	}
	if got := service.metadata["events"].Get("authorization"); len(got) != 1 || got[0] != "Bearer "+grpcTestEventRequest().ContextToken {
		t.Fatalf("events authorization metadata = %#v", got)
	}
}

func TestGRPCTransportDefaultsToCanonicalServicePath(t *testing.T) {
	dialer, service := startGRPCTransportTestServer(t)
	transport := GRPCTransport{Dialer: dialer}
	target := grpcTestTarget()
	target.Endpoint = "grpc://bufnet"
	if _, err := transport.Invoke(context.Background(), target, grpcTestExecuteRequest("invoke")); err != nil {
		t.Fatalf("default canonical service path failed: %v", err)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.requests["invoke"] == nil {
		t.Fatal("canonical default service was not called")
	}
}

func TestGRPCTransportRejectsNonCanonicalOrUnsafeServicePath(t *testing.T) {
	dialer, _ := startGRPCTransportTestServer(t)
	transport := GRPCTransport{Dialer: dialer}
	for _, endpoint := range []string{
		"grpc://bufnet/../private",
		"grpc://bufnet/agent.execution.v2.Execution",
		"grpc://bufnet/" + grpcServiceName + "?method=Invoke",
	} {
		target := grpcTestTarget()
		target.Endpoint = endpoint
		_, err := transport.Invoke(context.Background(), target, grpcTestExecuteRequest("invoke"))
		wantErr := ErrGRPCServicePath
		if strings.Contains(endpoint, "?") {
			// Generic target validation rejects queries before gRPC dispatch.
			wantErr = ErrInvalidTarget
		}
		if !errors.Is(err, wantErr) {
			t.Fatalf("endpoint %q error = %v, want %v", endpoint, err, wantErr)
		}
	}
}

func TestGRPCTransportBoundsAndValidatesResumeMetadata(t *testing.T) {
	dialer, service := startGRPCTransportTestServer(t)
	transport := GRPCTransport{Dialer: dialer}
	request := grpcTestExecuteRequest("resume")
	request.ResumeInput = map[string]any{"bad": make(chan int)}
	if _, err := transport.Resume(context.Background(), grpcTestTarget(), request); err == nil {
		t.Fatal("non-JSON resume input must be rejected before network call")
	}
	request.ResumeInput = map[string]any{"data": strings.Repeat("x", maxSignedResumeInputBytes)}
	if _, err := transport.Resume(context.Background(), grpcTestTarget(), request); err == nil {
		t.Fatal("oversized resume metadata must be rejected before network call")
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.requests["resume"] != nil {
		t.Fatal("invalid resume metadata reached the remote service")
	}
}

func TestFromProtoRejectsMalformedResponseAndEvent(t *testing.T) {
	if _, err := fromProtoExecuteResponse(&executionv2.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunId: "run", Status: "failed", Error: &executionv2.AppError{Code: "FAILED"}}); !errors.Is(err, ErrGRPCInvalidResponse) {
		t.Fatalf("malformed app error = %v", err)
	}
	if _, err := fromProtoExecuteResponse(&executionv2.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunId: "run", Status: "succeeded", Error: &executionv2.AppError{Code: "FAILED", Message: "not a terminal failure"}}); !errors.Is(err, ErrGRPCInvalidResponse) {
		t.Fatalf("error on non-failed response = %v", err)
	}
	if _, err := fromProtoExecuteResponse(&executionv2.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunId: "run", Status: "failed"}); !errors.Is(err, ErrGRPCInvalidResponse) {
		t.Fatalf("failed response without error = %v", err)
	}
	converted, err := fromProtoExecuteResponse(&executionv2.ExecuteResponse{
		ProtocolVersion: contract.ProtocolVersion, RunId: "run", Status: "failed",
		OutputSchema: "schema://agent/output/v1", Output: mustProtoStruct(map[string]any{"partial": "kept"}),
		Error: &executionv2.AppError{Code: "CAPABILITY_UNAVAILABLE", Message: "completed failure", Retryable: true},
	})
	var completed CompletedExecutionFailure
	var appErr contract.AppError
	if !errors.As(err, &completed) || !errors.As(err, &appErr) || converted.RunID != "run" ||
		completed.Response.RunID != "run" || completed.Response.ProtocolVersion != contract.ProtocolVersion ||
		completed.Response.Error == nil || completed.Response.Error.Code != "CAPABILITY_UNAVAILABLE" ||
		completed.Response.Output["partial"] != "kept" {
		t.Fatalf("valid terminal failure proof lost response or unwrap: response=%+v err=%v", converted, err)
	}
	if _, err := fromProtoExecutionEvent(&executionv2.ExecutionEvent{RunId: "run", Seq: 1, EventType: "started", Payload: mustProtoStruct(map[string]any{})}); !errors.Is(err, ErrGRPCEventProtocol) {
		t.Fatalf("event without timestamp = %v", err)
	}
}

func TestMapGRPCErrorPreservesUnknownExecutionOutcome(t *testing.T) {
	for _, code := range []codes.Code{codes.Unavailable, codes.ResourceExhausted, codes.DeadlineExceeded, codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.Unauthenticated} {
		mapped := mapGRPCError(status.Error(code, "untrusted transport text"))
		var appErr contract.AppError
		if !errors.Is(mapped, ErrGRPCTransportUncertain) || errors.As(mapped, &appErr) {
			t.Fatal("uncertain transport result became a completed application failure", code)
		}
	}
	if mapped := mapGRPCError(io.EOF); mapped == nil {
		t.Fatal("EOF should remain an explicit transport error")
	}
}

func TestGRPCTransportInteropWithPythonBridge(t *testing.T) {
	if os.Getenv("LEXAGENT_RUN_PYTHON_GRPC_INTEROP") != "1" {
		t.Skip("set LEXAGENT_RUN_PYTHON_GRPC_INTEROP=1 to run the Go-to-Python gRPC interoperability test")
	}
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	python := os.Getenv("LEXAGENT_PYTHON")
	if python == "" {
		python = "python"
	}
	script := filepath.Join(root, "sdk", "python", "tests", "grpc_bridge_interop_server.py")
	cmd := exec.Command(python, script)
	cmd.Dir = root
	pythonPath := filepath.Join(root, "sdk", "python")
	if existing := os.Getenv("PYTHONPATH"); existing != "" {
		pythonPath += string(os.PathListSeparator) + existing
	}
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr synchronizedBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Skipf("Python gRPC interop server cannot start: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()
	portLine := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			portLine <- scanner.Text()
			return
		}
		portLine <- ""
	}()
	var port int
	select {
	case line := <-portLine:
		port, err = strconv.Atoi(strings.TrimSpace(line))
		if err != nil || port < 1 || port > 65535 {
			t.Fatalf("Python bridge failed to publish its gRPC port; stdout=%q stderr=%q", line, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for Python bridge startup; stderr=%q", stderr.String())
	}

	target := grpcTestTarget()
	target.Endpoint = "grpc://127.0.0.1:" + strconv.Itoa(port)
	transport := GRPCTransport{}
	for _, operation := range []string{"invoke", "run", "resume", "cancel"} {
		request := grpcTestExecuteRequest(operation)
		if operation == "resume" {
			request.ResumeInput = map[string]any{"approval": "approved"}
		}
		var response contract.ExecuteResponse
		switch operation {
		case "invoke":
			response, err = transport.Invoke(context.Background(), target, request)
		case "run":
			response, err = transport.Run(context.Background(), target, request)
		case "resume":
			response, err = transport.Resume(context.Background(), target, request)
		case "cancel":
			response, err = transport.Cancel(context.Background(), target, request)
		}
		if err != nil {
			t.Fatalf("Go client -> Python bridge %s failed: %v", operation, err)
		}
		if response.RunID != testGRPCRunID || response.Output["operation"] != operation || response.Output["authorization"] != "Bearer "+request.ContextToken {
			t.Fatalf("Python bridge returned an unexpected %s response: %+v", operation, response)
		}
		if operation == "resume" && (response.Output["resume_dispatch"] != "" || response.Output["resume_input"] != `{"approval":"approved"}`) {
			t.Fatalf("Python bridge did not preserve trusted ResumeInput metadata: %+v", response.Output)
		}
	}
	eventStream, err := transport.Events(context.Background(), target, grpcTestEventRequest())
	if err != nil {
		t.Fatalf("Go client -> Python bridge Events failed: %v", err)
	}
	defer eventStream.Close()
	var events []contract.ExecutionEvent
	for event := range eventStream.Events {
		events = append(events, event)
	}
	if len(events) != 1 || events[0].EventType != "started" || events[0].Payload["source"] != "python-bridge" || events[0].OccurredAt.IsZero() {
		t.Fatalf("Go client received invalid Python bridge events: %+v", events)
	}
	if eventErr, ok := <-eventStream.Errors; ok && eventErr != nil {
		t.Fatalf("Go client received Python bridge event error: %v", eventErr)
	}
}

func TestTargetValidatesTransportFamilyAndSecureScheme(t *testing.T) {
	for _, target := range []Target{
		{InstallationID: "i", AgentID: "a", AgentVersionID: "v", Endpoint: "grpc://agent:9000", Transport: "grpc", Revision: 1, ManifestHash: "hash"},
		{InstallationID: "i", AgentID: "a", AgentVersionID: "v", Endpoint: "grpcs://agent:9443", Transport: "grpc", Revision: 1, ManifestHash: "hash"},
		{InstallationID: "i", AgentID: "a", AgentVersionID: "v", Endpoint: "https://agent:443", Transport: "http", Revision: 1, ManifestHash: "hash"},
	} {
		if err := target.Validate(); err != nil {
			t.Fatalf("valid transport family target %+v rejected: %v", target, err)
		}
	}
	invalid := Target{InstallationID: "i", AgentID: "a", AgentVersionID: "v", Endpoint: "grpcs://agent:9443", Transport: "http", Revision: 1, ManifestHash: "hash"}
	if err := invalid.Validate(); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("mismatched transport family error = %v", err)
	}
}
