package agentplatform

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ExecutionServer is the SDK's transport封装: it mounts the full Execution v2
// surface (invoke + optional run/resume/cancel/events lifecycle entries),
// verifies every caller through the platform PEP, and keeps the business seam
// behind the verified boundary. Generated Agents configure it instead of
// re-implementing transport, verification or the run state machine.
// ExecutionServer 是 SDK 的传输封装：挂载完整 Execution v2 入口（invoke 与可选
// run/resume/cancel/events 生命周期入口），所有调用先经平台 PEP 校验，业务接缝
// 保持在已验证边界之后。生成 Agent 只做配置，不重复实现传输、校验与状态机。

// EventSink lets a RunHandler append progress events through the store.
// EventSink 让 RunHandler 通过 Store 追加进度事件。
type EventSink interface {
	Append(eventType string, payload map[string]any) error
}

// RunHandler is the only business seam: verified envelope in, output or
// AppError out. The cancel channel must be observed for cooperative
// cancellation. / RunHandler 是唯一业务接缝：输入已验证信封，输出结果或
// AppError；业务必须观察取消通道以支持协作式取消。
type RunHandler func(ctx context.Context, request ExecuteRequest, events EventSink, cancelled <-chan struct{}) (map[string]any, error)

// ServerConfig wires a generated Agent to the platform.
// ServerConfig 将生成 Agent 接入平台。
type ServerConfig struct {
	PublicKey    ed25519.PublicKey
	Issuer       string
	Audience     string
	AgentID      string
	AgentVersion string
	Capabilities []string
	// Manifest optionally embeds the published declaration. Startup validates
	// its execution identity, routes and storage against this configuration.
	Manifest json.RawMessage
	Store    RunStore
	// Tracer is optional; nil means NoopTracer and no telemetry leaves the
	// process. / Tracer 可选；nil 表示 NoopTracer，不产生任何遥测输出。
	Tracer Tracer
	// Capability injects a per-execution governed client into business Context.
	// Capability 将逐运行的受控客户端注入业务上下文。
	Capability *CapabilityConfig
	// Runtime recovery requires an explicit, ordered business checkpoint plan.
	// Human approval resumes do not use this selector.
	RecoveryCheckpointSelector RecoveryCheckpointSelector
	// Now is optional (tests); nil means time.Now.
	Now func() time.Time
	// Invoke is required when "invoke" is advertised.
	Invoke func(ctx context.Context, request ExecuteRequest) (map[string]any, error)
	// Run is required when "run" is advertised.
	Run RunHandler
}

// ExecutionServer serves the Execution v2 surface for one Agent.
type ExecutionServer struct {
	cfg        ServerConfig
	capability map[string]bool
	activeMu   sync.Mutex
	active     map[string]*activeExecution
}

// ErrServerConfig is returned when the wiring is incomplete; the process must
// refuse to start rather than serve an unverified surface.
// ErrServerConfig 表示接线不完整；进程必须拒绝启动而不是服务未验证的接口。
var ErrServerConfig = errors.New("execution server configuration is incomplete")

// NewExecutionServer validates fail-closed wiring and returns the server.
func NewExecutionServer(cfg ServerConfig) (*ExecutionServer, error) {
	if len(cfg.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: platform public key is required", ErrServerConfig)
	}
	if cfg.Issuer == "" || cfg.Audience == "" || cfg.AgentID == "" {
		return nil, fmt.Errorf("%w: issuer, audience and agent id are required", ErrServerConfig)
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("%w: a run store is required", ErrServerConfig)
	}
	if cfg.AgentVersion == "" {
		cfg.AgentVersion = "0.1.0"
	}
	capability := map[string]bool{}
	for _, name := range cfg.Capabilities {
		capability[name] = true
	}
	if len(capability) == 0 {
		capability["invoke"] = true
	}
	if capability["invoke"] && cfg.Invoke == nil {
		return nil, fmt.Errorf("%w: invoke capability requires an invoke handler", ErrServerConfig)
	}
	if capability["run"] {
		if cfg.Run == nil {
			return nil, fmt.Errorf("%w: run capability requires a run handler", ErrServerConfig)
		}
		// The lifecycle entries always travel together with run so a started
		// run can always be observed, resumed and cancelled.
		// 生命周期入口必须与 run 同行：已启动的运行始终可观察、可恢复、可取消。
		for _, required := range []string{"resume", "cancel", "events"} {
			if !capability[required] {
				return nil, fmt.Errorf("%w: run capability requires %s", ErrServerConfig, required)
			}
		}
	}
	if cfg.Tracer == nil {
		cfg.Tracer = NoopTracer()
	}
	if len(cfg.Manifest) != 0 {
		if err := validateManifest(cfg, capability); err != nil {
			return nil, err
		}
		cfg.Manifest = append(json.RawMessage(nil), cfg.Manifest...)
	}
	return &ExecutionServer{cfg: cfg, capability: capability, active: make(map[string]*activeExecution)}, nil
}

// Handler returns the routed http.Handler for this server.
// Handler 返回该服务器的路由 http.Handler。
func (s *ExecutionServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/.well-known/agent-manifest.json", s.serveManifest)
	mux.HandleFunc("/internal/agent-execution/v2/invoke", s.wrapExecute("invoke", s.handleInvoke))
	mux.HandleFunc("/internal/agent-execution/v2/runs", s.wrapExecute("run", s.handleRun))
	mux.HandleFunc("/internal/agent-execution/v2/runs/{run_id}/resume", s.wrapExecute("resume", s.handleResume))
	mux.HandleFunc("/internal/agent-execution/v2/runs/{run_id}/cancel", s.wrapExecute("cancel", s.handleCancel))
	mux.HandleFunc("/internal/agent-execution/v2/runs/{run_id}/events", s.wrapEvents)
	mux.HandleFunc("/internal/agent-execution/v2/runs/{run_id}/checkpoint", s.wrapExecute("checkpoint", func(http.ResponseWriter, *http.Request, ExecuteRequest) {}))
	return mux
}

// ListenAndServe runs the server with graceful shutdown on ctx cancellation.
// ListenAndServe 启动服务器并在 ctx 取消时优雅关闭。
func (s *ExecutionServer) ListenAndServe(ctx context.Context, addr string) error {
	// Synchronous execution shares the platform's five-minute attempt budget.
	// Keep response writes alive beyond that budget; a shorter socket deadline
	// can discard a completed model response and leave its execution uncertain.
	server := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 6 * time.Minute}
	errs := make(chan error, 1)
	go func() { errs <- server.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errs:
		return err
	}
}

func (s *ExecutionServer) serveManifest(w http.ResponseWriter, _ *http.Request) {
	if len(s.cfg.Manifest) != 0 {
		writeServerJSON(w, http.StatusOK, s.cfg.Manifest)
		return
	}
	capabilities := make([]string, 0, len(s.capability))
	for name := range s.capability {
		capabilities = append(capabilities, name)
	}
	writeServerJSON(w, http.StatusOK, map[string]any{
		"manifest_version": "agent-manifest/v1", "agent_id": s.cfg.AgentID, "version": s.cfg.AgentVersion,
		"execution_protocols": []string{ProtocolVersion}, "capabilities": capabilities,
		"schemas": map[string]string{"input": "schema://" + s.cfg.AgentID + "/input/v1", "output": "schema://" + s.cfg.AgentID + "/output/v1"},
		"runtime": map[string]string{"transport": "http", "isolation": "container", "run_store": storeLabel(s.cfg.Store)},
	})
}

func storeLabel(store RunStore) string {
	if _, ok := store.(*MemoryRunStore); ok {
		return "memory-dev-only(L2/L3 forbidden)"
	}
	return "durable"
}

// wrapExecute guards an execution entry with the fail-closed ladder: method,
// strict envelope, bearer binding, PEP verification, then the business seam.
// wrapExecute 用失败闭合阶梯守护执行入口：方法、严格信封、Bearer 绑定、PEP
// 校验，之后才进入业务接缝。
func (s *ExecutionServer) wrapExecute(operation string, next func(w http.ResponseWriter, r *http.Request, request ExecuteRequest)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, span := s.cfg.Tracer.StartSpan(r.Context(), "agentplatform."+operation, Attribute{Key: "agentplatform.operation", Value: operation})
		defer span.End()
		r = r.WithContext(ctx)
		if r.Method != http.MethodPost {
			writeServerError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "operation requires POST")
			return
		}
		if !s.capability[operation] {
			writeServerError(w, http.StatusNotFound, "UNSUPPORTED_CAPABILITY", "capability is not advertised by this agent")
			return
		}
		request, ok := s.decodeExecute(w, r)
		if !ok {
			return
		}
		if request.Operation != operation {
			writeServerError(w, http.StatusBadRequest, "REQUEST_INVALID", "unexpected operation for this entry")
			return
		}
		if request.Scope.AgentID != s.cfg.AgentID || !boundBearer(r, request.ContextToken) {
			writeServerError(w, http.StatusUnauthorized, "CAPABILITY_INVALID", "execution capability is invalid")
			return
		}
		claims, err := VerifyContext(request, s.cfg.PublicKey, s.cfg.Issuer, s.cfg.Audience, s.now())
		if err != nil {
			// The failure reason is never echoed back; it may reveal tenant or
			// claim details. / 不回显失败原因，避免泄漏租户或声明细节。
			writeServerError(w, http.StatusUnauthorized, "CAPABILITY_INVALID", "execution capability is invalid")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), verifiedExecutionKey{}, claims))
		next(w, r, request)
	}
}

// wrapEvents applies the same ladder to event subscriptions, which use the
// EventRequest envelope and the events-scoped capability.
// wrapEvents 对事件订阅执行同样的阶梯；事件订阅使用 EventRequest 信封与
// events 作用域能力。
func (s *ExecutionServer) wrapEvents(w http.ResponseWriter, r *http.Request) {
	ctx, span := s.cfg.Tracer.StartSpan(r.Context(), "agentplatform.events", Attribute{Key: "agentplatform.operation", Value: "events"})
	defer span.End()
	r = r.WithContext(ctx)
	if r.Method != http.MethodPost {
		writeServerError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "operation requires POST")
		return
	}
	if !s.capability["events"] {
		writeServerError(w, http.StatusNotFound, "UNSUPPORTED_CAPABILITY", "capability is not advertised by this agent")
		return
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var request EventRequest
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeServerError(w, http.StatusBadRequest, "REQUEST_INVALID", "request must be one valid JSON object")
		return
	}
	if request.ProtocolVersion != ProtocolVersion {
		writeServerError(w, http.StatusBadRequest, "REQUEST_INVALID", "unexpected protocol version")
		return
	}
	if request.AfterSeq > MaxSafeExecutionEventSequence {
		writeServerError(w, http.StatusBadRequest, "REQUEST_INVALID", "event cursor is outside the safe integer range")
		return
	}
	if request.Scope.AgentID != s.cfg.AgentID || !boundBearer(r, request.ContextToken) {
		writeServerError(w, http.StatusUnauthorized, "CAPABILITY_INVALID", "execution capability is invalid")
		return
	}
	if _, err := VerifyEventContext(request, s.cfg.PublicKey, s.cfg.Issuer, s.cfg.Audience, s.now()); err != nil {
		writeServerError(w, http.StatusUnauthorized, "CAPABILITY_INVALID", "execution capability is invalid")
		return
	}
	s.handleEvents(w, r, request)
}

func (s *ExecutionServer) decodeExecute(w http.ResponseWriter, r *http.Request) (ExecuteRequest, bool) {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var request ExecuteRequest
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeServerError(w, http.StatusBadRequest, "REQUEST_INVALID", "request must be one valid JSON object")
		return ExecuteRequest{}, false
	}
	if request.ProtocolVersion != ProtocolVersion {
		writeServerError(w, http.StatusBadRequest, "REQUEST_INVALID", "unexpected protocol version")
		return ExecuteRequest{}, false
	}
	return request, true
}

func (s *ExecutionServer) handleInvoke(w http.ResponseWriter, r *http.Request, request ExecuteRequest) {
	active, created, err := s.admitExecution(r.Context(), request)
	if err != nil {
		writeServerError(w, http.StatusConflict, "RUN_GENERATION_UNVERIFIED", "run scope, input or execution generation cannot be verified")
		return
	}
	if !created {
		s.writeExecutionReplay(w, r, request, active)
		return
	}
	s.executeInvocation(w, request, active)
}

func (s *ExecutionServer) executeInvocation(w http.ResponseWriter, request ExecuteRequest, active *activeExecution) {
	var exitOnce sync.Once
	exit := func() {
		exitOnce.Do(func() {
			active.cancel()
			close(active.done)
		})
	}
	defer exit()
	runID := request.Scope.RunID
	defer func() {
		if recover() == nil {
			return
		}
		if s.cancellationRequested(runID) {
			exit()
			writeServerJSON(w, http.StatusOK, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: runID, Status: "cancelled"})
			return
		}
		failure := internalExecutionPanic()
		failErr := s.cfg.Store.Fail(runID, failure)
		record, exists := s.cfg.Store.GetRun(runID)
		if !exists {
			exit()
			writeServerError(w, http.StatusConflict, "RUN_RESULT_UNCONFIRMED", "run result is unavailable")
			return
		}
		if !record.Status.Terminal() {
			exit()
			writeServerError(w, http.StatusConflict, "RUN_RESULT_UNCONFIRMED", "run result is unavailable")
			return
		}
		exit()
		if record.Status == RunStatusCancelled {
			writeServerJSON(w, http.StatusOK, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: runID, Status: "cancelled"})
			return
		}
		if record.Error != nil {
			s.writeAppFailure(w, runID, record.Error)
			return
		}
		if record.Status == RunStatusSucceeded {
			writeServerJSON(w, http.StatusOK, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: runID, Status: string(record.Status), Output: record.Output})
			return
		}
		if failErr == nil && record.Status == RunStatusFailed {
			// Some RunStore implementations may omit the error field even after a
			// successful terminal transition. Keep the response sanitized.
			s.writeAppFailure(w, runID, &failure)
			return
		}
		writeServerError(w, http.StatusConflict, "RUN_RESULT_UNCONFIRMED", "run result is unavailable")
	}()
	if s.cancellationRequested(request.Scope.RunID) {
		exit()
		writeServerJSON(w, http.StatusOK, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: request.Scope.RunID, Status: "cancelled"})
		return
	}
	ctx, err := s.businessContextForActive(active.ctx, request, active)
	if err != nil {
		_ = s.cfg.Store.Fail(request.Scope.RunID, *appErrorOf(err))
		exit()
		s.writeAppFailure(w, request.Scope.RunID, err)
		return
	}
	output, err := s.cfg.Invoke(ctx, request)
	if s.cancellationRequested(request.Scope.RunID) {
		exit()
		writeServerJSON(w, http.StatusOK, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: request.Scope.RunID, Status: "cancelled"})
		return
	}
	if err != nil {
		var groupPause *AgentGroupPause
		if errors.As(err, &groupPause) {
			if !activeAgentGroupGatherUsed(ctx, active) {
				_ = s.cfg.Store.Fail(request.Scope.RunID, AppError{Code: "AGENT_GROUP_RESUME_REJECTED", Message: "original AgentGroup gather was not resumed"})
				exit()
				writeServerError(w, http.StatusConflict, "RUN_RESUME_UNCONFIRMED", "resume did not return to the original AgentGroup gather")
				return
			}
			if s.parkAgentGroup(active, request.Scope.RunID, groupPause) != nil {
				s.failUnparkedGroupWait(request.Scope.RunID)
				exit()
				writeServerError(w, http.StatusConflict, "RUN_GROUP_WAIT_UNCONFIRMED", "AgentGroup wait could not be recorded")
				return
			}
			exit()
			handoff := s.agentGroupHandoff(active, request.Scope.RunID)
			writeServerJSON(w, http.StatusOK, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: request.Scope.RunID, Status: "waiting", AgentGroupHandoff: handoff})
			return
		}
		var pause *HarnessPause
		if errors.As(err, &pause) {
			if s.parkExecution(active, request.Scope.RunID, pause) != nil {
				exit()
				writeServerError(w, http.StatusConflict, "RUN_PAUSE_UNCONFIRMED", "run pause could not be recorded")
				return
			}
			exit()
			handoff := s.handlerHandoff(active, request.Scope.RunID)
			writeServerJSON(w, http.StatusOK, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: request.Scope.RunID, Status: "waiting", Handoff: handoff})
			return
		}
		if !activeAgentGroupResumeConsumed(ctx, active) {
			logAgentGroupResumeRejection(request.Scope.RunID, "original_gather", err)
			_ = s.cfg.Store.Fail(request.Scope.RunID, AppError{Code: "AGENT_GROUP_RESUME_REJECTED", Message: "original AgentGroup gather was not resumed"})
			exit()
			writeServerError(w, http.StatusConflict, "RUN_RESUME_UNCONFIRMED", "resume did not return to the original AgentGroup gather")
			return
		}
		_ = s.cfg.Store.Fail(request.Scope.RunID, *appErrorOf(err))
		exit()
		s.writeAppFailure(w, request.Scope.RunID, err)
		return
	}
	if !activeAgentGroupResumeConsumed(ctx, active) {
		_ = s.cfg.Store.Fail(request.Scope.RunID, AppError{Code: "AGENT_GROUP_RESUME_REJECTED", Message: "original AgentGroup gather was not resumed"})
		exit()
		writeServerError(w, http.StatusConflict, "RUN_RESUME_UNCONFIRMED", "resume did not return to the original AgentGroup gather")
		return
	}
	if err := s.cfg.Store.Complete(request.Scope.RunID, output); err != nil {
		exit()
		writeServerError(w, http.StatusConflict, "RUN_RESULT_UNCONFIRMED", "run result could not be recorded")
		return
	}
	exit()
	writeServerJSON(w, http.StatusOK, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: request.Scope.RunID, Status: "succeeded", Output: output})
}

func (s *ExecutionServer) handleRun(w http.ResponseWriter, r *http.Request, request ExecuteRequest) {
	// HTTP acceptance must not cancel the asynchronous business context.
	active, created, err := s.admitExecution(context.WithoutCancel(r.Context()), request)
	if err != nil {
		writeServerError(w, http.StatusConflict, "RUN_GENERATION_UNVERIFIED", "run scope, input or execution generation cannot be verified")
		return
	}
	if created {
		go s.executeRun(request, active)
		writeServerJSON(w, http.StatusAccepted, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: request.Scope.RunID, Status: "running"})
		return
	}
	// A repeated signed run request is a read-only replay. Once this process's
	// exact handler has exited, it may return the waiting receipt; 202 alone
	// never proves that exit.
	s.writeExecutionReplay(w, r, request, active)
}

// executeRun drives one run through the business seam and records the result.
// executeRun 驱动一次运行穿过业务接缝并记录结果。
func (s *ExecutionServer) executeRun(request ExecuteRequest, active *activeExecution) {
	defer close(active.done)
	defer active.cancel()
	runID := request.Scope.RunID
	defer func() {
		if recover() == nil || s.cancellationRequested(runID) {
			return
		}
		_ = s.cfg.Store.Fail(runID, internalExecutionPanic())
	}()
	ctx, span := s.cfg.Tracer.StartSpan(active.ctx, "agentplatform.run.execute", Attribute{Key: "agentplatform.run_id", Value: runID})
	defer span.End()
	sink := &storeSink{server: s, runID: runID}
	cancelled, _ := s.cfg.Store.Cancelled(runID)
	if !active.resumed {
		// ResumeGeneration/Resume commits the resumed generation and its started
		// event atomically. Only a fresh accepted generation appends it here.
		// ResumeGeneration/Resume 会原子提交恢复代次及 started 事件；这里只为新接收的代次追加。
		if _, err := s.cfg.Store.AppendEvent(runID, EventStarted, map[string]any{}); err != nil {
			return
		}
	}
	ctx, err := s.businessContextForActive(ctx, request, active)
	if err != nil {
		_ = s.cfg.Store.Fail(runID, *appErrorOf(err))
		return
	}
	output, err := s.cfg.Run(ctx, request, sink, cancelled)
	if err != nil {
		var groupPause *AgentGroupPause
		if errors.As(err, &groupPause) {
			if !activeAgentGroupGatherUsed(ctx, active) {
				_ = s.cfg.Store.Fail(runID, AppError{Code: "AGENT_GROUP_RESUME_REJECTED", Message: "original AgentGroup gather was not resumed"})
				return
			}
			if s.parkAgentGroup(active, runID, groupPause) != nil {
				s.failUnparkedGroupWait(runID)
			}
			return
		}
		if !activeAgentGroupResumeConsumed(ctx, active) {
			_ = s.cfg.Store.Fail(runID, AppError{Code: "AGENT_GROUP_RESUME_REJECTED", Message: "original AgentGroup gather was not resumed"})
			return
		}
		var pause *HarnessPause
		if errors.As(err, &pause) {
			_ = s.parkExecution(active, runID, pause)
			return
		}
		_ = s.cfg.Store.Fail(runID, *appErrorOf(err))
		return
	}
	if !activeAgentGroupResumeConsumed(ctx, active) {
		_ = s.cfg.Store.Fail(runID, AppError{Code: "AGENT_GROUP_RESUME_REJECTED", Message: "original AgentGroup gather was not resumed"})
		return
	}
	_ = s.cfg.Store.Complete(runID, output)
}

func (s *ExecutionServer) handleResume(w http.ResponseWriter, r *http.Request, request ExecuteRequest) {
	runID := r.PathValue("run_id")
	if runID == "" || runID != request.Scope.RunID {
		writeServerError(w, http.StatusBadRequest, "REQUEST_INVALID", "path run id must match the verified scope")
		return
	}
	if request.ResumeInput == nil {
		writeServerError(w, http.StatusBadRequest, "REQUEST_INVALID", "signed resume_input is required")
		return
	}
	if isAgentGroupResumeRequest(request) {
		active, created, err := s.resumeAgentGroup(context.WithoutCancel(r.Context()), request)
		if err != nil {
			writeServerError(w, http.StatusConflict, "RUN_RESUME_UNCONFIRMED", "AgentGroup resume requires a valid exited handoff and current checkpoints")
			return
		}
		if !created {
			s.writeExecutionReplay(w, r, request, active)
			return
		}
		if active.originOperation == "invoke" {
			s.executeInvocation(w, request, active)
			return
		}
		go s.executeRun(request, active)
		writeServerJSON(w, http.StatusAccepted, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: runID, Status: "running"})
		return
	}
	if isRuntimeRecoveryRequest(request) {
		active, created, err := s.resumeRuntimeRecovery(context.WithoutCancel(r.Context()), request)
		if err != nil {
			writeServerError(w, http.StatusConflict, "RUN_RESUME_UNCONFIRMED", "runtime recovery requires valid stop provenance and current checkpoints")
			return
		}
		if !created {
			s.writeExecutionReplay(w, r, request, active)
			return
		}
		if active.originOperation == "invoke" {
			s.executeInvocation(w, request, active)
			return
		}
		go s.executeRun(request, active)
		writeServerJSON(w, http.StatusAccepted, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: runID, Status: "running"})
		return
	}
	s.activeMu.Lock()
	previous := s.active[runID]
	managedPause := previous != nil && (previous.parked || previous.resumed)
	s.activeMu.Unlock()
	if previous == nil {
		active, err := s.adoptHandoffExecution(context.WithoutCancel(r.Context()), request)
		if err != nil {
			writeServerError(w, http.StatusConflict, "RUN_RESUME_UNCONFIRMED", "resume requires a valid exited handoff and current checkpoint")
			return
		}
		if active.originOperation == "invoke" {
			s.executeInvocation(w, request, active)
			return
		}
		go s.executeRun(request, active)
		writeServerJSON(w, http.StatusAccepted, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: runID, Status: "running"})
		return
	}
	if !s.ownsExecution(request.Scope) {
		writeServerError(w, http.StatusNotFound, "RUN_UNKNOWN", "run is unavailable in this scope")
		return
	}
	if managedPause {
		active, created, err := s.resumeParkedExecution(context.WithoutCancel(r.Context()), request)
		if err != nil {
			writeServerError(w, http.StatusConflict, "RUN_RESUME_UNCONFIRMED", "resume requires an exited parked generation and the original business input")
			return
		}
		if !created {
			s.writeExecutionReplay(w, r, request, active)
			return
		}
		if active.originOperation == "invoke" {
			s.executeInvocation(w, request, active)
			return
		}
		go s.executeRun(request, active)
		writeServerJSON(w, http.StatusAccepted, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: runID, Status: "running"})
		return
	}
	// A live non-Harness RunHandler may be waiting on the store signal. Keep the
	// resume event token-free while leaving that existing handler in place.
	if err := s.cfg.Store.Resume(runID, map[string]any{"operation": "resume"}); err != nil {
		s.writeAppFailure(w, runID, err)
		return
	}
	status := "running"
	if record, ok := s.cfg.Store.GetRun(runID); ok {
		status = string(record.Status)
		if record.Status == RunStatusCancelled && !s.executionExited(request.Scope) {
			status = "cancelling"
		}
	}
	writeServerJSON(w, http.StatusAccepted, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: runID, Status: status})
}

func (s *ExecutionServer) handleCancel(w http.ResponseWriter, r *http.Request, request ExecuteRequest) {
	runID := r.PathValue("run_id")
	if runID == "" || runID != request.Scope.RunID {
		writeServerError(w, http.StatusBadRequest, "REQUEST_INVALID", "path run id must match the verified scope")
		return
	}
	reason := ""
	if value, ok := request.Input["reason"].(string); ok {
		reason = value
	}
	active, ok := s.controlExecution(r.Context(), request.Scope)
	if !ok {
		// A restarted process or a foreign generation is not stop evidence.
		writeServerError(w, http.StatusConflict, "REMOTE_STOP_UNCONFIRMED", "execution stop cannot be verified")
		return
	}
	_, err := s.cfg.Store.Cancel(runID, reason)
	if err != nil {
		s.writeAppFailure(w, runID, err)
		return
	}
	active.cancel()
	// Store.Cancel records intent; only the handler exit barrier proves stop.
	status := "cancelling"
	select {
	case <-active.done:
		status = "cancelled"
	default:
	}
	// Stop authority is not business-output read authority (e.g. after revoke).
	writeServerJSON(w, http.StatusAccepted, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: runID, Status: status})
}

// handleEvents replays the bounded event history as SSE and closes the
// stream; it is a replay endpoint, not an unbounded live tail.
// handleEvents 以 SSE 有界重放事件后关闭连接；这是重放端点而非无限实时流。
func (s *ExecutionServer) handleEvents(w http.ResponseWriter, r *http.Request, request EventRequest) {
	if request.AfterSeq > MaxSafeExecutionEventSequence {
		writeServerError(w, http.StatusBadRequest, "REQUEST_INVALID", "event cursor is outside the safe integer range")
		return
	}
	runID := r.PathValue("run_id")
	if runID == "" || runID != request.Scope.RunID {
		writeServerError(w, http.StatusBadRequest, "REQUEST_INVALID", "path run id must match the verified scope")
		return
	}
	if !s.ownsExecution(request.Scope) {
		writeServerError(w, http.StatusNotFound, "RUN_UNKNOWN", "run is unavailable in this scope")
		return
	}
	events, err := s.cfg.Store.EventsAfter(runID, request.AfterSeq)
	if err != nil {
		s.writeAppFailure(w, runID, err)
		return
	}
	if s.cfg.Capability != nil {
		if err := s.cfg.Capability.CheckEventAuthority(r.Context(), request); err != nil {
			s.writeAppFailure(w, runID, err)
			return
		}
	}
	if len(events) > 256 {
		events = events[:256]
	}
	validationCursor := request.AfterSeq
	for _, event := range events {
		if event.RunID != runID || event.Seq == 0 || event.Seq > MaxSafeExecutionEventSequence || event.Seq <= validationCursor {
			writeServerError(w, http.StatusInternalServerError, "EVENT_READ_UNCONFIRMED", "stored event sequence is invalid")
			return
		}
		validationCursor = event.Seq
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	cursor := request.AfterSeq
	for _, event := range events {
		if event.RunID != runID || event.Seq == 0 || event.Seq > MaxSafeExecutionEventSequence || event.Seq <= cursor {
			fmt.Fprint(w, "event: stream_error\ndata: {\"code\":\"EVENT_READ_UNCONFIRMED\"}\n\n")
			return
		}
		if _, err := VerifyEventContext(request, s.cfg.PublicKey, s.cfg.Issuer, s.cfg.Audience, s.now()); err != nil {
			fmt.Fprint(w, "event: stream_error\ndata: {\"code\":\"EVENT_READ_UNCONFIRMED\"}\n\n")
			return
		}
		if s.cfg.Capability != nil {
			if err := s.cfg.Capability.CheckEventAuthority(r.Context(), request); err != nil {
				fmt.Fprint(w, "event: stream_error\ndata: {\"code\":\"EVENT_READ_UNCONFIRMED\"}\n\n")
				return
			}
		}
		// The development store records cancellation intent immediately. Do not
		// expose it as a terminal SSE event before this handler has exited.
		if (event.EventType == EventCancelled || event.EventType == EventCompleted || event.EventType == EventFailed || event.EventType == EventWaiting) && !s.executionExited(request.Scope) {
			break
		}
		event.Payload = safeEventMetadata(event.Payload)
		payload, err := json.Marshal(event)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.Seq, event.EventType, payload)
		cursor = event.Seq
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// storeSink adapts the RunStore into the EventSink seen by business handlers.
// storeSink 将 RunStore 适配为业务处理器看到的 EventSink。
type storeSink struct {
	server *ExecutionServer
	runID  string
}

func (s *storeSink) Append(eventType string, payload map[string]any) error {
	_, err := s.server.cfg.Store.AppendEvent(s.runID, eventType, payload)
	return err
}

func (s *ExecutionServer) writeAppFailure(w http.ResponseWriter, runID string, err error) {
	appErr := appErrorOf(err)
	status := http.StatusInternalServerError
	if errors.Is(err, ErrIdempotencyConflict) {
		status = http.StatusConflict
	} else if errors.Is(err, ErrRunUnknown) {
		status = http.StatusNotFound
	} else {
		// Preserve policy/transport classifications instead of turning every
		// denied capability into HTTP 500. / 不把权限拒绝统一伪装成 500。
		switch appErr.Code {
		case "CAPABILITY_RENEWAL_DENIED", "CAPABILITY_DENIED", "POLICY_DENIED":
			status = http.StatusForbidden
		case "CAPABILITY_RENEWAL_UNAVAILABLE", "CAPABILITY_CONFIG_INVALID":
			status = http.StatusServiceUnavailable
		case "REQUEST_INVALID":
			status = http.StatusBadRequest
		}
	}
	writeServerJSON(w, status, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: runID, Status: "failed", Error: appErr})
}

func appErrorOf(err error) *AppError {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr
	}
	return &AppError{Code: "INTERNAL", Message: "the agent failed to process the request", Retryable: true}
}

func internalExecutionPanic() AppError {
	// Never include panic values or stack data: business panics may contain
	// credentials, user content, or implementation details.
	return AppError{Code: "INTERNAL", Message: "the agent failed to process the request", Retryable: true}
}

func (s *ExecutionServer) now() time.Time {
	if s.cfg.Now != nil {
		return s.cfg.Now()
	}
	return time.Now().UTC()
}

// boundBearer binds the envelope token to the request credential so a stolen
// header cannot be paired with a different body.
// boundBearer 将信封令牌与请求凭证绑定，窃取的头部无法与别的正文配对。
func boundBearer(r *http.Request, token string) bool {
	return token != "" && r.Header.Get("Authorization") == "Bearer "+token
}

func writeServerError(w http.ResponseWriter, status int, code, message string) {
	writeServerJSON(w, status, AppError{Code: code, Message: message, Retryable: false})
}

func writeServerJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
