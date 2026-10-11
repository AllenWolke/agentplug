package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
)

// Dispatcher is the platform-owned single-instance execution worker.  It
// consumes durable accepted Runs and calls the Agent's invoke contract; the
// Agent does not enqueue a second local business execution in this mode.
// Dispatcher 是平台单实例 Worker：消费持久化 accepted Run，调用 Agent invoke
// 契约；该模式下 Agent 不再重复入队本地业务执行。
type Dispatcher struct {
	coordinatedReconcile      func(context.Context, int) error
	coordinatedGuard          func(context.Context, sharedkernel.Scope) error
	repository                Repository
	token                     string
	client                    *http.Client
	gateway                   agentGateway
	resultRecorder            ConversationResultRecorder
	conversation              ConversationRecorder
	taskRecorder              TaskRecorder
	queue                     chan string
	childQueues               []chan string
	childWorkers              int
	pendingScanMu             sync.Mutex
	pendingCursor             string
	capacityMu                sync.Mutex
	started                   bool
	stop                      chan struct{}
	stopped                   chan struct{}
	once                      sync.Once
	inflightMu                sync.Mutex
	outcomeScanMu             sync.Mutex
	creationScanMu            sync.Mutex
	cancellationScanMu        sync.Mutex
	cancellationCursor        string
	outcomeCursor             string
	creationCursor            string
	inflight                  map[string]context.CancelFunc
	workers                   int
	startOnce                 sync.Once
	signer                    MachineRunContextSigner
	authorize                 func(context.Context, sharedkernel.Scope) error
	stopQuiescence            func(context.Context, sharedkernel.Scope) error
	cancellationQuiescence    func(context.Context, sharedkernel.Scope) error
	stopEvidence              StopEvidenceVerifier
	approvedResume            func(context.Context, sharedkernel.Scope, json.RawMessage) (map[string]any, error)
	approvedResumeRenewal     func(context.Context, sharedkernel.Scope, json.RawMessage) (map[string]any, error)
	recoveryCheckpoint        func(context.Context, sharedkernel.Scope, contract.RecoveryCheckpointReference) (map[string]any, error)
	recoveryCheckpointRenewal func(context.Context, sharedkernel.Scope, contract.RecoveryCheckpointReference) (map[string]any, error)
}

// agentGateway is the narrow platform-owned seam used by production
// dispatch. Keeping this interface in the execution module means HTTP, gRPC
// and sidecar transports remain replaceable without changing the Run state
// machine. / agentGateway 是平台执行模块依赖的窄端口，便于替换 HTTP、gRPC
// 和 sidecar Transport，而不改动 Run 状态机。
type agentGateway interface {
	Invoke(context.Context, agentgateway.Target, contract.ExecuteRequest) (contract.ExecuteResponse, error)
	Resume(context.Context, agentgateway.Target, contract.ExecuteRequest) (contract.ExecuteResponse, error)
}

type dispatchPolicy struct {
	MaxAttempts int
	Timeout     time.Duration
	Lease       time.Duration
}

func policyFromRequest(raw []byte) dispatchPolicy {
	policy := dispatchPolicy{MaxAttempts: 1, Timeout: 5 * time.Minute, Lease: dispatcherLeaseTTL}
	var envelope struct {
		Input struct {
			PolicySnapshot struct {
				Runtime struct {
					MaxAttempts int `json:"max_attempts"`
					TaskTimeout int `json:"task_timeout_seconds"`
					Lease       int `json:"lease_seconds"`
				} `json:"runtime"`
			} `json:"policy_snapshot"`
		} `json:"input"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return policy
	}
	if envelope.Input.PolicySnapshot.Runtime.MaxAttempts > 0 {
		policy.MaxAttempts = envelope.Input.PolicySnapshot.Runtime.MaxAttempts
	}
	if envelope.Input.PolicySnapshot.Runtime.TaskTimeout > 0 {
		policy.Timeout = time.Duration(envelope.Input.PolicySnapshot.Runtime.TaskTimeout) * time.Second
	}
	if envelope.Input.PolicySnapshot.Runtime.Lease > 0 {
		policy.Lease = time.Duration(envelope.Input.PolicySnapshot.Runtime.Lease) * time.Second
	}
	return policy
}

func NewDispatcher(repository Repository, token string, workers int) *Dispatcher {
	return newDispatcher(repository, token, nil, workers)
}

// NewDispatcherWithGateway makes the production path use the platform
// AgentGateway Port. The legacy constructor is retained for focused tests and
// compatibility adapters only; it must not be used by the modular process.
// NewDispatcherWithGateway 让生产路径真正经过 AgentGateway Port；旧构造器仅
// 保留给聚焦单测和兼容适配器，模块化生产入口不得继续使用。
func NewDispatcherWithGateway(repository Repository, token string, gateway agentGateway, workers int) *Dispatcher {
	return newDispatcher(repository, token, gateway, workers)
}

func (d *Dispatcher) SetResultRecorder(recorder ConversationResultRecorder) {
	d.resultRecorder = recorder
}

// SetSecurity injects authoritative IAM and signing Ports for every dispatch.
// SetSecurity 为每次投递注入权威 IAM 与签名端口，持久化旧令牌不再是执行凭据。
func (d *Dispatcher) SetSecurity(signer MachineRunContextSigner, authorize func(context.Context, sharedkernel.Scope) error) {
	d.signer, d.authorize = signer, authorize
}

func newDispatcher(repository Repository, token string, gateway agentGateway, workers int) *Dispatcher {
	if workers < 1 {
		workers = 1
	}
	return &Dispatcher{
		repository: repository,
		token:      token,
		client:     &http.Client{Timeout: 5 * time.Minute},
		gateway:    gateway,
		queue:      make(chan string, workers*4),
		stop:       make(chan struct{}),
		stopped:    make(chan struct{}),
		inflight:   make(map[string]context.CancelFunc),
		workers:    workers,
	}
}

// Cancel interrupts the current HTTP dispatch if this process owns one.
// Durable status CAS remains the source of truth in Module.cancel, so a
// remote/future dispatcher can implement the same method without changing the
// transport contract. / 取消当前 HTTP 投递；最终状态仍由平台 CAS 持久化。
func (d *Dispatcher) Cancel(runID string) {
	d.inflightMu.Lock()
	cancel := d.inflight[runID]
	d.inflightMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// tryRegisterInflight prevents duplicate queue entries from dispatching the
// same durable Run concurrently.  Enqueue is intentionally a best-effort
// latency optimization and reconciliation may observe the same row more than
// once; a per-process single-flight guard keeps one Run's Agent checkpoint and
// CAS transition ordered.  Durable leases remain the cross-process fence.
// tryRegisterInflight 防止重复队列项并发投递同一个持久化 Run。Enqueue 只是低延迟
// 优化，对账可能多次观察同一行；进程内 single-flight 保证单个 Run 的 Agent
// checkpoint 与 CAS 状态迁移有序，跨进程仍由持久化租约负责 fencing。
func (d *Dispatcher) tryRegisterInflight(runID string, cancel context.CancelFunc) bool {
	d.inflightMu.Lock()
	if _, exists := d.inflight[runID]; exists {
		d.inflightMu.Unlock()
		return false
	}
	d.inflight[runID] = cancel
	d.inflightMu.Unlock()
	return true
}

func (d *Dispatcher) unregisterInflight(runID string) {
	d.inflightMu.Lock()
	delete(d.inflight, runID)
	d.inflightMu.Unlock()
}

func (d *Dispatcher) Start(ctx context.Context) {
	d.startOnce.Do(func() { d.start(ctx) })
}

// start runs a bounded worker pool independently of reconciliation.
// start 将有界执行池与补偿循环分离，慢任务不得阻塞持久化补偿。
func (d *Dispatcher) start(ctx context.Context) {
	d.capacityMu.Lock()
	d.started = true
	d.capacityMu.Unlock()
	go func() {
		defer close(d.stopped)
		workerCtx, cancel := context.WithCancel(ctx)
		workerCtx = context.WithValue(workerCtx, dispatcherWorkerLifecycleKey{}, workerCtx)
		var workers sync.WaitGroup
		defer workers.Wait()
		defer cancel()
		queues := append([]chan string{d.queue}, d.childQueues...)
		for depth, queue := range queues {
			capacity := d.workers
			if depth > 0 {
				capacity = d.childWorkers
			}
			for i := 0; i < capacity; i++ {
				workers.Add(1)
				go func(depth int, queue chan string) {
					defer workers.Done()
					for {
						select {
						case <-workerCtx.Done():
							return
						case id := <-queue:
							if err := d.dispatchAtDepth(workerCtx, platformruntime.Run{ID: id}, depth); err != nil && !errors.Is(err, platformruntime.ErrLeaseConflict) {
								log.Printf("platform dispatcher run %s failed: %v", id, err)
							}
						}
					}
				}(depth, queue)
			}
		}
		// Reconciliation is deliberately repository-driven.  Enqueue is only a
		// latency optimization; accepted rows remain durable when the process
		// crashes or the in-memory queue is full.
		// 对账以仓储为事实源；Enqueue 只是低延迟优化，进程崩溃或内存队列
		// 满时 accepted 记录仍可被持久化补偿。
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		d.reconcile(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-d.stop:
				return
			case <-ticker.C:
				d.reconcile(ctx)
			}
		}
	}()
}

type pendingRepository interface {
	ListPending(int) ([]platformruntime.Run, error)
}

type pendingCursorRepository interface {
	ListPendingAfter(context.Context, string, int) ([]platformruntime.Run, error)
}

type expiredRunningRepository interface {
	ListRunningExpired(time.Time, int) ([]platformruntime.Run, error)
}

const dispatcherLeaseTTL = 5 * time.Minute

func (d *Dispatcher) reconcile(ctx context.Context) {
	if d.coordinatedReconcile != nil {
		if err := d.coordinatedReconcile(ctx, 16); err != nil {
			telemetry.RecordExecutionReconciliationFailure("coordination")
			log.Printf("execution coordination reconciliation code=COORDINATED_STOP_PENDING")
		}
	}
	d.reconcileCancellations(ctx)
	d.reconcileCreations(ctx)
	d.reconcileOutcomes(ctx)
	repository, ok := d.repository.(pendingRepository)
	if !ok {
		return
	}
	var runs []platformruntime.Run
	var err error
	if fair, supported := d.repository.(pendingCursorRepository); supported && len(d.childQueues) != 0 {
		d.pendingScanMu.Lock()
		queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		runs, err = fair.ListPendingAfter(queryCtx, d.pendingCursor, min(128, max(16, cap(d.queue))))
		cancel()
		if err == nil {
			if len(runs) == 0 {
				d.pendingCursor = ""
			} else {
				d.pendingCursor = runs[len(runs)-1].ID
			}
		}
		d.pendingScanMu.Unlock()
	} else {
		runs, err = repository.ListPending(cap(d.queue))
	}
	if err != nil {
		telemetry.RecordExecutionReconciliationFailure("dispatch")
		log.Printf("platform dispatcher reconciliation failed: %v", err)
		return
	}
	for _, run := range runs {
		d.Enqueue(run)
	}
	// A process can die after transitioning a Run to running. Reclaim only
	// expired leases; the dispatch path stops the old generation before reclaim.
	// Queuing is only a hint and does not transfer ownership.
	if repository, ok := d.repository.(expiredRunningRepository); ok {
		expired, err := repository.ListRunningExpired(time.Now().UTC(), cap(d.queue))
		if err != nil {
			telemetry.RecordExecutionReconciliationFailure("dispatch")
			log.Printf("platform dispatcher expired-lease reconciliation failed: %v", err)
			return
		}
		for _, run := range expired {
			d.Enqueue(run)
		}
	}
}

func (d *Dispatcher) Close(ctx context.Context) error {
	d.once.Do(func() { close(d.stop) })
	select {
	case <-d.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Dispatcher) Enqueue(run platformruntime.Run) {
	queue := d.queue
	if len(d.childQueues) != 0 {
		depth, err := scheduledDelegationDepth(run)
		if err != nil {
			log.Printf("execution queue rejected run_id=%s code=DELEGATION_DEPTH_INVALID", run.ID)
			return
		}
		if depth > 0 {
			queue = d.childQueues[depth-1]
		}
	}
	select {
	case queue <- run.ID:
	default:
		// The Run remains accepted and can be recovered by a future reconciler.
		// 队列满时不丢失事实状态；后续 reconciler 可重新领取 accepted Run。
	}
}

func (d *Dispatcher) dispatch(ctx context.Context, run platformruntime.Run) (returnedErr error) {
	return d.dispatchAtDepth(ctx, run, -1)
}

func (d *Dispatcher) dispatchAtDepth(ctx context.Context, run platformruntime.Run, expectedDepth int) (returnedErr error) {
	current, err := d.repository.Get(run.ID)
	if err != nil {
		return err
	}
	if expectedDepth >= 0 && len(d.childQueues) != 0 {
		actualDepth, err := scheduledDelegationDepth(current)
		if err != nil {
			return err
		}
		if actualDepth != expectedDepth {
			d.Enqueue(current)
			return nil
		}
	}
	// Restore the durable parent, not a stale queue snapshot.
	// 从持久化事实恢复父 Span，不能使用队列旧快照。
	ctx = telemetry.Restore(ctx, current.TraceContext)
	ctx, span := telemetry.Start(ctx, "platform.worker.execution", trace.SpanKindInternal)
	defer span.End()
	defer func() {
		if returnedErr != nil {
			telemetry.Failed(span, "EXECUTION_WORKER_FAILED")
		}
	}()
	// Queue snapshots are hints, never the execution command source of truth.
	// 队列快照只用于唤醒；实际阶段和恢复输入必须以持久化记录为准。
	run = current
	if run.AgentEndpoint == "" || len(run.RequestJSON) == 0 {
		return nil
	}
	if current.Status != platformruntime.StatusAccepted && current.Status != platformruntime.StatusRunning {
		return nil
	}
	// A stale owner may still be running remotely; expiration is not a stop ACK.
	// 旧租约到期不等于旧图退出；先停止旧世代，再由后续队列领取新世代。
	if current.Status == platformruntime.StatusRunning && current.LeaseToken != "" && !current.LeaseUntil.After(time.Now().UTC()) {
		store, ok := d.repository.(interface {
			BeginRecovery(string, uint64, time.Time) (platformruntime.Run, error)
		})
		if !ok {
			return errors.New("recovery repository unavailable")
		}
		pending, err := store.BeginRecovery(current.ID, current.Revision, time.Now().UTC())
		if err != nil {
			return err
		}
		return d.confirmCancellation(ctx, pending)
	}
	// The published task deadline bounds the whole execution generation,
	// including retry admission and backoff, rather than resetting per attempt.
	dispatchCtx, dispatchCancel := context.WithTimeout(ctx, policyFromRequest(run.RequestJSON).Timeout)
	if !d.tryRegisterInflight(run.ID, dispatchCancel) {
		// A duplicate queue item is harmless; the first owner is already
		// driving the durable Run.  Do not issue a second Agent resume/invoke.
		// 重复队列项无需报错，首个 owner 已在处理持久化 Run，不能再次调用
		// Agent 的 invoke/resume，否则 LangGraph interrupt 可能被重复消费。
		dispatchCancel()
		return nil
	}
	defer func() {
		d.unregisterInflight(run.ID)
		dispatchCancel()
	}()
	// Always claim using a new private token; observing a persisted token is
	// never proof of ownership. / 读取数据库令牌不代表拥有租约，执行前必须独立领取。
	claimed, claimErr := d.repository.AcquireLease(current.ID, newLeaseToken(current.ID), time.Now().UTC(), policyFromRequest(current.RequestJSON).Lease)
	if claimErr != nil {
		return claimErr
	}
	current = claimed
	running := current
	if current.Status == platformruntime.StatusAccepted {
		running, err = d.repository.TransitionLeased(run.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, current.Revision, current.LeaseToken)
		if err != nil {
			return err
		}
	}
	stopHeartbeat := d.startHeartbeat(dispatchCtx, dispatchCancel, running, policyFromRequest(run.RequestJSON).Lease)
	defer stopHeartbeat()
	if d.gateway != nil && d.signer != nil {
		// Coordinated child commands persist no bearer token. The gateway path
		// rechecks live authority and signs the claimed execution generation.
		return d.dispatchThroughGateway(dispatchCtx, run, running, policyFromRequest(run.RequestJSON))
	}
	var envelope struct {
		ContextToken string `json:"context_token"`
	}
	if err := json.Unmarshal(run.RequestJSON, &envelope); err != nil || envelope.ContextToken == "" {
		return d.failDispatch(ctx, run.ID, running, "INVALID_REQUEST", "platform worker received an invalid execution envelope")
	}
	if d.gateway != nil {
		return d.dispatchThroughGateway(dispatchCtx, run, running, policyFromRequest(run.RequestJSON))
	}
	if reader, ok := d.repository.(agentGroupResumeReader); ok {
		ref, err := reader.CurrentAgentGroupResumeReference(dispatchCtx, running)
		if err != nil || ref != nil {
			return d.failDispatch(ctx, run.ID, running, "GROUP_RESUME_GATEWAY_REQUIRED", "group resume requires a signed Agent gateway")
		}
	}
	if reader, ok := d.repository.(recoveryStopReferenceReader); ok {
		reference, err := reader.CurrentRecoveryStopReference(dispatchCtx, running)
		if err != nil || reference != nil {
			return d.failDispatch(ctx, run.ID, running, "RECOVERY_GATEWAY_REQUIRED", "runtime recovery requires a signed Agent gateway")
		}
	}
	requestBody := run.RequestJSON
	endpointSuffix := "/internal/agent-execution/v2/invoke"
	if len(run.ResumeInputJSON) > 0 {
		endpointSuffix = "/internal/agent-execution/v2/runs/" + run.ID + "/resume"
		var body map[string]any
		var decision map[string]any
		if json.Unmarshal(requestBody, &body) != nil || json.Unmarshal(run.ResumeInputJSON, &decision) != nil || decision == nil {
			return d.failDispatch(ctx, run.ID, running, "INVALID_RESUME_INPUT", "invalid resume body")
		}
		if decision["version"] == "harness-tool-resume/v1" {
			return d.failDispatch(ctx, run.ID, running, "RESUME_GATEWAY_REQUIRED", "approved tool resume requires the signed Agent gateway")
		}
		body["operation"], body["resume_input"] = "resume", decision
		requestBody, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	endpoint := strings.TrimRight(run.AgentEndpoint, "/") + endpointSuffix
	req, err := http.NewRequestWithContext(dispatchCtx, http.MethodPost, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return d.failDispatch(ctx, run.ID, running, "AGENT_DISPATCH_FAILED", "unable to construct Agent request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+envelope.ContextToken)
	var compatibilityRequest contract.ExecuteRequest
	if err := json.Unmarshal(requestBody, &compatibilityRequest); err != nil || (compatibilityRequest.Operation != "invoke" && compatibilityRequest.Operation != "run" && compatibilityRequest.Operation != "resume") {
		return d.failDispatch(ctx, run.ID, running, "AGENT_CONTRACT_INVALID", "Agent request operation is invalid")
	}
	bodyDigest := sha256.Sum256(requestBody)
	compatibilityBodyHash := hex.EncodeToString(bodyDigest[:])
	compatibilityPolicyHash := ""
	if policySnapshot, ok := compatibilityRequest.Input["policy_snapshot"].(map[string]any); ok {
		if hash, ok := policySnapshot["content_hash"].(string); ok && validGenerationJournalHash(hash) {
			compatibilityPolicyHash = hash
		}
	}
	policy := policyFromRequest(run.RequestJSON)
	var lastErr error
	lastCode := "AGENT_EXECUTION_FAILED"
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		if err := waitDispatchRetry(dispatchCtx, attempt); err != nil {
			return d.stopDispatch(ctx, running, "AGENT_TASK_INTERRUPTED")
		}
		attemptCtx, cancel := context.WithTimeout(dispatchCtx, policy.Timeout)
		attemptReq := req.Clone(attemptCtx)
		if attempt > 1 && req.GetBody != nil {
			body, bodyErr := req.GetBody()
			if bodyErr != nil {
				cancel()
				lastErr = bodyErr
				lastCode = "AGENT_REQUEST_REPLAY_FAILED"
				if eventErr := d.recordDispatchFailure(ctx, run.ID, attempt, lastCode, false, 0); eventErr != nil {
					return eventErr
				}
				continue
			}
			attemptReq.Body = body
		}
		if journal, ok := d.repository.(interface {
			RecordCompatibilityDispatch(context.Context, platformruntime.Run, string, string, string) error
		}); ok {
			if err := journal.RecordCompatibilityDispatch(attemptCtx, running, compatibilityRequest.Operation, compatibilityBodyHash, compatibilityPolicyHash); err != nil {
				cancel()
				return err
			}
		}
		resp, requestErr := d.client.Do(attemptReq)
		if requestErr != nil {
			cancel()
			// A caller cancellation is already durably recorded by Module.Cancel.
			// Do not append a misleading dispatch-failure event after the terminal
			// cancellation transaction has committed.
			// 调用方取消已由 Module.Cancel 持久化；终态事务提交后不能再追加
			// 误导性的调度失败事件。
			if errors.Is(requestErr, context.Canceled) {
				if currentRun, getErr := d.repository.Get(run.ID); getErr == nil && currentRun.Status == platformruntime.StatusCancelled {
					return nil
				}
			}
			lastErr = requestErr
			lastCode, _ = classifyDispatchFailure(0, requestErr)
			if eventErr := d.recordDispatchFailure(ctx, run.ID, attempt, lastCode, false, 0); eventErr != nil {
				return eventErr
			}
			return d.stopDispatch(ctx, running, lastCode)
		}
		status := resp.StatusCode
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		_ = resp.Body.Close()
		cancel()
		if status >= 200 && status < 300 {
			if readErr != nil {
				lastErr = fmt.Errorf("read agent response: %w", readErr)
				lastCode, _ = classifyDispatchFailure(status, readErr)
				if eventErr := d.recordDispatchFailure(ctx, run.ID, attempt, lastCode, false, status); eventErr != nil {
					return eventErr
				}
				return d.stopDispatch(ctx, running, lastCode)
			}
			// The Agent invoke response is part of the execution contract. A
			// HTTP 200 does not necessarily mean terminal success: LangGraph
			// may park at an interrupt and return `waiting`. Do not turn that
			// state into succeeded or the platform can never resume it.
			// Agent 的 HTTP 200 不等于终态成功；LangGraph interrupt 可能返回
			// waiting，平台必须保留等待态，否则后续无法 resume。
			var result struct {
				Status string         `json:"status"`
				Output map[string]any `json:"output"`
			}
			if len(body) > 0 && json.Unmarshal(body, &result) != nil {
				lastErr = errors.New("agent returned malformed execution response")
				lastCode = "AGENT_CONTRACT_INVALID"
				if eventErr := d.recordDispatchFailure(ctx, run.ID, attempt, lastCode, false, status); eventErr != nil {
					return eventErr
				}
				// A successful HTTP status with an invalid execution envelope is a
				// contract failure, not a transient transport failure. Retrying it
				// would repeat a request that the Agent cannot interpret safely.
				// HTTP 成功但执行响应非法属于契约错误，不是暂态网络错误；不能
				// 盲目重试，否则会重复触发无法安全解释的请求。
				return d.stopDispatch(ctx, running, lastCode)
			}
			switch strings.ToLower(strings.TrimSpace(result.Status)) {
			case "waiting":
				return d.finish(running, platformruntime.StatusWaiting, result.Output, map[string]any{"source": "platform_dispatcher"})
			case "cancelled":
				return d.finish(running, platformruntime.StatusCancelled, result.Output, map[string]any{"source": "platform_dispatcher"})
			case "failed":
				lastCode = "AGENT_EXECUTION_FAILED"
				if eventErr := d.recordDispatchFailure(ctx, run.ID, attempt, lastCode, false, status); eventErr != nil {
					return eventErr
				}
				return d.failDispatch(ctx, run.ID, running, lastCode, "agent returned failed status")
			case "succeeded":
				// Only explicit terminal success is accepted. / 只接受明确成功终态。
			default:
				lastErr = fmt.Errorf("agent returned unsupported status %q", result.Status)
				lastCode = "AGENT_CONTRACT_INVALID"
				if eventErr := d.recordDispatchFailure(ctx, run.ID, attempt, lastCode, false, status); eventErr != nil {
					return eventErr
				}
				return d.stopDispatch(ctx, running, lastCode)
			}
			return d.finish(running, platformruntime.StatusSucceeded, result.Output, map[string]any{"source": "platform_dispatcher"})
		}
		// Untrusted response bodies must not enter durable events or error logs.
		// 不可信上游响应正文不得进入持久化事件或错误日志。
		lastErr = fmt.Errorf("agent returned HTTP %d", status)
		lastCode, _ = classifyDispatchFailure(status, nil)
		if eventErr := d.recordDispatchFailure(ctx, run.ID, attempt, lastCode, false, status); eventErr != nil {
			return eventErr
		}
		return d.stopDispatch(ctx, running, lastCode)
	}
	if lastErr != nil {
		if currentRun, getErr := d.repository.Get(run.ID); getErr == nil && currentRun.Status == platformruntime.StatusCancelled {
			return nil
		}
		return d.failDispatch(ctx, run.ID, running, lastCode, "Agent transport or execution failed")
	}
	if currentRun, getErr := d.repository.Get(run.ID); getErr == nil && currentRun.Status == platformruntime.StatusCancelled {
		return nil
	}
	return d.failDispatch(ctx, run.ID, running, "AGENT_CONTRACT_INVALID", "Agent response did not provide an execution outcome")
}

// dispatchThroughGateway executes the same durable retry/state semantics as
// the compatibility HTTP loop, but all Agent calls go through the
// language-neutral AgentGateway Port. / 该函数沿用同一套重试和状态语义，
// 但生产 Agent 调用统一经过语言无关的 AgentGateway Port。
func (d *Dispatcher) dispatchThroughGateway(ctx context.Context, run platformruntime.Run, running platformruntime.Run, policy dispatchPolicy) error {
	var request contract.ExecuteRequest
	if err := json.Unmarshal(run.RequestJSON, &request); err != nil {
		return d.failDispatch(ctx, run.ID, running, "INVALID_REQUEST", "platform worker received an invalid execution contract")
	}
	if len(run.ResumeInputJSON) > 0 {
		if err := json.Unmarshal(run.ResumeInputJSON, &request.ResumeInput); err != nil || request.ResumeInput == nil {
			return d.failDispatch(ctx, run.ID, running, "INVALID_RESUME_INPUT", "invalid signed resume decision")
		}
		request.Operation = "resume"
		if request.ResumeInput["version"] == "harness-tool-resume/v1" && (d.signer == nil || d.approvedResume == nil) {
			return d.failDispatch(ctx, run.ID, running, "RESUME_AUTHORITY_UNAVAILABLE", "approved resume requires current authorization and signing")
		}
	}
	// The platform worker owns this durable Run and invokes the Agent business
	// seam synchronously. Re-sign the concrete invoke command, rather than
	// sending a run-scoped envelope to the SDK's strict invoke endpoint.
	// Persisted browser intent remains unchanged; dispatch provenance records
	// the actual operation/body/lease below. Unsigned compatibility fixtures
	// cannot rewrite a pre-existing token's operation binding.
	if request.Operation == "run" && d.signer != nil {
		request.Operation = "invoke"
	}
	validationErr := request.Validate()
	if d.signer != nil {
		validationErr = request.ValidateForSigning()
	}
	if err := validationErr; err != nil {
		// Contract validation errors contain only protocol field/category names;
		// unlike payloads or tokens, they are safe and useful for diagnosis.
		// 契约校验错误只包含协议字段/类别名；不同于业务正文和令牌，可安全用于诊断。
		return d.failDispatch(ctx, run.ID, running, "AGENT_CONTRACT_INVALID", "execution contract validation failed: "+err.Error())
	}
	target, err := targetFromRun(run, request)
	if err != nil {
		return d.failDispatch(ctx, run.ID, running, "AGENT_TARGET_INVALID", err.Error())
	}
	var lastErr error
	lastCode := "AGENT_EXECUTION_FAILED"
	baseRequest := request
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		if err := waitDispatchRetry(ctx, attempt); err != nil {
			return d.stopDispatch(ctx, running, "AGENT_TASK_INTERRUPTED")
		}
		request = baseRequest // never reuse a transient approval/recovery envelope
		attemptCtx, cancel := context.WithTimeout(ctx, policy.Timeout)
		// Every attempt rechecks the grant and receives its own short-lived token.
		// 每次重试均重验授权并重新签发短期令牌，不复用上一次执行凭据。
		if d.signer != nil {
			if d.authorize == nil {
				cancel()
				return d.failDispatch(ctx, run.ID, running, "AUTHORIZATION_UNAVAILABLE", "dispatch authorization is unavailable")
			}
			if err := d.authorize(attemptCtx, run.Scope); err != nil {
				cancel()
				return d.failDispatch(ctx, run.ID, running, "AUTHORIZATION_DENIED", "dispatch authorization denied")
			}
			if d.coordinatedGuard != nil && d.coordinatedGuard(attemptCtx, run.Scope) != nil {
				cancel()
				return d.failDispatch(ctx, run.ID, running, "ANCESTRY_DENIED", "coordinated ancestor authorization denied")
			}
			recovered, recoveryErr := d.prepareRecoveryDispatch(attemptCtx, running, &request)
			if recoveryErr != nil {
				cancel()
				return d.failDispatch(ctx, run.ID, running, "RECOVERY_REFERENCE_UNVERIFIED", "committed recovery source or checkpoint cannot be verified")
			}
			if !recovered {
				var groupErr error
				recovered, groupErr = d.prepareAgentGroupResume(attemptCtx, running, &request)
				if groupErr != nil {
					cancel()
					return d.failDispatch(ctx, run.ID, running, "GROUP_RESUME_UNVERIFIED", "committed group continuation cannot be verified")
				}
			}
			if request.Operation == "resume" && !recovered {
				var durable map[string]any
				if json.Unmarshal(run.ResumeInputJSON, &durable) != nil {
					cancel()
					return d.failDispatch(ctx, run.ID, running, "INVALID_RESUME_INPUT", "invalid approved resume reference")
				}
				if durable["version"] == "harness-tool-resume/v1" {
					if d.approvedResume == nil {
						cancel()
						return d.failDispatch(ctx, run.ID, running, "RESUME_AUTHORITY_UNAVAILABLE", "approved resume authority unavailable")
					}
					input, resolveErr := d.approvedResume(attemptCtx, run.Scope, run.ResumeInputJSON)
					if resolveErr != nil || input == nil {
						cancel()
						return d.failDispatch(ctx, run.ID, running, "TOOL_APPROVAL_DENIED", "current approved resume authorization denied")
					}
					request.ResumeInput = input // transient token, never stored with Run input
				}
			}
			request.ContextToken = ""
			token, signErr := d.signer.Sign(sharedkernel.BindExecutionLease(attemptCtx, running.Revision, running.LeaseToken), run.Scope, request)
			if signErr != nil || token == "" {
				cancel()
				return d.failDispatch(ctx, run.ID, running, "CONTEXT_SIGNING_FAILED", "unable to sign current execution command")
			}
			request.ContextToken = token
		}
		var response contract.ExecuteResponse
		bodyHash, hashErr := contract.CanonicalExecuteBodyHash(request)
		policyInput, _ := request.Input["policy_snapshot"].(map[string]any)
		policyHash, _ := policyInput["content_hash"].(string)
		if hashErr != nil {
			cancel()
			return d.failDispatch(ctx, run.ID, running, "AGENT_CONTRACT_INVALID", "execution command cannot be hashed")
		}
		command := platformruntime.DispatchCommand{RunID: running.ID, Revision: running.Revision, Operation: request.Operation, BodyHash: bodyHash, PolicyHash: policyHash}
		var recordErr error
		if recorder, ok := d.repository.(interface {
			RecordDispatchCommandWithTransport(platformruntime.DispatchCommand, string, string) error
		}); ok {
			recordErr = recorder.RecordDispatchCommandWithTransport(command, running.LeaseToken, target.Transport)
		} else {
			recordErr = d.repository.RecordDispatchCommand(command, running.LeaseToken)
		}
		if recordErr != nil {
			cancel()
			return recordErr
		}
		if request.Operation == "resume" {
			response, err = d.gateway.Resume(attemptCtx, target, request)
		} else {
			response, err = d.gateway.Invoke(attemptCtx, target, request)
		}
		cancel()
		if err != nil {
			lastErr = err
			// Keep the classified code for the final durable failure event.
			// 保留分类错误码供持久化终结事件使用，避免块内变量遮蔽。
			var retryable bool
			lastCode, retryable = classifyDispatchFailure(0, err)
			var completed agentgateway.CompletedExecutionFailure
			if !errors.As(err, &completed) || completed.Response.RunID != run.ID {
				// A typed error or Retryable flag alone proves no terminal execution.
				if eventErr := d.recordDispatchFailure(ctx, run.ID, attempt, lastCode, false, 0); eventErr != nil {
					return eventErr
				}
				return d.stopDispatch(ctx, running, lastCode)
			}
			if _, proofErr := agentgateway.NewCompletedExecutionFailure(completed.Response); proofErr != nil {
				return d.stopDispatch(ctx, running, "AGENT_CONTRACT_INVALID")
			}
			if eventErr := d.recordDispatchFailure(ctx, run.ID, attempt, lastCode, retryable, 0); eventErr != nil {
				return eventErr
			}
			if !retryable {
				break
			}
			if d.checkRetryEffectQuiescence(ctx, running) != nil {
				return d.stopDispatch(ctx, running, "AGENT_EFFECTS_UNCONFIRMED")
			}
			continue
		}
		if response.RunID != run.ID || response.ProtocolVersion != contract.ProtocolVersion || response.Status == "" {
			return d.stopDispatch(ctx, running, "AGENT_CONTRACT_INVALID")
		}
		if (response.AgentGroupHandoff != nil || response.Handoff != nil) && response.Status != "waiting" || (response.AgentGroupHandoff != nil && response.Handoff != nil) {
			return d.stopDispatch(ctx, running, "AGENT_HANDOFF_INVALID")
		}
		switch strings.ToLower(strings.TrimSpace(response.Status)) {
		case "waiting":
			payload := map[string]any{"source": "platform_agent_gateway"}
			if response.AgentGroupHandoff != nil {
				if response.Handoff != nil || d.signer == nil || response.AgentGroupHandoff.Validate(running.ID, running.Revision, bodyHash, running.LeaseToken) != nil {
					return d.stopDispatch(ctx, running, "AGENT_GROUP_HANDOFF_INVALID")
				}
				payload["agent_group_handoff"] = *response.AgentGroupHandoff
			}
			if response.Handoff != nil {
				if d.signer == nil || response.Handoff.Validate(running.ID, running.Revision, bodyHash, running.LeaseToken) != nil {
					return d.stopDispatch(ctx, running, "AGENT_HANDOFF_INVALID")
				}
				payload["handoff"] = *response.Handoff
			}
			return d.finish(running, platformruntime.StatusWaiting, response.Output, payload)
		case "cancelled":
			return d.finish(running, platformruntime.StatusCancelled, response.Output, map[string]any{"source": "platform_agent_gateway"})
		case "failed":
			if _, proofErr := agentgateway.NewCompletedExecutionFailure(response); proofErr != nil {
				return d.stopDispatch(ctx, running, "AGENT_CONTRACT_INVALID")
			}
			lastCode = "AGENT_EXECUTION_FAILED"
			retryable := false
			if response.Error != nil {
				lastCode, retryable = response.Error.Code, response.Error.Retryable
			}
			if eventErr := d.recordDispatchFailure(ctx, run.ID, attempt, lastCode, retryable, 0); eventErr != nil {
				return eventErr
			}
			if retryable && attempt < policy.MaxAttempts {
				if d.checkRetryEffectQuiescence(ctx, running) != nil {
					return d.stopDispatch(ctx, running, "AGENT_EFFECTS_UNCONFIRMED")
				}
				continue
			}
			return d.failDispatch(ctx, run.ID, running, lastCode, "agent returned failed status")
		case "succeeded":
			return d.finish(running, platformruntime.StatusSucceeded, response.Output, map[string]any{"source": "platform_agent_gateway"})
		default:
			return d.stopDispatch(ctx, running, "AGENT_CONTRACT_INVALID")
		}
	}
	if lastErr != nil {
		if currentRun, getErr := d.repository.Get(run.ID); getErr == nil && currentRun.Status == platformruntime.StatusCancelled {
			return nil
		}
		return d.failDispatch(ctx, run.ID, running, lastCode, "Agent transport or execution failed")
	}
	return d.failDispatch(ctx, run.ID, running, lastCode, "agent gateway execution failed")
}

// Backoff delays only retries already admitted by the existing error policy.
// It does not authorize replay of an unknown model, tool or remote execution.
// Cancellation/deadline and the lease heartbeat remain active while waiting.
func waitDispatchRetry(ctx context.Context, attempt int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if attempt <= 1 {
		return nil
	}
	delay := 250 * time.Millisecond
	for ordinal := 2; ordinal < attempt && delay < 2*time.Second; ordinal++ {
		delay *= 2
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

// finish commits the durable outcome before invoking any projection Port.
// finish 先原子提交执行结果，再调用业务投影端口；投影失败只补投影，不重跑 Agent。
func (d *Dispatcher) finish(running platformruntime.Run, status platformruntime.Status, output map[string]any, payload map[string]any) error {
	if status == platformruntime.StatusSucceeded {
		if approval, ok := output["approval_status"].(string); ok && (approval == "approved" || approval == "rejected") {
			// Run completion is not equivalent to publication approval.
			// Run执行完毕不等于内容获批；事件显式携带业务审核结果。
			payload = map[string]any{"source": payload["source"], "approval_status": approval, "published": approval == "approved"}
		}
	}
	if _, err := d.repository.FinalizeLeased(running.ID, status, running.Revision, running.LeaseToken, output, payload); err != nil {
		if errors.Is(err, ErrExecutionOutcomeUnconfirmed) {
			return d.stopUncertainExecution(running, "AGENT_EFFECTS_UNCONFIRMED")
		}
		return err
	}
	d.reconcileOutcomes(context.Background())
	return nil
}

func (d *Dispatcher) reconcileOutcomes(ctx context.Context) {
	if d.resultRecorder == nil {
		return
	}
	// Cursors are disposable scheduling hints. Independent replicas can scan
	// the same durable intents safely; consumer idempotency owns correctness.
	// 游标仅为可丢弃的调度提示；跨实例正确性仍由持久化待办和消费者幂等保证。
	if !d.outcomeScanMu.TryLock() {
		return
	}
	defer d.outcomeScanMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	outcomes, err := d.repository.PendingOutcomesAfter(d.outcomeCursor, 64)
	if err != nil {
		telemetry.RecordExecutionReconciliationFailure("outcome")
		log.Printf("execution outcome reconciliation failed code=OUTCOME_READ_FAILED")
		return
	}
	if len(outcomes) == 0 {
		d.outcomeCursor = ""
		return
	}
	for _, outcome := range outcomes {
		if ctx.Err() != nil {
			return
		}
		d.outcomeCursor = outcome.RunID
		run, err := d.repository.Get(outcome.RunID)
		if err != nil {
			telemetry.RecordExecutionReconciliationFailure("outcome")
			log.Printf("execution outcome reconciliation failed code=RUN_READ_FAILED")
			continue
		}
		// Never project a superseded result after a new resume command.
		// 后续恢复已改变版本时，不允许旧投影覆盖新结果。
		if run.Revision != outcome.Revision {
			continue
		}
		var output map[string]any
		if err := json.Unmarshal(outcome.OutputJSON, &output); err != nil {
			telemetry.RecordExecutionReconciliationFailure("outcome")
			log.Printf("execution outcome reconciliation failed code=OUTCOME_INVALID")
			continue
		}
		if run.Scope.SessionID != "" {
			projectionCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err = d.resultRecorder.RecordRunResult(projectionCtx, run.Scope, run.ID, output)
			cancel()
			if err != nil {
				telemetry.RecordExecutionReconciliationFailure("outcome")
				log.Printf("execution outcome projection pending run_id=%s code=PROJECTION_FAILED", run.ID)
				continue
			}
		}
		if err := d.repository.AcknowledgeOutcome(run.ID, outcome.Revision); err != nil {
			telemetry.RecordExecutionReconciliationFailure("outcome")
			log.Printf("execution outcome acknowledgment pending run_id=%s code=OUTCOME_ACK_FAILED", run.ID)
		}
	}
	if len(outcomes) < 64 {
		d.outcomeCursor = ""
	}
}

func targetFromRun(run platformruntime.Run, request contract.ExecuteRequest) (agentgateway.Target, error) {
	parsed, err := url.Parse(run.AgentEndpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return agentgateway.Target{}, agentgateway.ErrInvalidTarget
	}
	manifestHash := ""
	var envelope struct {
		Input struct {
			PolicySnapshot struct {
				ContentHash string `json:"content_hash"`
			} `json:"policy_snapshot"`
		} `json:"input"`
	}
	if raw, marshalErr := json.Marshal(request); marshalErr == nil {
		_ = json.Unmarshal(raw, &envelope)
	}
	manifestHash = strings.TrimSpace(envelope.Input.PolicySnapshot.ContentHash)
	if manifestHash == "" {
		return agentgateway.Target{}, agentgateway.ErrInvalidTarget
	}
	return agentgateway.Target{
		InstallationID: run.Scope.InstallationID,
		AgentID:        run.Scope.AgentID,
		AgentVersionID: run.Scope.AgentVersionID,
		Endpoint:       run.AgentEndpoint,
		Transport:      parsed.Scheme,
		Revision:       1,
		ManifestHash:   manifestHash,
	}, nil
}

// classifyDispatchFailure keeps retry policy explicit and auditable. Timeouts,
// network failures and 408/429/5xx are retryable; caller/contract 4xx errors
// are not. 机密响应正文不进入事件，只记录稳定分类和 HTTP 状态。
func classifyDispatchFailure(status int, err error) (string, bool) {
	if errors.Is(err, context.DeadlineExceeded) {
		return "AGENT_EXECUTION_TIMEOUT", true
	}
	if errors.Is(err, context.Canceled) {
		return "AGENT_DISPATCH_CANCELLED", false
	}
	if err != nil {
		// Gateway transports normalize HTTP/gRPC application failures into the
		// language-neutral AppError. Preserve its explicit retry decision instead
		// of treating every typed upstream error as a permanent transport failure.
		// Gateway Transport 会把 HTTP/gRPC 应用失败归一化为 AppError；必须尊重
		// 其中的 retryable 决策，不能把所有类型化上游错误误判为永久失败。
		var appErr contract.AppError
		if errors.As(err, &appErr) {
			return appErr.Code, appErr.Retryable
		}
		var networkErr net.Error
		if errors.As(err, &networkErr) {
			return "AGENT_TRANSPORT_RETRYABLE", true
		}
		return "AGENT_TRANSPORT_FAILED", false
	}
	switch {
	case status == http.StatusRequestTimeout || status == http.StatusTooManyRequests:
		return "AGENT_HTTP_RETRYABLE", true
	case status >= 500 && status <= 599:
		return "AGENT_HTTP_RETRYABLE", true
	default:
		return "AGENT_HTTP_NON_RETRYABLE", false
	}
}

func (d *Dispatcher) recordAttemptFailure(runID string, attempt int, code string, retryable bool, status int) error {
	_, err := d.repository.AppendEvent(runID, "attempt_failed", map[string]any{
		"attempt": attempt, "code": code, "retryable": retryable, "http_status": status,
	})
	return err
}

func newLeaseToken(runID string) string {
	return fmt.Sprintf("dispatcher:%s:%d", runID, time.Now().UnixNano())
}

func (d *Dispatcher) fail(runID string, running platformruntime.Run, code, message string) error {
	if current, err := d.repository.Get(runID); err == nil && current.Status == platformruntime.StatusCancelled {
		return nil
	}
	// A completed handler can still leave a provider charge or tool receipt
	// unknown. Do not release FIFO as ordinary failure before reconciliation.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if d.checkRetryEffectQuiescence(ctx, running) != nil {
		return d.stopUncertainExecution(running, "AGENT_EFFECTS_UNCONFIRMED")
	}
	return d.finish(running, platformruntime.StatusFailed, nil, map[string]any{"code": code, "message": message})
}

func (d *Dispatcher) checkRetryEffectQuiescence(ctx context.Context, running platformruntime.Run) error {
	if guard, ok := d.repository.(interface {
		CheckRetryOutcomeQuiescence(context.Context, sharedkernel.Scope) error
	}); ok {
		checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return guard.CheckRetryOutcomeQuiescence(checkCtx, running.Scope)
	}
	if d.stopQuiescence == nil {
		// Signed production dispatch must have its authoritative effect checker.
		// The unsigned in-memory compatibility fixtures have no effect providers.
		if d.signer != nil {
			return errors.New("execution effect authority unavailable")
		}
		return ctx.Err()
	}
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return d.stopQuiescence(checkCtx, running.Scope)
}
