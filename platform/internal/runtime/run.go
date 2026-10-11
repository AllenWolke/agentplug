package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type Status string

const (
	StatusAccepted  Status = "accepted"
	StatusRunning   Status = "running"
	StatusWaiting   Status = "waiting"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
	// Cancellation requested is not proof that the remote execution stopped.
	// 请求取消不等于远程任务已停止；停止确认前保留会话与执行租约。
	StatusCancelling Status = "cancelling"
	// Recovery must stop the old generation before a new worker can claim it.
	// 恢复前先确认旧世代停止；这不是用户取消，也不是业务终态。
	StatusRecovering Status = "recovering"
)

var (
	ErrRunNotFound         = errors.New("run not found")
	ErrIdempotencyConflict = errors.New("idempotency conflict")
	ErrInvalidTransition   = errors.New("invalid run transition")
	ErrRevisionConflict    = errors.New("run revision conflict")
	ErrLeaseConflict       = errors.New("run lease conflict")
	ErrInvalidRequest      = errors.New("invalid execution request")
)

type Run struct {
	ID             string
	Scope          sharedkernel.Scope
	AgentVersionID string
	IdempotencyKey string
	// RequestJSON is the signed Agent Execution v2 envelope retained by the
	// platform dispatcher.  It is never returned to untrusted callers.
	// RequestJSON 是平台调度器保留的已签名 v2 请求，只供内部派发，绝不回传给不可信调用方。
	RequestJSON []byte
	// TraceContext is metadata, not an authorization credential.
	// 追踪上下文只用于可观测关联，不作为授权凭据。
	TraceContext string
	// ResumeInputJSON is the durable decision included in the newly signed resume
	// command. Never reuse an invoke token to authorize this different body.
	// ResumeInputJSON 是恢复命令重新签名的持久化决策，禁止复用 Invoke 令牌。
	ResumeInputJSON []byte
	AgentEndpoint   string
	Status          Status
	Revision        uint64
	LeaseToken      string
	LeaseUntil      time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type CreateRequest struct {
	MessageID      string
	ID             string
	Scope          sharedkernel.Scope
	AgentVersionID string
	IdempotencyKey string
	Fingerprint    string
	RequestJSON    []byte
	TraceContext   string
	AgentEndpoint  string
}

// ScopeIdempotencyHash returns the stable bounded key used by SQL stores.
// ScopeIdempotencyHash 返回 SQL 仓储使用的固定长度幂等键，避免复合索引超过
// InnoDB 的最大索引字节数。
func ScopeIdempotencyHash(scope sharedkernel.Scope, idempotencyKey string) string {
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s:%s:%d:%s:%s", scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentInstanceID, scope.AgentID, scope.PrincipalType, scope.PrincipalID, scope.InstallationID, scope.AgentVersionID, scope.AuthorizationEpoch, scope.SessionID, idempotencyKey)
}

type CreateResult struct {
	Run      Run
	Replayed bool
}

type Store struct {
	mu          sync.Mutex
	runs        map[string]Run
	idempotency map[string]struct {
		fingerprint string
		runID       string
	}
	events    map[string][]Event
	outcomes  map[string]Outcome
	creations map[string]CreationProjection
	commands  map[string]DispatchCommand
	sessions  map[string]sessionLease
}

// ListPending returns accepted runs that have not crossed the Agent boundary.
// It is intentionally a small optional repository capability so a dispatcher
// can recover work after a process restart without making the HTTP module
// depend on a concrete database.
// ListPending 返回尚未跨越 Agent 边界的 accepted Run；它是可选仓储能力，
// 允许 Dispatcher 在进程重启后补偿，而不让 HTTP 模块依赖具体数据库。
func (s *Store) ListPending(limit int) ([]Run, error) {
	if limit < 1 {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]Run, 0, limit)
	for _, run := range s.runs {
		if (run.Status != StatusAccepted && !(run.Status == StatusRunning && run.LeaseToken == "")) || run.AgentEndpoint == "" || len(run.RequestJSON) == 0 {
			continue
		}
		result = append(result, run)
		if len(result) == limit {
			break
		}
	}
	return result, nil
}

// ListRunningExpired returns running runs whose dispatcher lease has expired.
// The result is bounded so a single reconciliation tick cannot monopolize the
// worker; AcquireLease must still fence each returned run before dispatch.
// ListRunningExpired 返回租约已过期的 running Run；结果有界，调用方必须
// 先 BeginRecovery 并确认旧世代停止，不能直接 AcquireLease 抢占。
func (s *Store) ListRunningExpired(now time.Time, limit int) ([]Run, error) {
	if limit < 1 {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]Run, 0, limit)
	for _, run := range s.runs {
		if run.Status != StatusRunning || run.AgentEndpoint == "" || len(run.RequestJSON) == 0 || run.LeaseUntil.IsZero() || run.LeaseUntil.After(now) {
			continue
		}
		result = append(result, run)
		if len(result) == limit {
			break
		}
	}
	return result, nil
}

func NewStore() *Store {
	return &Store{runs: map[string]Run{}, idempotency: map[string]struct{ fingerprint, runID string }{}, events: map[string][]Event{}, outcomes: map[string]Outcome{}, creations: map[string]CreationProjection{}, commands: map[string]DispatchCommand{}, sessions: map[string]sessionLease{}}
}

func (s *Store) Create(req CreateRequest) (CreateResult, error) {
	if req.ID == "" || req.AgentVersionID == "" || req.IdempotencyKey == "" || req.Fingerprint == "" {
		return CreateResult{}, ErrIdempotencyConflict
	}
	if err := req.Scope.Validate(); err != nil {
		return CreateResult{}, err
	}
	// Normalize duplicated identity fields before computing the idempotency
	// key, otherwise old callers that put the version only at the top level
	// would create a different key on replay.
	// 在计算幂等键前归一化重复身份字段，避免旧调用方仅填写顶层版本时
	// 重放请求生成不同的幂等键。
	if req.Scope.AgentVersionID == "" {
		req.Scope.AgentVersionID = req.AgentVersionID
	}
	if req.Scope.RunID == "" {
		req.Scope.RunID = req.ID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.idempotency[idempotencyKey(req.Scope, req.IdempotencyKey)]; ok {
		if previous.fingerprint != req.Fingerprint {
			return CreateResult{}, ErrIdempotencyConflict
		}
		return CreateResult{Run: s.runs[previous.runID], Replayed: true}, nil
	}
	now := time.Now().UTC()
	run := Run{ID: req.ID, Scope: req.Scope, AgentVersionID: req.AgentVersionID, IdempotencyKey: req.IdempotencyKey, RequestJSON: append([]byte(nil), req.RequestJSON...), TraceContext: req.TraceContext, AgentEndpoint: req.AgentEndpoint, Status: StatusAccepted, Revision: 1, CreatedAt: now, UpdatedAt: now}
	s.runs[run.ID] = run
	s.idempotency[idempotencyKey(req.Scope, req.IdempotencyKey)] = struct{ fingerprint, runID string }{req.Fingerprint, run.ID}
	s.appendEventLocked(run.ID, "accepted", map[string]any{"status": string(StatusAccepted)})
	s.creations[run.ID] = CreationProjection{RunID: run.ID, MessageID: req.MessageID, ConversationPending: true, TaskPending: true}
	return CreateResult{Run: run}, nil
}

func (s *Store) Get(id string) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return Run{}, ErrRunNotFound
	}
	return run, nil
}

func (s *Store) Transition(id string, from, to Status, expectedRevision uint64) (Run, error) {
	return s.transition(id, from, to, expectedRevision, "")
}

// TransitionLeased fences worker writes with its private lease token.
// TransitionLeased 使用私有租约令牌阻断失去所有权的 Worker 写入。
func (s *Store) TransitionLeased(id string, from, to Status, revision uint64, token string) (Run, error) {
	if token == "" {
		return Run{}, ErrLeaseConflict
	}
	return s.transition(id, from, to, revision, token)
}

func (s *Store) transition(id string, from, to Status, expectedRevision uint64, token string) (Run, error) {
	return s.transitionOutcome(id, from, to, expectedRevision, token, nil)
}

func (s *Store) transitionOutcome(id string, from, to Status, expectedRevision uint64, token string, outcome *Outcome) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return Run{}, ErrRunNotFound
	}
	if run.Revision != expectedRevision {
		return Run{}, ErrRevisionConflict
	}
	if token != "" && (run.LeaseToken != token || !run.LeaseUntil.After(time.Now().UTC())) {
		return Run{}, ErrLeaseConflict
	}
	if token != "" && s.checkSessionLeaseLocked(run, time.Now().UTC()) != nil {
		return Run{}, ErrLeaseConflict
	}
	if !validTransition(from, to) || run.Status != from {
		return Run{}, ErrInvalidTransition
	}
	run.Status = to
	run.Revision++
	run.UpdatedAt = time.Now().UTC()
	if to == StatusSucceeded || to == StatusFailed {
		run.LeaseToken = ""
		run.LeaseUntil = time.Time{}
	}
	s.runs[id] = run
	s.releaseSessionLocked(run)
	s.appendEventLocked(id, "status", map[string]any{"from": string(from), "to": string(to), "revision": run.Revision})
	if outcome != nil {
		outcome.RunID, outcome.Revision = id, run.Revision
		s.outcomes[id] = *outcome
		s.appendEventLocked(id, outcome.EventType, outcome.EventPayload)
	}
	return run, nil
}

// Cancel atomically transitions a non-terminal Run to cancelled and appends
// both the status and task_cancelled events under the same lock.  This mirrors
// the SQL repository transaction and prevents a successful status update from
// becoming visible without its audit event.
// Cancel 在同一把锁下完成终态迁移及两个事件追加，和 SQL 仓储保持一致，
// 避免状态成功但审计事件缺失。
func (s *Store) Cancel(id string, expectedRevision uint64) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return Run{}, ErrRunNotFound
	}
	if run.Status == StatusCancelled {
		return run, nil
	}
	if run.Status == StatusSucceeded || run.Status == StatusFailed {
		return Run{}, ErrInvalidTransition
	}
	if expectedRevision != 0 && run.Revision != expectedRevision {
		return Run{}, ErrRevisionConflict
	}
	from := run.Status
	if !validTransition(from, StatusCancelled) {
		return Run{}, ErrInvalidTransition
	}
	run.Status = StatusCancelled
	run.LeaseToken = ""
	run.LeaseUntil = time.Time{}
	run.Revision++
	run.UpdatedAt = time.Now().UTC()
	s.runs[id] = run
	s.appendEventLocked(id, "status", map[string]any{"from": string(from), "to": string(StatusCancelled), "revision": run.Revision})
	s.appendEventLocked(id, "task_cancelled", map[string]any{"source": "platform_cancel"})
	outcome, err := NewOutcome(StatusCancelled, map[string]any{}, map[string]any{"source": "platform_cancel"})
	if err != nil {
		return Run{}, err
	}
	outcome.RunID, outcome.Revision = run.ID, run.Revision
	s.outcomes[id] = outcome
	s.releaseSessionLocked(run)
	return run, nil
}

// PrepareResume atomically parks the resume command in the durable Run and
// moves waiting -> running. The dispatcher then consumes RequestJSON with the
// operation set to resume, so a process restart cannot lose the approval input.
// PrepareResume 将恢复输入原子写入持久化 Run，并将 waiting -> running；
// Dispatcher 随后消费 operation=resume 的请求，重启不会丢失审核输入。
func (s *Store) PrepareResume(id string, input []byte) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return Run{}, ErrRunNotFound
	}
	if run.Status != StatusWaiting {
		return Run{}, ErrInvalidTransition
	}
	if len(input) == 0 {
		return Run{}, ErrInvalidRequest
	}
	var decoded any
	if err := json.Unmarshal(input, &decoded); err != nil {
		return Run{}, ErrInvalidRequest
	}
	run.ResumeInputJSON = append([]byte(nil), input...)
	// Resume is a new command, not a transfer of the previous worker's lease.
	// 恢复是新命令，必须重新领取租约，不继承旧执行者的凭据。
	run.LeaseToken = ""
	run.LeaseUntil = time.Time{}
	run.Status = StatusRunning
	run.Revision++
	run.UpdatedAt = time.Now().UTC()
	s.runs[id] = run
	s.appendEventLocked(id, "status", map[string]any{"from": string(StatusWaiting), "to": string(StatusRunning), "revision": run.Revision})
	return run, nil
}

func (s *Store) AcquireLease(id, token string, now time.Time, ttl time.Duration) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return Run{}, ErrRunNotFound
	}
	if token == "" || ttl <= 0 || (run.Status != StatusAccepted && run.Status != StatusRunning) || (run.LeaseToken != "" && run.LeaseToken != token) {
		return Run{}, ErrLeaseConflict
	}
	if err := s.claimSessionLocked(run, token, now, now.Add(ttl)); err != nil {
		return Run{}, err
	}
	run.LeaseToken = token
	run.LeaseUntil = now.Add(ttl)
	run.Revision++
	s.runs[id] = run
	return run, nil
}

func (s *Store) Heartbeat(id, token string, expectedRevision uint64, now time.Time, ttl time.Duration) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return Run{}, ErrRunNotFound
	}
	if token == "" || ttl <= 0 || run.Status != StatusRunning || run.Revision != expectedRevision || run.LeaseToken != token || !run.LeaseUntil.After(now) {
		return Run{}, ErrLeaseConflict
	}
	if err := s.checkSessionLeaseLocked(run, now); err != nil {
		return Run{}, err
	}
	run.LeaseUntil = now.Add(ttl)
	s.sessions[SessionExecutionKey(run.Scope)] = sessionLease{RunID: run.ID, Token: token, Until: run.LeaseUntil}
	// Lease extension does not change the command revision/fencing generation.
	// 续租不改变命令版本；重新领取和状态迁移才推进 fencing 版本。
	s.runs[id] = run
	return run, nil
}

func (s *Store) Events(id string, afterSeq uint64) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[id]; !ok {
		return nil, ErrRunNotFound
	}
	all := s.events[id]
	result := make([]Event, 0, len(all))
	for _, event := range all {
		if event.Seq > afterSeq {
			result = append(result, event)
			if len(result) == 256 {
				break
			}
		}
	}
	return result, nil
}

// AppendEvent appends a durable run event and returns its monotonic sequence.
// AppendEvent 追加持久化运行事件并返回单调递增序号。
func (s *Store) AppendEvent(id, eventType string, payload map[string]any) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[id]; !ok {
		return Event{}, ErrRunNotFound
	}
	if eventType == "" {
		return Event{}, ErrInvalidTransition
	}
	s.appendEventLocked(id, eventType, payload)
	events := s.events[id]
	return events[len(events)-1], nil
}

type Event struct {
	Seq        uint64
	Type       string
	Payload    map[string]any
	OccurredAt time.Time
}

func (s *Store) appendEventLocked(runID, eventType string, payload map[string]any) {
	events := s.events[runID]
	events = append(events, Event{Seq: uint64(len(events) + 1), Type: eventType, Payload: payload, OccurredAt: time.Now().UTC()})
	s.events[runID] = events
}

func idempotencyKey(scope sharedkernel.Scope, key string) string {
	return ScopeIdempotencyHash(scope, key)
}

func validTransition(from, to Status) bool {
	return map[Status]map[Status]bool{
		StatusAccepted:   {StatusRunning: true, StatusCancelled: true, StatusFailed: true},
		StatusRunning:    {StatusWaiting: true, StatusSucceeded: true, StatusFailed: true, StatusCancelled: true},
		StatusWaiting:    {StatusRunning: true, StatusSucceeded: true, StatusFailed: true, StatusCancelled: true},
		StatusCancelling: {StatusCancelled: true},
	}[from][to]
}
