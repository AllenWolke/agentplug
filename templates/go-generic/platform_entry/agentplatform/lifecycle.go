package agentplatform

import (
	"errors"
	"sync"
	"time"
)

// Run lifecycle SPI. The SDK owns the run state machine so generated Agents
// never build a parallel one; business code only sees the RunHandler seam.
// 运行生命周期 SPI：状态机由 SDK 持有，生成 Agent 不得自建；业务代码只实现
// RunHandler 接缝。

type RunStatus string

const (
	RunStatusRunning   RunStatus = "running"
	RunStatusWaiting   RunStatus = "waiting"
	RunStatusSucceeded RunStatus = "succeeded"
	RunStatusFailed    RunStatus = "failed"
	RunStatusCancelled RunStatus = "cancelled"
)

// Terminal reports whether a run can no longer transition.
// Terminal 表示运行已进入终态，不允许再迁移。
func (s RunStatus) Terminal() bool {
	return s == RunStatusSucceeded || s == RunStatusFailed || s == RunStatusCancelled
}

// SSE event types carried by the events endpoint.
// events 端点输出的 SSE 事件类型。
const (
	EventAccepted  = "accepted"
	EventStarted   = "started"
	EventProgress  = "progress"
	EventWaiting   = "waiting"
	EventArtifact  = "artifact"
	EventCompleted = "completed"
	EventFailed    = "failed"
	EventCancelled = "cancelled"
)

// ExecutionEventRangeVersion defines disjoint per-execution-generation event
// sequence ranges: base=(revision-1)*ExecutionEventRangeWidth, with emitted
// events occupying base+1 through base+width-1.
const ExecutionEventRangeVersion = "sdk-event-range/v1"

const (
	// ExecutionEventRangeWidth sequence numbers are reserved per execution
	// revision. Emitted events use base+1 through base+width-1.
	ExecutionEventRangeWidth uint64 = 1 << 20
	// ExecutionEventRangeMaxRevision keeps every allocated sequence below 2^53.
	ExecutionEventRangeMaxRevision uint64 = 1 << 33
	// MaxSafeExecutionEventSequence is the largest interoperable JSON event cursor.
	MaxSafeExecutionEventSequence uint64 = (1 << 53) - 1
)

// ErrRunUnknown, ErrIdempotencyConflict and ErrInvalidTransition are the only
// lifecycle failures the transport layer maps; everything else is a store bug.
var (
	ErrRunUnknown          = errors.New("run is unknown")
	ErrIdempotencyConflict = errors.New("run id reused with a different idempotency key")
	ErrInvalidTransition   = errors.New("run state transition is invalid")
)

// RunRecord is the immutable view of one run returned by a RunStore.
// RunRecord 是 RunStore 返回的单次运行的只读视图。
type RunRecord struct {
	RunID          string
	Scope          ScopeKey
	IdempotencyKey string
	Status         RunStatus
	Output         map[string]any
	Error          *AppError
	Events         []ExecutionEvent
}

// RunStore is the platform run state SPI. L2/L3 deployments must provide a
// scoped, durable implementation (tenant isolation, restart recovery); the
// bundled MemoryRunStore is explicitly forbidden there.
// RunStore 是平台运行状态 SPI：L2/L3 必须提供带 Scope 隔离与重启恢复的持久化
// 实现；内置 MemoryRunStore 显式禁止用于 L2/L3。
type RunStore interface {
	// StartRun creates a run or returns the existing record for the same
	// run_id and idempotency key. A different key on the same run_id is a
	// conflict. / StartRun 创建运行；同 run_id 且同幂等键时返回既有记录，
	// 幂等键不同则视为冲突。
	StartRun(request ExecuteRequest) (RunRecord, bool, error)
	GetRun(runID string) (RunRecord, bool)
	// AppendEvent appends one event with the next per-run sequence number.
	// Appending to an unknown run fails. / 追加事件并分配下一次序号；
	// 未知运行必须失败。
	AppendEvent(runID string, eventType string, payload map[string]any) (ExecutionEvent, error)
	EventsAfter(runID string, afterSeq uint64) ([]ExecutionEvent, error)
	// MarkWaiting parks an interruptible run awaiting resume.
	MarkWaiting(runID string, payload map[string]any) error
	// Resume moves a waiting run back to running; other states are no-ops so
	// replayed resumes stay idempotent. / Resume 将 waiting 恢复为 running；
	// 其余状态幂等无操作。
	Resume(runID string, payload map[string]any) error
	Cancel(runID string, reason string) (RunRecord, error)
	Complete(runID string, output map[string]any) error
	Fail(runID string, appErr AppError) error
	// Cancelled is closed once cancellation has been requested; the business
	// handler must observe it. / 请求取消后关闭该通道，业务处理器必须观察。
	Cancelled(runID string) (<-chan struct{}, bool)
}

// GenerationRunStore is an optional RunStore extension for SDK entry points
// that hold a verified, non-zero execution revision. Implementations allocate
// event sequence ranges by revision; ordinary RunStore callers remain
// compatible and do not imply cross-generation recovery support.
type GenerationRunStore interface {
	StartGeneration(scope ScopeKey, idempotencyKey string, revision uint64) (RunRecord, bool, error)
	ResumeGeneration(scope ScopeKey, idempotencyKey string, revision uint64) error
}

// RecoveryGenerationRunStore explicitly permits replacing a stopped
// generation projection after the supervisor validates platform stop
// provenance. Implementations must reject nonterminal or conflicting records
// and retain only their actual prior events.
type RecoveryGenerationRunStore interface {
	GenerationRunStore
	RecoverGeneration(scope ScopeKey, idempotencyKey string, stoppedRevision, executionRevision uint64) (RunRecord, error)
}

// HandoffRunStore explicitly supports importing a platform-authorized waiting
// projection after a verified SDK handoff. Implementations must atomically
// reject conflicting Runs and must not synthesize prior events or outputs.
type HandoffRunStore interface {
	RunStore
	AdoptWaiting(scope ScopeKey, idempotencyKey string, lastEventSeq uint64) (RunRecord, error)
}

// MemoryRunStore is the development-only in-memory RunStore.
// MemoryRunStore 是仅限开发环境的内存 RunStore：
//
//	NOT FOR L2/L3 — state dies with the process and there is no cross-replica
//	recovery. Production deployments must inject a durable scoped store.
//	不可用于 L2/L3 —— 状态随进程消失且无跨副本恢复；生产必须注入持久化存储。
type MemoryRunStore struct {
	mu   sync.Mutex
	runs map[string]*memoryRun
}

type memoryRun struct {
	record        RunRecord
	sequenceBase  uint64
	generation    uint64
	legacySeqSafe bool
	cancel        chan struct{}
	cancelOnce    sync.Once
	resumeSignals chan struct{}
}

// NewMemoryRunStore returns an empty development store.
func NewMemoryRunStore() *MemoryRunStore {
	return &MemoryRunStore{runs: map[string]*memoryRun{}}
}

// StartRun is idempotent per (run_id, idempotency_key); scope belongs to the
// first caller and is never rewritten by replays.
// StartRun 以 (run_id, idempotency_key) 幂等；Scope 归首次调用方，
// 重放绝不改写。
func (m *MemoryRunStore) StartRun(request ExecuteRequest) (RunRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	runID := request.Scope.RunID
	if runID == "" {
		return RunRecord{}, false, ErrInvalidTransition
	}
	if existing, ok := m.runs[runID]; ok {
		if existing.record.IdempotencyKey != request.IdempotencyKey {
			return RunRecord{}, false, ErrIdempotencyConflict
		}
		return snapshotOf(existing), false, nil
	}
	run := &memoryRun{
		record: RunRecord{
			RunID:          runID,
			Scope:          request.Scope,
			IdempotencyKey: request.IdempotencyKey,
			Status:         RunStatusRunning,
		},
		cancel:        make(chan struct{}),
		resumeSignals: make(chan struct{}, 1),
	}
	m.runs[runID] = run
	event := appendLocked(run, EventAccepted, map[string]any{"idempotency_key": request.IdempotencyKey})
	_ = event
	return snapshotOf(run), true, nil
}

// StartGeneration creates the first projection for one run generation. A
// replay of that same generation returns the existing projection without
// adding another event; a different scope, key, or generation is rejected.
func (m *MemoryRunStore) StartGeneration(scope ScopeKey, idempotencyKey string, revision uint64) (RunRecord, bool, error) {
	base, maxSequence, ok := executionEventRange(revision)
	if !validHandoffIdentifier(scope.RunID) || idempotencyKey == "" || len(idempotencyKey) > 128 || !ok {
		return RunRecord{}, false, ErrInvalidTransition
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, exists := m.runs[scope.RunID]; exists {
		if stableExecutionScope(existing.record.Scope) != stableExecutionScope(scope) || existing.record.IdempotencyKey != idempotencyKey {
			return RunRecord{}, false, ErrIdempotencyConflict
		}
		if existing.generation != revision {
			return RunRecord{}, false, ErrInvalidTransition
		}
		return snapshotOf(existing), false, nil
	}
	if m.runs == nil {
		m.runs = make(map[string]*memoryRun)
	}
	run := &memoryRun{
		record: RunRecord{
			RunID:          scope.RunID,
			Scope:          scope,
			IdempotencyKey: idempotencyKey,
			Status:         RunStatusRunning,
		},
		sequenceBase:  base,
		generation:    revision,
		cancel:        make(chan struct{}),
		resumeSignals: make(chan struct{}, 1),
	}
	if next, canAppend := nextEventSequence(run); !canAppend || next > maxSequence {
		return RunRecord{}, false, ErrInvalidTransition
	}
	appendLocked(run, EventAccepted, map[string]any{"idempotency_key": idempotencyKey})
	m.runs[scope.RunID] = run
	return snapshotOf(run), true, nil
}

// AdoptWaiting imports only the current waiting projection. Historical events,
// outputs and side effects are intentionally unavailable in this process.
func (m *MemoryRunStore) AdoptWaiting(scope ScopeKey, idempotencyKey string, lastEventSeq uint64) (RunRecord, error) {
	if !validHandoffIdentifier(scope.RunID) || idempotencyKey == "" || len(idempotencyKey) > 128 || lastEventSeq == 0 || lastEventSeq >= 1<<53 {
		return RunRecord{}, ErrInvalidTransition
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.runs[scope.RunID]; exists {
		return RunRecord{}, ErrIdempotencyConflict
	}
	if m.runs == nil {
		m.runs = make(map[string]*memoryRun)
	}
	run := &memoryRun{
		record: RunRecord{
			RunID:          scope.RunID,
			Scope:          scope,
			IdempotencyKey: idempotencyKey,
			Status:         RunStatusWaiting,
		},
		sequenceBase:  lastEventSeq,
		legacySeqSafe: true,
		cancel:        make(chan struct{}),
		resumeSignals: make(chan struct{}, 1),
	}
	m.runs[scope.RunID] = run
	return snapshotOf(run), nil
}

func (m *MemoryRunStore) GetRun(runID string) (RunRecord, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[runID]
	if !ok {
		return RunRecord{}, false
	}
	return snapshotOf(run), true
}

func (m *MemoryRunStore) AppendEvent(runID string, eventType string, payload map[string]any) (ExecutionEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[runID]
	if !ok {
		return ExecutionEvent{}, ErrRunUnknown
	}
	if _, canAppend := nextEventSequence(run); !canAppend {
		return ExecutionEvent{}, ErrInvalidTransition
	}
	return appendLocked(run, eventType, payload), nil
}

// appendLocked assigns strictly increasing per-run sequence numbers; the
// caller must hold the store lock.
// appendLocked 分配单调递增的次序号；调用方必须已持锁。
func appendLocked(run *memoryRun, eventType string, payload map[string]any) ExecutionEvent {
	seq, _ := nextEventSequence(run)
	event := ExecutionEvent{
		RunID:      run.record.RunID,
		Seq:        seq,
		EventType:  eventType,
		OccurredAt: time.Now().UTC(),
		Payload:    payload,
	}
	if event.Payload == nil {
		event.Payload = map[string]any{}
	}
	run.record.Events = append(run.record.Events, event)
	return event
}

func executionEventRange(revision uint64) (base, maxSequence uint64, ok bool) {
	if revision == 0 || revision > ExecutionEventRangeMaxRevision {
		return 0, 0, false
	}
	base = (revision - 1) * ExecutionEventRangeWidth
	maxSequence = base + ExecutionEventRangeWidth - 1
	return base, maxSequence, maxSequence <= MaxSafeExecutionEventSequence
}

func nextEventSequence(run *memoryRun) (uint64, bool) {
	floor := run.sequenceBase
	if count := len(run.record.Events); count != 0 && run.record.Events[count-1].Seq > floor {
		floor = run.record.Events[count-1].Seq
	}
	if floor == ^uint64(0) {
		return 0, false
	}
	next := floor + 1
	if run.generation != 0 {
		base, maxSequence, ok := executionEventRange(run.generation)
		if !ok || next <= base || next > maxSequence {
			return 0, false
		}
	} else if run.legacySeqSafe && next >= 1<<53 {
		return 0, false
	}
	return next, true
}

func (m *MemoryRunStore) EventsAfter(runID string, afterSeq uint64) ([]ExecutionEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[runID]
	if !ok {
		return nil, ErrRunUnknown
	}
	events := make([]ExecutionEvent, 0, len(run.record.Events))
	for _, event := range run.record.Events {
		if event.Seq > afterSeq {
			events = append(events, event)
		}
	}
	return events, nil
}

func (m *MemoryRunStore) MarkWaiting(runID string, payload map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[runID]
	if !ok {
		return ErrRunUnknown
	}
	if run.record.Status != RunStatusRunning {
		return ErrInvalidTransition
	}
	if _, canAppend := nextEventSequence(run); !canAppend {
		return ErrInvalidTransition
	}
	run.record.Status = RunStatusWaiting
	appendLocked(run, EventWaiting, payload)
	return nil
}

// Resume is idempotent: only a waiting run transitions, and the resume signal
// is delivered exactly once per transition.
// Resume 幂等：仅 waiting 状态迁移，且每次迁移只投递一次恢复信号。
func (m *MemoryRunStore) Resume(runID string, payload map[string]any) error {
	m.mu.Lock()
	run, ok := m.runs[runID]
	if !ok {
		m.mu.Unlock()
		return ErrRunUnknown
	}
	if run.record.Status != RunStatusWaiting {
		m.mu.Unlock()
		return nil
	}
	if _, canAppend := nextEventSequence(run); !canAppend {
		m.mu.Unlock()
		return ErrInvalidTransition
	}
	run.record.Status = RunStatusRunning
	appendLocked(run, EventStarted, payload)
	m.mu.Unlock()
	select {
	case run.resumeSignals <- struct{}{}:
	default:
	}
	return nil
}

// ResumeGeneration advances only an existing waiting projection and appends
// its first real event in the newly authorized generation's range. No event
// or prior history is synthesized.
func (m *MemoryRunStore) ResumeGeneration(scope ScopeKey, idempotencyKey string, revision uint64) error {
	base, maxSequence, ok := executionEventRange(revision)
	if !validHandoffIdentifier(scope.RunID) || idempotencyKey == "" || len(idempotencyKey) > 128 || !ok {
		return ErrInvalidTransition
	}

	m.mu.Lock()
	run, exists := m.runs[scope.RunID]
	if !exists {
		m.mu.Unlock()
		return ErrRunUnknown
	}
	if stableExecutionScope(run.record.Scope) != stableExecutionScope(scope) || run.record.IdempotencyKey != idempotencyKey {
		m.mu.Unlock()
		return ErrIdempotencyConflict
	}
	if run.record.Status != RunStatusWaiting || (run.generation != 0 && revision <= run.generation) {
		m.mu.Unlock()
		return ErrInvalidTransition
	}
	lastSequence := run.sequenceBase
	if count := len(run.record.Events); count != 0 && run.record.Events[count-1].Seq > lastSequence {
		lastSequence = run.record.Events[count-1].Seq
	}
	if base < lastSequence || base == ^uint64(0) || base+1 > maxSequence {
		m.mu.Unlock()
		return ErrInvalidTransition
	}
	// All checks precede the state update, ensuring a full range cannot leave
	// a partially transitioned projection or emit a cancellation/resume signal.
	run.generation = revision
	run.sequenceBase = base
	run.legacySeqSafe = false
	run.record.Status = RunStatusRunning
	appendLocked(run, EventStarted, map[string]any{"operation": "resume"})
	m.mu.Unlock()
	select {
	case run.resumeSignals <- struct{}{}:
	default:
	}
	return nil
}

// RecoverGeneration imports a new running projection only after the SDK
// supervisor has verified the platform stop reference and handler-exit proof.
// It keeps all actual old events but does not carry old output or errors into
// the new generation.
func (m *MemoryRunStore) RecoverGeneration(scope ScopeKey, idempotencyKey string, stoppedRevision, executionRevision uint64) (RunRecord, error) {
	base, maxSequence, validRange := executionEventRange(executionRevision)
	if !validHandoffIdentifier(scope.RunID) || idempotencyKey == "" || len(idempotencyKey) > 128 ||
		stoppedRevision == 0 || stoppedRevision >= ExecutionEventRangeMaxRevision-2 ||
		executionRevision != stoppedRevision+3 || !validRange {
		return RunRecord{}, ErrInvalidTransition
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runs == nil {
		m.runs = make(map[string]*memoryRun)
	}
	run, exists := m.runs[scope.RunID]
	if exists {
		if stableExecutionScope(run.record.Scope) != stableExecutionScope(scope) || run.record.IdempotencyKey != idempotencyKey {
			return RunRecord{}, ErrIdempotencyConflict
		}
		if !run.record.Status.Terminal() || (run.generation != 0 && run.generation != stoppedRevision) {
			return RunRecord{}, ErrInvalidTransition
		}
		lastSequence := run.sequenceBase
		if eventSequence := actualLastEventSeq(run.record.Events); eventSequence > lastSequence {
			lastSequence = eventSequence
		}
		if base < lastSequence {
			return RunRecord{}, ErrInvalidTransition
		}
	} else {
		run = &memoryRun{
			record: RunRecord{RunID: scope.RunID, Scope: scope, IdempotencyKey: idempotencyKey},
		}
	}
	// The new started event must fit before replacing any terminal state.
	if base == ^uint64(0) || base+1 > maxSequence {
		return RunRecord{}, ErrInvalidTransition
	}
	run.record.RunID = scope.RunID
	run.record.Scope = scope
	run.record.IdempotencyKey = idempotencyKey
	run.record.Status = RunStatusRunning
	run.record.Output = nil
	run.record.Error = nil
	run.sequenceBase = base
	run.generation = executionRevision
	run.legacySeqSafe = false
	run.cancel = make(chan struct{})
	run.cancelOnce = sync.Once{}
	run.resumeSignals = make(chan struct{}, 1)
	appendLocked(run, EventStarted, map[string]any{"operation": "resume", "reason": "runtime_recovery"})
	m.runs[scope.RunID] = run
	return snapshotOf(run), nil
}

func (m *MemoryRunStore) Cancel(runID string, reason string) (RunRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[runID]
	if !ok {
		return RunRecord{}, ErrRunUnknown
	}
	if run.record.Status.Terminal() {
		return snapshotOf(run), nil
	}
	if _, canAppend := nextEventSequence(run); !canAppend {
		return RunRecord{}, ErrInvalidTransition
	}
	run.record.Status = RunStatusCancelled
	payload := map[string]any{}
	if reason != "" {
		payload["reason"] = reason
	}
	appendLocked(run, EventCancelled, payload)
	run.cancelOnce.Do(func() { close(run.cancel) })
	return snapshotOf(run), nil
}

func (m *MemoryRunStore) Complete(runID string, output map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[runID]
	if !ok {
		return ErrRunUnknown
	}
	if run.record.Status.Terminal() {
		return ErrInvalidTransition
	}
	if _, canAppend := nextEventSequence(run); !canAppend {
		return ErrInvalidTransition
	}
	run.record.Status = RunStatusSucceeded
	run.record.Output = output
	appendLocked(run, EventCompleted, map[string]any{})
	return nil
}

func (m *MemoryRunStore) Fail(runID string, appErr AppError) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[runID]
	if !ok {
		return ErrRunUnknown
	}
	if run.record.Status.Terminal() {
		return ErrInvalidTransition
	}
	if _, canAppend := nextEventSequence(run); !canAppend {
		return ErrInvalidTransition
	}
	run.record.Status = RunStatusFailed
	run.record.Error = &appErr
	appendLocked(run, EventFailed, map[string]any{"code": appErr.Code})
	return nil
}

func (m *MemoryRunStore) Cancelled(runID string) (<-chan struct{}, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[runID]
	if !ok {
		return nil, false
	}
	return run.cancel, true
}

// ResumeSignals exposes the per-run resume notification for handlers that
// park on interrupt; it is a development-store affordance.
// ResumeSignals 暴露每次运行的恢复通知，供中断挂起的业务处理器使用。
func (m *MemoryRunStore) ResumeSignals(runID string) (<-chan struct{}, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[runID]
	if !ok {
		return nil, false
	}
	return run.resumeSignals, true
}

func snapshotOf(run *memoryRun) RunRecord {
	snapshot := run.record
	snapshot.Events = append([]ExecutionEvent(nil), run.record.Events...)
	snapshot.Output = outputCopy(run.record.Output)
	if run.record.Error != nil {
		errCopy := *run.record.Error
		snapshot.Error = &errCopy
	}
	return snapshot
}

func outputCopy(output map[string]any) map[string]any {
	if output == nil {
		return nil
	}
	copied := make(map[string]any, len(output))
	for key, value := range output {
		copied[key] = value
	}
	return copied
}
