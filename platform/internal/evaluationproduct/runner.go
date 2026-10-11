package evaluationproduct

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
	"log"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var ErrUnsupportedMetric = errors.New("evaluation metric is not supported by the built-in evaluator")
var errFinalization = errors.New("evaluation finalization is awaiting durable recovery")

type RunnerOptions struct {
	Workers       int
	PollInterval  time.Duration
	LeaseDuration time.Duration
	CaseTimeout   time.Duration
}

// Runner is a durable, at-least-once product evaluator. The store lease is the
// authority; wakeups and active cancellation handles are only process-local
// optimizations. Agent calls are scoped, version-pinned and idempotent.
type Runner struct {
	store     ExecutionStore
	invoker   AgentInvoker
	metrics   MetricEvaluator
	artifacts ArtifactWriter
	options   RunnerOptions
	owner     string
	wake      chan struct{}

	mu                    sync.Mutex
	started               bool
	closed                bool
	cancel                context.CancelFunc
	active                map[string]context.CancelFunc
	wg                    sync.WaitGroup
	claimFailures         atomic.Uint64
	finalizeFailures      atomic.Uint64
	claimFailureStreak    atomic.Int32
	finalizeFailureStreak atomic.Int32
}

// WorkerStats reports safe counters without tenant IDs or input payloads.
// WorkerStats 提供无敏感字段的错误计数，供可观测适配器读取。
type WorkerStats struct {
	ClaimFailures    uint64 `json:"claim_failures"`
	FinalizeFailures uint64 `json:"finalize_failures"`
	Active           int    `json:"active"`
	Capacity         int    `json:"capacity"`
	Ready            bool   `json:"ready"`
}

func (r *Runner) Stats() WorkerStats {
	if r == nil {
		return WorkerStats{}
	}
	r.mu.Lock()
	active := len(r.active)
	capacity := r.options.Workers
	started := r.started && !r.closed
	r.mu.Unlock()
	return WorkerStats{
		ClaimFailures: r.claimFailures.Load(), FinalizeFailures: r.finalizeFailures.Load(),
		Active: active, Capacity: capacity,
		Ready: started && r.claimFailureStreak.Load() < 3 && r.finalizeFailureStreak.Load() < 3,
	}
}

// Ready reflects repeated claim failures instead of reporting a healthy idle
// worker while the durable queue is unavailable. / 队列持续领取失败不能伪装空闲健康。
func (r *Runner) Ready() error {
	if r == nil || r.store == nil {
		return errors.New("evaluation worker unavailable")
	}
	r.mu.Lock()
	active := r.started && !r.closed
	r.mu.Unlock()
	if !active || r.claimFailureStreak.Load() >= 3 || r.finalizeFailureStreak.Load() >= 3 {
		return errors.New("evaluation worker unavailable")
	}
	return nil
}

func NewRunner(store ExecutionStore, invoker AgentInvoker, metrics MetricEvaluator, artifacts ArtifactWriter, options RunnerOptions) (*Runner, error) {
	if store == nil || invoker == nil || artifacts == nil {
		return nil, errors.New("evaluation store, Agent Gateway invoker, and scoped artifact writer are required")
	}
	if options.Workers == 0 {
		options.Workers = 1
	}
	if options.PollInterval == 0 {
		options.PollInterval = time.Second
	}
	if options.LeaseDuration == 0 {
		options.LeaseDuration = 2 * time.Minute
	}
	if options.CaseTimeout == 0 {
		options.CaseTimeout = 45 * time.Second
	}
	if options.Workers < 1 || options.Workers > 64 || options.PollInterval < 10*time.Millisecond || options.LeaseDuration < 10*time.Second || options.CaseTimeout <= 0 || options.CaseTimeout*2 >= options.LeaseDuration {
		return nil, errors.New("invalid evaluation runner limits: case timeout must be less than half the lease")
	}
	owner, err := newID()
	if err != nil {
		return nil, err
	}
	if metrics == nil {
		metrics = BuiltinMetricEvaluator{}
	}
	return &Runner{store: store, invoker: invoker, metrics: metrics, artifacts: artifacts, options: options, owner: "eval-" + owner, wake: make(chan struct{}, options.Workers), active: make(map[string]context.CancelFunc)}, nil
}

func (r *Runner) Start(parent context.Context) error {
	if r == nil || r.store == nil {
		return errors.New("evaluation runner is unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("evaluation runner is closed")
	}
	if r.started {
		return nil
	}
	ctx, cancel := context.WithCancel(parent)
	r.cancel, r.started = cancel, true
	for worker := 0; worker < r.options.Workers; worker++ {
		r.wg.Add(1)
		go r.work(ctx)
	}
	return nil
}

func (r *Runner) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	if r.cancel != nil {
		r.cancel()
	}
	for _, cancel := range r.active {
		cancel()
	}
	r.mu.Unlock()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Runner) Enqueue(ctx context.Context, scope Scope, row Resource) error {
	if r == nil || !scope.valid() || row.Kind != KindRun || row.Scope != scope || !validID(row.ID) {
		return ErrInvalid
	}
	stored, err := r.store.Get(ctx, scope, KindRun, row.ID)
	if err != nil {
		return err
	}
	if stored.Scope != scope || stored.ID != row.ID || stored.Kind != KindRun {
		return ErrConflict
	}
	// Recovery workers may finish the durable row before its create call enqueues.
	// 补偿 Worker 可能先于创建请求的唤醒动作完成；终态唤醒幂等成功，但不得重跑。
	if stored.Status == "succeeded" || stored.Status == "failed" || stored.Status == "cancelled" {
		return nil
	}
	if stored.Status != "queued" && stored.Status != "running" {
		return ErrConflict
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return ErrUnavailable
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return nil
}

func (r *Runner) Cancel(ctx context.Context, scope Scope, runID string, expected uint64) error {
	row, err := r.store.Get(ctx, scope, KindRun, runID)
	if err != nil {
		return err
	}
	if row.Revision != expected || expected == 0 {
		return ErrConflict
	}
	key := scopedRunKey(scope, runID)
	r.mu.Lock()
	if cancel := r.active[key]; cancel != nil {
		cancel()
	}
	r.mu.Unlock()
	return nil
}

func (r *Runner) work(ctx context.Context) {
	defer r.wg.Done()
	ticker := time.NewTicker(r.options.PollInterval)
	defer ticker.Stop()
	backoff := r.options.PollInterval
	for {
		if ctx.Err() != nil {
			return
		}
		token, err := newID()
		if err != nil {
			r.claimFailures.Add(1)
			log.Print("evaluation_worker_error stage=lease_token code=TOKEN_GENERATION_FAILED")
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			continue
		}
		run, claimed, err := r.store.ClaimNextRun(ctx, r.owner, token, time.Now().UTC(), r.options.LeaseDuration)
		if err != nil {
			r.claimFailures.Add(1)
			r.claimFailureStreak.Add(1)
			log.Print("evaluation_worker_error stage=claim code=CLAIM_FAILED")
			if !waitWorkerRetry(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, 5*time.Second)
			continue
		}
		r.claimFailureStreak.Store(0)
		backoff = r.options.PollInterval
		if err == nil && claimed {
			r.process(ctx, run)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		case <-ticker.C:
		}
	}
}

func (r *Runner) process(parent context.Context, run Resource) {
	parent, span := telemetry.Start(parent, "platform.worker.evaluation", trace.SpanKindInternal)
	defer span.End()
	key := scopedRunKey(run.Scope, run.ID)
	ctx, cancel := context.WithCancel(parent)
	r.mu.Lock()
	r.active[key] = cancel
	r.mu.Unlock()
	defer func() {
		cancel()
		r.mu.Lock()
		delete(r.active, key)
		r.mu.Unlock()
		if recovered := recover(); recovered != nil {
			telemetry.Failed(span, "WORKER_PANIC")
			r.failRun(parent, run, "WORKER_PANIC")
		}
	}()
	if err := r.execute(ctx, &run); err != nil {
		telemetry.Failed(span, "EVALUATION_WORKER_FAILED")
		// A failed success commit has an unknown durable outcome. Let the
		// persisted lease expire; never overwrite it with a second failed
		// terminal transition or rerun already committed case effects.
		// 成功终结写入失败时数据库结果可能不确定；等待持久化租约接管，
		// 不叠加失败终态，也不重做已经提交的 Case 副作用。
		if errors.Is(err, errFinalization) {
			return
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, ErrConflict) || parent.Err() != nil {
			return
		}
		code := "EVALUATION_EXECUTION_FAILED"
		if errors.Is(err, ErrSnapshotInvalid) {
			code = "SNAPSHOT_INVALID"
		} else if errors.Is(err, errAgentInvocation) {
			code = "AGENT_INVOCATION_FAILED"
		} else if errors.Is(err, errArtifactPersistence) {
			code = "OUTPUT_ARTIFACT_FAILED"
		}
		r.failRun(parent, run, code)
	}
}

func (r *Runner) execute(ctx context.Context, run *Resource) error {
	request, err := ResolveExecutionSnapshot(ctx, r.store, run.Scope, *run)
	if err != nil {
		return err
	}
	data := request.Dataset()
	metrics := request.Metrics()
	results := make([]CaseResultData, len(data.Cases))
	for i, input := range data.Cases {
		if err := ctx.Err(); err != nil {
			return err
		}
		runData, err := decodeRunData(run.Data)
		if err != nil || !validID(runData.LeaseToken) {
			return snapshotInvalid("run lease disappeared during execution")
		}
		refreshed, err := r.store.RenewRunLease(ctx, run.Scope, run.ID, run.Revision, runData.LeaseToken, time.Now().UTC().Add(r.options.LeaseDuration))
		if err != nil {
			return err
		}
		*run = refreshed
		inputHash := Checksum(input)
		caseID := caseResultID(run.ID, i)
		caseRow, getErr := r.store.Get(ctx, run.Scope, KindCaseResult, caseID)
		if getErr == nil {
			stored, decodeErr := decodeCaseResult(caseRow)
			if caseRow.Scope != run.Scope || caseRow.ID != caseID || decodeErr != nil || stored.RunID != run.ID || stored.Index != i || stored.InputHash != inputHash || len(stored.Metrics) != len(metrics) || !validID(stored.OutputArtifactID) || !validSHA256(stored.OutputHash) {
				return snapshotInvalid("persisted case result does not match the frozen input")
			}
			for metricIndex, metric := range metrics {
				if stored.Metrics[metricIndex].MetricID != metric.ID {
					return snapshotInvalid("persisted case metric binding differs from the frozen suite")
				}
			}
			results[i] = stored
		} else if !errors.Is(getErr, ErrNotFound) {
			return getErr
		} else {
			// Keep gold labels in the evaluator only. The Agent receives the
			// input object, never the full dataset case or expected answer.
			// 金标只供评分器使用；Agent 只能看到 input，不能看到 expected。
			agentCase, caseErr := decodeEvaluationCase(input)
			if caseErr != nil {
				return snapshotInvalid("dataset case violates the frozen input contract")
			}
			caseCtx, caseCancel := context.WithTimeout(ctx, r.options.CaseTimeout)
			invocation, invokeErr := r.invoker.InvokeEvaluationCase(caseCtx, InvocationRequest{
				Scope: run.Scope, RunID: run.ID, IdempotencyKey: fmt.Sprintf("%s.case.%d", request.IdempotencyKey(), i),
				AgentID: request.AgentID(), AgentVersionID: request.AgentVersionID(), CaseIndex: i,
				InstallationID: request.InstallationID(), InstallationRevision: request.InstallationRevision(),
				Input: append(json.RawMessage(nil), agentCase.Input...),
			})
			if invokeErr != nil {
				caseCancel()
				return fmt.Errorf("%w: %v", errAgentInvocation, invokeErr)
			}
			if len(invocation.Output) == 0 || len(invocation.Output) > 64<<10 || !json.Valid(invocation.Output) {
				caseCancel()
				return fmt.Errorf("%w: invalid Agent output", errAgentInvocation)
			}
			output := append([]byte(nil), invocation.Output...)
			outputHash := Checksum(output)
			artifact, artifactErr := r.artifacts.PutEvaluationOutput(caseCtx, run.Scope, run.ID, i, caseID, output)
			if artifactErr != nil {
				caseCancel()
				return fmt.Errorf("%w: %v", errArtifactPersistence, artifactErr)
			}
			if !validID(artifact.ID) || artifact.SHA256 != outputHash || artifact.Size != int64(len(output)) {
				caseCancel()
				return fmt.Errorf("%w: artifact metadata does not verify", errArtifactPersistence)
			}
			caseData := CaseResultData{
				RunID: run.ID, Index: i, InputHash: inputHash, OutputHash: outputHash, OutputArtifactID: artifact.ID,
				ProviderMode:      normalizeProviderMode(invocation.ProviderMode),
				CitationGrounding: normalizeGrounding(invocation.CitationGrounding), DomainGrounding: normalizeGrounding(invocation.DomainGrounding),
				ProducedAt: time.Now().UTC(), Metrics: make([]MetricOutcome, 0, len(metrics)),
			}
			for _, metric := range metrics {
				metric.Formula = append(json.RawMessage(nil), metric.Formula...)
				outcome, scoreErr := r.metrics.EvaluateMetric(caseCtx, metric, append(json.RawMessage(nil), input...), append(json.RawMessage(nil), invocation.Output...))
				caseData.Metrics = append(caseData.Metrics, normalizeMetricOutcome(metric, outcome, scoreErr))
			}
			applyMetricGrounding(&caseData, metrics)
			caseCancel()
			caseBytes, _ := json.Marshal(caseData)
			caseRow = Resource{ID: caseID, Kind: KindCaseResult, Scope: run.Scope, Status: "completed", Revision: 1, CreatedBy: "platform-evaluation-product", CreatedAt: caseData.ProducedAt, UpdatedAt: caseData.ProducedAt, Data: caseBytes}
			if createErr := r.store.CommitRunCase(ctx, run.Scope, run.ID, run.Revision, runData.LeaseToken, caseRow); createErr != nil {
				if !errors.Is(createErr, ErrConflict) {
					return createErr
				}
				caseRow, getErr = r.store.Get(ctx, run.Scope, KindCaseResult, caseID)
				if getErr != nil {
					return getErr
				}
				stored, decodeErr := decodeCaseResult(caseRow)
				if caseRow.Scope != run.Scope || caseRow.ID != caseID || decodeErr != nil || stored.InputHash != inputHash || stored.OutputHash != outputHash {
					return snapshotInvalid("concurrent case result conflicts with this execution")
				}
				caseData = stored
			}
			results[i] = caseData
		}
		if err := r.saveProgress(ctx, run, i+1, 0); err != nil {
			return err
		}
	}
	return r.completeRun(ctx, run, request, data, metrics, results)
}

func (r *Runner) saveProgress(ctx context.Context, run *Resource, completed, failed int) error {
	data, err := decodeRunData(run.Data)
	if err != nil || data.LeaseToken == "" {
		return snapshotInvalid("run lease disappeared while saving progress")
	}
	data.ExecutionState, data.Total, data.Completed, data.Failed = "running", completed+failed, completed, failed
	run.Data, _ = json.Marshal(data)
	expected := run.Revision
	run.Revision++
	run.Status, run.UpdatedAt = "running", time.Now().UTC()
	if err := r.store.UpdateCAS(ctx, run.Scope, KindRun, run.ID, expected, *run); err != nil {
		return err
	}
	updated, err := r.store.RenewRunLease(ctx, run.Scope, run.ID, run.Revision, data.LeaseToken, time.Now().UTC().Add(r.options.LeaseDuration))
	if err != nil {
		return err
	}
	*run = updated
	return nil
}

func (r *Runner) completeRun(ctx context.Context, run *Resource, request ExecutionRequest, dataset DatasetSnapshot, metrics []MetricSnapshot, cases []CaseResultData) error {
	metricOutcomes := aggregateCaseMetrics(metrics, cases)
	providerMode := "real"
	citation, domain, artifactsPresent := "passed", "passed", true
	ids := make([]string, len(cases))
	for i, result := range cases {
		ids[i] = caseResultID(run.ID, i)
		if result.ProviderMode != "real" {
			providerMode = result.ProviderMode
		}
		if result.CitationGrounding != "passed" {
			citation = mergeGrounding(citation, result.CitationGrounding)
		}
		if result.DomainGrounding != "passed" {
			domain = mergeGrounding(domain, result.DomainGrounding)
		}
		if !validID(result.OutputArtifactID) || !validSHA256(result.OutputHash) {
			artifactsPresent = false
		}
	}
	produced := time.Now().UTC()
	evidenceData := EvidenceData{
		RunID: run.ID, SuiteID: request.Suite().ID, SuiteSnapshotHash: request.Suite().SnapshotHash, DatasetContentHash: dataset.ContentHash,
		AgentVersionID: request.AgentVersionID(), Status: "succeeded",
		ProviderMode: providerMode, SourceType: dataset.SourceType, SampleCount: len(cases), Metrics: metricOutcomes,
		MetricsPresent: len(metricOutcomes) == len(metrics), ArtifactsPresent: artifactsPresent,
		CitationGrounding: citation, DomainGrounding: domain, ProducedAt: produced, CaseResultIDs: ids,
	}
	reportHash, err := evaluationReportHash(evidenceData, cases)
	if err != nil {
		return err
	}
	evidenceData.ReportHash = reportHash
	evidenceData.Gate = evaluateEvidence(evidenceData, nil, produced)
	evidenceBytes, _ := json.Marshal(evidenceData)
	evidenceTime := produced
	evidence := Resource{ID: evidenceResourceID(run.ID), Kind: KindEvidence, Scope: run.Scope, Status: "completed", Revision: 1, CreatedBy: "platform-evaluation-product", CreatedAt: evidenceTime, UpdatedAt: evidenceTime, Data: evidenceBytes}
	runData, err := decodeRunData(run.Data)
	if err != nil || runData.LeaseToken == "" {
		return snapshotInvalid("run lease disappeared before finalization")
	}
	final := *run
	runData.ExecutionState = "succeeded"
	runData.Total, runData.Completed, runData.Failed = len(cases), len(cases), 0
	runData.ErrorCode, runData.LeaseOwner, runData.LeaseToken = "", "", ""
	runData.LeaseUntil = time.Time{}
	final.Data, _ = json.Marshal(runData)
	expected := run.Revision
	final.Revision++
	final.Status, final.UpdatedAt = "succeeded", time.Now().UTC()
	if err := r.store.FinalizeRun(ctx, run.Scope, expected, request.leaseToken, final, &evidence); err != nil {
		r.finalizeFailures.Add(1)
		r.finalizeFailureStreak.Add(1)
		log.Printf("evaluation_worker_error run_id=%s stage=finalize code=FINALIZE_FAILED", run.ID)
		return fmt.Errorf("%w: %v", errFinalization, err)
	}
	r.finalizeFailureStreak.Store(0)
	*run = final
	return nil
}

func (r *Runner) failRun(ctx context.Context, run Resource, code string) {
	data, err := decodeRunData(run.Data)
	if err != nil || data.LeaseToken == "" || run.Status != "running" {
		return
	}
	token := data.LeaseToken
	data.ExecutionState, data.ErrorCode = "failed", code
	data.LeaseOwner, data.LeaseToken, data.LeaseUntil = "", "", time.Time{}
	run.Data, _ = json.Marshal(data)
	expected := run.Revision
	run.Revision++
	run.Status, run.UpdatedAt = "failed", time.Now().UTC()
	// Retry only the same fenced terminal write, never the Agent invocation.
	// 仅重试同一 fenced 终结写入，不为补状态重跑模型或工具。
	for attempt := 0; attempt < 3; attempt++ {
		if err := r.store.FinalizeRun(ctx, run.Scope, expected, token, run, nil); err == nil {
			r.finalizeFailureStreak.Store(0)
			return
		} else {
			r.finalizeFailures.Add(1)
			r.finalizeFailureStreak.Add(1)
			log.Printf("evaluation_worker_error run_id=%s stage=finalize code=FINALIZE_FAILED attempt=%d", run.ID, attempt+1)
			if errors.Is(err, ErrConflict) || ctx.Err() != nil {
				return
			}
		}
		if attempt < 2 && !waitWorkerRetry(ctx, time.Duration(1<<attempt)*50*time.Millisecond) {
			return
		}
	}
	// The existing persisted lease expires and ClaimNextRun can recover; this
	// is not a success and must remain observable until durable finalization.
	// 持久化租约到期后可重新领取补偿，不能把此状态误报为终结成功。
}

func waitWorkerRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func aggregateCaseMetrics(metrics []MetricSnapshot, cases []CaseResultData) []MetricOutcome {
	out := make([]MetricOutcome, len(metrics))
	for metricIndex, metric := range metrics {
		status, direction := "passed", ""
		sum, count := 0.0, 0
		for _, result := range cases {
			if metricIndex >= len(result.Metrics) || result.Metrics[metricIndex].MetricID != metric.ID {
				status = "unknown"
				continue
			}
			item := result.Metrics[metricIndex]
			if direction == "" {
				direction = item.Direction
			} else if direction != item.Direction {
				status = "unknown"
			}
			if item.Status != "passed" {
				if item.Status == "blocked" && status != "unknown" {
					status = "blocked"
				} else {
					status = "unknown"
				}
			}
			if item.Value != nil && !math.IsNaN(*item.Value) && !math.IsInf(*item.Value, 0) {
				sum += *item.Value
				count++
			}
		}
		var value *float64
		if count == len(cases) && count > 0 {
			average := sum / float64(count)
			value = &average
		}
		if direction == "" {
			direction = "higher_is_better"
		}
		out[metricIndex] = MetricOutcome{MetricID: metric.ID, Status: status, Value: value, Direction: direction}
	}
	return out
}

// BuiltinMetricEvaluator deliberately supports only simple deterministic
// metrics. Domain plugins should implement MetricEvaluator and remain outside
// the platform control plane; unsupported built-ins yield UNKNOWN evidence.
type BuiltinMetricEvaluator struct{}

func (BuiltinMetricEvaluator) EvaluateMetric(_ context.Context, metric MetricSnapshot, input, output json.RawMessage) (MetricOutcome, error) {
	if metric.Kind == "agent_assertions" {
		return EvaluateAgentAssertions(context.Background(), metric, input, output)
	}
	var formula struct {
		Field       string  `json:"field"`
		OutputField string  `json:"output_field"`
		Tolerance   float64 `json:"tolerance"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(metric.Formula)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&formula); err != nil || strings.TrimSpace(formula.Field) == "" {
		return MetricOutcome{}, fmt.Errorf("invalid built-in metric formula")
	}
	if formula.OutputField == "" {
		formula.OutputField = "answer"
	}
	want, err := jsonFieldPath(input, formula.Field)
	if err != nil {
		return MetricOutcome{}, err
	}
	got, err := jsonFieldPath(output, formula.OutputField)
	if err != nil {
		return MetricOutcome{}, err
	}
	score := 0.0
	passed := false
	switch metric.Kind {
	case "exact_match":
		var expectedValue, actualValue any
		if json.Unmarshal(want, &expectedValue) != nil || json.Unmarshal(got, &actualValue) != nil {
			return MetricOutcome{}, errors.New("exact match values are not valid JSON")
		}
		passed = reflect.DeepEqual(expectedValue, actualValue)
	case "contains":
		var expectedText, actualText string
		if json.Unmarshal(want, &expectedText) != nil || json.Unmarshal(got, &actualText) != nil {
			return MetricOutcome{}, errors.New("contains metric requires string values")
		}
		passed = strings.Contains(actualText, expectedText)
	case "numeric_tolerance":
		if math.IsNaN(formula.Tolerance) || math.IsInf(formula.Tolerance, 0) || formula.Tolerance < 0 {
			return MetricOutcome{}, errors.New("numeric tolerance must be finite and non-negative")
		}
		var expectedNumber, actualNumber float64
		if json.Unmarshal(want, &expectedNumber) != nil || json.Unmarshal(got, &actualNumber) != nil || math.IsNaN(expectedNumber) || math.IsNaN(actualNumber) || math.IsInf(expectedNumber, 0) || math.IsInf(actualNumber, 0) {
			return MetricOutcome{}, errors.New("numeric tolerance metric requires finite numbers")
		}
		passed = math.Abs(expectedNumber-actualNumber) <= formula.Tolerance
	default:
		return MetricOutcome{}, ErrUnsupportedMetric
	}
	if passed {
		score = 1
	}
	status := "blocked"
	if passed {
		status = "passed"
	}
	return MetricOutcome{MetricID: metric.ID, Status: status, Value: &score, Direction: "higher_is_better"}, nil
}

func normalizeMetricOutcome(metric MetricSnapshot, outcome MetricOutcome, err error) MetricOutcome {
	if err != nil || outcome.MetricID != "" && outcome.MetricID != metric.ID || (outcome.Status != "passed" && outcome.Status != "blocked" && outcome.Status != "unknown") || (outcome.Direction != "higher_is_better" && outcome.Direction != "lower_is_better") || outcome.Value != nil && (math.IsNaN(*outcome.Value) || math.IsInf(*outcome.Value, 0)) {
		return MetricOutcome{MetricID: metric.ID, Status: "unknown", Direction: "higher_is_better"}
	}
	outcome.MetricID = metric.ID
	if outcome.Value == nil && outcome.Status == "passed" {
		outcome.Status = "unknown"
	}
	return outcome
}

func jsonFieldPath(raw json.RawMessage, path string) (json.RawMessage, error) {
	var current any
	if err := json.Unmarshal(raw, &current); err != nil {
		return nil, err
	}
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			if path == "answer" && len(strings.Split(path, ".")) == 1 {
				return append(json.RawMessage(nil), raw...), nil
			}
			return nil, fmt.Errorf("metric field %q is missing", path)
		}
		current, ok = object[part]
		if !ok {
			return nil, fmt.Errorf("metric field %q is missing", path)
		}
	}
	return json.Marshal(current)
}

func decodeRunData(raw []byte) (RunData, error) {
	var data RunData
	err := decodeSnapshotJSON(raw, &data)
	return data, err
}

func decodeCaseResult(row Resource) (CaseResultData, error) {
	var data CaseResultData
	if row.Kind != KindCaseResult || row.Status != "completed" || json.Unmarshal(row.Data, &data) != nil || !validID(data.RunID) || data.Index < 0 || !validSHA256(data.InputHash) || !validSHA256(data.OutputHash) || !validID(data.OutputArtifactID) || len(data.Metrics) == 0 {
		return CaseResultData{}, ErrSnapshotInvalid
	}
	if data.ProducedAt.IsZero() || (data.ProviderMode != "real" && data.ProviderMode != "mock" && data.ProviderMode != "replay" && data.ProviderMode != "synthetic" && data.ProviderMode != "unknown") ||
		(data.CitationGrounding != "passed" && data.CitationGrounding != "failed" && data.CitationGrounding != "unknown") ||
		(data.DomainGrounding != "passed" && data.DomainGrounding != "failed" && data.DomainGrounding != "unknown") {
		return CaseResultData{}, ErrSnapshotInvalid
	}
	for _, metric := range data.Metrics {
		if !validMetricOutcome(metric) {
			return CaseResultData{}, ErrSnapshotInvalid
		}
	}
	return data, nil
}

func normalizeProviderMode(value string) string {
	switch value {
	case "real", "mock", "replay", "synthetic":
		return value
	default:
		return "unknown"
	}
}

func normalizeGrounding(value string) string {
	switch value {
	case "passed", "failed", "unknown":
		return value
	default:
		return "unknown"
	}
}

func mergeGrounding(current, next string) string {
	if current == "failed" || next == "failed" {
		return "failed"
	}
	if next != "passed" {
		return "unknown"
	}
	return current
}

func caseResultID(runID string, index int) string {
	sum := sha256.Sum256([]byte(runID))
	return "case." + hex.EncodeToString(sum[:12]) + "." + strconv.Itoa(index)
}

func evidenceResourceID(runID string) string {
	sum := sha256.Sum256([]byte(runID))
	return "evidence." + hex.EncodeToString(sum[:12])
}

func scopedRunKey(scope Scope, runID string) string {
	return scope.TenantID + "\x00" + scope.DepartmentID + "\x00" + scope.ApplicationID + "\x00" + runID
}

var (
	errAgentInvocation     = errors.New("evaluation Agent invocation failed")
	errArtifactPersistence = errors.New("evaluation output artifact persistence failed")
)
