package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Fixed labels keep monitoring cardinality independent of tenants and inputs.
// 固定标签使监控基数不随租户和请求内容增长。
var requestClasses = [...]string{"2xx", "3xx", "4xx", "5xx"}
var requestCount [4]atomic.Uint64
var requestsInFlight atomic.Int64
var platformReady atomic.Int64
var tracePipelineErrors atomic.Uint64
var traceExporterConfigured atomic.Bool
var modelProviderTransportSuccess atomic.Uint64
var modelProviderTransportFailure atomic.Uint64
var modelProviderResponseInvalid atomic.Uint64
var modelProviderConnectRetries atomic.Uint64
var executionReconciliationStages = [...]string{"dispatch", "cancellation", "creation", "outcome"}
var executionReconciliationFailures [len(executionReconciliationStages)]atomic.Uint64

// RecordExecutionReconciliationFailure accepts only fixed stages to avoid
// high-cardinality or sensitive error labels in the metrics endpoint.
func RecordExecutionReconciliationFailure(stage string) {
	for i, allowed := range executionReconciliationStages {
		if stage == allowed {
			executionReconciliationFailures[i].Add(1)
			return
		}
	}
}

// EvaluationWorkerMetrics contains only process-level aggregates.
// EvaluationWorkerMetrics 只包含进程级汇总，不包含租户或评测内容。
type EvaluationWorkerMetrics struct {
	ClaimFailures    uint64
	FinalizeFailures uint64
	Active           int
	Capacity         int
	Ready            bool
}

var evaluationWorkerSource struct {
	sync.RWMutex
	read func() EvaluationWorkerMetrics
}

type EvaluationQueueMetrics struct {
	Depth          int64
	OldestQueuedAt time.Time
}

type BudgetReconciliationMetrics struct {
	Pending  int64
	OldestAt time.Time
}

type RunRecoveryMetrics struct {
	Cancelling         int64
	Recovering         int64
	OldestCancellingAt time.Time
	OldestRecoveringAt time.Time
}

var evaluationQueueSource struct {
	sync.RWMutex
	read func(context.Context) (EvaluationQueueMetrics, error)
}

var budgetReconciliationSource struct {
	sync.RWMutex
	read func(context.Context) (BudgetReconciliationMetrics, error)
}

var runRecoverySource struct {
	sync.RWMutex
	read func(context.Context) (RunRecoveryMetrics, error)
}

var databaseProbeSource struct {
	sync.RWMutex
	probe func(context.Context) error
}

// SetDatabaseProbe records actual SQL connectivity, not an inferred process state.
func SetDatabaseProbe(probe func(context.Context) error) {
	databaseProbeSource.Lock()
	databaseProbeSource.probe = probe
	databaseProbeSource.Unlock()
}

func SetBudgetReconciliationSource(read func(context.Context) (BudgetReconciliationMetrics, error)) {
	budgetReconciliationSource.Lock()
	budgetReconciliationSource.read = read
	budgetReconciliationSource.Unlock()
}

func SetRunRecoverySource(read func(context.Context) (RunRecoveryMetrics, error)) {
	runRecoverySource.Lock()
	runRecoverySource.read = read
	runRecoverySource.Unlock()
}

func SetEvaluationQueueSource(read func(context.Context) (EvaluationQueueMetrics, error)) {
	evaluationQueueSource.Lock()
	evaluationQueueSource.read = read
	evaluationQueueSource.Unlock()
}

func SetEvaluationWorkerSource(read func() EvaluationWorkerMetrics) {
	evaluationWorkerSource.Lock()
	evaluationWorkerSource.read = read
	evaluationWorkerSource.Unlock()
}

var latencyBounds = [...]float64{0.1, 0.25, 0.5, 1, 2, 5, 10}
var latencyBuckets [len(latencyBounds)]atomic.Uint64
var latencyCount atomic.Uint64
var latencyMicros atomic.Uint64

func recordRequest(status int, duration time.Duration) {
	class := status/100 - 2
	if class < 0 || class >= len(requestCount) {
		class = len(requestCount) - 1
	}
	requestCount[class].Add(1)
	latencyCount.Add(1)
	latencyMicros.Add(uint64(duration.Microseconds()))
	seconds := duration.Seconds()
	for i, bound := range latencyBounds {
		if seconds <= bound {
			latencyBuckets[i].Add(1)
		}
	}
}

// SetReadiness records the result of the actual readiness probe.
// SetReadiness 记录真实就绪探针结果，不另行伪造依赖健康状态。
func SetReadiness(ready bool) {
	if ready {
		platformReady.Store(1)
	} else {
		platformReady.Store(0)
	}
}

// RecordModelProviderTransport records only the outcome of a real HTTP attempt.
// RecordModelProviderTransport 仅记录真实模型 HTTP 调用结果，不记录身份和请求内容。
func RecordModelProviderTransport(success bool) {
	if success {
		modelProviderTransportSuccess.Add(1)
	} else {
		modelProviderTransportFailure.Add(1)
	}
}

// RecordModelProviderResponseInvalid counts an HTTP-successful but invalid model payload.
// RecordModelProviderResponseInvalid 记录 HTTP 成功但模型响应内容不符合契约的次数。
func RecordModelProviderResponseInvalid() { modelProviderResponseInvalid.Add(1) }

// RecordModelProviderConnectRetry 只计未获取连接的受限重试，不记录地址或请求。
func RecordModelProviderConnectRetry() { modelProviderConnectRetries.Add(1) }

// MetricsHandler serves only from the internal platform listener.
// 指标只从平台内部监听器提供，不暴露请求路径或身份字段。
func MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var output strings.Builder
		output.WriteString("# HELP agent_gateway_requests_total Completed platform HTTP requests.\n")
		output.WriteString("# TYPE agent_gateway_requests_total counter\n")
		for i, class := range requestClasses {
			fmt.Fprintf(&output, "agent_gateway_requests_total{status_class=%q} %d\n", class, requestCount[i].Load())
		}
		output.WriteString("# HELP agent_gateway_requests_in_flight Current platform HTTP requests.\n")
		output.WriteString("# TYPE agent_gateway_requests_in_flight gauge\n")
		fmt.Fprintf(&output, "agent_gateway_requests_in_flight %d\n", requestsInFlight.Load())
		output.WriteString("# HELP agent_platform_ready Last platform readiness probe result.\n")
		output.WriteString("# TYPE agent_platform_ready gauge\n")
		fmt.Fprintf(&output, "agent_platform_ready %d\n", platformReady.Load())
		configured := 0
		if traceExporterConfigured.Load() {
			configured = 1
		}
		output.WriteString("# HELP agent_trace_exporter_configured Whether an OTLP trace exporter is configured.\n")
		output.WriteString("# TYPE agent_trace_exporter_configured gauge\n")
		fmt.Fprintf(&output, "agent_trace_exporter_configured %d\n", configured)
		output.WriteString("# HELP agent_trace_pipeline_errors_total OpenTelemetry trace pipeline errors including failed exports.\n")
		output.WriteString("# TYPE agent_trace_pipeline_errors_total counter\n")
		fmt.Fprintf(&output, "agent_trace_pipeline_errors_total %d\n", tracePipelineErrors.Load())
		output.WriteString("# HELP agent_model_provider_transport_total Model provider HTTP transport outcomes.\n")
		output.WriteString("# TYPE agent_model_provider_transport_total counter\n")
		fmt.Fprintf(&output, "agent_model_provider_transport_total{result=\"success\"} %d\n", modelProviderTransportSuccess.Load())
		fmt.Fprintf(&output, "agent_model_provider_transport_total{result=\"failure\"} %d\n", modelProviderTransportFailure.Load())
		output.WriteString("# HELP agent_model_provider_response_invalid_total Invalid model payloads after successful HTTP responses.\n")
		output.WriteString("# TYPE agent_model_provider_response_invalid_total counter\n")
		fmt.Fprintf(&output, "agent_model_provider_response_invalid_total %d\n", modelProviderResponseInvalid.Load())
		writeContextCacheMetrics(&output)
		output.WriteString("# HELP agent_model_provider_connect_retries_total Bounded retries before a model connection is acquired.\n")
		output.WriteString("# TYPE agent_model_provider_connect_retries_total counter\n")
		fmt.Fprintf(&output, "agent_model_provider_connect_retries_total %d\n", modelProviderConnectRetries.Load())
		output.WriteString("# HELP agent_execution_reconciliation_failures_total Durable Run recovery failures by fixed stage.\n")
		output.WriteString("# TYPE agent_execution_reconciliation_failures_total counter\n")
		for i, stage := range executionReconciliationStages {
			fmt.Fprintf(&output, "agent_execution_reconciliation_failures_total{stage=%q} %d\n", stage, executionReconciliationFailures[i].Load())
		}
		databaseProbeSource.RLock()
		probeDatabase := databaseProbeSource.probe
		databaseProbeSource.RUnlock()
		if probeDatabase != nil {
			queryCtx, cancel := context.WithTimeout(r.Context(), 750*time.Millisecond)
			err := probeDatabase(queryCtx)
			cancel()
			available := 1
			if err != nil {
				available = 0
			}
			output.WriteString("# HELP agent_platform_database_probe_success Whether the current SQL connection probe succeeded.\n")
			output.WriteString("# TYPE agent_platform_database_probe_success gauge\n")
			fmt.Fprintf(&output, "agent_platform_database_probe_success %d\n", available)
		}
		evaluationWorkerSource.RLock()
		readWorker := evaluationWorkerSource.read
		evaluationWorkerSource.RUnlock()
		if readWorker != nil {
			worker := readWorker()
			ready := 0
			if worker.Ready {
				ready = 1
			}
			output.WriteString("# HELP agent_evaluation_worker_ready Evaluation worker readiness.\n")
			output.WriteString("# TYPE agent_evaluation_worker_ready gauge\n")
			fmt.Fprintf(&output, "agent_evaluation_worker_ready %d\n", ready)
			output.WriteString("# HELP agent_evaluation_worker_active Active evaluation runs in this process.\n")
			output.WriteString("# TYPE agent_evaluation_worker_active gauge\n")
			fmt.Fprintf(&output, "agent_evaluation_worker_active %d\n", worker.Active)
			output.WriteString("# HELP agent_evaluation_worker_capacity Configured evaluation workers in this process.\n")
			output.WriteString("# TYPE agent_evaluation_worker_capacity gauge\n")
			fmt.Fprintf(&output, "agent_evaluation_worker_capacity %d\n", worker.Capacity)
			output.WriteString("# HELP agent_evaluation_worker_failures_total Evaluation worker durable-store failures.\n")
			output.WriteString("# TYPE agent_evaluation_worker_failures_total counter\n")
			fmt.Fprintf(&output, "agent_evaluation_worker_failures_total{stage=\"claim\"} %d\n", worker.ClaimFailures)
			fmt.Fprintf(&output, "agent_evaluation_worker_failures_total{stage=\"finalize\"} %d\n", worker.FinalizeFailures)
		}
		evaluationQueueSource.RLock()
		readQueue := evaluationQueueSource.read
		evaluationQueueSource.RUnlock()
		if readQueue != nil {
			queryCtx, cancel := context.WithTimeout(r.Context(), 750*time.Millisecond)
			queue, err := readQueue(queryCtx)
			cancel()
			output.WriteString("# HELP agent_evaluation_queue_scrape_success Whether the durable queue query succeeded.\n")
			output.WriteString("# TYPE agent_evaluation_queue_scrape_success gauge\n")
			if err != nil || queue.Depth < 0 || (queue.Depth > 0 && queue.OldestQueuedAt.IsZero()) {
				output.WriteString("agent_evaluation_queue_scrape_success 0\n")
			} else {
				age := time.Since(queue.OldestQueuedAt).Seconds()
				if queue.Depth == 0 || age < 0 {
					age = 0
				}
				output.WriteString("agent_evaluation_queue_scrape_success 1\n")
				output.WriteString("# HELP agent_evaluation_queue_depth Durable queued evaluation runs.\n")
				output.WriteString("# TYPE agent_evaluation_queue_depth gauge\n")
				fmt.Fprintf(&output, "agent_evaluation_queue_depth %d\n", queue.Depth)
				output.WriteString("# HELP agent_evaluation_queue_oldest_age_seconds Age of the oldest queued evaluation run.\n")
				output.WriteString("# TYPE agent_evaluation_queue_oldest_age_seconds gauge\n")
				fmt.Fprintf(&output, "agent_evaluation_queue_oldest_age_seconds %g\n", age)
			}
		}
		budgetReconciliationSource.RLock()
		readBudget := budgetReconciliationSource.read
		budgetReconciliationSource.RUnlock()
		if readBudget != nil {
			queryCtx, cancel := context.WithTimeout(r.Context(), 750*time.Millisecond)
			budget, err := readBudget(queryCtx)
			cancel()
			output.WriteString("# HELP agent_model_budget_reconciliation_scrape_success Whether the durable budget query succeeded.\n")
			output.WriteString("# TYPE agent_model_budget_reconciliation_scrape_success gauge\n")
			if err != nil || budget.Pending < 0 || (budget.Pending > 0 && budget.OldestAt.IsZero()) {
				output.WriteString("agent_model_budget_reconciliation_scrape_success 0\n")
			} else {
				age := time.Since(budget.OldestAt).Seconds()
				if budget.Pending == 0 || age < 0 {
					age = 0
				}
				output.WriteString("agent_model_budget_reconciliation_scrape_success 1\n")
				output.WriteString("# HELP agent_model_budget_reconciliation_pending Durable reservations awaiting reconciliation.\n")
				output.WriteString("# TYPE agent_model_budget_reconciliation_pending gauge\n")
				fmt.Fprintf(&output, "agent_model_budget_reconciliation_pending %d\n", budget.Pending)
				output.WriteString("# HELP agent_model_budget_reconciliation_oldest_age_seconds Age of the oldest pending reservation.\n")
				output.WriteString("# TYPE agent_model_budget_reconciliation_oldest_age_seconds gauge\n")
				fmt.Fprintf(&output, "agent_model_budget_reconciliation_oldest_age_seconds %g\n", age)
			}
		}
		runRecoverySource.RLock()
		readRecovery := runRecoverySource.read
		runRecoverySource.RUnlock()
		if readRecovery != nil {
			queryCtx, cancel := context.WithTimeout(r.Context(), 750*time.Millisecond)
			recovery, err := readRecovery(queryCtx)
			cancel()
			output.WriteString("# HELP agent_execution_recovery_scrape_success Whether the durable Run recovery query succeeded.\n")
			output.WriteString("# TYPE agent_execution_recovery_scrape_success gauge\n")
			if err != nil || recovery.Cancelling < 0 || recovery.Recovering < 0 ||
				(recovery.Cancelling > 0 && recovery.OldestCancellingAt.IsZero()) ||
				(recovery.Recovering > 0 && recovery.OldestRecoveringAt.IsZero()) {
				output.WriteString("agent_execution_recovery_scrape_success 0\n")
			} else {
				output.WriteString("agent_execution_recovery_scrape_success 1\n")
				for _, stage := range []struct {
					name   string
					count  int64
					oldest time.Time
				}{
					{"cancelling", recovery.Cancelling, recovery.OldestCancellingAt},
					{"recovering", recovery.Recovering, recovery.OldestRecoveringAt},
				} {
					age := time.Since(stage.oldest).Seconds()
					if stage.count == 0 || age < 0 {
						age = 0
					}
					fmt.Fprintf(&output, "agent_execution_recovery_pending{stage=%q} %d\n", stage.name, stage.count)
					fmt.Fprintf(&output, "agent_execution_recovery_oldest_age_seconds{stage=%q} %g\n", stage.name, age)
				}
			}
		}
		output.WriteString("# HELP agent_gateway_request_duration_seconds Platform HTTP request duration.\n")
		output.WriteString("# TYPE agent_gateway_request_duration_seconds histogram\n")
		for i, bound := range latencyBounds {
			fmt.Fprintf(&output, "agent_gateway_request_duration_seconds_bucket{le=%q} %d\n", fmt.Sprint(bound), latencyBuckets[i].Load())
		}
		fmt.Fprintf(&output, "agent_gateway_request_duration_seconds_bucket{le=\"+Inf\"} %d\n", latencyCount.Load())
		fmt.Fprintf(&output, "agent_gateway_request_duration_seconds_sum %g\n", float64(latencyMicros.Load())/1e6)
		fmt.Fprintf(&output, "agent_gateway_request_duration_seconds_count %d\n", latencyCount.Load())
		_, _ = w.Write([]byte(output.String()))
	})
}
