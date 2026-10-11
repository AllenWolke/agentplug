package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsExposeMeasuredStatusWithoutRequestIdentity(t *testing.T) {
	before := requestCount[3].Load()
	handler := HTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	request := httptest.NewRequest(http.MethodGet, "/tenant-secret/run?id=private", nil)
	request.Header.Set("Authorization", "Bearer private-secret")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if actual := requestCount[3].Load(); actual != before+1 {
		t.Fatalf("expected one recorded 5xx request, got %d from %d", actual, before)
	}
	result := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(result, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, expected := range []string{
		"agent_gateway_requests_total{status_class=\"5xx\"}",
		"agent_gateway_request_duration_seconds_bucket{le=\"+Inf\"}",
		"agent_trace_pipeline_errors_total ",
	} {
		if !strings.Contains(result.Body.String(), expected) {
			t.Fatalf("metrics lack %q", expected)
		}
	}
	for _, secret := range []string{"tenant-secret", "private-secret"} {
		if strings.Contains(result.Body.String(), secret) {
			t.Fatalf("metrics exposed %q", secret)
		}
	}
}

func TestDurableEvaluationQueueMetricsFailClosedAndRecover(t *testing.T) {
	SetEvaluationQueueSource(func(context.Context) (EvaluationQueueMetrics, error) {
		return EvaluationQueueMetrics{Depth: 2, OldestQueuedAt: time.Now().Add(-7 * time.Minute)}, nil
	})
	t.Cleanup(func() { SetEvaluationQueueSource(nil) })
	read := func() string {
		response := httptest.NewRecorder()
		MetricsHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return response.Body.String()
	}
	before := read()
	if !strings.Contains(before, "agent_evaluation_queue_scrape_success 1") || !strings.Contains(before, "agent_evaluation_queue_depth 2") || !strings.Contains(before, "agent_evaluation_queue_oldest_age_seconds 4") {
		t.Fatalf("durable queue age/depth not exported: %s", before)
	}
	SetEvaluationQueueSource(func(context.Context) (EvaluationQueueMetrics, error) {
		return EvaluationQueueMetrics{}, errors.New("database unavailable")
	})
	failed := read()
	if !strings.Contains(failed, "agent_evaluation_queue_scrape_success 0") || strings.Contains(failed, "agent_evaluation_queue_depth ") || strings.Contains(failed, "agent_evaluation_queue_oldest_age_seconds ") {
		t.Fatal("failed SQL query exported stale or false-zero queue values")
	}
	SetEvaluationQueueSource(func(context.Context) (EvaluationQueueMetrics, error) {
		return EvaluationQueueMetrics{}, nil
	})
	recovered := read()
	if !strings.Contains(recovered, "agent_evaluation_queue_scrape_success 1") || !strings.Contains(recovered, "agent_evaluation_queue_depth 0") || !strings.Contains(recovered, "agent_evaluation_queue_oldest_age_seconds 0") {
		t.Fatal("empty queue did not recover to a valid zero")
	}
}

func TestDatabaseProbeExportsFailureAndRecoveryWithoutErrorDetails(t *testing.T) {
	SetDatabaseProbe(func(context.Context) error { return errors.New("private database address and password") })
	t.Cleanup(func() { SetDatabaseProbe(nil) })
	read := func() string {
		response := httptest.NewRecorder()
		MetricsHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return response.Body.String()
	}
	failed := read()
	if !strings.Contains(failed, "agent_platform_database_probe_success 0") || strings.Contains(failed, "private database") {
		t.Fatal("failed SQL probe was hidden or leaked error details")
	}
	SetDatabaseProbe(func(context.Context) error { return nil })
	if !strings.Contains(read(), "agent_platform_database_probe_success 1") {
		t.Fatal("recovered SQL probe did not restore metric")
	}
}

func TestExecutionReconciliationMetricUsesOnlyFixedStages(t *testing.T) {
	before := executionReconciliationFailures[1].Load()
	RecordExecutionReconciliationFailure("cancellation")
	RecordExecutionReconciliationFailure("tenant-secret")
	response := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metrics := response.Body.String()
	if !strings.Contains(metrics, fmt.Sprintf("agent_execution_reconciliation_failures_total{stage=\"cancellation\"} %d", before+1)) {
		t.Fatal("cancellation failure was not exported")
	}
	if strings.Contains(metrics, "tenant-secret") {
		t.Fatal("unbounded stage was exported as a metric label")
	}
}

func TestDurableRunRecoveryMetricsFailClosedAndRecover(t *testing.T) {
	read := func() string {
		response := httptest.NewRecorder()
		MetricsHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return response.Body.String()
	}
	SetRunRecoverySource(func(context.Context) (RunRecoveryMetrics, error) {
		return RunRecoveryMetrics{
			Cancelling: 2, Recovering: 1,
			OldestCancellingAt: time.Now().Add(-7 * time.Minute),
			OldestRecoveringAt: time.Now().Add(-8 * time.Minute),
		}, nil
	})
	t.Cleanup(func() { SetRunRecoverySource(nil) })
	before := read()
	for _, expected := range []string{
		"agent_execution_recovery_scrape_success 1",
		"agent_execution_recovery_pending{stage=\"cancelling\"} 2",
		"agent_execution_recovery_pending{stage=\"recovering\"} 1",
		"agent_execution_recovery_oldest_age_seconds{stage=\"cancelling\"} 4",
	} {
		if !strings.Contains(before, expected) {
			t.Fatalf("recovery backlog metric missing %q", expected)
		}
	}
	SetRunRecoverySource(func(context.Context) (RunRecoveryMetrics, error) {
		return RunRecoveryMetrics{}, errors.New("private database address and password")
	})
	failed := read()
	if !strings.Contains(failed, "agent_execution_recovery_scrape_success 0") || strings.Contains(failed, "agent_execution_recovery_pending{") || strings.Contains(failed, "agent_execution_recovery_oldest_age_seconds{") || strings.Contains(failed, "private database") {
		t.Fatal("failed SQL recovery query leaked details or exported stale/false-zero values")
	}
	SetRunRecoverySource(func(context.Context) (RunRecoveryMetrics, error) { return RunRecoveryMetrics{}, nil })
	recovered := read()
	if !strings.Contains(recovered, "agent_execution_recovery_scrape_success 1") || !strings.Contains(recovered, "agent_execution_recovery_pending{stage=\"cancelling\"} 0") || !strings.Contains(recovered, "agent_execution_recovery_oldest_age_seconds{stage=\"recovering\"} 0") {
		t.Fatal("empty recovery backlog did not export valid zero")
	}
}

func TestDurableBudgetReconciliationMetricsFailClosedAndRecover(t *testing.T) {
	SetBudgetReconciliationSource(func(context.Context) (BudgetReconciliationMetrics, error) {
		return BudgetReconciliationMetrics{Pending: 3, OldestAt: time.Now().Add(-20 * time.Minute)}, nil
	})
	t.Cleanup(func() { SetBudgetReconciliationSource(nil) })
	read := func() string {
		response := httptest.NewRecorder()
		MetricsHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return response.Body.String()
	}
	before := read()
	if !strings.Contains(before, "agent_model_budget_reconciliation_scrape_success 1") || !strings.Contains(before, "agent_model_budget_reconciliation_pending 3") || !strings.Contains(before, "agent_model_budget_reconciliation_oldest_age_seconds 12") {
		t.Fatal("durable budget reconciliation age/count not exported")
	}
	SetBudgetReconciliationSource(func(context.Context) (BudgetReconciliationMetrics, error) {
		return BudgetReconciliationMetrics{}, errors.New("database unavailable")
	})
	failed := read()
	if !strings.Contains(failed, "agent_model_budget_reconciliation_scrape_success 0") || strings.Contains(failed, "agent_model_budget_reconciliation_pending ") || strings.Contains(failed, "agent_model_budget_reconciliation_oldest_age_seconds ") {
		t.Fatal("failed budget SQL query exported stale or false-zero values")
	}
	SetBudgetReconciliationSource(func(context.Context) (BudgetReconciliationMetrics, error) {
		return BudgetReconciliationMetrics{}, nil
	})
	recovered := read()
	if !strings.Contains(recovered, "agent_model_budget_reconciliation_scrape_success 1") || !strings.Contains(recovered, "agent_model_budget_reconciliation_pending 0") || !strings.Contains(recovered, "agent_model_budget_reconciliation_oldest_age_seconds 0") {
		t.Fatal("empty reconciliation queue did not recover to a valid zero")
	}
}

func TestMetricsReadActualEvaluationWorkerSnapshot(t *testing.T) {
	SetEvaluationWorkerSource(func() EvaluationWorkerMetrics {
		return EvaluationWorkerMetrics{ClaimFailures: 3, FinalizeFailures: 2, Active: 1, Capacity: 2, Ready: false}
	})
	t.Cleanup(func() { SetEvaluationWorkerSource(nil) })
	result := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(result, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, expected := range []string{
		"agent_evaluation_worker_ready 0",
		"agent_evaluation_worker_active 1",
		"agent_evaluation_worker_capacity 2",
		"agent_evaluation_worker_failures_total{stage=\"claim\"} 3",
		"agent_evaluation_worker_failures_total{stage=\"finalize\"} 2",
	} {
		if !strings.Contains(result.Body.String(), expected) {
			t.Fatalf("worker metrics lack %q", expected)
		}
	}
	SetEvaluationWorkerSource(func() EvaluationWorkerMetrics { return EvaluationWorkerMetrics{Ready: true, Capacity: 2} })
	result = httptest.NewRecorder()
	MetricsHandler().ServeHTTP(result, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(result.Body.String(), "agent_evaluation_worker_ready 1") {
		t.Fatal("worker recovery was not exported")
	}
}
