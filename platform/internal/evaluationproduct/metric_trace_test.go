package evaluationproduct

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// Test the real metric HTTP port, not a replacement evaluator.
// 验证实际评测 HTTP Port 的父级传播和安全错误，不替换评测器。
func TestMetricRunnerPortTraceAndSafeFailure(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			old := otel.GetTracerProvider()
			exporter := tracetest.NewInMemoryExporter()
			provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
			otel.SetTracerProvider(provider)
			t.Cleanup(func() {
				otel.SetTracerProvider(old)
				if err := provider.Shutdown(context.Background()); err != nil {
					t.Error(err)
				}
			})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := propagation.TraceContext{}.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
				if !trace.SpanContextFromContext(ctx).IsValid() || r.Header.Get("baggage") != "" {
					t.Error("missing parent or leaked baggage")
				}
				_, span := telemetry.Start(ctx, "fixture.metric", trace.SpanKindServer)
				defer span.End()
				if failed {
					http.Error(w, "private-fixture-upstream-error", http.StatusBadGateway)
					return
				}
				var request metricRunnerRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					return
				}
				_, _ = fmt.Fprintf(w, `{"metric_id":"%s","version":"%s","formula_hash":"%s","status":"OK","numerator":1,"denominator":1,"value":1}`, request.Metric, request.Version, request.FormulaHash)
			}))
			defer server.Close()
			ctx, parent := telemetry.Start(context.Background(), "fixture.worker", trace.SpanKindInternal)
			metric := MetricSnapshot{MetricID: "retrieval", Version: "1", Kind: "recall_at_k", FormulaHash: "fixture-hash", Formula: json.RawMessage(`{"input_relevant_field":"relevant","output_ranked_field":"ranked","k":1}`)}
			_, err := (RemoteMetricEvaluator{URL: server.URL, Token: "private-fixture-token", Timeout: time.Second}).EvaluateMetric(ctx, metric, json.RawMessage(`{"relevant":["a"]}`), json.RawMessage(`{"ranked":["a"]}`))
			parent.End()
			if (err != nil) != failed {
				t.Fatalf("unexpected error: %v", err)
			}
			spans := map[string]tracetest.SpanStub{}
			for _, span := range exporter.GetSpans() {
				spans[span.Name] = span
				for _, attr := range span.Attributes {
					if strings.Contains(attr.Value.AsString(), "private-fixture") {
						t.Error("private data exported")
					}
				}
			}
			client := spans["platform.evaluation.metric_runner"]
			if len(spans) != 3 || client.Parent.SpanID() != spans["fixture.worker"].SpanContext.SpanID() || spans["fixture.metric"].Parent.SpanID() != client.SpanContext.SpanID() {
				t.Fatal("metric parent chain broken")
			}
			if failed && (client.Status.Code != codes.Error || client.Status.Description != "METRIC_RUNNER_FAILED") {
				t.Fatal("missing safe failure status")
			}
		})
	}
}
