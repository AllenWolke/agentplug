package telemetry

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// A restarted worker keeps the real parent, with no reconstructed fake span.
// 重启 Worker 恢复真实父级，不根据业务 TraceID 伪造父 Span。
func TestDurableTraceRestoresParentAndPreservesCancellation(t *testing.T) {
	restoreGlobals(t)
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	otel.SetTracerProvider(provider)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	parentCtx, parent := Start(context.Background(), "request", trace.SpanKindServer)
	raw := Capture(parentCtx)
	parent.End()
	workerCtx, cancel := context.WithCancel(context.Background())
	ctx, worker := Start(Restore(workerCtx, raw), "worker", trace.SpanKindInternal)
	worker.End()
	cancel()
	if ctx.Err() != context.Canceled {
		t.Fatal("restoration lost worker cancellation")
	}
	spans := exporter.GetSpans()
	if len(spans) != 2 || spans[1].Parent.SpanID() != spans[0].SpanContext.SpanID() || spans[1].SpanContext.TraceID() != spans[0].SpanContext.TraceID() {
		t.Fatal("durable trace lost parent chain")
	}
	if Capture(context.Background()) != "" {
		t.Fatal("missing span fabricated metadata")
	}
	for _, broken := range []string{"{", strings.Repeat("x", 1025), `{"traceparent":"invalid"}`} {
		if trace.SpanContextFromContext(Restore(context.Background(), broken)).IsValid() {
			t.Fatal("malformed tracing metadata became valid")
		}
	}
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(parentCtx, carrier)
	carrier["Authorization"] = "private-fixture-secret"
	carrier["baggage"] = "private-fixture-secret"
	if strings.Contains(Capture(Restore(context.Background(), `{"traceparent":"`+carrier["traceparent"]+`","baggage":"private-fixture-secret","Authorization":"private-fixture-secret"}`)), "private-fixture-secret") {
		t.Fatal("private metadata persisted")
	}
}
