package capability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestKnowledgeHTTPPortPreservesRealParentAndSafeFailure(t *testing.T) {
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
	for _, failed := range []bool{false, true} {
		exporter.Reset()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("traceparent") == "" || r.Header.Get("baggage") != "" || r.Header.Get("X-Trace-ID") != "business-trace-fixture" {
				t.Error("knowledge request lost standard parent or forwarded private baggage")
			}
			ctx := propagation.TraceContext{}.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			_, span := telemetry.Start(ctx, "fixture.rag", trace.SpanKindServer)
			defer span.End()
			if failed {
				w.WriteHeader(503)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"request_id":"fixture","items":[]}}`))
		}))
		knowledge, err := NewHTTPKnowledgeProvider(server.URL, "private-fixture-secret", []uint64{1}, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		handler := telemetry.HTTP(telemetry.Module("capability", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := knowledge.Search(r.Context(), harnessContext{TraceID: "business-trace-fixture"}, knowledgeQuery{Query: "private-fixture-query", TopK: 1})
			if failed != (err != nil) {
				t.Error("provider failure mismatch")
			}
			if err != nil {
				w.WriteHeader(503)
			} else {
				w.WriteHeader(204)
			}
		})))
		request := httptest.NewRequest("POST", "/private-fixture-query", nil)
		request.Header.Set("traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
		request.Header.Set("baggage", "private-fixture-secret")
		handler.ServeHTTP(httptest.NewRecorder(), request)
		server.Close()
		byName := map[string]tracetest.SpanStub{}
		for _, span := range exporter.GetSpans() {
			byName[span.Name] = span
			if span.SpanContext.TraceID().String() != "11111111111111111111111111111111" {
				t.Error("trace identity changed")
			}
			for _, attr := range span.Attributes {
				if strings.Contains(attr.Value.AsString(), "private-fixture") {
					t.Error("sensitive attribute exported")
				}
			}
		}
		if len(byName) != 4 || byName["platform.module.capability"].Parent.SpanID() != byName["platform.http"].SpanContext.SpanID() || byName["platform.knowledge.rag"].Parent.SpanID() != byName["platform.module.capability"].SpanContext.SpanID() || byName["fixture.rag"].Parent.SpanID() != byName["platform.knowledge.rag"].SpanContext.SpanID() {
			t.Fatal("actual HTTP/module/provider/downstream parent chain missing")
		}
		if failed && (byName["platform.knowledge.rag"].Status.Code != codes.Error || byName["platform.module.capability"].Status.Code != codes.Error) {
			t.Fatal("failed Port was marked successful")
		}
	}
}
