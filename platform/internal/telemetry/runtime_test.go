package telemetry

import (
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

func restoreGlobals(t *testing.T) {
	t.Helper()
	provider, propagator := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(provider)
		otel.SetTextMapPropagator(propagator)
		// Do not reinstall OTel's unresolved global forwarding handler as its
		// own delegate. 不把全局转发器装回自身，避免测试清理形成委托循环。
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {}))
	})
}

func TestSDKExportsOTLPWithServiceAndParentTraceAndNoSecrets(t *testing.T) {
	restoreGlobals(t)
	var mu sync.Mutex
	var requests []*collector.ExportTraceServiceRequest
	collectorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" {
			t.Error("wrong OTLP path")
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Error(err)
		}
		if strings.Contains(string(raw), "private-fixture-token") {
			t.Error("sensitive request data exported")
		}
		message := &collector.ExportTraceServiceRequest{}
		if err := proto.Unmarshal(raw, message); err != nil {
			t.Error(err)
		}
		mu.Lock()
		requests = append(requests, message)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	defer collectorServer.Close()
	runtime, err := New(context.Background(), Config{Endpoint: collectorServer.URL, Service: "fixture-platform", Version: "fixture-source", SampleRatio: 1})
	if err != nil {
		t.Fatal(err)
	}
	runtime.Install()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	handler := HTTP(Module("fixture", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := Start(r.Context(), "fixture.port", trace.SpanKindClient)
		header := http.Header{}
		Inject(ctx, header)
		if !strings.HasPrefix(header.Get("traceparent"), "00-11111111111111111111111111111111-") {
			t.Error("outbound lost inbound trace")
		}
		span.End()
		w.WriteHeader(http.StatusNoContent)
	})))
	request := httptest.NewRequest(http.MethodPost, "/private-fixture-token?key=private-fixture-token", strings.NewReader("private-fixture-token"))
	request.Header.Set("Authorization", "Bearer private-fixture-token")
	request.Header.Set("traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runtime.Provider.ForceFlush(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	parents := map[string]string{}
	ids := map[string]string{}
	foundService := false
	for _, request := range requests {
		for _, resource := range request.ResourceSpans {
			for _, attr := range resource.Resource.Attributes {
				foundService = foundService || attr.Key == "service.name" && attr.Value.GetStringValue() == "fixture-platform"
			}
			for _, scope := range resource.ScopeSpans {
				for _, span := range scope.Spans {
					if len(span.TraceId) != 16 || span.TraceId[0] != 0x11 {
						t.Error("exported trace identity changed")
					}
					parents[span.Name], ids[span.Name] = string(span.ParentSpanId), string(span.SpanId)
				}
			}
		}
	}
	if !foundService || len(ids) != 3 || parents["platform.module.fixture"] != ids["platform.http"] || parents["fixture.port"] != ids["platform.module.fixture"] {
		t.Fatalf("missing exported parent chain: spans=%d service=%v", len(ids), foundService)
	}
}

func TestSamplingErrorStatusAndSSEFlush(t *testing.T) {
	restoreGlobals(t)
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter), sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())))
	defer provider.Shutdown(context.Background())
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	handler := HTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503); w.(http.Flusher).Flush() }))
	writer := httptest.NewRecorder()
	handler.ServeHTTP(writer, httptest.NewRequest("GET", "/", nil))
	spans := exporter.GetSpans()
	if !writer.Flushed || len(spans) != 1 || spans[0].Status.Code != codes.Error || spans[0].Status.Description != "HTTP_SERVER_ERROR" {
		t.Fatal("SSE flush or error status lost")
	}
	exporter.Reset()
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("traceparent", "00-11111111111111111111111111111111-2222222222222222-00")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if len(exporter.GetSpans()) != 0 {
		t.Fatal("parent sampling decision ignored")
	}
}

func TestTelemetryRejectsMalformedAndSecretBearingConfiguration(t *testing.T) {
	for _, config := range []Config{
		{Service: "fixture", SampleRatio: math.NaN()},
		{Service: "fixture", SampleRatio: math.Inf(1)},
		{Service: "fixture", SampleRatio: -1},
		{Service: "fixture", SampleRatio: 2},
		{Service: "fixture", Endpoint: "http://user:password@localhost", SampleRatio: 1},
		{Service: "fixture", Endpoint: "http://localhost?key=private-fixture-token", SampleRatio: 1},
		{Service: "fixture", Endpoint: "file:///tmp/collector", SampleRatio: 1},
	} {
		if _, err := New(context.Background(), config); err == nil {
			t.Fatal("invalid telemetry configuration accepted")
		} else if strings.Contains(err.Error(), "private-fixture-token") {
			t.Fatal("secret-bearing config leaked")
		}
	}
}
