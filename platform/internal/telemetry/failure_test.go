package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestModuleFailureAndPanicAreExplicitAndPreserveFlush(t *testing.T) {
	restoreGlobals(t)
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	writer := httptest.NewRecorder()
	Module("failure", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
		w.(http.Flusher).Flush()
	})).ServeHTTP(writer, httptest.NewRequest("GET", "/", nil))
	spans := exporter.GetSpans()
	if !writer.Flushed || len(spans) != 1 || spans[0].Status.Code != codes.Error || spans[0].Status.Description != "MODULE_PORT_FAILED" {
		t.Fatal("module failure or SSE flushing lost")
	}
	exporter.Reset()
	func() {
		defer func() {
			if recover() != "private-fixture-panic" {
				t.Error("panic was swallowed or changed")
			}
		}()
		Module("panic", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("private-fixture-panic") })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}()
	spans = exporter.GetSpans()
	if len(spans) != 1 || spans[0].Status.Description != "MODULE_PORT_PANIC" {
		t.Fatal("module panic missing safe error code")
	}
}

func TestUnavailableCollectorDoesNotBlockBusinessOrShutdown(t *testing.T) {
	restoreGlobals(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	defer close(release)
	runtime, err := New(context.Background(), Config{Endpoint: server.URL, Service: "failure-fixture", SampleRatio: 1})
	if err != nil {
		t.Fatal(err)
	}
	runtime.Install()
	beforePipelineErrors := tracePipelineErrors.Load()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		handler := HTTP(Module("fixture", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })))
		// Saturate the bounded exporter queue; span delivery is not business admission.
		// 填满有界导出队列；Span投递不能成为业务执行前置条件。
		for i := 0; i < 4096; i++ {
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
		}
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("collector outage blocked business")
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("OTLP exporter never attempted delivery")
	}
	deadline := time.Now().Add(4 * time.Second)
	for runtime.Errors.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if runtime.Errors.Load() == 0 {
		t.Error("background exporter failure was not counted")
	}
	if tracePipelineErrors.Load() <= beforePipelineErrors {
		t.Error("background exporter failure was not exported to metrics")
	}
	metrics := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "agent_trace_exporter_configured 1") ||
		!strings.Contains(metrics.Body.String(), "agent_trace_pipeline_errors_total ") {
		t.Error("trace exporter state or failure counter is missing from metrics")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := runtime.Close(ctx); err == nil {
		t.Error("unflushed shutdown must not pretend success")
	}
	if time.Since(started) > time.Second {
		t.Error("shutdown ignored bounded context")
	}
}
