package modelgateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestApprovedModelPortPropagatesParentWithoutPrivateAttributes(t *testing.T) {
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
			t.Error("invalid provider parent or leaked baggage")
		}
		_, span := telemetry.Start(ctx, "fixture.model", trace.SpanKindServer)
		defer span.End()
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"approved answer"}}],"usage":{"prompt_tokens":7,"completion_tokens":3}}`))
	}))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL+"/v1", nil, true)
	ctx, parent := telemetry.Start(context.Background(), "fixture.capability", trace.SpanKindInternal)
	_, err := adapter.Generate(ctx, trustedScope(), testSnapshot(), GenerateRequest{ModelVersionID: testVersionID, ProviderID: testProviderID, ModelID: testModelID, Model: "chat-model", Messages: []Message{{Role: "user", Content: "private-fixture-prompt"}}, MaxTokens: 80})
	parent.End()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]tracetest.SpanStub{}
	for _, span := range exporter.GetSpans() {
		byName[span.Name] = span
		for _, attr := range span.Attributes {
			if strings.Contains(attr.Value.AsString(), "private-fixture") || strings.Contains(attr.Value.AsString(), testSecret) {
				t.Error("private model data exported")
			}
		}
	}
	if len(byName) != 3 || byName["platform.model.provider"].Parent.SpanID() != byName["fixture.capability"].SpanContext.SpanID() || byName["fixture.model"].Parent.SpanID() != byName["platform.model.provider"].SpanContext.SpanID() {
		t.Fatal("approved model parent chain missing")
	}
}
