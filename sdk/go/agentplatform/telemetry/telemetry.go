// Package telemetry provides the OpenTelemetry implementation of the SDK's
// tracing seam. Generated Agents call Setup once at startup and inject the
// returned Tracer into ServerConfig.
// telemetry 包提供 SDK 追踪接缝的 OpenTelemetry 实现：生成 Agent 在启动时调用
// 一次 Setup，并把返回的 Tracer 注入 ServerConfig。
package telemetry

import (
	"context"
	"strings"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Setup wires OTLP-over-HTTP tracing for one process. An empty endpoint
// yields the no-op tracer: absence of a collector must never fail startup.
// Setup 为进程接通 OTLP/HTTP 追踪；端点为空时返回 no-op tracer——缺失收集器
// 绝不能导致启动失败。
func Setup(ctx context.Context, serviceName, endpoint string) (agentplatform.Tracer, func(context.Context) error, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return agentplatform.NoopTracer(), func(context.Context) error { return nil }, nil
	}
	options := []otlptracehttp.Option{otlptracehttp.WithEndpointURL(endpoint)}
	if strings.HasPrefix(endpoint, "http://") {
		options = append(options, otlptracehttp.WithInsecure())
	}
	exporter, err := otlptracehttp.New(ctx, options...)
	if err != nil {
		return nil, nil, err
	}
	resource, err := sdkresource.New(ctx, sdkresource.WithAttributes(semconv.ServiceName(serviceName)))
	if err != nil {
		return nil, nil, err
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return otelTracer{tracer: provider.Tracer(serviceName)}, provider.Shutdown, nil
}

// otelTracer adapts the OTel tracer onto the dependency-free SDK seam.
// otelTracer 将 OTel tracer 适配到零依赖的 SDK 接缝。
type otelTracer struct {
	tracer trace.Tracer
}

type otelSpan struct {
	span trace.Span
}

func (t otelTracer) StartSpan(ctx context.Context, name string, attrs ...agentplatform.Attribute) (context.Context, agentplatform.Span) {
	otelAttrs := make([]attribute.KeyValue, 0, len(attrs))
	for _, attr := range attrs {
		otelAttrs = append(otelAttrs, attribute.String(attr.Key, attr.Value))
	}
	ctx, span := t.tracer.Start(ctx, name, trace.WithAttributes(otelAttrs...))
	return ctx, otelSpan{span: span}
}

func (s otelSpan) End() { s.span.End() }
