// Package telemetry owns platform tracing infrastructure, never business policy.
// telemetry 只拥有平台追踪基础设施，不承载授权或业务策略。
package telemetry

import (
	"context"
	"errors"
	"math"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type Config struct {
	Endpoint    string
	Service     string
	Version     string
	SampleRatio float64
}

type Runtime struct {
	Provider           *sdktrace.TracerProvider
	Errors             atomic.Uint64
	ExporterConfigured bool
}

// New creates a real SDK even when local development does not use a collector.
// 即使本地没有 Collector，也使用真实 SDK；导出地址为空时不伪造导出成功。
func New(ctx context.Context, config Config) (*Runtime, error) {
	if config.Service == "" || math.IsNaN(config.SampleRatio) || math.IsInf(config.SampleRatio, 0) || config.SampleRatio < 0 || config.SampleRatio > 1 {
		return nil, errors.New("invalid telemetry configuration")
	}
	options := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(resource.NewSchemaless(attribute.String("service.name", config.Service), attribute.String("service.version", config.Version))),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(config.SampleRatio))),
	}
	if config.Endpoint != "" {
		endpoint, err := url.Parse(config.Endpoint)
		if err != nil || (endpoint.Scheme != "https" && endpoint.Scheme != "http") || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return nil, errors.New("invalid telemetry collector endpoint")
		}
		// OTEL_EXPORTER_OTLP_ENDPOINT is a base URL, not a signal-specific path.
		// 通用 OTLP 地址是基地址；追加 trace 信号路径，避免误投 Collector 根路径。
		endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/v1/traces"
		exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint.String()), otlptracehttp.WithTimeout(2*time.Second))
		if err != nil {
			return nil, errors.New("telemetry exporter initialization failed")
		}
		options = append(options, sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(time.Second), sdktrace.WithExportTimeout(2*time.Second), sdktrace.WithMaxQueueSize(2048)))
	}
	return &Runtime{Provider: sdktrace.NewTracerProvider(options...), ExporterConfigured: config.Endpoint != ""}, nil
}

// Install is called once by process composition; no request can replace it.
// 仅在进程组合时安装，请求输入不能替换 TracerProvider 或传播器。
func (r *Runtime) Install() {
	otel.SetTracerProvider(r.Provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	traceExporterConfigured.Store(r.ExporterConfigured)
	// Exporter errors can contain collector URLs. Count, never log raw errors.
	// 导出错误可能带地址；仅计数，不把原始错误或凭据写入日志。
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {
		r.Errors.Add(1)
		tracePipelineErrors.Add(1)
	}))
}

func (r *Runtime) Close(ctx context.Context) error { return r.Provider.Shutdown(ctx) }
