package agentplatform

import "context"

// Tracer is the SDK's minimal tracing seam. The core package stays
// dependency-free; the telemetry subpackage provides the OpenTelemetry
// implementation and injects it here.
// Tracer 是 SDK 的最小追踪接缝：核心包保持零依赖，由 telemetry 子包提供
// OpenTelemetry 实现并注入。
type Tracer interface {
	// StartSpan returns a context carrying the span plus the span handle.
	StartSpan(ctx context.Context, name string, attrs ...Attribute) (context.Context, Span)
}

// Span ends the observation window for one operation.
// Span 结束一次操作的观测窗口。
type Span interface {
	End()
}

// Attribute is one string key/value label attached to a span. Sensitive
// claims (tokens, tenant ids) must never become attributes.
// Attribute 是附加到 Span 的字符串键值；敏感声明（令牌、租户 ID）禁止作为属性。
type Attribute struct {
	Key   string
	Value string
}

type noopTracer struct{}

type noopSpan struct{}

// NoopTracer is the fail-safe default: no telemetry leaves the process when
// no tracer is configured.
// NoopTracer 是失败安全默认值：未配置追踪器时不产生任何遥测输出。
func NoopTracer() Tracer { return noopTracer{} }

func (noopTracer) StartSpan(ctx context.Context, _ string, _ ...Attribute) (context.Context, Span) {
	return ctx, noopSpan{}
}

func (noopSpan) End() {}
