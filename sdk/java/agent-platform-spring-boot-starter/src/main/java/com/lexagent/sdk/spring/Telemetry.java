package com.lexagent.sdk.spring;

import com.lexagent.sdk.Tracing.Attribute;
import com.lexagent.sdk.Tracing.NoopTracer;
import com.lexagent.sdk.Tracing.Tracer;

/** OpenTelemetry implementation of the SDK's tracing seam.
 *
 * An empty endpoint yields the no-op tracer: absence of a collector must never
 * fail startup. A configured endpoint with the OpenTelemetry SDK absent fails
 * loudly instead of silently dropping telemetry.
 *
 * OTel 实现 SDK 追踪接缝：端点为空时返回 no-op tracer——缺失收集器绝不能导致
 * 启动失败；配置了端点但 OTel 依赖缺失时大声失败，而不是静默丢弃遥测。
 */
public final class Telemetry {
    private Telemetry() {}

    /** The tracer plus a shutdown hook owned by the caller. / tracer 与由调用方
     * 持有的关闭回调。 */
    public record Setup(Tracer tracer, Runnable shutdown) {
        public static Setup noop() {
            return new Setup(new NoopTracer(), () -> {
            });
        }
    }

    public static Setup setup(String serviceName, String endpoint) {
        String trimmed = endpoint == null ? "" : endpoint.trim();
        if (trimmed.isEmpty()) {
            return Setup.noop();
        }
        return OtelBridge.setup(serviceName, trimmed);
    }

    /** Only loaded when an endpoint is configured, so the optional OpenTelemetry
     * classes never break core startup. / 仅在配置端点后才加载，可选的 OTel 类
     * 绝不影响核心启动。
     */
    private static final class OtelBridge {
        static Setup setup(String serviceName, String endpoint) {
            try {
                return wired(serviceName, endpoint);
            } catch (NoClassDefFoundError error) {
                throw new IllegalStateException(
                        "agent-platform.otlp-endpoint is configured but the OpenTelemetry SDK is not on the "
                                + "classpath; add the io.opentelemetry:opentelemetry-exporter-otlp dependencies",
                        error);
            }
        }

        private static Setup wired(String serviceName, String endpoint) {
            io.opentelemetry.api.trace.Tracer otel = provider(serviceName, endpoint);
            return new Setup(new Tracer() {
                @Override
                public com.lexagent.sdk.Tracing.Span startSpan(String name, Attribute... attributes) {
                    io.opentelemetry.api.trace.Span span = otel.spanBuilder(name).startSpan();
                    for (Attribute attribute : attributes) {
                        span.setAttribute(attribute.key(), attribute.value());
                    }
                    return span::end;
                }
            }, () -> {
            });
        }

        private static io.opentelemetry.api.trace.Tracer provider(String serviceName, String endpoint) {
            io.opentelemetry.sdk.trace.SdkTracerProvider provider = io.opentelemetry.sdk.trace.SdkTracerProvider
                    .builder()
                    .setResource(io.opentelemetry.sdk.resources.Resource.getDefault().toBuilder()
                            .put("service.name", serviceName).build())
                    .addSpanProcessor(io.opentelemetry.sdk.trace.export.BatchSpanProcessor.builder(
                            io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter.builder()
                                    .setEndpoint(endpoint).build())
                            .build())
                    .build();
            return provider.get(serviceName);
        }
    }
}
