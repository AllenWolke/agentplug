package com.lexagent.sdk;

/** The SDK's minimal tracing seam. / SDK 的最小追踪接缝。

 * The core package stays dependency-free; the Spring Boot starter provides the
 * OpenTelemetry implementation and injects it into the server configuration.
 * 核心包保持零依赖，由 Spring Boot Starter 提供 OpenTelemetry 实现并注入。
 */
public final class Tracing {
    private Tracing() {}

    /** One string key/value label attached to a span. Sensitive claims (tokens,
     * tenant ids) must never become attributes.
     * 附加到 Span 的字符串键值；敏感声明（令牌、租户 ID）禁止作为属性。
     */
    public record Attribute(String key, String value) {}

    /** A span closes itself; the SDK never leaks spans into business code.
     * Span 自行关闭；SDK 绝不把 Span 泄漏给业务代码。
     */
    public interface Span extends AutoCloseable {
        void end();

        @Override
        default void close() {
            end();
        }
    }

    public interface Tracer {
        Span startSpan(String name, Attribute... attributes);
    }

    /** The fail-safe default: no telemetry leaves the process when no tracer is
     * configured. / 失败安全默认值：未配置追踪器时不产生任何遥测输出。
     */
    public static final class NoopTracer implements Tracer {
        @Override
        public Span startSpan(String name, Attribute... attributes) {
            return new Span() {
                @Override
                public void end() {
                    // no-op by design / 设计上即为空操作
                }
            };
        }
    }
}
