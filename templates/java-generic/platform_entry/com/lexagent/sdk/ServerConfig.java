package com.lexagent.sdk;

import com.lexagent.sdk.Lifecycle.EventSink;
import com.lexagent.sdk.Lifecycle.RunSignals;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;

/** Server configuration + the business seams. Mirrors the Go and Python SDK
 * ServerConfig semantics: the lifecycle entries travel together, the store is
 * required, and an advertised capability without its handler refuses to start.
 * 服务器配置与业务接缝：与 Go/Python SDK 的 ServerConfig 语义一致——生命周期
 * 入口同行、存储必填、宣告了能力却没有处理器时拒绝启动。
 */
public final class ServerConfig {

    /** Raised when the wiring is incomplete; the process must refuse to start
     * rather than serve an unverified surface. / 接线不完整；进程必须拒绝启动。
     */
    public static final class ServerConfigError extends RuntimeException {
        public ServerConfigError(String message) {
            super(message);
        }
    }

    /** Synchronous business seam behind the verified boundary.
     * 已验证边界之后的同步业务接缝。
     */
    @FunctionalInterface
    public interface InvokeHandler {
        Map<String, Object> invoke(ExecutionContract.ExecuteRequest request, CapabilityClient capabilities) throws Exception;
    }

    /** Asynchronous business seam: observe the signals (cooperative
     * cancellation, resume), report progress through the sink and return the
     * run output. / 异步业务接缝：观察信号（协作式取消、恢复），通过事件接缝
     * 汇报进度并返回运行输出。
     */
    @FunctionalInterface
    public interface RunHandler {
        Map<String, Object> run(ExecutionContract.ExecuteRequest request, EventSink events, RunSignals signals, CapabilityClient capabilities)
                throws Exception;
    }

    private final PublicKey publicKey;
    private final String issuer;
    private final String audience;
    private final String agentId;
    private final Lifecycle.RunStore store;
    private final List<String> capabilities;
    private final String agentVersion;
    private final String manifest;
    private final Tracing.Tracer tracer;
    private final InvokeHandler invoke;
    private final RunHandler run;
    private final CapabilityClient.Config capability;
    private final java.util.function.LongSupplier now;
    private final RecoveryPlan.Selector recoveryCheckpointSelector;

    private ServerConfig(Builder builder) {
        this.publicKey = builder.publicKey;
        this.issuer = builder.issuer;
        this.audience = builder.audience;
        this.agentId = builder.agentId;
        this.store = builder.store;
        this.capabilities = builder.capabilities == null || builder.capabilities.isEmpty()
                ? List.of("invoke") : List.copyOf(builder.capabilities);
        this.agentVersion = builder.agentVersion == null || builder.agentVersion.isBlank()
                ? "0.1.0" : builder.agentVersion;
        this.manifest = builder.manifest;
        this.tracer = builder.tracer == null ? new Tracing.NoopTracer() : builder.tracer;
        this.invoke = builder.invoke;
        this.run = builder.run;
        this.capability = builder.capability;
        // Optional (tests): absent means the wall clock. / 可选（测试用）：缺省即真实时钟。
        this.now = builder.now;
        this.recoveryCheckpointSelector = builder.recoveryCheckpointSelector;
        // Fail closed on incomplete wiring: a half-configured server must
        // never accept traffic. / 接线不完整即失败闭合：半配置的服务器绝不放行。
        if (publicKey == null) {
            throw new ServerConfigError("platform public key is required");
        }
        if (isBlank(issuer) || isBlank(audience) || isBlank(agentId)) {
            throw new ServerConfigError("issuer, audience and agent id are required");
        }
        if (store == null) {
            throw new ServerConfigError("a run store is required");
        }
        if (advertised().getOrDefault("invoke", false) && invoke == null) {
            throw new ServerConfigError("invoke capability requires an invoke handler");
        }
        if (advertised().getOrDefault("run", false)) {
            if (run == null) {
                throw new ServerConfigError("run capability requires a run handler");
            }
            // The lifecycle entries always travel together with run so a
            // started run can always be observed, resumed and cancelled.
            // 生命周期入口必须与 run 同行：已启动的运行始终可观察、可恢复、可取消。
            for (String required : List.of("resume", "cancel", "events")) {
                if (!advertised().getOrDefault(required, false)) {
                    throw new ServerConfigError("run capability requires " + required);
                }
            }
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    public static Builder builder() {
        return new Builder();
    }

    public PublicKey publicKey() {
        return publicKey;
    }

    public String issuer() {
        return issuer;
    }

    public String audience() {
        return audience;
    }

    public String agentId() {
        return agentId;
    }

    public Lifecycle.RunStore store() {
        return store;
    }

    public List<String> capabilities() {
        return capabilities;
    }

    public String agentVersion() {
        return agentVersion;
    }

    public String manifest() { return manifest; }

    public Tracing.Tracer tracer() {
        return tracer;
    }

    public InvokeHandler invoke() {
        return invoke;
    }

    public RunHandler run() {
        return run;
    }
    public CapabilityClient.Config capability() { return capability; }

    /** Optional injectable clock in epoch seconds; null means the wall clock. / 可选
     * 注入时钟（epoch 秒）；null 表示真实时钟。 */
    public java.util.function.LongSupplier now() {
        return now;
    }

    /** Business selector for fixed ordered checkpoints during signed runtime recovery. */
    public RecoveryPlan.Selector recoveryCheckpointSelector() { return recoveryCheckpointSelector; }

    /** Capabilities this server advertises; the manifest and the routing both
     * read this map so they can never disagree. / 服务器宣告的能力；manifest
     * 与路由读同一份，绝不可能不一致。
     */
    public Map<String, Boolean> advertised() {
        Map<String, Boolean> result = new java.util.LinkedHashMap<>();
        for (String name : capabilities) {
            result.put(name, true);
        }
        result.putIfAbsent("invoke", true);
        return result;
    }

    public static final class Builder {
        private PublicKey publicKey;
        private String issuer;
        private String audience;
        private String agentId;
        private Lifecycle.RunStore store;
        private List<String> capabilities;
        private String agentVersion;
        private String manifest;
        private Tracing.Tracer tracer;
        private InvokeHandler invoke;
        private RunHandler run;
        private CapabilityClient.Config capability;
        private java.util.function.LongSupplier now;
        private RecoveryPlan.Selector recoveryCheckpointSelector;

        public Builder publicKey(PublicKey value) {
            this.publicKey = value;
            return this;
        }

        public Builder issuer(String value) {
            this.issuer = value;
            return this;
        }

        public Builder audience(String value) {
            this.audience = value;
            return this;
        }

        public Builder agentId(String value) {
            this.agentId = value;
            return this;
        }

        public Builder store(Lifecycle.RunStore value) {
            this.store = value;
            return this;
        }

        public Builder capabilities(List<String> value) {
            this.capabilities = value;
            return this;
        }

        public Builder agentVersion(String value) {
            this.agentVersion = value;
            return this;
        }

        /** Published JSON declaration; execution wiring is checked at startup. */
        public Builder manifest(String value) { this.manifest = value; return this; }

        public Builder tracer(Tracing.Tracer value) {
            this.tracer = value;
            return this;
        }

        public Builder invoke(InvokeHandler value) {
            this.invoke = value;
            return this;
        }

        public Builder run(RunHandler value) {
            this.run = value;
            return this;
        }
        public Builder capability(CapabilityClient.Config value) { this.capability = value; return this; }

        /** Pin the clock for tests; omit for the wall clock. / 测试钉住时钟；省略即真实时钟。 */
        public Builder now(java.util.function.LongSupplier value) {
            this.now = value;
            return this;
        }

        public Builder recoveryCheckpointSelector(RecoveryPlan.Selector value) {
            this.recoveryCheckpointSelector = value;
            return this;
        }

        public ServerConfig build() {
            return new ServerConfig(this);
        }
    }
}
