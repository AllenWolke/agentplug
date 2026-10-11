package generated;

import com.lexagent.sdk.ExecutionContract.ExecuteRequest;
import com.lexagent.sdk.ExecutionServer;
import com.lexagent.sdk.Lifecycle;
import com.lexagent.sdk.MemoryRunStore;
import com.lexagent.sdk.ServerConfig;
import com.lexagent.sdk.ServerConfig.InvokeHandler;
import com.lexagent.sdk.ServerConfig.RunHandler;
import java.net.InetSocketAddress;
import java.security.PublicKey;
import java.util.List;

/**
 * Wires the vendored platform SDK around the Spring AI workflow.
 *
 * Tests reuse this exact wiring; the store stays injectable so a durable
 * implementation can replace the development memory store in production.
 * 通用装配：把 vendored 平台 SDK 接到 Spring AI 工作流之外；测试复用同一接线，
 * 存储可注入以便生产环境替换开发内存存储。
 */
public final class ExecutionBoundary {

    /** Must equal the agent_id advertised in the manifest so the Gateway signs
     * tokens for exactly this Agent. / 必须与 manifest 中宣告的 agent_id 一致，
     * 使网关只为该 Agent 签发令牌。 */
    public static final String DEFAULT_AUDIENCE = "generated-java-spring-ai-agent";

    private ExecutionBoundary() {}

    public static ExecutionServer server(PublicKey publicKey, String agentId, MemoryRunStore store,
            Workflow workflow) {
        return server(publicKey, agentId, store, workflow,
                com.lexagent.sdk.CapabilityClient.Config.fromEnvironment());
    }

    /** Injectable platform authorization wiring for deterministic boundary tests. */
    static ExecutionServer server(PublicKey publicKey, String agentId, MemoryRunStore store,
            Workflow workflow, com.lexagent.sdk.CapabilityClient.Config capability) {
        return new ExecutionServer(ServerConfig.builder()
                .publicKey(publicKey)
                .issuer("platform-runtime-gateway")
                .audience(agentId)
                .agentId(agentId)
                // NOT FOR L2/L3: swap in a scoped durable RunStore for production.
                // 不可用于 L2/L3：生产环境请替换为带 Scope 的持久化 RunStore。
                .store(store == null ? new MemoryRunStore() : store)
                // The lifecycle entries travel together so a started run can
                // always be observed, resumed and cancelled.
                // 生命周期入口同行，已启动的运行始终可观察、可恢复、可取消。
                .capabilities(List.of("invoke", "run", "resume", "cancel", "events"))
                .capability(capability)
                .invoke(invoke(workflow))
                .run(run(workflow))
                .build());
    }

    private static InvokeHandler invoke(Workflow workflow) {
        return workflow::invoke;
    }

    private static RunHandler run(Workflow workflow) {
        return (request, events, signals, capabilities) -> {
            events.append(Lifecycle.EVENT_PROGRESS, java.util.Map.of(
                    "stage", "spring-ai", "thread", Thread.currentThread().getName()));
            if (signals.isCancelled()) {
                throw new IllegalStateException("run was cancelled");
            }
            return workflow.invoke(request, capabilities);
        };
    }

    /** The bind address for the execution surface. / 执行接口面的绑定地址。 */
    public static InetSocketAddress bindAddress(int port) {
        return new InetSocketAddress("0.0.0.0", port);
    }
}
