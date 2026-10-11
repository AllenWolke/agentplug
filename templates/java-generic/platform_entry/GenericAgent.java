package generated;

import com.lexagent.sdk.ExecutionContract.ExecuteRequest;
import com.lexagent.sdk.ExecutionServer;
import com.lexagent.sdk.Lifecycle;
import com.lexagent.sdk.MemoryRunStore;
import com.lexagent.sdk.ServerConfig;
import java.net.InetSocketAddress;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Framework-free entry: the vendored platform SDK owns transport, the PEP and
 * the run state machine; this class only configures it and implements the two
 * business seams. Business code belongs in {@link AgentController}.
 *
 * 与框架解耦的入口：vendored 平台 SDK 持有传输、PEP 与运行状态机；本类只做配置
 * 并实现两个业务接缝。业务代码放在 {@link AgentController}。
 */
public final class GenericAgent {

    /** Must equal the agent_id advertised in the manifest so the Gateway signs
     * tokens for exactly this Agent. / 必须与 manifest 中宣告的 agent_id 一致，
     * 使网关只为该 Agent 签发令牌。 */
    public static final String DEFAULT_AUDIENCE = "generated-java-agent";

    private GenericAgent() {}

    /** Build the boundary; tests reuse this exact wiring. / 构造边界；测试复用
     * 同一接线。
     */
    public static ExecutionServer server(PublicKey publicKey, String agentId, MemoryRunStore store,
            AgentController controller) {
        return server(publicKey, agentId, store, controller,
                com.lexagent.sdk.CapabilityClient.Config.fromEnvironment());
    }

    /** Injectable platform authorization wiring for deterministic boundary tests. */
    static ExecutionServer server(PublicKey publicKey, String agentId, MemoryRunStore store,
            AgentController controller, com.lexagent.sdk.CapabilityClient.Config capability) {
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
                .invoke((request, capabilities) -> output(request, controller.invoke(describe(request), capabilities)))
                .run((request, events, signals, capabilities) -> {
                    events.append(Lifecycle.EVENT_PROGRESS, Map.of("stage", "business"));
                    if (signals.isCancelled()) {
                        throw new IllegalStateException("run was cancelled");
                    }
                    return output(request, controller.invoke(describe(request), capabilities));
                })
                .build());
    }

    public static void main(String[] args) throws Exception {
        // Fail closed: without platform-injected verification material the Agent
        // refuses to start rather than accepting unverified callers.
        // 失败闭合：没有平台注入的校验材料时，Agent 拒绝启动。
        PublicKey key = PlatformKey.fromEnv();
        String agentId = environment("AGENT_PLATFORM_AGENT_ID", DEFAULT_AUDIENCE);
        int port = Integer.parseInt(environment("PORT", "8080"));
        ExecutionServer server = server(key, agentId, null, new AgentController());
        server.start(new InetSocketAddress("0.0.0.0", port));
    }

    private static String environment(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    /** The business sees the input plus the verified run identity, never the
     * raw token. / 业务只看到输入与已验证的运行身份，绝不接触原始令牌。
     */
    private static String describe(ExecuteRequest request) {
        Object task = request.input().get("task");
        return task == null ? String.valueOf(request.input()) : String.valueOf(task);
    }

    private static Map<String, Object> output(ExecuteRequest request, String value) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("framework", "generic");
        output.put("run_id", request.scope().runId());
        output.put("result", value);
        return output;
    }
}
