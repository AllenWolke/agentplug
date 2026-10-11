package generated;

import com.lexagent.sdk.ExecutionContract.ExecuteRequest;
import com.lexagent.sdk.CapabilityClient;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.ai.chat.client.ChatClient;

/**
 * The business seam behind the verified boundary.
 *
 * Model requests go through the per-execution SDK capability client. A direct
 * ChatClient cannot bypass platform policy. Echo is a transport fixture only.
 *
 * 已验证边界之后的业务接缝：模型请求走逐运行 SDK 客户端，禁止直接 ChatClient
 * 绕过平台治理；回显仅用于传输夹具，不冒称模型答案。
 */
public final class Workflow {

    /** Deterministic answers for the policy tool demo. / 策略工具演示的确定性答案。 */
    private final Map<String, String> policies;

    private final ChatClient chat;

    public Workflow(ChatClient chat, Map<String, String> policies) {
        this.chat = chat;
        this.policies = policies;
    }

    /** Build the echo fallback used when no model is configured. / 构造无模型时
     * 的回显降级。 */
    public static Workflow echoFallback() {
        return new Workflow(null, Map.of());
    }

    public Map<String, Object> invoke(ExecuteRequest request, CapabilityClient capabilities) throws CapabilityClient.Failure {
        if (capabilities != null) {
            // All model usage stays behind platform governance and token renewal.
            // 模型调用统一经过平台治理与续签，业务节点不持有厂商密钥。
            String task = String.valueOf(request.input().getOrDefault("task", "summarize the policy snapshot"));
            Map<String, Object> answer = capabilities.post("/internal/model/generate", Map.of(
                "messages", java.util.List.of(Map.of("role", "user", "content", task)),
                "usage_step", "workflow.answer"));
            return Map.of("framework", "spring-ai", "run_id", request.scope().runId(), "answer", answer.getOrDefault("text", ""));
        }
        if (chat == null) {
            return echo(request);
        }
        throw new CapabilityClient.Failure("CAPABILITY_CONFIG_INVALID", 503, false);
    }

    private static Map<String, Object> echo(ExecuteRequest request) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("framework", "spring-ai");
        output.put("run_id", request.scope().runId());
        output.put("echo", request.input());
        return output;
    }
}
