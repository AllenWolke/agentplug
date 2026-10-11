package generated;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.lexagent.sdk.ExecutionContract.ExecuteRequest;
import com.lexagent.sdk.ExecutionContract.ScopeKey;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;

/** Workflow tests reject direct providers and keep domain tools deterministic.
 * 工作流拒绝直接厂商调用，领域工具保持确定性。
 */
final class WorkflowTest {

    private ExecuteRequest request() {
        return new ExecuteRequest(com.lexagent.sdk.ExecutionContract.PROTOCOL_VERSION, "x".repeat(32),
                scope(), "invoke", "idem-key-0001", "schema://example/input/v1",
                Map.of("policy_snapshot", Map.of("content_hash", "a".repeat(64)), "task", "summarize"));
    }

    private static ScopeKey scope() {
        return new ScopeKey("tenant-a", "business-department", "business-app", "instance-a", "installation-a", "workflow-agent",
                "v2", "user", "user-a", "session-a", "run-workflow", 1, "0".repeat(32), "", 0);
    }

    @Test
    void echoFallbackStaysDeterministicWithoutAModel() throws Exception {
        Map<String, Object> output = Workflow.echoFallback().invoke(request(), null);
        assertEquals("spring-ai", output.get("framework"));
        assertEquals("run-workflow", output.get("run_id"));
        assertEquals(request().input(), output.get("echo"));
    }

    @Test
    void directChatClientWithoutPlatformIsRejected() {
        // A configured direct client must not be called without platform policy.
        // 已配置的直连客户端也不得绕过平台策略。
        var directCalls = new java.util.concurrent.atomic.AtomicInteger();
        ChatModel stub = new ChatModel() {
            @Override
            public ChatResponse call(Prompt prompt) {
                directCalls.incrementAndGet();
                return new ChatResponse(List.of(
                        new org.springframework.ai.chat.model.Generation(new AssistantMessage("policy summary"))));
            }
        };
        Workflow workflow = new Workflow(ChatClient.builder(stub).build(), Map.of(
                "data_retention", "Regulatory data must be retained for 5 years and then deleted."));
        var error = assertThrows(com.lexagent.sdk.CapabilityClient.Failure.class, () -> workflow.invoke(request(), null));
        assertEquals("CAPABILITY_CONFIG_INVALID", error.code());
        assertEquals(0, directCalls.get());
    }

    @Test
    void toolObjectAnswersDeterministically() {
        PolicyTools tools = new PolicyTools(Map.of(
                "data_retention", "Regulatory data must be retained for 5 years and then deleted."));
        assertTrue(tools.lookupPolicy("data_retention").contains("5 years"));
        assertTrue(tools.lookupPolicy("unknown_topic").contains("no policy registered"));
    }
}
