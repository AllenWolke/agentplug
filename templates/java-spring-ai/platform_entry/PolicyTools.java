package generated;

import java.util.Map;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

/**
 * Real Spring AI tool object: methods annotated with {@link Tool @Tool} are
 * advertised to the model and executed by the ChatClient on the model's behalf.
 * Business tools may perform I/O; they run behind the verified boundary and see
 * only the arguments the model passes.
 *
 * 真实 Spring AI 工具对象：带 {@link Tool @Tool} 注解的方法会通告给模型，由
 * ChatClient 代表模型执行。业务工具可以执行 I/O；它们运行在已验证边界之后，
 * 只能看到模型传入的参数。
 */
public final class PolicyTools {

    private final Map<String, String> policies;

    public PolicyTools(Map<String, String> policies) {
        this.policies = policies;
    }

    @Tool(description = "Look up the effective compliance policy text for a topic, "
            + "for example 'data_retention' or 'cross_border_transfer'.")
    public String lookupPolicy(
            @ToolParam(description = "The policy topic to look up") String topic) {
        return policies.getOrDefault(topic, "no policy registered for topic: " + topic);
    }
}
