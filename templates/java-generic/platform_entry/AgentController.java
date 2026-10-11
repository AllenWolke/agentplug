package generated;

/**
 * Business entry point. IAM, run state, retries and audit are owned by the
 * platform adapter, not duplicated in this Agent. / 业务入口由平台适配器负责
 * IAM、运行状态、重试和审计，Agent 只保留领域逻辑。
 */
public final class AgentController {
    public String invoke(String input, com.lexagent.sdk.CapabilityClient capabilities) {
        if (input == null || input.length() > 1_048_576) {
            throw new IllegalArgumentException("input is missing or too large");
        }
        // Business code may call capabilities.post(...); never build a provider.
        // 业务节点可调用 capabilities.post(...)，不得重复装配厂商客户端。
        return input;
    }
}
