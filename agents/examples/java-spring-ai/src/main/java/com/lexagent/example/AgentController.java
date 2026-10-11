package com.lexagent.example;

import com.lexagent.sdk.ContextVerifier;
import com.lexagent.sdk.ExecutionContract;

/** Spring Controller seam; framework annotations are intentionally optional.
 * Spring Controller 接缝；示例不强迫平台 SDK 依赖 Spring。
 */
public final class AgentController {
    private final ContextVerifier verifier;
    public AgentController(ContextVerifier verifier) { this.verifier = verifier; }

    public ExecutionContract.ExecuteResponse invoke(ExecutionContract.ExecuteRequest request) {
        // Signature and claims are verified by middleware before this method.
        // 签名和声明必须由中间件在进入本方法前完成校验。
        return new ExecutionContract.ExecuteResponse(ExecutionContract.PROTOCOL_VERSION,
            request.scope().runId(), "succeeded", "schema://example/output/v1",
            java.util.Map.of("framework", "spring-ai"), null);
    }
}
