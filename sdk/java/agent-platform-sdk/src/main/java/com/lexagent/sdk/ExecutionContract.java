package com.lexagent.sdk;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import java.util.Map;
import java.time.Instant;

/** Language-neutral records for Agent Execution v2. / Agent Execution v2 的语言无关记录。 */
public final class ExecutionContract {
    public static final String PROTOCOL_VERSION = "agent-execution/v2";
    private ExecutionContract() {}

    public record ScopeKey(String tenantId, String departmentId, String applicationId,
        String agentInstanceId, String installationId, String agentId, String agentVersionId, String principalType,
        String principalId, String sessionId, String runId, long authorizationEpoch,
        String traceId, String parentRunId, int delegationDepth) {
        public ScopeKey {
            if (installationId == null || installationId.isBlank()) {
                throw new IllegalArgumentException("installation_id is required");
            }
        }
    }

    public record ExecuteRequest(String protocolVersion, String contextToken, ScopeKey scope,
        String operation, String idempotencyKey, String inputSchema, Map<String, Object> input,
        @JsonInclude(JsonInclude.Include.NON_NULL) Map<String, Object> resumeInput) {
        public ExecuteRequest(String protocolVersion, String contextToken, ScopeKey scope,
            String operation, String idempotencyKey, String inputSchema, Map<String, Object> input) {
            this(protocolVersion, contextToken, scope, operation, idempotencyKey, inputSchema, input, null);
        }
    }

    public record AppError(String code, String message, boolean retryable, Map<String, Object> details) {}
    public record ExecuteResponse(String protocolVersion, String runId, String status,
        String outputSchema, Map<String, Object> output, AppError error,
        @JsonProperty("handoff") @JsonInclude(JsonInclude.Include.NON_NULL) HandlerHandoff handoff,
        @JsonProperty("agent_group_handoff") @JsonInclude(JsonInclude.Include.NON_NULL) AgentGroupHandoff agentGroupHandoff) {
        public ExecuteResponse(String protocolVersion, String runId, String status,
            String outputSchema, Map<String, Object> output, AppError error) {
            this(protocolVersion, runId, status, outputSchema, output, error, null, null);
        }
        public ExecuteResponse(String protocolVersion, String runId, String status,
            String outputSchema, Map<String, Object> output, AppError error, HandlerHandoff handoff) {
            this(protocolVersion, runId, status, outputSchema, output, error, handoff, null);
        }
    }

    /** Process-local proof that this SDK's HarnessPause handler actually exited. */
    public record HandlerHandoff(
        @JsonProperty("version") String version,
        @JsonProperty("run_id") String runId,
        @JsonProperty("execution_revision") long executionRevision,
        @JsonProperty("body_hash") String bodyHash,
        @JsonProperty("lease_token_hash") String leaseTokenHash,
        @JsonProperty("input_fingerprint") String inputFingerprint,
        @JsonProperty("origin_operation") String originOperation,
        @JsonProperty("harness_key") String harnessKey,
        @JsonProperty("tool_name") String toolName,
        @JsonProperty("call_id") String callId,
        @JsonProperty("last_event_seq") long lastEventSeq) {}

    /** Non-secret proof of an exited SDK AgentGroup wait, separate from tool approval. */
    public record AgentGroupHandoff(
        @JsonProperty("version") String version,
        @JsonProperty("run_id") String runId,
        @JsonProperty("execution_revision") long executionRevision,
        @JsonProperty("body_hash") String bodyHash,
        @JsonProperty("lease_token_hash") String leaseTokenHash,
        @JsonProperty("input_fingerprint") String inputFingerprint,
        @JsonProperty("origin_operation") String originOperation,
        @JsonProperty("group_key") String groupKey,
        @JsonProperty("operation_key") String operationKey,
        @JsonProperty("last_event_seq") long lastEventSeq,
        @JsonProperty("checkpoint") Map<String, Object> checkpoint,
        @JsonProperty("child_keys") List<String> childKeys) {
        public AgentGroupHandoff {
            checkpoint = checkpoint == null ? null : Map.copyOf(checkpoint);
            childKeys = childKeys == null ? null : List.copyOf(childKeys);
        }
    }

    public record EventRequest(String protocolVersion, String contextToken, ScopeKey scope,
        long afterSeq, String policySnapshotHash) {
        public EventRequest {
            if (afterSeq < 0 || afterSeq >= Lifecycle.MAX_EVENT_SEQUENCE_EXCLUSIVE)
                throw new IllegalArgumentException("event cursor is outside the safe integer range");
        }
    }
    public record ExecutionEvent(String runId, long seq, String eventType, Instant occurredAt,
        Map<String, Object> payload) {}

    /** The claim names follow the gateway's compact JWS register (iss, aud, sub,
     * iat, exp) exactly like the Go and Python SDKs; the historical record
     * defaulted to snake_case long names and could never verify real platform
     * tokens. / 声明名与 Go/Python SDK 一样严格采用网关的紧凑 JWS 注册名
     * （iss、aud、sub、iat、exp）；旧记录默认按 snake_case 长名映射，导致从来
     * 无法验证真实平台令牌。
     */
    public record CapabilityClaims(
        @JsonProperty("iss") String issuer,
        @JsonProperty("aud") String audience,
        @JsonProperty("subject_type") String subjectType,
        @JsonProperty("sub") String subjectId,
        @JsonProperty("tenant_id") String tenantId,
        @JsonProperty("application_id") String applicationId,
        @JsonProperty("agent_instance_id") String agentInstanceId,
        @JsonProperty("installation_id") String installationId,
        @JsonProperty("authorization_epoch") long authorizationEpoch,
        @JsonProperty("actions") List<String> actions,
        @JsonProperty("policy_snapshot_hash") String policySnapshotHash,
        @JsonProperty("body_hash") String bodyHash,
        @JsonProperty("iat") long issuedAt,
        @JsonProperty("exp") long expiresAt,
        @JsonProperty("department_id") String departmentId,
        @JsonProperty("agent_id") String agentId,
        @JsonProperty("agent_version_id") String agentVersionId,
        @JsonProperty("run_id") String runId,
        @JsonProperty("session_id") String sessionId,
        @JsonProperty("trace_id") String traceId,
        @JsonProperty("execution_revision") Long executionRevision,
        @JsonProperty("lease_token_hash") String leaseTokenHash,
        @JsonProperty("parent_run_id") String parentRunId) {
        // Keep callers constructing legacy root capabilities source-compatible.
        public CapabilityClaims(String issuer, String audience, String subjectType, String subjectId,
                String tenantId, String applicationId, String agentInstanceId, String installationId,
                long authorizationEpoch, List<String> actions, String policySnapshotHash, String bodyHash,
                long issuedAt, long expiresAt, String departmentId, String agentId, String agentVersionId,
                String runId, String sessionId, String traceId, Long executionRevision, String leaseTokenHash) {
            this(issuer, audience, subjectType, subjectId, tenantId, applicationId, agentInstanceId,
                    installationId, authorizationEpoch, actions, policySnapshotHash, bodyHash, issuedAt,
                    expiresAt, departmentId, agentId, agentVersionId, runId, sessionId, traceId,
                    executionRevision, leaseTokenHash, null);
        }
    }
}
