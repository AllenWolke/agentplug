package com.lexagent.sdk;

import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.HexFormat;
import java.security.MessageDigest;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializationFeature;

/** Verifies the cryptographic boundary; JSON mapping stays framework-pluggable.
 * 校验密码学边界；JSON 映射保持可由 Spring/Jackson 等框架插拔。
 */
public final class ContextVerifier {
    private static final ObjectMapper CANONICAL_MAPPER = new ObjectMapper()
        .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
        .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
        .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    /** Injectable clock (epoch seconds) so shared fixtures with pinned timestamps
     * verify deterministically, matching the Go and Python SDKs.
     * 可注入时钟（epoch 秒），让钉死时间戳的共享夹具可确定性校验，与 Go/Python
     * SDK 一致。
     */
    private final java.util.function.LongSupplier clock;

    public ContextVerifier() {
        this(() -> Instant.now().getEpochSecond());
    }

    public ContextVerifier(java.util.function.LongSupplier nowSeconds) {
        this.clock = nowSeconds;
    }

    /** Verify the complete JWS/claim/body binding at the Java transport edge.
     * 在 Java 传输边界完成 JWS、声明和正文绑定校验。
     */
    public ExecutionContract.CapabilityClaims verify(ExecutionContract.ExecuteRequest request,
            PublicKey key, String issuer, String audience) {
        try {
            String[] parts = request.contextToken().split("\\.");
            if (parts.length != 3) throw new SecurityException("invalid capability shape");
            @SuppressWarnings("unchecked")
            Map<String, Object> header = CANONICAL_MAPPER.readValue(Base64.getUrlDecoder().decode(parts[0]), Map.class);
            if (!"EdDSA".equals(header.get("alg"))) throw new SecurityException("invalid capability algorithm");
            verifySignature(request.contextToken(), key);
            ExecutionContract.CapabilityClaims claims = CANONICAL_MAPPER.readValue(
                Base64.getUrlDecoder().decode(parts[1]), ExecutionContract.CapabilityClaims.class);
            verifyClaims(claims, request, issuer, audience, canonicalBodyHash(request));
            return claims;
        } catch (SecurityException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new SecurityException("capability verification failed", exception);
        }
    }

    /** Verify a signed SSE subscription without weakening event-only capability scope.
     * 校验签名 SSE 订阅，不能用执行令牌替代 events 权限。
     */
    public ExecutionContract.CapabilityClaims verifyEvent(ExecutionContract.EventRequest request,
            PublicKey key, String issuer, String audience) {
        try {
            if (request == null || request.afterSeq() < 0 || request.afterSeq() >= Lifecycle.MAX_EVENT_SEQUENCE_EXCLUSIVE)
                throw new SecurityException("event cursor is outside the safe integer range");
            String[] parts = request.contextToken().split("\\.");
            if (parts.length != 3) throw new SecurityException("invalid capability shape");
            verifySignature(request.contextToken(), key);
            ExecutionContract.CapabilityClaims claims = CANONICAL_MAPPER.readValue(
                Base64.getUrlDecoder().decode(parts[1]), ExecutionContract.CapabilityClaims.class);
            var scope = request.scope();
        long now = clock.getAsLong();
        if (!issuer.equals(claims.issuer()) || !audience.equals(claims.audience())
                || !scope.tenantId().equals(claims.tenantId()) || !scope.applicationId().equals(claims.applicationId())
                || !scope.agentInstanceId().equals(claims.agentInstanceId()) || !scope.installationId().equals(claims.installationId()) || !scope.principalId().equals(claims.subjectId())
                || scope.authorizationEpoch() != claims.authorizationEpoch() || !claims.actions().contains("events")
                || (claims.parentRunId() != null && !claims.parentRunId().equals(scope.parentRunId()))
                || !request.policySnapshotHash().equals(claims.policySnapshotHash())
                || !canonicalEventHash(request).equals(claims.bodyHash()) || claims.expiresAt() <= now
                || claims.expiresAt() - claims.issuedAt() > 300) throw new SecurityException("capability scope or lifetime mismatch");
            return claims;
        } catch (SecurityException exception) { throw exception;
        } catch (Exception exception) { throw new SecurityException("capability verification failed", exception); }
    }

    /** Cross-language canonical hash matching the Go and Python SDK rules.
     * 跨语言规范化哈希，与 Go/Python SDK 规则一致。
     */
    public static String canonicalBodyHash(ExecutionContract.ExecuteRequest request) {
        try {
            Map<String, Object> envelope = new LinkedHashMap<>();
            envelope.put("protocol_version", request.protocolVersion());
            envelope.put("scope", canonicalScope(request.scope()));
            envelope.put("operation", request.operation());
            envelope.put("idempotency_key", request.idempotencyKey());
            envelope.put("input_schema", request.inputSchema());
            envelope.put("input", request.input());
            // Bind the complete resume decision, including an explicit empty object.
            // 绑定完整恢复决策；显式空对象也不能与缺失字段混淆。
            if (request.resumeInput() != null) {
                envelope.put("resume_input", request.resumeInput());
            }
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(CANONICAL_MAPPER.writeValueAsBytes(envelope)));
        } catch (Exception exception) {
            throw new SecurityException("cannot canonicalize execution request", exception);
        }
    }

    public static String canonicalEventHash(ExecutionContract.EventRequest request) {
        try {
            Map<String, Object> envelope = new LinkedHashMap<>();
            envelope.put("protocol_version", request.protocolVersion()); envelope.put("scope", canonicalScope(request.scope()));
            envelope.put("after_seq", request.afterSeq()); envelope.put("policy_snapshot_hash", request.policySnapshotHash());
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(CANONICAL_MAPPER.writeValueAsBytes(envelope)));
        } catch (Exception exception) { throw new SecurityException("cannot canonicalize event request", exception); }
    }

    private static Map<String, Object> canonicalScope(ExecutionContract.ScopeKey scope) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("tenant_id", scope.tenantId()); value.put("department_id", scope.departmentId());
        value.put("application_id", scope.applicationId()); value.put("agent_instance_id", scope.agentInstanceId());
        value.put("installation_id", scope.installationId());
        value.put("agent_id", scope.agentId()); value.put("agent_version_id", scope.agentVersionId());
        value.put("principal_type", scope.principalType()); value.put("principal_id", scope.principalId());
        value.put("session_id", scope.sessionId()); value.put("run_id", scope.runId());
        value.put("authorization_epoch", scope.authorizationEpoch()); value.put("trace_id", scope.traceId());
        if (scope.parentRunId() != null && !scope.parentRunId().isBlank()) value.put("parent_run_id", scope.parentRunId());
        if (scope.delegationDepth() != 0) value.put("delegation_depth", scope.delegationDepth());
        return value;
    }
    public void verifySignature(String token, PublicKey key) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) throw new SecurityException("invalid capability shape");
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update((parts[0] + "." + parts[1]).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            if (!verifier.verify(Base64.getUrlDecoder().decode(parts[2]))) {
                throw new SecurityException("invalid capability signature");
            }
        } catch (SecurityException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new SecurityException("capability verification failed", exception);
        }
    }

    public void verifyClaims(ExecutionContract.CapabilityClaims claims,
            ExecutionContract.ExecuteRequest request, String issuer, String audience,
            String canonicalBodyHash) {
        var scope = request.scope();
        long now = clock.getAsLong();
		Object policyValue = request.input().get("policy_snapshot");
		String snapshotHash = policyValue instanceof java.util.Map<?, ?> policy
				? String.valueOf(policy.get("content_hash")) : "";
        if (!issuer.equals(claims.issuer()) || !audience.equals(claims.audience())
                || !scope.tenantId().equals(claims.tenantId())
                || !scope.applicationId().equals(claims.applicationId())
                || !scope.agentInstanceId().equals(claims.agentInstanceId())
                || !scope.installationId().equals(claims.installationId())
                || !scope.principalId().equals(claims.subjectId())
                || scope.authorizationEpoch() != claims.authorizationEpoch()
                || !claims.actions().contains(request.operation())
                || (claims.parentRunId() != null && !claims.parentRunId().equals(scope.parentRunId()))
				|| snapshotHash.isBlank() || !snapshotHash.equals(claims.policySnapshotHash())
                || canonicalBodyHash == null || !canonicalBodyHash.equals(claims.bodyHash())
                || claims.expiresAt() <= now || claims.expiresAt() - claims.issuedAt() > 300) {
            throw new SecurityException("capability scope or lifetime mismatch");
        }
    }
}
