package com.lexagent.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Array;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.function.LongSupplier;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Per-execution governed capability client, never a shared model provider.
 * 逐运行的受控公共能力客户端，不持有模型厂商密钥，不跨用户共享。
 */
public final class CapabilityClient implements CapabilityPort {
    private final CheckpointCapacity checkpointCapacity = new CheckpointCapacity();
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final List<String> BINDINGS = List.of("iss", "aud", "subject_type", "sub", "tenant_id", "department_id", "application_id", "installation_id", "agent_instance_id", "agent_id", "agent_version_id", "run_id", "parent_run_id", "session_id", "trace_id", "authorization_epoch", "actions", "body_hash", "policy_snapshot_hash", "execution_revision", "lease_token_hash");

    public static class Failure extends Exception {
        private final String code;
        private final int status;
        private final boolean retryable;
        private final Map<String, Object> details;
        public Failure(String code, int status, boolean retryable) {
            this(code, status, retryable, Map.of());
        }
        public Failure(String code, int status, boolean retryable, Map<String, Object> details) {
            super("platform capability failed");
            this.code = code; this.status = status; this.retryable = retryable;
            this.details = details == null ? Map.of() : Map.copyOf(details);
        }
        public String code() { return code; }
        public int status() { return status; }
        public boolean retryable() { return retryable; }
        public Map<String, Object> details() { return details; }
        public ExecutionContract.AppError appError() { return new ExecutionContract.AppError(code, getMessage(), retryable, details); }
    }

    /** Deployment config; an absent endpoint means no client, not direct access.
     * 部署配置：未配置端点不注入客户端，并非允许直连厂商。
     */
    public record Config(String baseUrl, String internalToken, String signingSecret, LongSupplier now, String workloadClientId, String workloadClientSecret) {
        public Config(String baseUrl, String internalToken, String signingSecret, LongSupplier now) { this(baseUrl, internalToken, signingSecret, now, "", ""); }
        public Config {
            URI uri;
            try { uri = URI.create(baseUrl); }
            catch (Exception ignored) { throw new IllegalArgumentException("invalid platform capability target"); }
            if (!List.of("http", "https").contains(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getFragment() != null || internalToken == null || internalToken.isBlank() || signingSecret == null || signingSecret.isBlank()) {
                throw new IllegalArgumentException("platform capability wiring is incomplete");
            }
            workloadClientId = workloadClientId == null ? "" : workloadClientId.trim();
            workloadClientSecret = workloadClientSecret == null ? "" : workloadClientSecret.trim();
            if (workloadClientId.isEmpty() != workloadClientSecret.isEmpty() || (!workloadClientSecret.isEmpty() && (workloadClientSecret.length() < 32 || workloadClientSecret.length() > 512))) throw new IllegalArgumentException("Agent workload credentials must be configured together");
            baseUrl = baseUrl.replaceAll("/+$", "");
            if (now == null) now = () -> Instant.now().getEpochSecond();
        }
        public static Config fromEnvironment() {
            String base = System.getenv("PLATFORM_CAPABILITY_URL");
            if (base == null || base.isBlank()) return null;
            String clientId = System.getenv("AGENT_CLIENT_ID"); clientId = clientId == null ? "" : clientId.trim();
            boolean secretConfigured = System.getenv("AGENT_CLIENT_SECRET") != null || System.getenv("AGENT_CLIENT_SECRET_FILE") != null;
            if (clientId.isEmpty() && secretConfigured) throw new IllegalArgumentException("Agent workload credentials must be configured together");
            return new Config(base.trim(), credential("INTERNAL_TOKEN"), credential("INTERNAL_SIGNING_SECRET"), null, clientId, clientId.isEmpty() ? "" : credential("AGENT_CLIENT_SECRET"));
        }
        // Record's generated toString would expose credentials in diagnostics.
        // 覆盖 record 默认字符串，防止诊断日志泄漏内部凭据。
        @Override public String toString() { return "CapabilityClient.Config[redacted]"; }
        private static String credential(String name) {
            String value = System.getenv(name);
            String file = System.getenv(name + "_FILE");
            try {
                if ((value == null || value.isBlank()) && file != null && !file.isBlank()) value = Files.readString(Path.of(file)).trim();
            } catch (Exception ignored) { throw new IllegalArgumentException("platform credential file unavailable"); }
            if (value == null || value.isBlank() || List.of("dev-internal-token", "change-me").contains(value.trim())) throw new IllegalArgumentException("explicit platform credential required");
            return value.trim();
        }
    }

    @FunctionalInterface public interface SendLimiter { AutoCloseable acquire(Duration remaining) throws Exception; }
    public record CallObservation(String path,double wallMs,String status) {}
    private volatile SendLimiter sendLimiter;
    private volatile java.util.function.Consumer<CallObservation> callObserver;
    public void setSendLimiter(SendLimiter limiter){this.sendLimiter=limiter;}
    public void setCallObserver(java.util.function.Consumer<CallObservation> observer){this.callObserver=observer;}
    private static final HttpClient SHARED_HTTP=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).followRedirects(HttpClient.Redirect.NEVER).build();
    private static final class ObservationLost extends Failure { ObservationLost(){super("CAPABILITY_RENEWAL_UNAVAILABLE",503,true);} }
    private final Config config;
    private final HttpClient http;
    private final Map<String, Object> context;
    private final String businessInputFingerprint;
    private final String operation;
    private final Object lock = new Object();
    private volatile AgentGroupResumeBinding agentGroupResumeBinding;
    private volatile Thread agentGroupResumeThread;
    private volatile Thread agentGroupGatherThread;
    private volatile boolean agentGroupResumeCheckpointVerified;
    private volatile boolean agentGroupResumeConsumed;
    private volatile RecoveryPlan.RuntimeRecoveryBinding runtimeRecoveryBinding;

    public CapabilityClient(Config config, ExecutionContract.ExecuteRequest request) {
        this(config, ExecutionTracker.businessHash(request), request.operation());
        var s = request.scope();
        context.put("tenant_id", s.tenantId()); context.put("department_id", s.departmentId()); context.put("application_id", s.applicationId());
        context.put("installation_id", s.installationId()); context.put("agent_instance_id", s.agentInstanceId()); context.put("agent_id", s.agentId()); context.put("agent_version_id", s.agentVersionId());
        context.put("principal_type", s.principalType()); context.put("actor_id", s.principalId()); context.put("request_id", request.idempotencyKey());
        context.put("task_id", s.runId()); context.put("session_id", s.sessionId()); context.put("thread_id", s.sessionId()); context.put("trace_id", s.traceId());
        context.put("authorization_epoch", s.authorizationEpoch()); context.put("idempotency_key", request.idempotencyKey()); context.put("platform_context_token", request.contextToken());
        if (s.parentRunId() != null && !s.parentRunId().isEmpty()) context.put("parent_run_id", s.parentRunId());
        if (!(request.input().get("policy_snapshot") instanceof Map<?, ?> policy)) throw new IllegalArgumentException("immutable policy snapshot is missing");
        for (String key : List.of("model_profile_id", "prompt_version_id", "tool_policy_id", "memory_policy_id", "knowledge_policy_id", "runtime_policy_id")) {
            if (!(policy.get(key) instanceof String value) || value.isBlank()) throw new IllegalArgumentException("six immutable policy references are required");
            context.put(key, value);
        }
    }

    private CapabilityClient(Config config) {
        this(config, null, null);
    }

    private CapabilityClient(Config config, String businessInputFingerprint) {
        this(config, businessInputFingerprint, null);
    }

    private CapabilityClient(Config config, String businessInputFingerprint, String operation) {
        this.config = config;
        this.http = SHARED_HTTP;
        context = new LinkedHashMap<>();
        this.businessInputFingerprint = businessInputFingerprint;
        this.operation = operation;
    }

    /** Check events-only current history access without a business policy envelope. */
    public static void checkEventAuthority(Config config, ExecutionContract.EventRequest request) throws Failure {
        if (config.workloadClientId().isEmpty() || config.workloadClientSecret().isEmpty()) throw new Failure("CAPABILITY_CONFIG_INVALID", 503, false);
        byte[] raw;
        try { raw = JSON.copy().setPropertyNamingStrategy(com.fasterxml.jackson.databind.PropertyNamingStrategies.SNAKE_CASE).writeValueAsBytes(request); }
        catch (Exception ignored) { throw new Failure("REQUEST_INVALID", 400, false); }
        if (raw.length > 32768) throw new Failure("REQUEST_INVALID", 400, false);
        Map<String, Object> result = new CapabilityClient(config).send("/internal/context/events/check", raw, request.contextToken(), 32768, 5);
        if (!Boolean.TRUE.equals(result.get("allowed"))) throw new Failure("CAPABILITY_DENIED", 403, false);
    }

    public Map<String, Object> post(String path, Map<String, Object> input) throws Failure {
        return postWithin(path, input, Duration.ofSeconds(310));
    }

    private Map<String, Object> postWithin(String path, Map<String, Object> input, Duration requestedTimeout) throws Failure {
        if (!path.startsWith("/internal/") || path.contains("..") || path.contains("?") || path.contains("#") || path.equals("/internal/context/renew")) throw new Failure("REQUEST_INVALID", 400, false);
        if (requestedTimeout == null || requestedTimeout.isNegative() || requestedTimeout.isZero()) throw new Failure("REQUEST_INVALID", 400, false);
        guardUnconsumedAgentGroupResume(path, input);
        RecoveryPlan.RuntimeRecoveryBinding recoveryBinding = runtimeRecoveryBinding;
        if (recoveryBinding != null) recoveryBinding.beforePost(path, input);
        Duration timeout = requestedTimeout.compareTo(Duration.ofSeconds(310)) > 0 ? Duration.ofSeconds(310) : requestedTimeout;
        long started = System.nanoTime();
        byte[] body;
        String token;
        // Single-flight only the refresh and snapshot; business requests stay parallel.
        // 只串行续签与快照，公共能力请求仍可并行，不跨运行共享锁。
        synchronized (lock) {
            renew(false, timeout);
            body = encode(input);
            token = (String) context.get("platform_context_token");
        }
        long elapsed = Math.max(0, System.nanoTime() - started);
        long remaining = Math.max(1L, timeout.toNanos() - elapsed);
        Map<String,Object> response;
        try{response=send(path,body,token,1<<20,Duration.ofNanos(remaining));}
        catch(ObservationLost lost){
            if(!path.equals("/internal/tool/invoke"))throw lost;
            long receiptRemaining=timeout.toNanos()-Math.max(0,System.nanoTime()-started);
            if(receiptRemaining<=0||Thread.currentThread().isInterrupted())throw new Failure("TOOL_RESULT_UNKNOWN",409,false);
            Map<String,Object> command=new LinkedHashMap<>();for(String field:List.of("name","call_id","payload"))command.put(field,input.get(field));
            if(!(command.get("name") instanceof String)||!(command.get("call_id") instanceof String)||!(command.get("payload") instanceof Map<?,?>))throw new Failure("TOOL_RESULT_UNKNOWN",409,false);
            if(input.containsKey("confirmation_token"))command.put("confirmation_token",input.get("confirmation_token"));
            Map<String,Object> receipt;
            try{receipt=postWithin("/internal/tool/receipt",command,Duration.ofNanos(Math.min(receiptRemaining,Duration.ofSeconds(5).toNanos())));}
            catch(Failure error){if(Set.of("TOOL_CONFIRMATION_REQUIRED","MODEL_BUDGET_EXCEEDED").contains(error.code()))throw new Failure("CAPABILITY_DENIED",403,false);if(Optimization.authorityFailure(error))throw error;throw new Failure("TOOL_RESULT_UNKNOWN",409,false);}
            if(!"tool-receipt/v1".equals(receipt.get("version"))||!java.util.Objects.equals(input.get("name"),receipt.get("tool_name"))||!java.util.Objects.equals(input.get("call_id"),receipt.get("call_id")))throw new Failure("TOOL_RECEIPT_REJECTED",409,false);
            if(!"completed".equals(receipt.get("status")))throw new Failure("TOOL_RESULT_UNKNOWN",409,false);
            if(!(receipt.get("receipt") instanceof Map<?,?> result)||!result.containsKey("data")||!(result.get("observation") instanceof Map<?,?> observation)||!"runtime-observation/v1".equals(observation.get("version"))||!java.util.Objects.equals(input.get("name"),observation.get("tool_name"))||!java.util.Objects.equals(input.get("call_id"),observation.get("call_id"))||!"succeeded".equals(observation.get("status"))||!"completed".equals(observation.get("effect"))||!"untrusted_data".equals(observation.get("instruction_trust")))throw new Failure("TOOL_RECEIPT_REJECTED",409,false);
            response=new LinkedHashMap<>();for(var entry:result.entrySet()){if(!(entry.getKey() instanceof String key))throw new Failure("TOOL_RECEIPT_REJECTED",409,false);response.put(key,entry.getValue());}
        }

        if (recoveryBinding != null) recoveryBinding.observePost(path, input, response, nowEpochSeconds());
        return response;
    }

    /** Read the caller-bound published Harness limits; this fixed endpoint is read-only.
     * This method deliberately bypasses checkpoint-step start consumption because it cannot mutate state or dispatch work.
     */
    private Map<String, Object> readHarnessPolicy() throws Failure {
        String path = "/internal/runtime/harness-policy";
        byte[] body = encode(Map.of());
        long started = System.nanoTime();
        String token;
        synchronized (lock) {
            renew(false, Duration.ofSeconds(5));
            token = (String) context.get("platform_context_token");
        }
        long remaining = Math.max(1L, Duration.ofSeconds(5).toNanos() - Math.max(0, System.nanoTime() - started));
        return send(path, body, token, 32768, Duration.ofNanos(remaining));
    }

    /** Execute the exact approved operation; never issue approval or retry unknown effects. */
    public Map<String, Object> invokeTool(String name, String callId, Map<String, Object> payload, String confirmationToken) throws Failure {
        if (name == null || name.isBlank() || name.getBytes(StandardCharsets.UTF_8).length > 128
                || callId == null || callId.isBlank() || callId.getBytes(StandardCharsets.UTF_8).length > 128
                || payload == null || confirmationToken == null || confirmationToken.getBytes(StandardCharsets.UTF_8).length > 8192)
            throw new Failure("REQUEST_INVALID", 400, false);
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("name", name); input.put("call_id", callId); input.put("payload", payload);
        if (!confirmationToken.isEmpty()) input.put("confirmation_token", confirmationToken);
        return post("/internal/tool/invoke", input);
    }

    /** Plans/reserves targets without dispatching or granting permissions. */
    String taskId() { synchronized (lock) { return (String) context.get("task_id"); } }

    String businessInputFingerprint() {
        if (businessInputFingerprint == null) throw new IllegalStateException("business input fingerprint is unavailable");
        return businessInputFingerprint;
    }

    void bindAgentGroupResume(AgentGroupResumeBinding binding) {
        if (binding == null || agentGroupResumeBinding != null || binding.handoff() == null
                || !businessInputFingerprint().equals(binding.handoff().inputFingerprint()))
            throw new IllegalArgumentException("AgentGroup resume binding is invalid");
        agentGroupResumeBinding = binding;
    }

    void bindRuntimeRecovery(RecoveryPlan.RuntimeRecoveryBinding binding) {
        if (binding == null || operation == null || !"resume".equals(operation) || runtimeRecoveryBinding != null)
            throw new IllegalArgumentException("runtime recovery binding is invalid");
        runtimeRecoveryBinding = binding;
    }

    AgentGroupResumeBinding authorizeAgentGroupInvocation(String groupKey, String operationKey, String inputHash) throws Failure {
        RecoveryPlan.RuntimeRecoveryBinding recoveryBinding = runtimeRecoveryBinding;
        AgentGroupResumeBinding binding = agentGroupResumeBinding;
        if (binding == null) {
            if (recoveryBinding != null) recoveryBinding.authorizeAgentGroupInvocation(groupKey, operationKey, inputHash);
            return null;
        }
        var handoff = binding.handoff();
        if (agentGroupResumeConsumed || !handoff.groupKey().equals(groupKey)
                || !handoff.operationKey().equals(operationKey)
                || !handoff.inputFingerprint().equals(businessInputFingerprint())
                || !binding.inputHash().equals(inputHash)) {
            throw new Failure("AGENT_GROUP_RESUME_REJECTED", 409, false);
        }
        Thread current = Thread.currentThread();
        if (agentGroupResumeThread != null && agentGroupResumeThread != current)
            throw new Failure("AGENT_GROUP_RESUME_REJECTED", 409, false);
        agentGroupResumeThread = current;
        if (recoveryBinding != null) recoveryBinding.authorizeAgentGroupInvocation(groupKey, operationKey, inputHash);
        return binding;
    }

    void authorizeAgentGroupCheckpointLoaded(String groupKey, String operationKey, String inputHash) throws Failure {
        RecoveryPlan.RuntimeRecoveryBinding binding = runtimeRecoveryBinding;
        if (binding != null) binding.authorizeAgentGroupCheckpointLoaded(groupKey, operationKey, inputHash);
    }

    void finishAgentGroupInvocation(String groupKey, String operationKey, String inputHash) throws Failure {
        RecoveryPlan.RuntimeRecoveryBinding binding = runtimeRecoveryBinding;
        if (binding != null) binding.finishAgentGroupInvocation(groupKey, operationKey, inputHash);
    }

    /** Consume the exact one-use no-head start authorized by this verified recovery plan. */
    public boolean authorizeRuntimeRecoveryStart(String namespace, String key, String schemaId,
            String inputHash) throws Failure {
        RecoveryPlan.RuntimeRecoveryBinding binding = runtimeRecoveryBinding;
        if (binding == null) return false;
        binding.authorizeInitialStart(namespace, key, schemaId, inputHash);
        return true;
    }

    /** True only while this verified invocation is resuming its fixed AgentGroup gather. */
    public boolean isAgentGroupResume() {
        AgentGroupResumeBinding groupBinding = agentGroupResumeBinding;
        if (groupBinding != null && !agentGroupResumeConsumed) return true;
        RecoveryPlan.RuntimeRecoveryBinding recoveryBinding = runtimeRecoveryBinding;
        return recoveryBinding != null && recoveryBinding.isAgentGroupResume();
    }

    boolean agentGroupResumeSatisfied() {
        return agentGroupResumeBinding == null || agentGroupResumeConsumed;
    }

    void markAgentGroupResumeCheckpointVerified(AgentGroupResumeBinding binding) throws Failure {
        if (binding == null || binding != agentGroupResumeBinding || agentGroupResumeConsumed
                || Thread.currentThread() != agentGroupResumeThread)
            throw new Failure("AGENT_GROUP_RESUME_REJECTED", 409, false);
        agentGroupResumeCheckpointVerified = true;
    }

    private void guardUnconsumedAgentGroupResume(String path, Map<String, Object> input) throws Failure {
        if (agentGroupResumeBinding == null || agentGroupResumeConsumed) return;
        var handoff = agentGroupResumeBinding.handoff();
        if ("/internal/state/checkpoint".equals(path) && input != null
                && Thread.currentThread() == agentGroupResumeThread
                && "load".equals(input.get("operation"))
                && "coordination".equals(input.get("namespace"))
                && handoff.groupKey().equals(input.get("key"))
                && AgentGroupRunner.STATE_SCHEMA.equals(input.get("schema_id"))
                && input.get("revision") instanceof Number revision
                && new BigDecimal(revision.toString()).compareTo(BigDecimal.ZERO) == 0) return;
        if ("/internal/agent/gather".equals(path) && Thread.currentThread() == agentGroupGatherThread
                && input != null && handoff.operationKey().equals(input.get("operation_key"))) return;
        throw new Failure("AGENT_GROUP_RESUME_REQUIRED", 409, false);
    }

    /** Read only the saved slot: no input/output body and no dispatch permit. */
    public Map<String, Object> readAgentAdmissionState(String operationKey, int ordinal, String childKey, String inputFingerprint, String outputSchema) throws Failure {
        if (!HarnessRunner.skillIdentifier(operationKey) || ordinal < 0 || ordinal > 15 || childKey == null || !childKey.matches("[0-9a-f]{64}")
                || inputFingerprint == null || !inputFingerprint.matches("[0-9a-f]{64}") || outputSchema == null || !outputSchema.startsWith("schema://")
                || outputSchema.getBytes(StandardCharsets.UTF_8).length > 256 || outputSchema.chars().anyMatch(ch -> "*\0\r\n\t ".indexOf(ch) >= 0)) throw new Failure("REQUEST_INVALID", 400, false);
        Map<String, Object> result = post("/internal/agent/admission-state", Map.of("operation_key", operationKey, "ordinal", ordinal));
        JsonNode state = JSON.valueToTree(result).path("admission_state");
        JsonNode rev = state.path("revision"), ord = state.path("ordinal");
        String runId = taskId();
        if (!state.isObject() || !state.path("version").asText().equals("agent-child-admission-state/v1") || runId == null || runId.isEmpty()
                || !state.path("parent_run_id").asText().equals(runId) || !state.path("operation_key").asText().equals(operationKey)
                || !ord.isIntegralNumber() || !ord.canConvertToInt() || ord.intValue() != ordinal || !state.path("child_key").asText().equals(childKey)
                || !state.path("input_fingerprint").asText().equals(inputFingerprint) || !state.path("output_schema").asText().equals(outputSchema)
                || !rev.isIntegralNumber() || !rev.canConvertToLong() || rev.longValue() < 2) throw new Failure("AGENT_ADMISSION_STATE_REJECTED", 502, false);
        String status = state.path("status").asText();
        if (status.equals("preparing")) {
            if (rev.longValue() != 2 || !state.path("child_run_id").isTextual() || !state.path("child_run_id").asText().isEmpty()) throw new Failure("AGENT_ADMISSION_STATE_REJECTED", 502, false);
        } else if (!List.of("accepted", "running", "completed", "failed", "cancelled", "uncertain").contains(status)
                || rev.longValue() < 3 || !state.path("child_run_id").asText().equals("child-" + childKey.substring(0, 48))) throw new Failure("AGENT_ADMISSION_STATE_REJECTED", 502, false);
        return result;
    }

    public Map<String, Object> runAgentGroup(List<Map<String, Object>> inputs, AgentGroupRunner.Options options)
            throws Failure, AgentGroupPause {
        return AgentGroupRunner.run(this, inputs, options);
    }

    public Map<String, Object> routeAgents(String operationKey, String taskType, int count) throws Failure {
        if (!HarnessRunner.skillIdentifier(operationKey) || !HarnessRunner.skillIdentifier(taskType) || count < 1 || count > 16) throw new Failure("REQUEST_INVALID", 400, false);
        Map<String, Object> result = post("/internal/agent/route", Map.of("operation_key", operationKey, "task_type", taskType, "count", count));
        String runId; synchronized (lock) {runId = (String) context.get("task_id");}
        JsonNode route = JSON.valueToTree(result).path("route");
        if (!route.isObject() || !route.path("version").asText().equals("agent-route/v1") || !route.path("operation_key").asText().equals(operationKey)
                || !route.path("task_type").asText().equals(taskType) || runId == null || runId.isEmpty() || !route.path("parent_run_id").asText().equals(runId)
                || !route.path("child_depth").isIntegralNumber() || !route.path("child_depth").canConvertToInt() || route.path("child_depth").asInt() < 1 || route.path("child_depth").asInt() > 4
                || !route.path("targets").isArray() || route.path("targets").size() != count) throw new Failure("AGENT_ROUTE_REJECTED", 502, false);
        Set<String> seen = new java.util.HashSet<>();
        for (JsonNode target : route.path("targets")) {
            if (!target.isObject()) throw new Failure("AGENT_ROUTE_REJECTED", 502, false);
            for (String key : List.of("installation_id", "agent_id", "version_id")) if (!target.path(key).isTextual() || !HarnessRunner.skillIdentifier(target.path(key).asText())) throw new Failure("AGENT_ROUTE_REJECTED", 502, false);
            if (!seen.add(target.path("installation_id").asText())) throw new Failure("AGENT_ROUTE_REJECTED", 502, false);
            for (String key : List.of("input_schema", "output_schema")) {
                JsonNode schema = target.path(key);
                if (!schema.isTextual() || !schema.asText().startsWith("schema://") || schema.asText().getBytes(StandardCharsets.UTF_8).length > 256
                        || schema.asText().chars().anyMatch(c -> "*\u0000\r\n\t ".indexOf(c) >= 0)) throw new Failure("AGENT_ROUTE_REJECTED", 502, false);
            }
        }
        return result;
    }

    /** Freeze input for a saved routing ordinal. This receipt does not admit or dispatch a Run. */
    public Map<String, Object> prepareAgentChild(String operationKey, int ordinal, String inputSchema, Map<String, Object> input) throws Failure {
        if (!HarnessRunner.skillIdentifier(operationKey) || ordinal < 0 || ordinal > 15 || inputSchema == null
                || !inputSchema.startsWith("schema://") || inputSchema.getBytes(StandardCharsets.UTF_8).length > 256
                || inputSchema.chars().anyMatch(c -> "*\u0000\r\n\t ".indexOf(c) >= 0)
                || input == null || input.containsKey("policy_snapshot")) throw new Failure("REQUEST_INVALID", 400, false);
        JsonNode frozen;
        try {
            byte[] encoded = JSON.writeValueAsBytes(input);
            if (encoded.length > 65536) throw new Failure("REQUEST_INVALID", 400, false);
            frozen = JSON.readTree(encoded);
            if (!frozen.isObject()) throw new Failure("REQUEST_INVALID", 400, false);
        } catch (Failure known) { throw known; }
        catch (Exception invalid) { throw new Failure("REQUEST_INVALID", 400, false); }
        Map<String, Object> result = post("/internal/agent/prepare", Map.of("operation_key", operationKey, "ordinal", ordinal,
                "expected_revision", 1, "input_schema", inputSchema, "input", frozen));
        JsonNode prepared = JSON.valueToTree(result.get("preparation"));
        String runId;
        synchronized (lock) { runId = (String) context.get("task_id"); }
        if (prepared == null || !prepared.isObject() || !prepared.path("version").asText().equals("agent-child-preparation/v1")
                || runId == null || runId.isEmpty() || !prepared.path("parent_run_id").asText().equals(runId)
                || !prepared.path("operation_key").asText().equals(operationKey)
                || !prepared.path("ordinal").isIntegralNumber() || !prepared.path("ordinal").canConvertToInt() || prepared.path("ordinal").asInt() != ordinal
                || !prepared.path("status").asText().equals("preparing") || !prepared.path("revision").isIntegralNumber()
                || !prepared.path("revision").canConvertToInt() || prepared.path("revision").asInt() != 2
                || !prepared.path("input_schema").asText().equals(inputSchema)) throw new Failure("AGENT_PREPARATION_REJECTED", 502, false);
        for (String key : List.of("child_key", "input_fingerprint")) {
            if (!prepared.path(key).isTextual() || !prepared.path(key).asText().matches("[0-9a-f]{64}")) throw new Failure("AGENT_PREPARATION_REJECTED", 502, false);
        }
        return result;
    }

    /** Persist stop intent; cancelling/recovering never acknowledge remote termination. */
    public Map<String, Object> cancelAgentChild(String operationKey, int ordinal, String childKey, long expectedExecutionRevision) throws Failure {
        if (!HarnessRunner.skillIdentifier(operationKey) || ordinal < 0 || ordinal > 15 || childKey == null || !childKey.matches("[0-9a-f]{64}") || expectedExecutionRevision < 1)
            throw new Failure("REQUEST_INVALID", 400, false);
        Map<String, Object> result = post("/internal/agent/cancel", Map.of("operation_key", operationKey, "ordinal", ordinal, "expected_execution_revision", expectedExecutionRevision));
        JsonNode child = JSON.valueToTree(result.get("cancellation"));
        String runId; synchronized (lock) { runId = (String) context.get("task_id"); }
        if (child == null || !child.isObject() || !child.path("version").asText().equals("agent-child-cancellation/v1")
                || runId == null || runId.isEmpty() || !child.path("parent_run_id").asText().equals(runId)
                || !child.path("operation_key").asText().equals(operationKey) || !child.path("ordinal").isIntegralNumber()
                || !child.path("ordinal").canConvertToInt() || child.path("ordinal").asInt() != ordinal
                || !child.path("child_key").asText().equals(childKey) || !child.path("child_run_id").asText().equals("child-" + childKey.substring(0, 48))
                || !child.path("execution_revision").isIntegralNumber() || !child.path("execution_revision").canConvertToLong() || child.path("execution_revision").asLong() < 1
                || !Set.of("cancelling", "recovering", "cancelled", "completed", "failed").contains(child.path("status").asText()))
            throw new Failure("AGENT_CANCELLATION_REJECTED", 502, false);
        return result;
    }

    /** Admit the frozen preparation once; query an unknown outcome rather than dispatching again. */
    public Map<String, Object> admitAgentChild(String operationKey, int ordinal, String childKey, String inputFingerprint) throws Failure {
        if (!HarnessRunner.skillIdentifier(operationKey) || ordinal < 0 || ordinal > 15 || childKey == null || !childKey.matches("[0-9a-f]{64}")
                || inputFingerprint == null || !inputFingerprint.matches("[0-9a-f]{64}")) throw new Failure("REQUEST_INVALID", 400, false);
        Map<String, Object> result = post("/internal/agent/admit", Map.of("operation_key", operationKey, "ordinal", ordinal, "expected_revision", 2));
        JsonNode child = JSON.valueToTree(result.get("admission"));
        String runId; synchronized (lock) { runId = (String) context.get("task_id"); }
        if (child == null || !child.isObject() || !child.path("version").asText().equals("agent-child-admission/v1")
                || runId == null || runId.isEmpty() || !child.path("parent_run_id").asText().equals(runId)
                || !child.path("operation_key").asText().equals(operationKey) || !child.path("ordinal").isIntegralNumber()
                || !child.path("ordinal").canConvertToInt() || child.path("ordinal").asInt() != ordinal
                || !child.path("child_key").asText().equals(childKey) || !child.path("child_run_id").asText().equals("child-" + childKey.substring(0, 48))
                || !child.path("input_fingerprint").asText().equals(inputFingerprint) || !child.path("revision").isIntegralNumber()
                || !child.path("revision").canConvertToLong() || child.path("revision").asLong() < 3
                || !Set.of("accepted", "running", "completed", "failed", "cancelled", "uncertain").contains(child.path("status").asText()))
            throw new Failure("AGENT_ADMISSION_REJECTED", 502, false);
        return result;
    }

    /** Read only a bound immediate child. Its output remains untrusted business data. */
    public Map<String, Object> readAgentChild(String operationKey, int ordinal, String childKey, String outputSchema) throws Failure {
        if (!HarnessRunner.skillIdentifier(operationKey) || ordinal < 0 || ordinal > 15 || childKey == null || !childKey.matches("[0-9a-f]{64}")
                || outputSchema == null || !outputSchema.startsWith("schema://") || outputSchema.getBytes(StandardCharsets.UTF_8).length > 256
                || outputSchema.chars().anyMatch(c -> "*\u0000\r\n\t ".indexOf(c) >= 0)) throw new Failure("REQUEST_INVALID", 400, false);
        Map<String, Object> result = post("/internal/agent/child", Map.of("operation_key", operationKey, "ordinal", ordinal));
        String runId; synchronized (lock) { runId = (String) context.get("task_id"); }
        return validateAgentChildResult(result, runId, operationKey, ordinal, childKey, outputSchema);
    }

    private static Map<String, Object> validateAgentChildResult(Map<String, Object> result, String runId, String operationKey, int ordinal, String childKey, String outputSchema) throws Failure {
        JsonNode child = JSON.valueToTree(result.get("child"));
        if (child == null || !child.isObject() || !child.path("version").asText().equals("agent-child-result/v1")
                || runId == null || runId.isEmpty() || !child.path("parent_run_id").asText().equals(runId)
                || !child.path("operation_key").asText().equals(operationKey) || !child.path("ordinal").isIntegralNumber()
                || !child.path("ordinal").canConvertToInt() || child.path("ordinal").asInt() != ordinal
                || !child.path("child_key").asText().equals(childKey) || !child.path("child_run_id").asText().equals("child-" + childKey.substring(0, 48))
                || !child.path("execution_revision").isIntegralNumber() || !child.path("execution_revision").canConvertToLong() || child.path("execution_revision").asLong() < 1
                || !Set.of("accepted", "running", "waiting", "completed", "failed", "cancelled", "cancelling", "recovering", "uncertain").contains(child.path("status").asText())
                || !child.path("output_schema").asText().equals(outputSchema) || !child.path("instruction_trust").asText().equals("untrusted_data")
                || !child.path("output_bytes").isIntegralNumber() || !child.path("output_bytes").canConvertToLong() || child.path("output_bytes").asLong() < 0
                || !child.path("output_omitted").isBoolean() || !child.has("output")) throw new Failure("AGENT_CHILD_REJECTED", 502, false);
        long size = child.path("output_bytes").asLong();
        boolean omitted = child.path("output_omitted").asBoolean();
        JsonNode output = child.get("output");
        if (!output.isNull()) {
            if (!output.isObject() || !child.path("status").asText().equals("completed") || omitted || size == 0 || size > 16384
                    || !child.path("output_digest").isTextual() || !child.path("output_digest").asText().matches("[0-9a-f]{64}")) throw new Failure("AGENT_CHILD_REJECTED", 502, false);
            try { if (JSON.writeValueAsBytes(output).length > 98304) throw new Failure("AGENT_CHILD_REJECTED", 502, false); }
            catch (Failure known) { throw known; }
            catch (Exception invalid) { throw new Failure("AGENT_CHILD_REJECTED", 502, false); }
        } else if (!child.path("output_digest").asText("").isEmpty()
                || (omitted && (!child.path("status").asText().equals("completed") || size <= 16384))
                || (!omitted && (child.path("status").asText().equals("completed") || size != 0))) throw new Failure("AGENT_CHILD_REJECTED", 502, false);
        return result;
    }

    public record AgentChildBinding(String childKey, String outputSchema) {}

    /** Read one whole admitted plan with saved bindings in route ordinal order. */
    public Map<String, Object> gatherAgentChildren(String operationKey, List<AgentChildBinding> bindings) throws Failure {
        if (!HarnessRunner.skillIdentifier(operationKey) || bindings == null) throw new Failure("REQUEST_INVALID", 400, false);
        List<AgentChildBinding> frozen;
        try { frozen = List.copyOf(bindings); }
        catch (RuntimeException invalid) { throw new Failure("REQUEST_INVALID", 400, false); }
        if (frozen.isEmpty() || frozen.size() > 16) throw new Failure("REQUEST_INVALID", 400, false);
        Set<String> seen = new java.util.HashSet<>();
        for (AgentChildBinding binding : frozen) {
            if (binding.childKey() == null || !binding.childKey().matches("[0-9a-f]{64}") || !seen.add(binding.childKey())
                    || binding.outputSchema() == null || !binding.outputSchema().startsWith("schema://") || binding.outputSchema().getBytes(StandardCharsets.UTF_8).length > 256
                    || binding.outputSchema().chars().anyMatch(c -> "*\u0000\r\n\t ".indexOf(c) >= 0)) throw new Failure("REQUEST_INVALID", 400, false);
        }
        boolean resumingGroup = agentGroupResumeBinding != null && !agentGroupResumeConsumed;
        if (resumingGroup) {
            var expected = agentGroupResumeBinding.handoff();
            if (!agentGroupResumeCheckpointVerified || Thread.currentThread() != agentGroupResumeThread
                    || !expected.operationKey().equals(operationKey)
                    || expected.childKeys().size() != frozen.size())
                throw new Failure("AGENT_GROUP_RESUME_REJECTED", 409, false);
            for (int index = 0; index < frozen.size(); index++)
                if (!expected.childKeys().get(index).equals(frozen.get(index).childKey()))
                    throw new Failure("AGENT_GROUP_RESUME_REJECTED", 409, false);
            agentGroupGatherThread = Thread.currentThread();
        }
        Map<String, Object> result;
        try {
            result = post("/internal/agent/gather", Map.of("operation_key", operationKey));
        } finally {
            if (resumingGroup) agentGroupGatherThread = null;
        }
        String runId; synchronized (lock) { runId = (String) context.get("task_id"); }
        JsonNode group = JSON.valueToTree(result.get("group"));
        if (group == null || !group.isObject() || !group.path("version").asText().equals("agent-group-result/v1")
                || runId == null || runId.isEmpty() || !group.path("parent_run_id").asText().equals(runId) || !group.path("operation_key").asText().equals(operationKey)
                || !group.path("instruction_trust").asText().equals("untrusted_data") || !group.path("terminal").isBoolean() || !group.path("outputs_complete").isBoolean()
                || !group.path("children").isArray() || group.path("children").size() != frozen.size()) throw new Failure("AGENT_GROUP_REJECTED", 502, false);
        for (String key : List.of("completed", "failed", "cancelled", "pending", "outputs_omitted")) {
            JsonNode count = group.path(key);
            if (!count.isIntegralNumber() || !count.canConvertToInt() || count.asInt() < 0 || count.asInt() > frozen.size()) throw new Failure("AGENT_GROUP_REJECTED", 502, false);
        }
        try { if (JSON.writeValueAsBytes(result).length > 524288) throw new Failure("AGENT_GROUP_REJECTED", 502, false); }
        catch (Failure known) { throw known; }
        catch (Exception invalid) { throw new Failure("AGENT_GROUP_REJECTED", 502, false); }
        int completed = 0, failed = 0, cancelled = 0, pending = 0, omitted = 0;
        boolean uncertain = false;
        for (int ordinal = 0; ordinal < frozen.size(); ordinal++) {
            JsonNode child = group.path("children").get(ordinal);
            AgentChildBinding binding = frozen.get(ordinal);
            try { validateAgentChildResult(Map.of("child", child), runId, operationKey, ordinal, binding.childKey(), binding.outputSchema()); }
            catch (Failure invalid) { throw new Failure("AGENT_GROUP_REJECTED", 502, false); }
            String state = child.path("status").asText();
            switch (state) { case "completed" -> completed++; case "failed" -> failed++; case "cancelled" -> cancelled++; default -> pending++; }
            uncertain |= state.equals("uncertain");
            if (child.path("output_omitted").asBoolean()) omitted++;
        }
        boolean terminal = pending == 0;
        String state = uncertain ? "uncertain" : !terminal ? "in_progress" : failed > 0 ? "failed" : cancelled > 0 ? "cancelled" : "completed";
        boolean complete = terminal && completed == frozen.size() && omitted == 0;
        if (!group.path("status").asText().equals(state) || group.path("terminal").asBoolean() != terminal || group.path("outputs_complete").asBoolean() != complete
                || group.path("completed").asInt() != completed || group.path("failed").asInt() != failed || group.path("cancelled").asInt() != cancelled
                || group.path("pending").asInt() != pending || group.path("outputs_omitted").asInt() != omitted) throw new Failure("AGENT_GROUP_REJECTED", 502, false);
        if (resumingGroup) {
            if (!terminal || !complete || !"completed".equals(state))
                throw new Failure("AGENT_GROUP_RESUME_REJECTED", 409, false);
            agentGroupResumeConsumed = true;
        }
        return result;
    }

    String currentRunId() throws Failure { synchronized(lock){Object run=context.get("task_id");if(!(run instanceof String value)||value.isBlank())throw new Failure("CONTEXT_INVALID",409,false);return value;} }

    /** Persistent public Harness, including explicit human-approval pause/resume. */
    public Map<String, Object> runHarness(Map<String, Object> input, HarnessRunner.Options options) throws Failure {
        String runId;
        synchronized (lock) { runId = (String) context.get("task_id"); }
        HarnessRunner.Port port = new HarnessRunner.Port() {
            @Override public Map<String, Object> post(String path, Map<String, Object> body) throws Failure {
                return CapabilityClient.this.post(path, body);
            }
            @Override public Map<String, Object> postWithin(String path, Map<String, Object> body, Duration timeout) throws Failure {
                return CapabilityClient.this.postWithin(path, body, timeout);
            }
            @Override public Map<String, Object> readHarnessPolicy() throws Failure {
                return CapabilityClient.this.readHarnessPolicy();
            }
        };
        // A verified group continuation resumes its Gather, then starts the
        // remaining workflow. It is not a tool-approval Harness continuation.
        boolean harnessResume = "resume".equals(operation)
                && !(agentGroupResumeBinding != null && agentGroupResumeConsumed);
        return HarnessRunner.run(port, runId, input, options, harnessResume, runtimeRecoveryBinding);
    }

    /** Prepare an approved prompt/context without invoking a model. */
    public Map<String, Object> prepareContext(List<Map<String, Object>> messages, List<String> functionNames) throws Failure {
        return post("/internal/context/prepare", Map.of("messages", messages, "function_names", functionNames == null ? List.of() : functionNames));
    }

    /** Load summary or one section; no lifecycle administration or grants. */
    public Map<String, Object> loadSkill(String skillId, String section) throws Failure {
        if (skillId == null || skillId.isEmpty() || skillId.getBytes(StandardCharsets.UTF_8).length > 128 || section == null || section.getBytes(StandardCharsets.UTF_8).length > 128) throw new Failure("REQUEST_INVALID", 400, false);
        return post("/internal/skill/load", Map.of("skill_id", skillId, "section", section));
    }

    /** Read current (revision=0) or immutable historical run-scoped state. */
    public Map<String, Object> loadCheckpoint(String namespace, String key, String schemaId, long revision) throws Failure {
        if (revision < 0 || revision > checkpointCapacity.limit(checkpointScope())) throw new Failure("REQUEST_INVALID", 400, false);
        return checkpointCapacity.remember(checkpointScope(), post("/internal/state/checkpoint", Map.of("operation", "load", "namespace", namespace, "key", key, "schema_id", schemaId, "revision", revision)));
    }

    /**
     * Read one checkpoint through its frozen recovery reference. The platform validates the reference
     * shape, expiry, and current head; this read alone does not authorize resuming or executing work.
     */
    public Map<String, Object> loadRecoveryCheckpoint(Map<String, Object> reference) throws Failure {
        Set<String> fields = Set.of("state_key", "revision", "schema_id", "content_hash", "execution_revision", "expires_at");
        if (reference == null || !reference.keySet().equals(fields)) throw new Failure("REQUEST_INVALID", 400, false);
        for (String field : fields) if (reference.get(field) == null) throw new Failure("REQUEST_INVALID", 400, false);
        try {
            validateJsonValue(reference, new IdentityHashMap<>(), 0);
            byte[] encoded = JSON.writeValueAsBytes(reference);
            if (encoded.length > 4096) throw new Failure("REQUEST_INVALID", 400, false);
            Map<String, Object> snapshot = JSON.readValue(encoded,
                    JSON.getTypeFactory().constructMapType(Map.class, String.class, Object.class));
            if (!snapshot.keySet().equals(fields) || snapshot.values().stream().anyMatch(value -> value == null))
                throw new Failure("REQUEST_INVALID", 400, false);
            return checkpointCapacity.remember(checkpointScope(), post("/internal/state/checkpoint", Map.of("operation", "load", "reference", snapshot)));
        } catch (Failure failure) {
            throw failure;
        } catch (Exception ignored) {
            throw new Failure("REQUEST_INVALID", 400, false);
        }
    }

    private static void validateJsonValue(Object value, IdentityHashMap<Object, Boolean> ancestors, int depth) {
        if (value == null || depth > 64) throw new IllegalArgumentException("invalid checkpoint reference value");
        if (value instanceof String || value instanceof Boolean || value instanceof Byte || value instanceof Short
                || value instanceof Integer || value instanceof Long || value instanceof BigInteger || value instanceof BigDecimal) return;
        if (value instanceof Float number) {
            if (!Float.isFinite(number)) throw new IllegalArgumentException("non-finite checkpoint reference number");
            return;
        }
        if (value instanceof Double number) {
            if (!Double.isFinite(number)) throw new IllegalArgumentException("non-finite checkpoint reference number");
            return;
        }
        if (ancestors.put(value, Boolean.TRUE) != null) throw new IllegalArgumentException("cyclic checkpoint reference value");
        try {
            if (value instanceof Map<?, ?> map) {
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (!(entry.getKey() instanceof String)) throw new IllegalArgumentException("non-string checkpoint reference key");
                    validateJsonValue(entry.getValue(), ancestors, depth + 1);
                }
                return;
            }
            if (value instanceof List<?> list) {
                for (Object item : list) validateJsonValue(item, ancestors, depth + 1);
                return;
            }
            if (value.getClass().isArray()) {
                int length = Array.getLength(value);
                for (int index = 0; index < length; index++) validateJsonValue(Array.get(value, index), ancestors, depth + 1);
                return;
            }
            throw new IllegalArgumentException("unsupported checkpoint reference value");
        } finally {
            ancestors.remove(value);
        }
    }

    /** CAS checkpoint write; never silently retries a changed revision. */
    public Map<String, Object> saveCheckpoint(String namespace, String key, String schemaId, Map<String, Object> value, long expectedRevision, String idempotencyKey) throws Failure {
        if (expectedRevision < 0 || expectedRevision >= checkpointCapacity.limit(checkpointScope()) || value == null || idempotencyKey == null || idempotencyKey.isEmpty()) throw new Failure("REQUEST_INVALID", 400, false);
        return checkpointCapacity.remember(checkpointScope(), post("/internal/state/checkpoint", Map.of("operation", "save", "namespace", namespace, "key", key, "schema_id", schemaId, "value", value, "expected_revision", expectedRevision, "idempotency_key", idempotencyKey)));
    }

    private byte[] encode(Map<String, Object> input) throws Failure {
        try { return JSON.writeValueAsBytes(Map.of("context", context, "input", input)); }
        catch (Exception ignored) { throw new Failure("REQUEST_INVALID", 400, false); }
    }

    /** Native function calling through the governed model and tool gateways.
     * A model suggestion never confirms a sensitive tool on behalf of a user.
     */
    public Map<String, Object> generateWithFunctions(Map<String, Object> input, int maxRounds) throws Failure {
        if (maxRounds < 1 || maxRounds > 8) throw new Failure("FUNCTION_ROUND_LIMIT", 400, false);
        JsonNode serialized = JSON.valueToTree(input);
        if (!serialized.path("messages").isArray() || serialized.path("messages").isEmpty() || !serialized.path("idempotency_key").isTextual() || serialized.path("idempotency_key").asText().isEmpty()) throw new Failure("REQUEST_INVALID", 400, false);
        Map<String, Object> current = JSON.convertValue(serialized, JSON.getTypeFactory().constructMapType(Map.class, String.class, Object.class));
        List<Object> messages = new ArrayList<>(); serialized.path("messages").forEach(message -> messages.add(JSON.convertValue(message, Object.class)));
        String key = serialized.path("idempotency_key").asText();
        for (int round = 0; round < maxRounds; round++) {
            if (Thread.currentThread().isInterrupted()) throw new Failure("CANCELLED", 409, false);
            current.put("messages", messages); current.put("idempotency_key", functionStepKey(key, round, "model"));
            Map<String, Object> result = post("/internal/model/generate", current);
            if ("incomplete".equals(result.get("completion_status"))) return result;
            JsonNode response = JSON.valueToTree(result), calls = response.path("tool_calls");
            if (calls.isMissingNode() && !"tool_calls".equals(result.get("completion_status"))) return result;
            if (!calls.isArray() || calls.isEmpty() || calls.size() > 32) throw new Failure("FUNCTION_RESPONSE_INVALID", 502, false);
            if (round == maxRounds - 1) throw new Failure("FUNCTION_ROUND_LIMIT", 409, false);
            JsonNode bindings = response.path("function_bindings");
            if (!bindings.isObject()) throw new Failure("FUNCTION_RESPONSE_INVALID", 502, false);
            messages.add(Map.of("role", "assistant", "content", response.path("text").asText(), "tool_calls", JSON.convertValue(calls, Object.class)));
            for (JsonNode call : calls) {
                JsonNode function = call.path("function"); String name = function.path("name").asText(), id = call.path("id").asText();
                JsonNode tool = bindings.path(name), arguments;
                try { arguments = JSON.readTree(function.path("arguments").asText()); }
                catch (Exception ignored) { throw new Failure("FUNCTION_RESPONSE_INVALID", 502, false); }
                if (!tool.isTextual() || tool.asText().isBlank() || id.isBlank() || arguments == null || !arguments.isObject()) throw new Failure("FUNCTION_RESPONSE_INVALID", 502, false);
                Map<String, Object> receipt = post("/internal/tool/invoke", Map.of("name", tool.asText(), "call_id", functionStepKey(key, round, id), "payload", JSON.convertValue(arguments, Object.class), "confirmed", false));
                String content;
                try {
                    JsonNode observation = JSON.valueToTree(receipt.get("observation"));
                    if (receipt.containsKey("observation")) {
                        if (observation == null || !observation.isObject() || !observation.path("version").asText().equals("runtime-observation/v1") || !observation.path("tool_name").asText().equals(tool.asText()) || !observation.path("call_id").asText().equals(functionStepKey(key, round, id)) || !Set.of("succeeded", "failed", "timeout", "cancelled").contains(observation.path("status").asText()) || !observation.path("effect").asText().equals("completed") || !observation.path("instruction_trust").asText().equals("untrusted_data") || !observation.has("context_output") || JSON.writeValueAsBytes(observation.get("context_output")).length > 2048) throw new Failure("TOOL_OBSERVATION_REJECTED", 502, false);
                        content = JSON.writeValueAsString(Map.of("version", "runtime-observation/v1", "tool_name", tool.asText(), "status", observation.path("status").asText(), "error_type", observation.path("error_type").asText(), "effect", "completed", "instruction_trust", "untrusted_data", "context_truncated", observation.path("context_truncated").asBoolean(), "output_truncated", observation.path("truncated").asBoolean(), "context_output", JSON.convertValue(observation.get("context_output"), Object.class)));
                    } else { content = JSON.writeValueAsString(receipt); }
                }
                catch (Failure error) { throw error; }
                catch (Exception ignored) { throw new Failure("FUNCTION_RESPONSE_INVALID", 502, false); }
                messages.add(Map.of("role", "tool", "tool_call_id", id, "content", content));
            }
        }
        throw new Failure("FUNCTION_ROUND_LIMIT", 409, false);
    }

    private String functionStepKey(String key, int round, String phase) throws Failure {
        try { return "function-" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(JSON.writeValueAsBytes(List.of(key, round, phase)))); }
        catch (Exception ignored) { throw new Failure("REQUEST_INVALID", 400, false); }
    }

    private JsonNode claims(String token) throws Failure {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) throw new IllegalArgumentException();
            JsonNode node = JSON.readTree(Base64.getUrlDecoder().decode(parts[1]));
            if (node == null || !node.isObject()) throw new IllegalArgumentException();
            return node;
        } catch (Exception ignored) { throw new Failure("CAPABILITY_RENEWAL_DENIED", 403, false); }
    }

    // Replayed output is still protected data; re-check authority without a business call.
    synchronized void authorizeReplay() throws Failure { validateCurrentExecution(); }

    /** Recheck current platform authority even with an unexpired signed token. */
    public synchronized void validateCurrentExecution() throws Failure { renew(true); }

    long nowEpochSeconds() { return config.now().getAsLong(); }

    private void renew() throws Failure {
        renew(false, Duration.ofSeconds(10));
    }

    private void renew(boolean force) throws Failure {
        renew(force, Duration.ofSeconds(10));
    }

    private void renew(boolean force, Duration timeout) throws Failure {
        String token = (String) context.get("platform_context_token");
        JsonNode old = claims(token);
        if (!old.path("exp").isIntegralNumber() || old.path("execution_revision").asLong() <= 0) throw new Failure("CAPABILITY_RENEWAL_DENIED", 403, false);
        if (!force && old.path("exp").asLong() > config.now().getAsLong() + 15) return;
        Map<String, Object> response = send("/internal/context/renew", encode(Map.of()), token, 32768, timeout);
        if (!(response.get("context_token") instanceof String fresh)) throw new Failure("CAPABILITY_RENEWAL_UNAVAILABLE", 503, true);
        JsonNode next = claims(fresh);
        for (String field : BINDINGS) if (!old.path(field).equals(next.path(field))) throw new Failure("CAPABILITY_RENEWAL_DENIED", 403, false);
        if (!next.path("exp").isIntegralNumber() || next.path("exp").asLong() <= config.now().getAsLong() + 15) throw new Failure("CAPABILITY_RENEWAL_DENIED", 403, false);
        context.put("platform_context_token", fresh);
    }

    private Map<String, Object> send(String path, byte[] body, String token, int limit, int seconds) throws Failure {
        return send(path, body, token, limit, Duration.ofSeconds(seconds));
    }

    private Map<String, Object> send(String path, byte[] body, String token, int limit, Duration timeout) throws Failure {
        try {
            URI target = URI.create(config.baseUrl() + path);
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
            byte[] proof = JSON.writeValueAsBytes(List.of("platform-capability/v2", "POST", target.getRawPath(), digest));
            Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(config.signingSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            HttpRequest.Builder builder = HttpRequest.newBuilder(target).timeout(timeout)
                .header("Content-Type", "application/json").header("X-Internal-Token", config.internalToken())
                .header("X-Platform-Context", "Bearer " + token).header("X-Context-Signature", "sha256=" + HexFormat.of().formatHex(mac.doFinal(proof)))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
            if (!config.workloadClientId().isEmpty()) builder.header("X-Agent-Client-ID", config.workloadClientId()).header("X-Agent-Client-Secret", config.workloadClientSecret());
            HttpRequest request = builder.build();
            HttpResponse<byte[]> response;
            SendLimiter limiter=sendLimiter;AutoCloseable permit=null;long sendStarted=System.nanoTime();String sendStatus="failed";
            try{if(limiter!=null){permit=limiter.acquire(timeout);if(permit==null)throw new Failure("CAPABILITY_LIMITER_INVALID",409,false);}response=http.send(request,ignored->new BoundedBody(limit));sendStatus=response.statusCode()<400?"succeeded":"failed";}
            finally{if(permit!=null)permit.close();var observer=callObserver;if(observer!=null)try{observer.accept(new CallObservation(path,(System.nanoTime()-sendStarted)/1_000_000.0,sendStatus));}catch(RuntimeException ignored){}}

            if ((response.statusCode() == 401 || response.statusCode() == 403) && path.equals("/internal/context/renew")) throw new Failure("CAPABILITY_RENEWAL_DENIED", 403, false);
            JsonNode envelope;
            try { envelope = JSON.readTree(response.body()); } catch (Exception ignored) { envelope = null; }
            if (response.statusCode() >= 400 && !path.equals("/internal/context/renew")) {
                String code = envelope == null ? "" : envelope.path("error_code").asText();
                if (envelope != null && envelope.path("data").path("observation").path("version").asText().equals("runtime-observation/v1") && envelope.path("data").path("observation").path("effect").asText().equals("unknown")) throw new Failure("TOOL_RESULT_UNKNOWN", response.statusCode(), false);
                if (code.matches("[A-Z0-9_]{1,64}")) throw new Failure(code, response.statusCode(), response.statusCode() >= 500,
                    childStopControlErrorDetails(code, response.statusCode(), envelope));
                if (response.statusCode() == 401 || response.statusCode() == 403) throw new Failure("CAPABILITY_DENIED", 403, false);
            }
            if (response.statusCode() != 200 || envelope == null || !envelope.path("data").isObject()) throw new Failure("CAPABILITY_RENEWAL_UNAVAILABLE", 503, true);
            return JSON.convertValue(envelope.get("data"), JSON.getTypeFactory().constructMapType(Map.class, String.class, Object.class));
        } catch (Failure error) { throw error;
        } catch (InterruptedException error) { Thread.currentThread().interrupt(); throw new Failure("CANCELLED", 409, false);
        } catch (java.io.IOException lost) { throw new ObservationLost();
        } catch (Exception ignored) { throw new Failure("CAPABILITY_RENEWAL_UNAVAILABLE", 503, true); }
    }

    // Preserve only the precise stop-CAS hint. No arbitrary platform error
    // data crosses the SDK boundary, even for a conflict response.
    private static Map<String, Object> childStopControlErrorDetails(String code, int status, JsonNode envelope) {
        if (!code.equals("AGENT_STOP_REVISION_CONFLICT") || status != 409 || envelope == null) return Map.of();
        JsonNode data = envelope.get("data");
        if (data == null || !data.isObject() || data.size() != 1 || !data.has("stop_control")) return Map.of();
        JsonNode control = data.get("stop_control");
        if (control == null || !control.isObject() || control.size() != 3
                || !control.has("version") || !control.has("status") || !control.has("execution_revision")) return Map.of();
        JsonNode version = control.get("version"), childStatus = control.get("status"), revision = control.get("execution_revision");
        if (!version.isTextual() || !version.asText().equals("agent-child-stop-control-conflict/v1")
                || !childStatus.isTextual() || !List.of("accepted", "running", "waiting").contains(childStatus.asText())
                || !revision.isIntegralNumber() || !revision.canConvertToLong() || revision.longValue() < 1) return Map.of();
        return Map.of("stop_control", Map.of("version", version.asText(), "status", childStatus.asText(), "execution_revision", revision.longValue()));
    }

    /** Reject excess bytes before buffering; do not use an unbounded body handler.
     * 缓冲前限制响应大小，超限取消订阅，避免先读完整响应才检查。
     */
    private static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final int limit;
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private Flow.Subscription subscription;
        BoundedBody(int limit) { this.limit = limit; }
        public CompletionStage<byte[]> getBody() { return result; }
        public void onSubscribe(Flow.Subscription value) { subscription = value; value.request(Long.MAX_VALUE); }
        public void onNext(List<ByteBuffer> items) {
            for (ByteBuffer item : items) {
                if (item.remaining() > limit - bytes.size()) { subscription.cancel(); result.completeExceptionally(new IllegalStateException("response limit exceeded")); return; }
                byte[] chunk = new byte[item.remaining()]; item.get(chunk); bytes.writeBytes(chunk);
            }
        }
        public void onError(Throwable error) { result.completeExceptionally(error); }
        public void onComplete() { result.complete(bytes.toByteArray()); }
    }
    /** Public conveniences retain this exact authenticated Run binding. */
    public synchronized PublicCapabilities capabilities() {
        Object value = context.get("task_id");
        if (!(value instanceof String text) || text.isEmpty()) value = context.get("session_id");
        if (!(value instanceof String text) || text.isEmpty()) value = context.get("request_id");
        return new PublicCapabilities(this, value instanceof String text ? text : "");
    }

    private synchronized String checkpointScope() throws Failure {
        Map<String, Object> scope = new LinkedHashMap<>(context);
        scope.remove("platform_context_token"); scope.remove("trace_id");
        return PublicCapabilities.digest(scope);
    }

}
