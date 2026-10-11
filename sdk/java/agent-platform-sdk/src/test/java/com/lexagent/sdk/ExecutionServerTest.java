package com.lexagent.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.lexagent.sdk.ExecutionContract.EventRequest;
import com.lexagent.sdk.ExecutionContract.ExecuteRequest;
import com.lexagent.sdk.ExecutionContract.ScopeKey;
import com.lexagent.sdk.ServerConfig.ServerConfigError;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** ExecutionServer black-box tests over real HTTP: the fail-closed ladder, the
 * full lifecycle legs, SSE replay and cooperative cancellation.
 * ExecutionServer 真实 HTTP 黑盒测试：失败闭合阶梯、完整生命周期腿、SSE 重放与
 * 协作式取消。
 */
final class ExecutionServerTest {
    private static final ObjectMapper JSON = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .findAndRegisterModules();

    private final Minter minter = new Minter();
    private final MemoryRunStore store = new MemoryRunStore();
    private final AtomicBoolean released = new AtomicBoolean(false);
    private final AtomicInteger runHandlerCalls = new AtomicInteger();
    private final AtomicInteger invokeHandlerCalls = new AtomicInteger();
    private final AtomicInteger currentAuthorizationRequests = new AtomicInteger();
    private final AtomicReference<String> platformFixtureFailure = new AtomicReference<>();
    private com.sun.net.httpserver.HttpServer httpd;
    private com.sun.net.httpserver.HttpServer platformHttpd;
    private ExecutionServer executionServer;

    @AfterEach
    void tearDown() {
        if (httpd != null) {
            httpd.stop(0);
        }
        if (platformHttpd != null) platformHttpd.stop(0);
        if (executionServer != null) executionServer.stop();
    }

    // -- kit ------------------------------------------------------------

    /** Mints gateway-shaped capabilities exactly like the platform gateway: the
     * body hash covers the wire envelope minus the bearer token itself.
     * 完全按平台网关的方式签发执行能力令牌：正文哈希覆盖除令牌外的线上信封。
     */
    private static final class Minter {
        final KeyPair pair = keyPair();
        final String issuer = "platform-runtime-gateway";
        final String audience = "conformance-agent";

        private static KeyPair keyPair() {
            try {
                return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            } catch (Exception exception) {
                throw new IllegalStateException(exception);
            }
        }

        String executeToken(ExecuteRequest request, List<String> actions) throws Exception {
            return executeToken(request, actions, 1, "b".repeat(64));
        }

        String executeToken(ExecuteRequest request, List<String> actions, long executionRevision,
                String leaseTokenHash) throws Exception {
            Map<String, Object> policy = request.input() instanceof Map<?, ?> map
                    && map.get("policy_snapshot") instanceof Map<?, ?> snapshot ? cast(snapshot) : Map.of();
            return sign(claims(ContextVerifier.canonicalBodyHash(request),
                    String.valueOf(policy.getOrDefault("content_hash", "")), actions, request.scope(), executionRevision, leaseTokenHash));
        }

        String eventToken(EventRequest request) throws Exception {
            return sign(claims(ContextVerifier.canonicalEventHash(request), request.policySnapshotHash(),
                    List.of("events"), request.scope(), 1, "b".repeat(64)));
        }

        private Map<String, Object> claims(String bodyHash, String snapshotHash, List<String> actions,
                ScopeKey scope, long executionRevision, String leaseTokenHash) {
            long now = java.time.Instant.now().getEpochSecond();
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("iss", issuer);
            claims.put("aud", audience);
            claims.put("subject_type", "user");
            claims.put("sub", "user-a");
            claims.put("tenant_id", "tenant-a");
            claims.put("department_id", "business-department");
            claims.put("application_id", "business-app");
            claims.put("agent_instance_id", "instance-a");
            claims.put("installation_id", "installation-a");
            claims.put("agent_id", "conformance-agent");
            claims.put("agent_version_id", "v2");
            claims.put("run_id", scope.runId());
            claims.put("session_id", scope.sessionId());
            claims.put("trace_id", scope.traceId());
            claims.put("authorization_epoch", 1);
            claims.put("actions", actions);
            claims.put("policy_snapshot_hash", snapshotHash);
            claims.put("body_hash", bodyHash);
            claims.put("execution_revision", executionRevision);
            claims.put("lease_token_hash", leaseTokenHash);
            claims.put("iat", now);
            claims.put("exp", now + 120);
            return claims;
        }

        private String sign(Map<String, Object> claims) throws Exception {
            Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
            String header = encoder.encodeToString(JSON.writeValueAsBytes(Map.of("alg", "EdDSA", "typ", "JWT")));
            String payload = encoder.encodeToString(JSON.writeValueAsBytes(claims));
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(pair.getPrivate());
            signature.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
            return header + "." + payload + "." + encoder.encodeToString(signature.sign());
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> verifiedClaims(String token) throws Exception {
            String[] parts = token.split("\\.");
            if (parts.length != 3) throw new SecurityException("invalid token shape");
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(pair.getPublic());
            verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!verifier.verify(Base64.getUrlDecoder().decode(parts[2]))) throw new SecurityException("invalid token signature");
            return JSON.readValue(Base64.getUrlDecoder().decode(parts[1]), Map.class);
        }

        String renewedToken(Map<String, Object> original, long now) throws Exception {
            var claims = new LinkedHashMap<>(original);
            claims.put("exp", now + 120);
            return sign(claims);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> cast(Map<?, ?> value) {
        return (Map<String, Object>) value;
    }

    private static ScopeKey scope(String runId) {
        return new ScopeKey("tenant-a", "business-department", "business-app", "instance-a", "installation-a", "conformance-agent",
                "v2", "user", "user-a", "session-a", runId, 1, "0".repeat(32), "", 0);
    }

    private ExecuteRequest envelope(String operation, String runId, String idempotency) {
        return new ExecuteRequest(ExecutionContract.PROTOCOL_VERSION, "x".repeat(32), scope(runId),
                operation, idempotency, "schema://example/input/v1",
                Map.of("policy_snapshot", Map.of("content_hash", "a".repeat(64),
                        "model_profile_id", "model-v1", "prompt_version_id", "prompt-v1",
                        "tool_policy_id", "tool-v1", "memory_policy_id", "memory-v1",
                        "knowledge_policy_id", "knowledge-v1", "runtime_policy_id", "runtime-v1")),
                "resume".equals(operation) ? Map.of("decision", "approve") : null);
    }

    private EventRequest eventEnvelope(String runId, long afterSeq) {
        return new EventRequest(ExecutionContract.PROTOCOL_VERSION, "x".repeat(32), scope(runId),
                afterSeq, "a".repeat(64));
    }

    private void serve() throws Exception {
        serve(null, false);
    }

    private void serveWithCurrentAuthorization(boolean deny, boolean pauseFirst) throws Exception {
        platformHttpd = com.sun.net.httpserver.HttpServer.create(
                new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        platformHttpd.createContext("/internal/context/renew", exchange -> handleRenewalFixture(exchange, deny));
        platformHttpd.start();
        CapabilityClient.Config capability = new CapabilityClient.Config(
                "http://127.0.0.1:" + platformHttpd.getAddress().getPort(),
                "fixture-internal-token", "fixture-signing-secret",
                () -> java.time.Instant.now().getEpochSecond());
        serve(capability, pauseFirst);
    }

    private void serve(CapabilityClient.Config capability, boolean pauseFirst) throws Exception {
        serve(capability, pauseFirst, null);
    }

    private void serve(CapabilityClient.Config capability, boolean pauseFirst, Tracing.Tracer tracer) throws Exception {
        ExecutionServer server = new ExecutionServer(ServerConfig.builder()
                .publicKey(minter.pair.getPublic())
                .issuer(minter.issuer)
                .audience(minter.audience)
                .agentId("conformance-agent")
                .store(store)
                .capability(capability)
                .capabilities(List.of("invoke", "run", "resume", "cancel", "events"))
                .tracer(tracer)
                .invoke((request, capabilities) -> {
                    invokeHandlerCalls.incrementAndGet();
                    return Map.of("echo", request.input());
                })
                .run((request, events, signals, capabilities) -> {
                    int call = runHandlerCalls.incrementAndGet();
                    events.append(Lifecycle.EVENT_PROGRESS, Map.of("stage", "business"));
                    if (pauseFirst && call == 1) {
                        throw HarnessPause.from(Map.of("status", "approval_required",
                                "pending", Map.of("name", "runtime.inspect", "call_id", "approval-call")),
                                "harness-key");
                    }
                    // Park until cancel or release so cooperative cancellation
                    // is real. / 挂起直到取消或放行，让协作式取消真实生效。
                    while (!signals.isCancelled() && !released.get()) {
                        Thread.sleep(10);
                    }
                    if (signals.isCancelled()) {
                        throw new IllegalStateException("run was cancelled");
                    }
                    return Map.of("echo", request.input());
                })
                .build());
        executionServer = server;
        httpd = server.start(new java.net.InetSocketAddress("127.0.0.1", 0));
    }

    private void handleRenewalFixture(com.sun.net.httpserver.HttpExchange exchange, boolean deny) throws java.io.IOException {
        currentAuthorizationRequests.incrementAndGet();
        try {
            byte[] body = exchange.getRequestBody().readNBytes(32769);
            if (!"POST".equals(exchange.getRequestMethod())
                    || !"/internal/context/renew".equals(exchange.getRequestURI().getRawPath())
                    || body.length > 32768
                    || !"fixture-internal-token".equals(exchange.getRequestHeaders().getFirst("X-Internal-Token"))) {
                throw new IllegalArgumentException("request envelope");
            }
            String bearer = exchange.getRequestHeaders().getFirst("X-Platform-Context");
            if (bearer == null || !bearer.startsWith("Bearer ")) throw new IllegalArgumentException("context bearer");
            String token = bearer.substring("Bearer ".length());
            String signature = exchange.getRequestHeaders().getFirst("X-Context-Signature");
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
            byte[] proof = JSON.writeValueAsBytes(List.of("platform-capability/v2", "POST",
                    "/internal/context/renew", digest));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec("fixture-signing-secret".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            String expectedSignature = "sha256=" + HexFormat.of().formatHex(mac.doFinal(proof));
            if (signature == null || !MessageDigest.isEqual(expectedSignature.getBytes(StandardCharsets.US_ASCII),
                    signature.getBytes(StandardCharsets.US_ASCII))) throw new IllegalArgumentException("request signature");

            Map<?, ?> request = JSON.readValue(body, Map.class);
            if (!request.keySet().equals(java.util.Set.of("context", "input"))
                    || !(request.get("context") instanceof Map<?, ?> context)
                    || !(request.get("input") instanceof Map<?, ?> input) || !input.isEmpty()) {
                throw new IllegalArgumentException("request binding shape");
            }
            Map<String, Object> claims = minter.verifiedClaims(token);
            if (!"platform-runtime-gateway".equals(claims.get("iss"))
                    || !"conformance-agent".equals(claims.get("aud"))
                    || !"user".equals(claims.get("subject_type"))
                    || !"user-a".equals(claims.get("sub"))
                    || !"tenant-a".equals(claims.get("tenant_id"))
                    || !"business-department".equals(claims.get("department_id"))
                    || !"business-app".equals(claims.get("application_id"))
                    || !"instance-a".equals(claims.get("agent_instance_id"))
                    || !"installation-a".equals(claims.get("installation_id"))
                    || !"conformance-agent".equals(claims.get("agent_id"))
                    || !"v2".equals(claims.get("agent_version_id"))
                    || !(claims.get("actions") instanceof List<?> actions) || !actions.contains("resume")
                    || !"a".repeat(64).equals(claims.get("policy_snapshot_hash"))
                    || !(claims.get("body_hash") instanceof String bodyHash) || !bodyHash.matches("[a-f0-9]{64}")
                    || !(claims.get("execution_revision") instanceof Number revision) || revision.longValue() < 1
                    || !(claims.get("lease_token_hash") instanceof String leaseHash) || !leaseHash.matches("[a-f0-9]{64}")
                    || !claims.get("run_id").equals(context.get("task_id"))
                    || !claims.get("session_id").equals(context.get("session_id"))
                    || !claims.get("trace_id").equals(context.get("trace_id"))
                    || !claims.get("tenant_id").equals(context.get("tenant_id"))
                    || !claims.get("department_id").equals(context.get("department_id"))
                    || !claims.get("application_id").equals(context.get("application_id"))
                    || !claims.get("agent_instance_id").equals(context.get("agent_instance_id"))
                    || !claims.get("installation_id").equals(context.get("installation_id"))
                    || !claims.get("agent_id").equals(context.get("agent_id"))
                    || !claims.get("agent_version_id").equals(context.get("agent_version_id"))
                    || !claims.get("subject_type").equals(context.get("principal_type"))
                    || !claims.get("sub").equals(context.get("actor_id"))
                    || !claims.get("authorization_epoch").equals(context.get("authorization_epoch"))
                    || !token.equals(context.get("platform_context_token"))
                    || !"idem-run".equals(context.get("request_id"))
                    || !"idem-run".equals(context.get("idempotency_key"))
                    || !"model-v1".equals(context.get("model_profile_id"))
                    || !"prompt-v1".equals(context.get("prompt_version_id"))
                    || !"tool-v1".equals(context.get("tool_policy_id"))
                    || !"memory-v1".equals(context.get("memory_policy_id"))
                    || !"knowledge-v1".equals(context.get("knowledge_policy_id"))
                    || !"runtime-v1".equals(context.get("runtime_policy_id"))) {
                throw new IllegalArgumentException("current execution binding");
            }
            if (deny) {
                writeFixtureJson(exchange, 403, Map.of("error_code", "CAPABILITY_DENIED"));
            } else {
                String renewed = minter.renewedToken(claims, java.time.Instant.now().getEpochSecond());
                writeFixtureJson(exchange, 200, Map.of("data", Map.of("context_token", renewed)));
            }
        } catch (Exception rejected) {
            platformFixtureFailure.set(rejected.getClass().getSimpleName());
            writeFixtureJson(exchange, 400, Map.of("error_code", "INVALID_FIXTURE_REQUEST"));
        }
    }

    private static void writeFixtureJson(com.sun.net.httpserver.HttpExchange exchange, int status, Object value)
            throws java.io.IOException {
        byte[] bytes = JSON.writeValueAsBytes(value);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (var out = exchange.getResponseBody()) { out.write(bytes); }
    }

    private Response post(String path, Object payload, String token, String authorization) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base() + path))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(JSON.writeValueAsBytes(payload)));
        request.header("Authorization", authorization == null ? "Bearer " + token : authorization);
        HttpResponse<String> response = HttpClient.newHttpClient().send(request.build(),
                HttpResponse.BodyHandlers.ofString());
        return new Response(response.statusCode(), response.body());
    }

    private String base() {
        return "http://127.0.0.1:" + httpd.getAddress().getPort();
    }

    private Response invoke(String runId, List<String> actions, String idempotency) throws Exception {
        return invoke(envelope("invoke", runId, idempotency), actions);
    }

    private Response invoke(ExecuteRequest request, List<String> actions) throws Exception {
        String token = minter.executeToken(request, actions);
        ExecuteRequest signed = new ExecuteRequest(request.protocolVersion(), token, request.scope(),
                request.operation(), request.idempotencyKey(), request.inputSchema(), request.input());
        return post(ExecutionServer.INVOKE_PATH, signed, token, null);
    }

    private Response run(String runId, List<String> actions) throws Exception {
        return run(envelope("run", runId, "idem-run"), actions);
    }

    private Response run(ExecuteRequest request, List<String> actions) throws Exception {
        String token = minter.executeToken(request, actions);
        ExecuteRequest signed = new ExecuteRequest(request.protocolVersion(), token, request.scope(),
                request.operation(), request.idempotencyKey(), request.inputSchema(), request.input());
        return post(ExecutionServer.RUNS_PATH, signed, token, null);
    }

    private Response lifecycle(String runId, String action, List<String> actions) throws Exception {
        return lifecycle(runId, action, actions, "idem-" + action, 1, "b".repeat(64));
    }

    private Response lifecycle(String runId, String action, List<String> actions, String idempotency,
            long executionRevision, String leaseTokenHash) throws Exception {
        ExecuteRequest request = envelope(action, runId, "idem-" + action);
        request = new ExecuteRequest(request.protocolVersion(), request.contextToken(), request.scope(),
                request.operation(), idempotency, request.inputSchema(), request.input(), request.resumeInput());
        String token = minter.executeToken(request, actions, executionRevision, leaseTokenHash);
        ExecuteRequest signed = new ExecuteRequest(request.protocolVersion(), token, request.scope(),
                request.operation(), request.idempotencyKey(), request.inputSchema(), request.input(), request.resumeInput());
        return post(ExecutionServer.RUNS_PATH + "/" + runId + "/" + action, signed, token, null);
    }

    private Response events(String runId) throws Exception {
        EventRequest request = eventEnvelope(runId, 0);
        String token = minter.eventToken(request);
        EventRequest signed = new EventRequest(request.protocolVersion(), token, request.scope(),
                request.afterSeq(), request.policySnapshotHash());
        return post(ExecutionServer.RUNS_PATH + "/" + runId + "/events", signed, token, null);
    }

    private void waitForStatus(String runId, String status) throws Exception {
        for (int i = 0; i < 300; i++) {
            if (store.getRun(runId) != null && status.equals(store.getRun(runId).status())) {
                return;
            }
            Thread.sleep(10);
        }
        throw new AssertionError("run " + runId + " never reached " + status);
    }

    private record Response(int status, String body) {}

    // -- tests ----------------------------------------------------------

    @Test
    void runInitializationFailureIsSanitizedAndLeavesTerminalReplayReceipt() throws Exception {
        Tracing.Tracer tracer = (name, attributes) -> {
            if ("agentplatform.run.execute".equals(name))
                throw new IllegalStateException("sensitive-initialization-detail");
            return () -> {};
        };
        serve(null, false, tracer);

        assertEquals(202, run("run-init-failure", List.of("run")).status());
        waitForStatus("run-init-failure", Lifecycle.FAILED);
        var failed = store.getRun("run-init-failure");
        assertEquals("INTERNAL", failed.error().code());
        assertEquals("the agent failed to process the request", failed.error().message());
        assertEquals(0, runHandlerCalls.get());
        assertEquals(List.of(Lifecycle.EVENT_ACCEPTED, Lifecycle.EVENT_FAILED), failed.events().stream()
                .map(ExecutionContract.ExecutionEvent::eventType).toList());
        assertTrue(!JSON.writeValueAsString(failed).contains("sensitive-initialization-detail"));

        Response replay = run("run-init-failure", List.of("run"));
        assertEquals(200, replay.status());
        assertTrue(replay.body().contains("failed"));
        assertTrue(!replay.body().contains("sensitive-initialization-detail"));
    }

    @Test
    void invokeCapabilityInitializationFailureIsSanitizedAndTerminal() throws Exception {
        serveWithCurrentAuthorization(false, false);
        ExecuteRequest request = new ExecuteRequest(ExecutionContract.PROTOCOL_VERSION, "x".repeat(32),
                scope("invoke-init-failure"), "invoke", "idem-invoke-init-failure", "schema://example/input/v1",
                Map.of("policy_snapshot", Map.of("content_hash", "a".repeat(64))), null);

        Response response = invoke(request, List.of("invoke"));
        assertEquals(500, response.status());
        assertTrue(response.body().contains("INTERNAL"));
        assertTrue(!response.body().contains("six immutable policy references are required"));
        assertTrue(!response.body().contains("fixture-internal-token"));
        assertTrue(!response.body().contains("fixture-signing-secret"));
        assertEquals(0, invokeHandlerCalls.get());
        assertEquals(0, currentAuthorizationRequests.get());
        var failed = store.getRun("invoke-init-failure");
        assertEquals(Lifecycle.FAILED, failed.status());
        assertEquals("INTERNAL", failed.error().code());
        assertEquals(List.of(Lifecycle.EVENT_ACCEPTED, Lifecycle.EVENT_FAILED), failed.events().stream()
                .map(ExecutionContract.ExecutionEvent::eventType).toList());
    }

    @Test
    void configurationFailsClosed() {
        assertThrows(ServerConfigError.class, () -> ServerConfig.builder()
                .issuer("issuer").audience("aud").agentId("agent").store(new MemoryRunStore())
                .capabilities(List.of("invoke")).build());
        assertThrows(ServerConfigError.class, () -> ServerConfig.builder()
                .publicKey(minter.pair.getPublic()).audience("aud").agentId("agent")
                .store(new MemoryRunStore()).capabilities(List.of("invoke")).build());
        assertThrows(ServerConfigError.class, () -> ServerConfig.builder()
                .publicKey(minter.pair.getPublic()).issuer("issuer").audience("aud").agentId("agent")
                .store(new MemoryRunStore()).capabilities(List.of("run", "resume", "cancel", "events"))
                .invoke((request, capabilities) -> Map.of()).build());
    }

    @Test
    void unverifiedCallersNeverReachTheBusinessSeam() throws Exception {
        serve();
        Minter forged = new Minter();
        ExecuteRequest request = envelope("run", "run-401", "idem-key-0001");
        String token = forged.executeToken(request, List.of("run"));
        ExecuteRequest signed = new ExecuteRequest(request.protocolVersion(), token, request.scope(),
                request.operation(), request.idempotencyKey(), request.inputSchema(), request.input());
        // A different platform key must never pass. / 不同的平台密钥绝不放行。
        Response response = post(ExecutionServer.RUNS_PATH, signed, token, null);
        assertEquals(401, response.status());
        assertEquals("CAPABILITY_INVALID", JSON.readTree(response.body()).get("code").asText());
        // A stolen header cannot be paired with a different body.
        // 窃取的头部无法与别的正文配对。
        String ours = minter.executeToken(request, List.of("run"));
        ExecuteRequest stolen = new ExecuteRequest(request.protocolVersion(), ours, request.scope(),
                request.operation(), request.idempotencyKey(), request.inputSchema(), request.input());
        assertEquals(401, post(ExecutionServer.RUNS_PATH, stolen, ours, "Bearer forged").status());
        // The delegated actions must include the operation. / 被委派动作必须含该操作。
        assertEquals(401, run("run-401", List.of("invoke")).status());
        assertEquals(null, store.getRun("run-401"));
    }

    @Test
    void invokeServesTheBusinessOutput() throws Exception {
        serve();
        Response response = invoke("run-invoke", List.of("invoke"), "idem-invoke");
        assertEquals(200, response.status());
        JsonNode body = JSON.readTree(response.body());
        assertEquals("run-invoke", body.get("run_id").asText());
        assertEquals("succeeded", body.get("status").asText());
        assertTrue(body.get("output").get("echo").get("policy_snapshot").get("content_hash").asText()
                .startsWith("aaaa"));
    }

    @Test
    void servesTheFullLifecycleLegsWithSseReplay() throws Exception {
        serve();
        released.set(true);
        Response response = run("run-full", List.of("run", "resume", "cancel", "invoke"));
        assertEquals(202, response.status(), response.body());
        assertEquals("running", JSON.readTree(response.body()).get("status").asText());
        waitForStatus("run-full", Lifecycle.SUCCEEDED);
        Thread.sleep(25);

        Response events = events("run-full");
        assertEquals(200, events.status());
        List<String> types = new ArrayList<>();
        for (String block : events.body().split("\n\n")) {
            if (block.isBlank()) {
                continue;
            }
            String id = field(block, "id");
            String event = field(block, "event");
            String data = field(block, "data");
            JsonNode payload = JSON.readTree(data);
            // Every SSE frame is complete and self-describing. / SSE 帧完整且自描述。
            assertEquals(id, payload.get("seq").asText());
            assertEquals("run-full", payload.get("run_id").asText());
            types.add(event);
        }
        assertEquals(List.of("accepted", "started", "progress", "completed"), types);

        // A completed ordinary run cannot be resumed without a verified pause handoff.
        Response resume = lifecycle("run-full", "resume", List.of("resume", "run", "invoke"));
        assertEquals(503, resume.status()); // This server intentionally has no current-authorization client.
        assertEquals("CAPABILITY_CONFIG_INVALID", JSON.readTree(resume.body()).get("code").asText());
    }

    @Test
    void completedOrdinaryRunRejectsUnconfirmedResume() throws Exception {
        serveWithCurrentAuthorization(false, false);
        released.set(true);
        assertEquals(202, run("run-completed-no-pause", List.of("run", "resume")).status());
        waitForStatus("run-completed-no-pause", Lifecycle.SUCCEEDED);
        Thread.sleep(25);

        Response resume = lifecycle("run-completed-no-pause", "resume", List.of("resume", "run"),
                "idem-run", 2, "c".repeat(64));
        assertEquals(409, resume.status(), resume.body());
        assertEquals("RUN_RESUME_UNCONFIRMED", JSON.readTree(resume.body()).get("code").asText());
        assertEquals(Lifecycle.SUCCEEDED, store.getRun("run-completed-no-pause").status());
        assertEquals(1, runHandlerCalls.get());
        assertEquals(1, currentAuthorizationRequests.get());
        assertEquals(null, platformFixtureFailure.get());
    }

    @Test
    void controlledPauseResumesAndReplaysOnlyTheSameGeneration() throws Exception {
        serveWithCurrentAuthorization(false, true);
        assertEquals(202, run("run-controlled-pause", List.of("run", "resume")).status());
        waitForStatus("run-controlled-pause", Lifecycle.WAITING);
        // park() writes WAITING just before the handler's finally block records
        // process-local exit evidence. Give that bounded handoff a chance to finish.
        Thread.sleep(25);
        released.set(true);

        Response resume = lifecycle("run-controlled-pause", "resume", List.of("resume", "run"),
                "idem-run", 2, "c".repeat(64));
        assertEquals(202, resume.status(), resume.body());
        assertEquals("running", JSON.readTree(resume.body()).get("status").asText());
        waitForStatus("run-controlled-pause", Lifecycle.SUCCEEDED);
        Thread.sleep(25);

        Response replay = lifecycle("run-controlled-pause", "resume", List.of("resume", "run"),
                "idem-run", 2, "c".repeat(64));
        assertEquals(200, replay.status(), replay.body());
        assertEquals("succeeded", JSON.readTree(replay.body()).get("status").asText());
        assertTrue(JSON.readTree(replay.body()).get("output").get("echo").isObject());
        assertEquals(2, runHandlerCalls.get());
        // Resume admission and protected completed-output replay each perform
        // their own current-authorization check.
        assertEquals(3, currentAuthorizationRequests.get());
        assertEquals(null, platformFixtureFailure.get());

        List<ExecutionContract.ExecutionEvent> history = store.eventsAfter("run-controlled-pause", 0);
        List<String> types = history.stream()
                .map(ExecutionContract.ExecutionEvent::eventType).toList();
        assertEquals(List.of("accepted", "started", "progress", "waiting", "started", "progress", "completed"), types);
        var startedEvents = history.stream()
                .filter(event -> Lifecycle.EVENT_STARTED.equals(event.eventType())).toList();
        assertEquals(2, startedEvents.size());
        assertEquals(Map.of("operation", "resume"), startedEvents.get(1).payload());
    }

    @Test
    void resumeFailsClosedWithoutCurrentAuthorizationConfiguration() throws Exception {
        serve();
        Response missing = lifecycle("run-no-current-auth-config", "resume", List.of("resume"),
                "idem-run", 2, "c".repeat(64));
        assertEquals(503, missing.status());
        assertEquals("CAPABILITY_CONFIG_INVALID", JSON.readTree(missing.body()).get("code").asText());
        assertEquals(0, currentAuthorizationRequests.get());
    }

    @Test
    void resumeFailsClosedWhenCurrentAuthorizationIsDenied() throws Exception {
        serveWithCurrentAuthorization(true, false);
        Response denied = lifecycle("run-current-auth-denied", "resume", List.of("resume"),
                "idem-run", 2, "c".repeat(64));
        assertEquals(403, denied.status(), denied.body());
        assertEquals("CAPABILITY_RENEWAL_DENIED", JSON.readTree(denied.body()).get("error").get("code").asText());
        assertEquals(1, currentAuthorizationRequests.get());
        assertEquals(null, platformFixtureFailure.get());
        assertEquals(null, store.getRun("run-current-auth-denied"));
    }

    @Test
    void runHonoursCooperativeCancellation() throws Exception {
        serve();
        assertEquals(202, run("run-cancel", List.of("run", "cancel", "invoke")).status());
        for (int i = 0; i < 300; i++) {
            if (store.eventsAfter("run-cancel", 0L).stream()
                    .anyMatch(e -> Lifecycle.EVENT_PROGRESS.equals(e.eventType()))) {
                break;
            }
            Thread.sleep(10);
        }
        Response cancel = lifecycle("run-cancel", "cancel", List.of("cancel", "run", "invoke"));
        assertEquals(202, cancel.status());
        for (int i = 0; i < 100 && !"cancelled".equals(JSON.readTree(cancel.body()).get("status").asText()); i++) {
            Thread.sleep(10);
            cancel = lifecycle("run-cancel", "cancel", List.of("cancel"));
        }
        assertEquals("cancelled", JSON.readTree(cancel.body()).get("status").asText());
        // The cancellation is observable in the event history.
        // 取消在事件历史中可观察。
        Lifecycle.RunRecord record = store.getRun("run-cancel");
        assertEquals(Lifecycle.CANCELLED, record.status());
        assertTrue(record.events().stream().anyMatch(e -> Lifecycle.EVENT_CANCELLED.equals(e.eventType())));
        released.set(true);
    }

    @Test
    void invokeCancellationWaitsForActualHandlerExitAndNeverLeaksOutput() throws Exception {
        var entered = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        var executor = java.util.concurrent.Executors.newSingleThreadExecutor();
        var server = new ExecutionServer(ServerConfig.builder()
                .publicKey(minter.pair.getPublic()).issuer(minter.issuer).audience(minter.audience)
                .agentId("conformance-agent").store(store).capabilities(List.of("invoke", "cancel", "events"))
                .invoke((request, capabilities) -> {
                    entered.countDown();
                    // A handler that suppresses interruption must not receive a fabricated stop ack.
                    while (release.getCount() != 0) {
                        try { release.await(); } catch (InterruptedException ignored) { }
                    }
                    return Map.of("private_answer", "must not be returned by cancellation");
                }).build());
        httpd = server.start(new java.net.InetSocketAddress("127.0.0.1", 0));
        try {
            var pending = executor.submit(() -> invoke("invoke-stop", List.of("invoke"), "invoke-stop-key"));
            assertTrue(entered.await(3, java.util.concurrent.TimeUnit.SECONDS));
            var cancel = lifecycle("invoke-stop", "cancel", List.of("cancel"));
            assertEquals(202, cancel.status());
            assertEquals("cancelling", JSON.readTree(cancel.body()).get("status").asText());
            assertEquals(0, JSON.readTree(cancel.body()).get("output").size());
            assertTrue(!events("invoke-stop").body().contains("event: cancelled"));
            release.countDown();
            assertEquals("cancelled", JSON.readTree(pending.get(3, java.util.concurrent.TimeUnit.SECONDS).body()).get("status").asText());
            cancel = lifecycle("invoke-stop", "cancel", List.of("cancel"));
            assertEquals("cancelled", JSON.readTree(cancel.body()).get("status").asText());
            assertTrue(!cancel.body().contains("private_answer"));
            assertEquals(409, lifecycle("never-admitted", "cancel", List.of("cancel")).status());
        } finally { release.countDown(); executor.shutdownNow(); server.stop(); }
    }

    private static String field(String block, String name) {
        for (String line : block.split("\n")) {
            if (line.startsWith(name + ": ")) {
                return line.substring(name.length() + 2);
            }
        }
        throw new AssertionError("missing SSE field " + name + " in " + block);
    }

    @Test
    void businessReviewRecoveryRequiresCommittedActorAndNoToolPrivilege() throws Exception {
        serve();
        var parser = ExecutionServer.class.getDeclaredMethod("parseRuntimeRecovery", ExecuteRequest.class,
                ExecutionContract.CapabilityClaims.class, long.class);
        parser.setAccessible(true);
        long now = java.time.Instant.now().getEpochSecond();
        for (String scenario : List.of("valid", "self", "extra", "null", "token", "invoke", "invalid_id")) {
            var review = new LinkedHashMap<String,Object>(Map.of("decision","approve","reviewer_id","assigned-reviewer"));
            var reference = new LinkedHashMap<String,Object>(Map.ofEntries(
                Map.entry("version","runtime-recovery-stop/v1"),Map.entry("run_id","business-review"),
                Map.entry("stopped_revision",2),Map.entry("ready_revision",4),Map.entry("operation","resume"),
                Map.entry("body_hash","d".repeat(64)),Map.entry("policy_hash","a".repeat(64)),
                Map.entry("lease_token_hash","c".repeat(64)),Map.entry("request_hash","e".repeat(64)),
                Map.entry("resume_input_hash","f".repeat(64)),Map.entry("source","sdk-cancel-exit/v1"),
                Map.entry("checkpoints",List.of(Map.of("state_key","1".repeat(64),"revision",1,
                    "schema_id","schema://test/graph/v1","content_hash","2".repeat(64),"execution_revision",2,
                    "expires_at",java.time.Instant.ofEpochSecond(now+600).toString())))));
            var marker = new LinkedHashMap<String,Object>(Map.of("version","runtime-recovery/v1",
                    "origin_operation","invoke","reference",reference,"business_review",review));
            switch(scenario) {
                case "self" -> review.put("reviewer_id","user-a");
                case "extra" -> review.put("comment","private");
                case "null" -> marker.put("business_review",null);
                case "token" -> marker.put("confirmation_token","untrusted");
                case "invoke" -> reference.put("operation","invoke");
                case "invalid_id" -> review.put("reviewer_id","with space");
            }
            var base = envelope("resume","business-review","review-idem");
            var request = new ExecuteRequest(base.protocolVersion(),base.contextToken(),base.scope(),
                base.operation(),base.idempotencyKey(),base.inputSchema(),base.input(),marker);
            var claims = JSON.convertValue(minter.verifiedClaims(minter.executeToken(request,List.of("resume"),5,"b".repeat(64))),
                    ExecutionContract.CapabilityClaims.class);
            if (scenario.equals("valid")) org.junit.jupiter.api.Assertions.assertNotNull(parser.invoke(executionServer,request,claims,now));
            else assertThrows(java.lang.reflect.InvocationTargetException.class,()->parser.invoke(executionServer,request,claims,now),scenario);
        }
    }
}
