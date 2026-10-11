package generated;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.lexagent.sdk.ContextVerifier;
import com.lexagent.sdk.ExecutionContract.EventRequest;
import com.lexagent.sdk.ExecutionContract.ExecuteRequest;
import com.lexagent.sdk.ExecutionContract.ScopeKey;
import com.lexagent.sdk.ExecutionServer;
import com.lexagent.sdk.Lifecycle;
import com.lexagent.sdk.MemoryRunStore;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
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
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Lifecycle tests over real HTTP against the template's own wiring.
 *
 * 模板自身接线的真实 HTTP 生命周期测试：令牌按平台网关的方式现场铸造，证明
 * invoke 与 run → events（SSE）→ 已完成运行的 resume 受控拒绝 → cancel
 * 终态快照，以及未验证调用方绝不触达业务接缝。
 */
final class ExecutionBoundaryTest {
    private static final ObjectMapper JSON = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .findAndRegisterModules();
    private static final String AUDIENCE = "conformance-agent";

    private final KeyPair pair = keyPair();
    private final MemoryRunStore store = new MemoryRunStore();
    private com.sun.net.httpserver.HttpServer httpd;
    private com.sun.net.httpserver.HttpServer platformHttpd;
    private final AtomicInteger currentAuthorizationRequests = new AtomicInteger();
    private final AtomicReference<String> platformFixtureFailure = new AtomicReference<>();

    private static KeyPair keyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    @AfterEach
    void tearDown() {
        if (httpd != null) {
            httpd.stop(0);
        }
        if (platformHttpd != null) {
            platformHttpd.stop(0);
        }
    }

    private void serve() throws Exception {
        serve(null);
    }

    private void serveWithCurrentAuthorization() throws Exception {
        platformHttpd = com.sun.net.httpserver.HttpServer.create(
                new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        platformHttpd.createContext("/internal/context/renew", this::handleRenewalFixture);
        platformHttpd.createContext("/internal/context/events/check", this::handleEventAuthorityFixture);
        platformHttpd.start();
        serve(new com.lexagent.sdk.CapabilityClient.Config(
                "http://127.0.0.1:" + platformHttpd.getAddress().getPort(),
                "fixture-internal-token", "fixture-signing-secret", () -> java.time.Instant.now().getEpochSecond(),
                "fixture-worker", "w".repeat(43)));
    }

    private void serve(com.lexagent.sdk.CapabilityClient.Config capability) throws Exception {
        ExecutionServer server = GenericAgent.server(pair.getPublic(), AUDIENCE, store, new AgentController(), capability);
        httpd = server.start(new java.net.InetSocketAddress("127.0.0.1", 0));
    }

    private int port() {
        return httpd.getAddress().getPort();
    }

    private Response post(String path, Object payload, String token, String authorization) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port() + path))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(JSON.writeValueAsBytes(payload)));
        request.header("Authorization", authorization == null ? "Bearer " + token : authorization);
        HttpResponse<String> response = HttpClient.newHttpClient().send(request.build(),
                HttpResponse.BodyHandlers.ofString());
        return new Response(response.statusCode(), response.body());
    }

    private ExecuteRequest envelope(String operation, String runId, String idempotency) {
        return new ExecuteRequest(com.lexagent.sdk.ExecutionContract.PROTOCOL_VERSION, "x".repeat(32), scope(runId),
                operation, idempotency, "schema://example/input/v1",
                Map.of("policy_snapshot", Map.of("content_hash", "a".repeat(64),
                        "model_profile_id", "model-v1", "prompt_version_id", "prompt-v1",
                        "tool_policy_id", "tool-v1", "memory_policy_id", "memory-v1",
                        "knowledge_policy_id", "knowledge-v1", "runtime_policy_id", "runtime-v1"),
                        "task", "echo-" + runId),
                "resume".equals(operation) ? Map.of("decision", "approve") : null);
    }

    private EventRequest eventEnvelope(String runId) {
        return new EventRequest(com.lexagent.sdk.ExecutionContract.PROTOCOL_VERSION, "x".repeat(32), scope(runId),
                0, "a".repeat(64));
    }

    private static ScopeKey scope(String runId) {
        return new ScopeKey("tenant-a", "business-department", "business-app", "instance-a", "installation-a", AUDIENCE,
                "v2", "user", "user-a", "session-a", runId, 1, "0".repeat(32), "", 0);
    }

    private String token(ExecuteRequest request, List<String> actions) throws Exception {
        return mintWith(pair, request, actions);
    }

    private String mintWith(KeyPair signWith, ExecuteRequest request, List<String> actions) throws Exception {
        Map<String, Object> claims = baseClaims(actions);
        bindScope(claims, request.scope());
        claims.put("body_hash", ContextVerifier.canonicalBodyHash(request));
        return sign(claims, signWith);
    }

    /** Mint an events-only capability: the body hash covers the event envelope,
     * never an execution envelope. / 铸造仅允许订阅事件的能力。
     */
    private String eventToken(EventRequest request) throws Exception {
        Map<String, Object> claims = baseClaims(List.of("events"));
        bindScope(claims, request.scope());
        claims.put("body_hash", ContextVerifier.canonicalEventHash(request));
        return sign(claims, pair);
    }

    private static void bindScope(Map<String, Object> claims, ScopeKey scope) {
        claims.put("department_id", scope.departmentId());
        claims.put("agent_id", scope.agentId());
        claims.put("agent_version_id", scope.agentVersionId());
        claims.put("run_id", scope.runId());
        claims.put("session_id", scope.sessionId());
        claims.put("trace_id", scope.traceId());
        claims.put("execution_revision", 1);
        claims.put("lease_token_hash", "b".repeat(64));
    }

    private Map<String, Object> baseClaims(List<String> actions) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", "platform-runtime-gateway");
        claims.put("aud", AUDIENCE);
        claims.put("subject_type", "user");
        claims.put("sub", "user-a");
        claims.put("tenant_id", "tenant-a");
        claims.put("application_id", "business-app");
        claims.put("agent_instance_id", "instance-a");
        claims.put("installation_id", "installation-a");
        claims.put("authorization_epoch", 1);
        claims.put("actions", actions);
        claims.put("policy_snapshot_hash", "a".repeat(64));
        long now = java.time.Instant.now().getEpochSecond();
        claims.put("iat", now);
        claims.put("exp", now + 120);
        return claims;
    }

    private static String sign(Map<String, Object> claims, KeyPair signWith) throws Exception {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString(JSON.writeValueAsBytes(Map.of("alg", "EdDSA", "typ", "JWT")));
        String payload = encoder.encodeToString(JSON.writeValueAsBytes(claims));
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(signWith.getPrivate());
        signature.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
        return header + "." + payload + "." + encoder.encodeToString(signature.sign());
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> verifiedClaims(String token) throws Exception {
        String[] parts = token.split("\\.");
        if (parts.length != 3) throw new SecurityException("invalid token shape");
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(pair.getPublic());
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        if (!verifier.verify(Base64.getUrlDecoder().decode(parts[2]))) throw new SecurityException("invalid token signature");
        return JSON.readValue(Base64.getUrlDecoder().decode(parts[1]), Map.class);
    }

    private void handleRenewalFixture(com.sun.net.httpserver.HttpExchange exchange) throws java.io.IOException {
        currentAuthorizationRequests.incrementAndGet();
        try {
            byte[] body = exchange.getRequestBody().readNBytes(32769);
            if (!"POST".equals(exchange.getRequestMethod())
                    || !"/internal/context/renew".equals(exchange.getRequestURI().getRawPath())
                    || body.length > 32768
                    || !"fixture-internal-token".equals(exchange.getRequestHeaders().getFirst("X-Internal-Token"))
                    || !"fixture-worker".equals(exchange.getRequestHeaders().getFirst("X-Agent-Client-ID"))
                    || !"w".repeat(43).equals(exchange.getRequestHeaders().getFirst("X-Agent-Client-Secret"))) {
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
            Map<String, Object> claims = verifiedClaims(token);
            if (!"platform-runtime-gateway".equals(claims.get("iss"))
                    || !AUDIENCE.equals(claims.get("aud"))
                    || !"user".equals(claims.get("subject_type"))
                    || !"user-a".equals(claims.get("sub"))
                    || !"tenant-a".equals(claims.get("tenant_id"))
                    || !"business-department".equals(claims.get("department_id"))
                    || !"business-app".equals(claims.get("application_id"))
                    || !"instance-a".equals(claims.get("agent_instance_id"))
                    || !"installation-a".equals(claims.get("installation_id"))
                    || !AUDIENCE.equals(claims.get("agent_id"))
                    || !"v2".equals(claims.get("agent_version_id"))
                    || !(claims.get("actions") instanceof List<?> actions) || !actions.contains("resume")
                    || !"a".repeat(64).equals(claims.get("policy_snapshot_hash"))
                    || !(claims.get("body_hash") instanceof String bodyHash) || !bodyHash.matches("[a-f0-9]{64}")
                    || !(claims.get("execution_revision") instanceof Number revision) || revision.longValue() < 1
                    || !(claims.get("lease_token_hash") instanceof String leaseHash) || !leaseHash.matches("[a-f0-9]{64}")
                    || !"run-full".equals(claims.get("run_id"))
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
                    || !"idem-resume".equals(context.get("request_id"))
                    || !"idem-resume".equals(context.get("idempotency_key"))
                    || !"model-v1".equals(context.get("model_profile_id"))
                    || !"prompt-v1".equals(context.get("prompt_version_id"))
                    || !"tool-v1".equals(context.get("tool_policy_id"))
                    || !"memory-v1".equals(context.get("memory_policy_id"))
                    || !"knowledge-v1".equals(context.get("knowledge_policy_id"))
                    || !"runtime-v1".equals(context.get("runtime_policy_id"))) {
                throw new IllegalArgumentException("current execution binding");
            }
            Map<String, Object> renewedClaims = new LinkedHashMap<>(claims);
            renewedClaims.put("exp", java.time.Instant.now().getEpochSecond() + 120);
            writeFixtureJson(exchange, 200, Map.of("data", Map.of("context_token", sign(renewedClaims, pair))));
        } catch (Exception rejected) {
            platformFixtureFailure.set(rejected.getClass().getSimpleName());
            writeFixtureJson(exchange, 400, Map.of("error_code", "INVALID_FIXTURE_REQUEST"));
        }
    }

    private void handleEventAuthorityFixture(com.sun.net.httpserver.HttpExchange exchange) throws java.io.IOException {
        try {
            byte[] body = exchange.getRequestBody().readNBytes(32769);
            if (!"POST".equals(exchange.getRequestMethod())
                    || !"/internal/context/events/check".equals(exchange.getRequestURI().getRawPath())
                    || body.length > 32768
                    || !"fixture-internal-token".equals(exchange.getRequestHeaders().getFirst("X-Internal-Token"))
                    || !"fixture-worker".equals(exchange.getRequestHeaders().getFirst("X-Agent-Client-ID"))
                    || !"w".repeat(43).equals(exchange.getRequestHeaders().getFirst("X-Agent-Client-Secret"))) {
                throw new IllegalArgumentException("event authority request envelope");
            }
            String bearer = exchange.getRequestHeaders().getFirst("X-Platform-Context");
            if (bearer == null || !bearer.startsWith("Bearer ")) throw new IllegalArgumentException("event context bearer");
            String token = bearer.substring("Bearer ".length());
            String signature = exchange.getRequestHeaders().getFirst("X-Context-Signature");
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
            byte[] proof = JSON.writeValueAsBytes(List.of("platform-capability/v2", "POST",
                    "/internal/context/events/check", digest));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec("fixture-signing-secret".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            String expectedSignature = "sha256=" + HexFormat.of().formatHex(mac.doFinal(proof));
            if (signature == null || !MessageDigest.isEqual(expectedSignature.getBytes(StandardCharsets.US_ASCII),
                    signature.getBytes(StandardCharsets.US_ASCII))) throw new IllegalArgumentException("event request signature");
            Map<?, ?> request = JSON.readValue(body, Map.class);
            if (!(request.get("scope") instanceof Map<?, ?> scope)
                    || !"run-full".equals(scope.get("run_id"))
                    || !token.equals(request.get("context_token"))) throw new IllegalArgumentException("event request scope");
            Map<String, Object> claims = verifiedClaims(token);
            if (!"platform-runtime-gateway".equals(claims.get("iss"))
                    || !AUDIENCE.equals(claims.get("aud"))
                    || !(claims.get("actions") instanceof List<?> actions) || !actions.contains("events")
                    || !claims.get("run_id").equals(scope.get("run_id"))
                    || !claims.get("agent_id").equals(scope.get("agent_id"))
                    || !claims.get("tenant_id").equals(scope.get("tenant_id"))
                    || !claims.get("department_id").equals(scope.get("department_id"))
                    || !claims.get("application_id").equals(scope.get("application_id"))
                    || !claims.get("agent_instance_id").equals(scope.get("agent_instance_id"))
                    || !claims.get("installation_id").equals(scope.get("installation_id"))
                    || !claims.get("session_id").equals(scope.get("session_id"))
                    || !claims.get("trace_id").equals(scope.get("trace_id"))) {
                throw new IllegalArgumentException("event caller scope binding");
            }
            writeFixtureJson(exchange, 200, Map.of("data", Map.of("allowed", true)));
        } catch (Exception rejected) {
            platformFixtureFailure.set(rejected.getClass().getSimpleName());
            writeFixtureJson(exchange, 400, Map.of("error_code", "INVALID_EVENT_FIXTURE_REQUEST"));
        }
    }

    private static void writeFixtureJson(com.sun.net.httpserver.HttpExchange exchange, int status, Object value)
            throws java.io.IOException {
        byte[] bytes = JSON.writeValueAsBytes(value);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (var out = exchange.getResponseBody()) { out.write(bytes); }
    }

    private Response signed(String path, ExecuteRequest request, List<String> actions) throws Exception {
        String token = token(request, actions);
        ExecuteRequest signed = new ExecuteRequest(request.protocolVersion(), token, request.scope(),
                request.operation(), request.idempotencyKey(), request.inputSchema(), request.input(), request.resumeInput());
        return post(path, signed, token, null);
    }

    private void waitForStatus(String runId, String status) throws Exception {
        for (int i = 0; i < 300; i++) {
            Lifecycle.RunRecord record = store.getRun(runId);
            if (record != null && status.equals(record.status())) {
                return;
            }
            if (record != null && Lifecycle.TERMINAL_STATUSES.contains(record.status())) {
                String errorCode = record.error() == null ? "" : record.error().code();
                String fixtureError = platformFixtureFailure.get();
                throw new AssertionError("run " + runId + " reached terminal " + record.status()
                        + " before " + status + "; error_code=" + errorCode
                        + "; current_authorization_fixture_error=" + fixtureError);
            }
            Thread.sleep(10);
        }
        Lifecycle.RunRecord record = store.getRun(runId);
        String eventTypes = record == null ? "[]" : record.events().stream()
                .map(event -> event.eventType()).toList().toString();
        String errorCode = record == null || record.error() == null ? "" : record.error().code();
        throw new AssertionError("run " + runId + " never reached " + status + "; observed_status="
                + (record == null ? "missing" : record.status()) + "; error_code=" + errorCode
                + "; events=" + eventTypes + "; current_authorization_fixture_error=" + platformFixtureFailure.get());
    }

    private static String field(String block, String name) {
        for (String line : block.split("\n")) {
            if (line.startsWith(name + ": ")) {
                return line.substring(name.length() + 2);
            }
        }
        throw new AssertionError("missing SSE field " + name);
    }

    private record Response(int status, String body) {}

    @Test
    void unverifiedCallersNeverReachTheBusinessSeam() throws Exception {
        serve();
        // A forged platform key must never pass. / 伪造的平台密钥绝不放行。
        KeyPair forged = keyPair();
        ExecuteRequest request = envelope("run", "run-401", "idem-key-0001");
        String forgedToken = mintWith(forged, request, List.of("run"));
        ExecuteRequest signed = new ExecuteRequest(request.protocolVersion(), forgedToken, request.scope(),
                request.operation(), request.idempotencyKey(), request.inputSchema(), request.input());
        Response response = post(ExecutionServer.RUNS_PATH, signed, forgedToken, null);
        assertEquals(401, response.status());
        assertEquals("CAPABILITY_INVALID", JSON.readTree(response.body()).get("code").asText());
        assertNull(store.getRun("run-401"));

        // The delegated actions must include the operation. / 被委派动作必须含该操作。
        assertEquals(401, signed(ExecutionServer.RUNS_PATH, envelope("run", "run-401b", "idem-key-0002"),
                List.of("invoke")).status());
        assertNull(store.getRun("run-401b"));
    }

    @Test
    void servesTheFullLifecycleLegsWithSseReplay() throws Exception {
        serveWithCurrentAuthorization();
        Response run = signed(ExecutionServer.RUNS_PATH, envelope("run", "run-full", "idem-run"),
                List.of("run", "resume", "cancel", "invoke"));
        assertEquals(202, run.status());
        assertEquals("running", JSON.readTree(run.body()).get("status").asText());
        waitForStatus("run-full", Lifecycle.SUCCEEDED);

        String token = eventToken(eventEnvelope("run-full"));
        EventRequest eventRequest = eventEnvelope("run-full");
        EventRequest signedEvent = new EventRequest(eventRequest.protocolVersion(), token, eventRequest.scope(),
                eventRequest.afterSeq(), eventRequest.policySnapshotHash());
        Response events = post(ExecutionServer.RUNS_PATH + "/run-full/events", signedEvent, token, null);
        assertEquals(200, events.status());
        List<String> types = new ArrayList<>();
        for (String block : events.body().split("\n\n")) {
            if (block.isBlank()) {
                continue;
            }
            JsonNode payload = JSON.readTree(field(block, "data"));
            assertEquals(field(block, "id"), payload.get("seq").asText());
            assertEquals("run-full", payload.get("run_id").asText());
            types.add(field(block, "event"));
        }
        assertEquals(List.of("accepted", "started", "progress", "completed"), types);

        // Ordinary completed runs require a current authorization check before the
        // controlled-resume gate rejects them; no checkpoint or new generation is created.
        // 普通已完成运行先通过当前授权核验，再由受控恢复门禁拒绝；不会读取 checkpoint 或新建代次。
        Response resume = signed(ExecutionServer.RUNS_PATH + "/run-full/resume",
                envelope("resume", "run-full", "idem-resume"), List.of("resume", "run", "invoke"));
        assertEquals(409, resume.status());
        assertEquals("RUN_RESUME_UNCONFIRMED", JSON.readTree(resume.body()).get("code").asText());
        assertEquals(1, currentAuthorizationRequests.get());
        assertNull(platformFixtureFailure.get());
        assertEquals(Lifecycle.SUCCEEDED, store.getRun("run-full").status());
        assertEquals(1, store.eventsAfter("run-full", 0).stream()
                .filter(event -> Lifecycle.EVENT_STARTED.equals(event.eventType())).count());

        // Stop acknowledges handler exit without returning business output.
        Response cancel = signed(ExecutionServer.RUNS_PATH + "/run-full/cancel",
                envelope("cancel", "run-full", "idem-cancel"), List.of("cancel", "run", "invoke"));
        assertEquals(202, cancel.status());
        assertEquals("cancelled", JSON.readTree(cancel.body()).get("status").asText());
        assertEquals(0, JSON.readTree(cancel.body()).get("output").size());
    }

    @Test
    void invokeServesTheBusinessOutput() throws Exception {
        serve();
        Response invoke = signed(ExecutionServer.INVOKE_PATH, envelope("invoke", "run-invoke", "idem-invoke"),
                List.of("invoke"));
        assertEquals(200, invoke.status());
        JsonNode body = JSON.readTree(invoke.body());
        assertEquals("succeeded", body.get("status").asText());
        assertEquals("generic", body.get("output").get("framework").asText());
        assertEquals("run-invoke", body.get("output").get("run_id").asText());
        assertTrue(body.get("output").get("result").asText().contains("echo-run-invoke"));
    }
}
