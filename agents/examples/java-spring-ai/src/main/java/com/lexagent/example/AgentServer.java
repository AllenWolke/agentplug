package com.lexagent.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.lexagent.sdk.ContextVerifier;
import com.lexagent.sdk.ExecutionContract;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Runnable HTTP boundary around a Spring AI workflow seam.
 * 可运行的 HTTP 边界；Spring AI 工作流保持在该边界之后。
 */
public final class AgentServer {
    private static final String ISSUER = "platform-runtime-gateway";
    private static final String AUDIENCE = "example-java-spring-ai";
    private final ObjectMapper json = new ObjectMapper().setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
    private final ContextVerifier verifier = new ContextVerifier();
    private final PublicKey publicKey;
    private final Map<String, String> runs = new ConcurrentHashMap<>();

    private AgentServer(PublicKey publicKey) { this.publicKey = publicKey; }

    public static void main(String[] args) throws Exception {
        String encoded = System.getenv("AGENT_PLATFORM_PUBLIC_KEY_X509_BASE64");
        if (encoded == null || encoded.isBlank()) throw new IllegalStateException("AGENT_PLATFORM_PUBLIC_KEY_X509_BASE64 is required");
        PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(Base64.getUrlDecoder().decode(encoded)));
        int port = Integer.parseInt(System.getenv().getOrDefault("AGENT_PORT", "8080"));
        AgentServer agent = new AgentServer(key); HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/.well-known/agent-manifest.json", agent::manifest);
        server.createContext("/internal/agent-execution/v2/invoke", exchange -> agent.execute(exchange, "invoke", false));
        server.createContext("/internal/agent-execution/v2/runs", exchange -> agent.execute(exchange, "run", true));
        server.createContext("/internal/agent-execution/v2/runs/", agent::runOperation);
        server.start();
    }

    private void manifest(HttpExchange exchange) throws IOException {
        send(exchange, 200, Map.of("manifest_version", "agent-manifest/v1", "agent_id", "example-java-spring-ai", "version", "2.0.0", "execution_protocols", new String[]{ExecutionContract.PROTOCOL_VERSION}, "capabilities", new String[]{"invoke", "run", "resume", "cancel", "events"}, "schemas", Map.of("input", "schema://example-java-spring-ai/input/v1", "output", "schema://example-java-spring-ai/output/v1", "event", "schema://agent-platform/event/v1", "checkpoint", "schema://agent-platform/checkpoint/v1"), "runtime", Map.of("transport", "http", "isolation", "container", "health_path", "/health/ready")));
    }

    private void execute(HttpExchange exchange, String operation, boolean async) throws IOException {
        try {
            requirePost(exchange); ExecutionContract.ExecuteRequest request = read(exchange, ExecutionContract.ExecuteRequest.class);
            authorize(exchange, request.contextToken());
            if (!ExecutionContract.PROTOCOL_VERSION.equals(request.protocolVersion()) || !operation.equals(request.operation())) throw new SecurityException("protocol or operation mismatch");
            verifier.verify(request, publicKey, ISSUER, AUDIENCE);
            if (async) runs.put(request.scope().runId(), "running");
            // Spring AI workflow is called only after this PEP has completed.
            // 仅在 PEP 校验成功后才调用 Spring AI 工作流。
            send(exchange, async ? 202 : 200, new ExecutionContract.ExecuteResponse(ExecutionContract.PROTOCOL_VERSION, request.scope().runId(), async ? "running" : "succeeded", "schema://example-java-spring-ai/output/v1", Map.of("framework", "spring-ai"), null));
        } catch (SecurityException exception) { error(exchange, 401, "CAPABILITY_INVALID", "execution capability is invalid");
        } catch (IllegalArgumentException exception) { error(exchange, 400, "REQUEST_INVALID", "request must be valid JSON"); }
    }

    private void runOperation(HttpExchange exchange) throws IOException {
        String[] parts = exchange.getRequestURI().getPath().substring("/internal/agent-execution/v2/runs/".length()).split("/");
        if (parts.length != 2 || parts[0].isBlank()) { error(exchange, 404, "RUN_NOT_FOUND", "run path is invalid"); return; }
        String runId = parts[0], action = parts[1];
        if ("events".equals(action)) { events(exchange, runId); return; }
        if (!"resume".equals(action) && !"cancel".equals(action)) { error(exchange, 404, "RUN_OPERATION_UNKNOWN", "unsupported run operation"); return; }
        try {
            requirePost(exchange); ExecutionContract.ExecuteRequest request = read(exchange, ExecutionContract.ExecuteRequest.class);
            authorize(exchange, request.contextToken()); if (!runId.equals(request.scope().runId()) || !action.equals(request.operation())) throw new SecurityException("run scope mismatch");
            verifier.verify(request, publicKey, ISSUER, AUDIENCE); if (!runs.containsKey(runId)) { error(exchange, 404, "RUN_NOT_FOUND", "run does not exist"); return; }
            String status = "cancel".equals(action) ? "cancelled" : "running"; runs.put(runId, status);
            send(exchange, 200, new ExecutionContract.ExecuteResponse(ExecutionContract.PROTOCOL_VERSION, runId, status, "schema://example-java-spring-ai/output/v1", Map.of(), null));
        } catch (SecurityException exception) { error(exchange, 401, "CAPABILITY_INVALID", "execution capability is invalid");
        } catch (IllegalArgumentException exception) { error(exchange, 400, "REQUEST_INVALID", "request must be valid JSON"); }
    }

    private void events(HttpExchange exchange, String runId) throws IOException {
        try {
            requirePost(exchange); ExecutionContract.EventRequest request = read(exchange, ExecutionContract.EventRequest.class);
            authorize(exchange, request.contextToken()); if (!runId.equals(request.scope().runId())) throw new SecurityException("run scope mismatch");
            verifier.verifyEvent(request, publicKey, ISSUER, AUDIENCE); String status = runs.get(runId);
            if (status == null) { error(exchange, 404, "RUN_NOT_FOUND", "run does not exist"); return; }
            ExecutionContract.ExecutionEvent event = new ExecutionContract.ExecutionEvent(runId, request.afterSeq() + 1, "cancelled".equals(status) ? "cancelled" : "progress", Instant.now(), Map.of("status", status));
            String body = "id: " + event.seq() + "\nevent: " + event.eventType() + "\ndata: " + json.writeValueAsString(event) + "\n\n";
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream"); exchange.sendResponseHeaders(200, body.getBytes(StandardCharsets.UTF_8).length); exchange.getResponseBody().write(body.getBytes(StandardCharsets.UTF_8)); exchange.close();
        } catch (SecurityException exception) { error(exchange, 401, "CAPABILITY_INVALID", "event capability is invalid");
        } catch (IllegalArgumentException exception) { error(exchange, 400, "REQUEST_INVALID", "request must be valid JSON"); }
    }

    private <T> T read(HttpExchange exchange, Class<T> type) throws IOException { return json.readValue(exchange.getRequestBody().readAllBytes(), type); }
    private static void requirePost(HttpExchange exchange) { if (!"POST".equals(exchange.getRequestMethod())) throw new IllegalArgumentException("POST required"); }
    private static void authorize(HttpExchange exchange, String token) { if (!("Bearer " + token).equals(exchange.getRequestHeaders().getFirst("Authorization"))) throw new SecurityException("bearer mismatch"); }
    private void send(HttpExchange exchange, int status, Object payload) throws IOException { byte[] body = json.writeValueAsBytes(payload); exchange.getResponseHeaders().set("Content-Type", "application/json"); exchange.sendResponseHeaders(status, body.length); exchange.getResponseBody().write(body); exchange.close(); }
    private void error(HttpExchange exchange, int status, String code, String message) throws IOException { send(exchange, status, new ExecutionContract.AppError(code, message, false, Map.of())); }
}
