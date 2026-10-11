package com.lexagent.sdk;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.lexagent.sdk.ExecutionContract.ExecuteRequest;
import com.lexagent.sdk.ExecutionContract.ScopeKey;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

final class CapabilityClientTest {
    private static final ObjectMapper JSON = new ObjectMapper().setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
    private final long now = Instant.now().getEpochSecond();
    private final KeyPair keys;
    CapabilityClientTest() throws Exception { keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair(); }

    private String sign(Map<String,Object> claims) throws Exception {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(JSON.writeValueAsBytes(Map.of("alg","EdDSA")));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(JSON.writeValueAsBytes(claims));
        Signature signature = Signature.getInstance("Ed25519"); signature.initSign(keys.getPrivate()); signature.update((header+"."+payload).getBytes(StandardCharsets.UTF_8));
        return header+"."+payload+"."+Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
    }

    private Map<String,Object> tokenClaims(String token) throws Exception {
        return JSON.readValue(Base64.getUrlDecoder().decode(token.split("\\.")[1]), JSON.getTypeFactory().constructMapType(Map.class,String.class,Object.class));
    }

    private ExecuteRequest request(String operation) throws Exception {
        var scope = new ScopeKey("tenant","department","app","instance","install","agent","v1","user","actor","session",operation+"-run",1,"a".repeat(32),"",0);
        Map<String,Object> policy = new LinkedHashMap<>(); policy.put("content_hash","hash");
        for(String key:List.of("model_profile_id","prompt_version_id","tool_policy_id","memory_policy_id","knowledge_policy_id","runtime_policy_id"))policy.put(key,key+"-v1");
        var unsigned = new ExecuteRequest(ExecutionContract.PROTOCOL_VERSION,"",scope,operation,"idempotency-key","schema://input",Map.of("policy_snapshot",policy));
        Map<String,Object> claims = new LinkedHashMap<>();
        claims.put("iss","platform");claims.put("aud","agent");claims.put("sub","actor");claims.put("subject_type","user");
        claims.put("tenant_id","tenant");claims.put("department_id","department");claims.put("application_id","app");claims.put("agent_instance_id","instance");claims.put("installation_id","install");
        claims.put("agent_id","agent");claims.put("agent_version_id","v1");claims.put("run_id",scope.runId());claims.put("session_id","session");claims.put("trace_id",scope.traceId());
        claims.put("authorization_epoch",1);claims.put("actions",List.of(operation));claims.put("policy_snapshot_hash","hash");claims.put("body_hash",ContextVerifier.canonicalBodyHash(unsigned));
        claims.put("iat",now);claims.put("exp",now+5);claims.put("execution_revision",3);claims.put("lease_token_hash","c".repeat(64));
        return new ExecuteRequest(unsigned.protocolVersion(),sign(claims),scope,operation,unsigned.idempotencyKey(),unsigned.inputSchema(),unsigned.input());
    }

    private CapabilityClient.Config config(HttpServer platform) {
        return new CapabilityClient.Config("http://127.0.0.1:"+platform.getAddress().getPort(),"internal","secret",()->now,"fixture-worker","w".repeat(43));
    }

    @Test
    void checkpointUsesSignedPlatformTransportAndKeepsLargeIntegers() throws Exception {
        var calls = new AtomicInteger();
        HttpServer platform = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        platform.createContext("/", exchange -> {
            try {
                byte[] requestBody = exchange.getRequestBody().readAllBytes();
                String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(requestBody));
                Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec("secret".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
                assertEquals("sha256=" + HexFormat.of().formatHex(mac.doFinal(JSON.writeValueAsBytes(List.of("platform-capability/v2", "POST", exchange.getRequestURI().toString(), digest)))), exchange.getRequestHeaders().getFirst("X-Context-Signature"));
                Map<String,Object> result;
                if (exchange.getRequestURI().getPath().endsWith("/renew")) {
                    var claims = tokenClaims(exchange.getRequestHeaders().getFirst("X-Platform-Context").substring(7));
                    claims.put("exp", now + 60); result = Map.of("context_token", sign(claims));
                } else {
                    calls.incrementAndGet();
                    assertTrue(List.of("/internal/state/checkpoint", "/internal/context/prepare", "/internal/tool/invoke").contains(exchange.getRequestURI().getPath()));
                    JsonNode input = JSON.readTree(requestBody).path("input");
                    if (exchange.getRequestURI().getPath().endsWith("/invoke")) {
                        assertEquals("approved-call", input.path("call_id").asText());
                        assertEquals("opaque-approval", input.path("confirmation_token").asText());
                        assertFalse(input.has("confirmed"));
                    }
                    if (input.path("operation").asText().equals("save")) {
                        assertEquals("stable", input.path("idempotency_key").asText());
                        assertEquals(9007199254740993L, input.path("value").path("sequence").asLong());
                    }
                    result = exchange.getRequestURI().getPath().endsWith("/prepare") ? Map.of("messages", List.of(Map.of("role", "system", "content", "approved"), Map.of("role", "user", "content", "question")), "prompt_template_hash", "published") : Map.of("checkpoint", Map.of("revision", 1, "value", Map.of("sequence", 9007199254740993L)));
                }
                byte[] response = JSON.writeValueAsBytes(Map.of("data", result));
                exchange.sendResponseHeaders(200, response.length); exchange.getResponseBody().write(response);
            } catch (Exception error) { throw new java.io.IOException("checkpoint fixture failed", error); }
            finally { exchange.close(); }
        });
        platform.start();
        try {
            var client = new CapabilityClient(config(platform), request("invoke"));
            var value = Map.<String,Object>of("sequence", 9007199254740993L);
            client.saveCheckpoint("harness", "loop", "schema://state/v1", value, 0, "stable");
            var restored = client.loadCheckpoint("harness", "loop", "schema://state/v1", 0);
            assertEquals(9007199254740993L, JSON.valueToTree(restored).path("checkpoint").path("value").path("sequence").asLong());
            assertThrows(CapabilityClient.Failure.class, () -> client.saveCheckpoint("harness", "loop", "schema://state/v1", value, 0, ""));
            assertThrows(CapabilityClient.Failure.class, () -> client.loadCheckpoint("harness", "loop", "schema://state/v1", 65));
            assertEquals(2, calls.get());
            var prepared = client.prepareContext(List.of(Map.of("role", "user", "content", "question")), List.of());
            assertEquals("published", prepared.get("prompt_template_hash"));
            assertEquals(3, calls.get());
            client.invokeTool("clock.now", "approved-call", Map.of(), "opaque-approval");
            assertEquals(4, calls.get());
            assertThrows(CapabilityClient.Failure.class, () -> client.invokeTool("clock.now", "", Map.of(), "opaque-approval"));
            assertEquals(4, calls.get());
        } finally { platform.stop(0); }
    }

    @Test
    void nativeFunctionLoopUsesPublishedBindingStableKeysWithoutAutomaticApproval() throws Exception {
        var models = new AtomicInteger(); var tools = new AtomicInteger();
        var identities = new java.util.ArrayList<String>();
        HttpServer platform = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        platform.createContext("/", exchange -> {
            try {
                assertNotNull(exchange.getRequestHeaders().getFirst("X-Context-Signature"));
                JsonNode input = JSON.readTree(exchange.getRequestBody().readAllBytes()).path("input");
                Map<String,Object> result;
                if (exchange.getRequestURI().getPath().endsWith("/renew")) {
                    var claims = tokenClaims(exchange.getRequestHeaders().getFirst("X-Platform-Context").substring(7));
                    claims.put("exp", now + 60); result = Map.of("context_token", sign(claims));
                } else if (exchange.getRequestURI().getPath().endsWith("/invoke")) {
                    tools.incrementAndGet(); identities.add(input.path("call_id").asText());
                    assertEquals("runtime.inspect", input.path("name").asText()); assertFalse(input.path("confirmed").asBoolean());
                    result = Map.of("data", Map.of("healthy", true));
                    if (tools.get() == 2) result = Map.of("data", Map.of("raw_output", "excluded-original-body"), "observation", Map.of("version", "runtime-observation/v1", "tool_name", "runtime.inspect", "call_id", input.path("call_id").asText(), "status", "succeeded", "effect", "completed", "instruction_trust", "untrusted_data", "context_output", Map.of("healthy", true)));
                } else {
                    identities.add(input.path("idempotency_key").asText());
                    if (models.incrementAndGet() % 2 == 1) {
                        result = Map.of("text", "", "completion_status", "tool_calls", "function_bindings", Map.of("inspect", "runtime.inspect"), "tool_calls", List.of(Map.of("id", "call-1", "type", "function", "function", Map.of("name", "inspect", "arguments", "{}"))));
                    } else {
                        assertEquals(3, input.path("messages").size()); assertEquals("call-1", input.path("messages").get(2).path("tool_call_id").asText());
                        if (models.get() == 4) {
                            String content = input.path("messages").get(2).path("content").asText();
                            assertFalse(content.contains("excluded-original-body"));
                            assertTrue(JSON.readTree(content).path("context_output").path("healthy").asBoolean());
                        }
                        result = Map.of("text", "ready");
                    }
                }
                byte[] body = JSON.writeValueAsBytes(Map.of("data", result));
                exchange.sendResponseHeaders(200, body.length); exchange.getResponseBody().write(body);
            } catch (Exception error) { throw new java.io.IOException("fixture failed", error); }
            finally { exchange.close(); }
        });
        platform.start();
        try {
            var client = new CapabilityClient(config(platform), request("invoke"));
            Map<String,Object> input = Map.of("messages", List.of(Map.of("role", "user", "content", "inspect")), "function_names", List.of("inspect"), "idempotency_key", "stable");
            for (int repeat = 0; repeat < 2; repeat++) assertEquals("ready", client.generateWithFunctions(input, 2).get("text"));
            assertEquals(4, models.get()); assertEquals(2, tools.get());
            assertEquals(identities.subList(0, 3), identities.subList(3, 6));
            assertNotEquals(identities.get(0), identities.get(2)); assertEquals("stable", input.get("idempotency_key"));
            CapabilityClient.Failure failure = assertThrows(CapabilityClient.Failure.class, () -> client.generateWithFunctions(input, 1));
            assertEquals("FUNCTION_ROUND_LIMIT", failure.code()); assertEquals(2, tools.get());
        } finally { platform.stop(0); }
    }

    @Test
    void concurrentCallsRenewOnceAndUseBoundOperationSignature() throws Exception {
        var renewals = new AtomicInteger(); var calls = new AtomicInteger();
        HttpServer platform = HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        platform.createContext("/",exchange->{
            try {
                assertEquals("fixture-worker",exchange.getRequestHeaders().getFirst("X-Agent-Client-ID"));
                assertEquals("w".repeat(43),exchange.getRequestHeaders().getFirst("X-Agent-Client-Secret"));
                byte[] body = exchange.getRequestBody().readAllBytes();
                String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
                Mac mac = Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec("secret".getBytes(StandardCharsets.UTF_8),"HmacSHA256"));
                String expected = "sha256="+HexFormat.of().formatHex(mac.doFinal(JSON.writeValueAsBytes(List.of("platform-capability/v2","POST",exchange.getRequestURI().toString(),digest))));
                assertEquals(expected,exchange.getRequestHeaders().getFirst("X-Context-Signature"));
                var context = JSON.readTree(body).get("context");assertEquals("tenant",context.path("tenant_id").asText());assertEquals("actor",context.path("actor_id").asText());assertEquals("session",context.path("session_id").asText());assertEquals("install",context.path("installation_id").asText());
                String old = exchange.getRequestHeaders().getFirst("X-Platform-Context").substring(7);
                Map<String,Object> claims = tokenClaims(old);
                byte[] response;
                if(exchange.getRequestURI().getPath().endsWith("/renew")) {
                    renewals.incrementAndGet();claims.put("exp",now+60);response=JSON.writeValueAsBytes(Map.of("data",Map.of("context_token",sign(claims))));
                } else {
                    assertTrue(((Number)claims.get("exp")).longValue()>now+15);calls.incrementAndGet();response=JSON.writeValueAsBytes(Map.of("data",Map.of("text","answer")));
                }
                exchange.sendResponseHeaders(200,response.length);exchange.getResponseBody().write(response);
            } catch (Exception error) { throw new java.io.IOException("fixture failed",error); }
            finally { exchange.close(); }
        });platform.start();
        var workers = Executors.newFixedThreadPool(8);
        try {
            assertEquals("CapabilityClient.Config[redacted]",config(platform).toString());
            var client = new CapabilityClient(config(platform),request("invoke"));
            var futures = new java.util.ArrayList<Future<Map<String,Object>>>();
            for(int i=0;i<8;i++)futures.add(workers.submit(()->client.post("/internal/model/generate",Map.of("messages",List.of("question")))));
            for(var result:futures)assertEquals("answer",result.get().get("text"));
            assertEquals(1,renewals.get());assertEquals(8,calls.get());
        } finally { workers.shutdownNow(); platform.stop(0); }
    }

    @Test
    void failedRenewalNeverCallsCapabilityOrChangesTheExecution() throws Exception {
        for(String mode:List.of("revoked","invalid_json","changed_scope","oversized","redirect")) {
            var calls = new AtomicInteger();var attempts = new AtomicInteger();
            HttpServer platform=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
            platform.createContext("/",exchange->{
                try {
                    if(!exchange.getRequestURI().getPath().endsWith("/renew")){calls.incrementAndGet();exchange.sendResponseHeaders(200,-1);return;}
                    attempts.incrementAndGet();byte[] response="not json".getBytes(StandardCharsets.UTF_8);int status=200;
                    switch(mode){
                        case "revoked":status=403;break;
                        case "changed_scope":var claims=tokenClaims(exchange.getRequestHeaders().getFirst("X-Platform-Context").substring(7));claims.put("tenant_id","other");claims.put("exp",now+60);response=JSON.writeValueAsBytes(Map.of("data",Map.of("context_token",sign(claims))));break;
                        case "oversized":response="x".repeat(32769).getBytes(StandardCharsets.UTF_8);break;
                        case "redirect":status=302;exchange.getResponseHeaders().set("Location","/internal/model/generate");break;
                    }
                    exchange.sendResponseHeaders(status,response.length);exchange.getResponseBody().write(response);
                } catch(Exception error){throw new java.io.IOException("fixture failed",error);}finally{exchange.close();}
            });platform.start();
            try {
                var client=new CapabilityClient(config(platform),request("invoke"));
                var error=assertThrows(CapabilityClient.Failure.class,()->client.post("/internal/model/generate",Map.of()));
                assertEquals(0,calls.get(),mode);
                assertThrows(CapabilityClient.Failure.class,()->client.post("/internal/model/generate",Map.of()));assertEquals(2,attempts.get());assertEquals(0,calls.get());
                if(mode.equals("revoked") || mode.equals("changed_scope")){assertEquals(403,error.status());assertFalse(error.retryable());}
            }finally{platform.stop(0);}
        }
    }

    @Test
    void signedInvokeAndRunPassIndependentClientsToBusinessHandlers() throws Exception {
        var calls=new AtomicInteger();var renewals=new AtomicInteger();
        var revoked=new java.util.concurrent.atomic.AtomicBoolean();
        HttpServer platform=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        platform.createContext("/",exchange->{try{
            if(revoked.get() && exchange.getRequestURI().getPath().endsWith("/renew")){exchange.sendResponseHeaders(403,-1);return;}
            byte[] body;
            if(exchange.getRequestURI().getPath().endsWith("/renew")){renewals.incrementAndGet();var claims=tokenClaims(exchange.getRequestHeaders().getFirst("X-Platform-Context").substring(7));claims.put("exp",now+60);body=JSON.writeValueAsBytes(Map.of("data",Map.of("context_token",sign(claims))));}
            else{calls.incrementAndGet();body=JSON.writeValueAsBytes(Map.of("data",Map.of("text","governed")));}
            exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);
        }catch(Exception error){throw new java.io.IOException("fixture failed",error);}finally{exchange.close();}});platform.start();
        var store=new MemoryRunStore();var clients=java.util.Collections.synchronizedList(new java.util.ArrayList<CapabilityClient>());
        var server=new ExecutionServer(ServerConfig.builder().publicKey(keys.getPublic()).issuer("platform").audience("agent").agentId("agent").store(store).now(()->now).capability(config(platform))
            .capabilities(List.of("invoke","run","resume","cancel","events"))
            .invoke((r,c)->{assertNotNull(c);clients.add(c);return c.post("/internal/model/generate",Map.of());})
            .run((r,events,signals,c)->{assertNotNull(c);clients.add(c);return c.post("/internal/model/generate",Map.of());}).build());
        HttpServer agent=server.start(new InetSocketAddress("127.0.0.1",0));
        try{
            for(String operation:List.of("invoke","run")){
                var request=request(operation);String path=operation.equals("invoke")?ExecutionServer.INVOKE_PATH:ExecutionServer.RUNS_PATH;
                var wire=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+agent.getAddress().getPort()+path)).header("Authorization","Bearer "+request.contextToken()).header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofByteArray(JSON.writeValueAsBytes(request))).build();
                var response=HttpClient.newHttpClient().send(wire,HttpResponse.BodyHandlers.ofString());assertEquals(operation.equals("invoke")?200:202,response.statusCode(),response.body());
                if(operation.equals("run")){long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(3);while(System.nanoTime()<deadline && !Lifecycle.SUCCEEDED.equals(store.getRun("run-run").status()))Thread.sleep(5);assertEquals(Lifecycle.SUCCEEDED,store.getRun("run-run").status());}
            }
            assertEquals(2,calls.get());assertEquals(2,renewals.get());assertEquals(2,clients.size());assertNotSame(clients.get(0),clients.get(1));
            revoked.set(true);
            var deniedRequest=request("invoke");
            var deniedWire=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+agent.getAddress().getPort()+ExecutionServer.INVOKE_PATH)).header("Authorization","Bearer "+deniedRequest.contextToken()).header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofByteArray(JSON.writeValueAsBytes(deniedRequest))).build();
            var denied=HttpClient.newHttpClient().send(deniedWire,HttpResponse.BodyHandlers.ofString());
            assertEquals(403,denied.statusCode());
            var failure=JSON.readTree(denied.body()).get("error");assertEquals("CAPABILITY_RENEWAL_DENIED",failure.path("code").asText());assertFalse(failure.path("retryable").asBoolean());assertEquals(2,calls.get());
        }finally{agent.stop(0);server.stop();platform.stop(0);}
    }

    @Test
    void stopRevisionConflictExposesOnlyExactBoundedControlMetadata() throws Exception {
        var call = new AtomicInteger();
        Map<String,Object> valid = Map.of("stop_control", Map.of(
            "version", "agent-child-stop-control-conflict/v1", "status", "running", "execution_revision", 7L));
        Map<String,Object> extra = Map.of("stop_control", Map.of(
            "version", "agent-child-stop-control-conflict/v1", "status", "running", "execution_revision", 7L, "output", "private-sentinel"));
        byte[][] responses = new byte[][] {
            JSON.writeValueAsBytes(Map.of("error_code", "AGENT_STOP_REVISION_CONFLICT", "message", "safe", "data", valid)),
            JSON.writeValueAsBytes(Map.of("error_code", "AGENT_STOP_REVISION_CONFLICT", "message", "safe", "data", extra)),
            "{\"error_code\":\"AGENT_STOP_REVISION_CONFLICT\",\"data\":{\"stop_control\":{\"version\":\"agent-child-stop-control-conflict/v1\",\"status\":\"cancelled\",\"execution_revision\":7}}}".getBytes(StandardCharsets.UTF_8),
            JSON.writeValueAsBytes(Map.of("error_code", "AGENT_ROUTE_CONFLICT", "message", "safe", "data", valid)),
            ("{\"error_code\":\"AGENT_STOP_REVISION_CONFLICT\",\"data\":{\"stop_control\":{\"version\":\"agent-child-stop-control-conflict/v1\",\"status\":\"running\",\"execution_revision\":7}}}" + " ".repeat(1 << 20)).getBytes(StandardCharsets.UTF_8),
        };
        HttpServer platform = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        platform.createContext("/", exchange -> {
            try {
                byte[] body;
                int status = 200;
                if (exchange.getRequestURI().getPath().endsWith("/renew")) {
                    var claims = tokenClaims(exchange.getRequestHeaders().getFirst("X-Platform-Context").substring(7));
                    claims.put("exp", now + 60);
                    body = JSON.writeValueAsBytes(Map.of("data", Map.of("context_token", sign(claims))));
                } else {
                    body = responses[Math.min(call.getAndIncrement(), responses.length - 1)];
                    status = 409;
                }
                exchange.sendResponseHeaders(status, body.length);
                exchange.getResponseBody().write(body);
            } catch (Exception error) {
                throw new java.io.IOException("stop control fixture failed", error);
            } finally { exchange.close(); }
        });
        platform.start();
        try {
            var client = new CapabilityClient(config(platform), request("run"));
            var validFailure = assertThrows(CapabilityClient.Failure.class,
                () -> client.cancelAgentChild("stop-op", 0, "a".repeat(64), 6));
            assertEquals("AGENT_STOP_REVISION_CONFLICT", validFailure.code());
            assertEquals(409, validFailure.status());
            assertFalse(validFailure.retryable());
            assertEquals(valid.get("stop_control"), validFailure.details().get("stop_control"));
            assertEquals(validFailure.details(), validFailure.appError().details());

            var extraFailure = assertThrows(CapabilityClient.Failure.class,
                () -> client.cancelAgentChild("stop-op", 0, "a".repeat(64), 6));
            assertEquals(Map.of(), extraFailure.details());
            assertFalse(extraFailure.getMessage().contains("private-sentinel"));

            var malformedFailure = assertThrows(CapabilityClient.Failure.class,
                () -> client.cancelAgentChild("stop-op", 0, "a".repeat(64), 6));
            assertEquals(Map.of(), malformedFailure.details());

            var ordinaryFailure = assertThrows(CapabilityClient.Failure.class,
                () -> client.cancelAgentChild("stop-op", 0, "a".repeat(64), 6));
            assertEquals("AGENT_ROUTE_CONFLICT", ordinaryFailure.code());
            assertEquals(Map.of(), ordinaryFailure.details());

            var oversizedFailure = assertThrows(CapabilityClient.Failure.class,
                () -> client.cancelAgentChild("stop-op", 0, "a".repeat(64), 6));
            assertEquals("CAPABILITY_RENEWAL_UNAVAILABLE", oversizedFailure.code());
            assertEquals(Map.of(), oversizedFailure.details());
            assertEquals(5, call.get(), "the SDK must not retry the caller's positive CAS automatically");
        } finally { platform.stop(0); }
    }
    @Test
    void childCapabilityPreservesParentAcrossRenewal() throws Exception {
        for (String mode : List.of("same", "changed", "removed")) {
            var calls = new AtomicInteger(); var renewals = new AtomicInteger();
            HttpServer platform = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            platform.createContext("/", exchange -> {
                try {
                    var envelope = JSON.readTree(exchange.getRequestBody().readAllBytes());
                    assertEquals("parent-root", envelope.path("context").path("parent_run_id").asText());
                    Map<String,Object> result;
                    if (exchange.getRequestURI().getPath().endsWith("/renew")) {
                        renewals.incrementAndGet();
                        var claims = tokenClaims(exchange.getRequestHeaders().getFirst("X-Platform-Context").substring(7));
                        claims.put("exp", now + 120);
                        if (mode.equals("changed")) claims.put("parent_run_id", "another-parent");
                        if (mode.equals("removed")) claims.remove("parent_run_id");
                        result = Map.of("context_token", sign(claims));
                    } else { calls.incrementAndGet(); result = Map.of("text", "answer"); }
                    byte[] body = JSON.writeValueAsBytes(Map.of("data", result));
                    exchange.sendResponseHeaders(200, body.length); exchange.getResponseBody().write(body);
                } catch (Exception error) { throw new java.io.IOException("child lineage fixture failed", error); }
                finally { exchange.close(); }
            }); platform.start();
            try {
                var original = request("invoke"); var s = original.scope();
                var scope = new ScopeKey(s.tenantId(), s.departmentId(), s.applicationId(), s.agentInstanceId(), s.installationId(), s.agentId(), s.agentVersionId(), s.principalType(), s.principalId(), s.sessionId(), s.runId(), s.authorizationEpoch(), s.traceId(), "parent-root", 1);
                var unsigned = new ExecuteRequest(original.protocolVersion(), "", scope, original.operation(), original.idempotencyKey(), original.inputSchema(), original.input());
                var claims = tokenClaims(original.contextToken()); claims.put("parent_run_id", "parent-root"); claims.put("body_hash", ContextVerifier.canonicalBodyHash(unsigned));
                var request = new ExecuteRequest(unsigned.protocolVersion(), sign(claims), scope, unsigned.operation(), unsigned.idempotencyKey(), unsigned.inputSchema(), unsigned.input());
                var client = new CapabilityClient(config(platform), request);
                if (mode.equals("same")) { assertEquals("answer", client.post("/internal/model/generate", Map.of()).get("text")); assertEquals(1, calls.get()); }
                else { var error = assertThrows(CapabilityClient.Failure.class, () -> client.post("/internal/model/generate", Map.of())); assertEquals("CAPABILITY_RENEWAL_DENIED", error.code()); assertEquals(0, calls.get()); }
                assertEquals(1, renewals.get());
            } finally { platform.stop(0); }
        }
    }

    @Test
    void groupWaitAcceptsExactWireIntegersAndRejectsChangedState() throws Exception {
        for (boolean tamper : List.of(false, true)) {
            var stored = new java.util.concurrent.atomic.AtomicReference<Map<String,Object>>();
            var admissions = new AtomicInteger(); var gathers = new AtomicInteger();
            HttpServer platform = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            platform.createContext("/", exchange -> {
                try {
                    String path = exchange.getRequestURI().getPath();
                    JsonNode input = JSON.readTree(exchange.getRequestBody().readAllBytes()).path("input");
                    assertNotNull(exchange.getRequestHeaders().getFirst("X-Context-Signature"));
                    Map<String,Object> result;
                    if (path.endsWith("/renew")) {
                        var claims = tokenClaims(exchange.getRequestHeaders().getFirst("X-Platform-Context").substring(7));
                        claims.put("exp", now + 120); result = Map.of("context_token", sign(claims));
                    } else if (path.endsWith("/checkpoint")) {
                        if ("save".equals(input.path("operation").asText())) {
                            long revision = input.path("expected_revision").asLong() + 1;
                            stored.set(Map.of("revision", revision, "schema_id", AgentGroupRunner.STATE_SCHEMA,
                                    "value", JSON.convertValue(input.path("value"), Map.class),
                                    "content_hash", "a".repeat(64), "expires_at", Instant.ofEpochSecond(now+300).toString(),
                                    "execution_revision", 3));
                        }
                        var cp = stored.get();
                        if (tamper && gathers.get() > 0 && cp != null) {
                            var changed = new LinkedHashMap<String,Object>(cp);
                            var value = new LinkedHashMap<String,Object>((Map<String,Object>) cp.get("value"));
                            value.put("ordinal", 0); changed.put("value", value); cp = changed;
                        }
                        result = new LinkedHashMap<>(); result.put("state_key", "b".repeat(64)); result.put("checkpoint", cp);
                    } else if (path.endsWith("/route")) {
                        result = Map.of("route", Map.of("version","agent-route/v1","parent_run_id","invoke-run",
                                "operation_key","teaching-support","task_type","documents.answer","child_depth",1,
                                "targets",List.of(Map.of("installation_id","docs-install","agent_id","docs-agent","version_id","docs-v1",
                                        "input_schema","schema://docs/input/v1","output_schema","schema://docs/output/v1"))));
                    } else if (path.endsWith("/prepare")) {
                        result = Map.of("preparation", Map.of("version","agent-child-preparation/v1","parent_run_id","invoke-run",
                                "operation_key","teaching-support","ordinal",0,"status","preparing","revision",2,
                                "input_schema","schema://docs/input/v1","child_key","c".repeat(64),"input_fingerprint","d".repeat(64)));
                    } else if (path.endsWith("/admit")) {
                        admissions.incrementAndGet(); result = Map.of("admission", Map.of("version","agent-child-admission/v1",
                                "parent_run_id","invoke-run","operation_key","teaching-support","ordinal",0,
                                "child_key","c".repeat(64),"child_run_id","child-"+"c".repeat(48),"input_fingerprint","d".repeat(64),
                                "revision",3,"status","accepted"));
                    } else if (path.endsWith("/gather")) {
                        gathers.incrementAndGet(); var child = new LinkedHashMap<String,Object>();
                        child.put("version","agent-child-result/v1"); child.put("parent_run_id","invoke-run"); child.put("operation_key","teaching-support");
                        child.put("ordinal",0); child.put("child_key","c".repeat(64)); child.put("child_run_id","child-"+"c".repeat(48));
                        child.put("execution_revision",3); child.put("status","running"); child.put("output_schema","schema://docs/output/v1");
                        child.put("instruction_trust","untrusted_data"); child.put("output_bytes",0); child.put("output_omitted",false); child.put("output",null);
                        var group = new LinkedHashMap<String,Object>(); group.put("version","agent-group-result/v1"); group.put("operation_key","teaching-support");
                        group.put("parent_run_id","invoke-run"); group.put("instruction_trust","untrusted_data"); group.put("status","in_progress");
                        group.put("terminal",false); group.put("outputs_complete",false); group.put("children",List.of(child));
                        for(String key:List.of("completed","failed","cancelled","outputs_omitted")) group.put(key,0); group.put("pending",1);
                        result = Map.of("group",group);
                    } else { throw new java.io.IOException("unexpected fixture capability"); }
                    byte[] response = JSON.writeValueAsBytes(Map.of("data", result));
                    exchange.sendResponseHeaders(200,response.length); exchange.getResponseBody().write(response);
                } catch (Exception error) { throw new java.io.IOException("group fixture failed",error); }
                finally { exchange.close(); }
            });
            platform.start();
            try {
                var client = new CapabilityClient(config(platform),request("invoke"));
                var options = new AgentGroupRunner.Options("teaching-group","teaching-support","documents.answer");
                if (tamper) {
                    var error = assertThrows(CapabilityClient.Failure.class,()->client.runAgentGroup(List.of(Map.of("question","teaching")),options));
                    assertEquals("AGENT_GROUP_STATE_REJECTED",error.code());
                } else {
                    var pause = assertThrows(AgentGroupPause.class,()->client.runAgentGroup(List.of(Map.of("question","teaching")),options));
                    assertEquals("teaching-group",pause.groupKey());
                }
                assertEquals(1,admissions.get()); assertEquals(1,gathers.get());
            } finally { platform.stop(0); }
        }
    }

    @Test
    void completedGroupContinuationStartsHarnessAndOrdinaryResumeStillRequiresHead() throws Exception {
        for (boolean groupResume : List.of(false, true)) {
            var contexts = new AtomicInteger();
            HttpServer platform = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            platform.createContext("/", exchange -> {
                try {
                    String path = exchange.getRequestURI().getPath(); Map<String,Object> result;
                    if (path.endsWith("/renew")) {
                        var claims = tokenClaims(exchange.getRequestHeaders().getFirst("X-Platform-Context").substring(7));
                        claims.put("exp", now+120); result = Map.of("context_token",sign(claims));
                    } else if (path.endsWith("/gather")) {
                        var child = new LinkedHashMap<String,Object>();
                        child.put("version","agent-child-result/v1"); child.put("parent_run_id","resume-run");
                        child.put("operation_key","teaching-support"); child.put("ordinal",0); child.put("child_key","c".repeat(64));
                        child.put("child_run_id","child-"+"c".repeat(48)); child.put("status","completed");
                        child.put("execution_revision",4); child.put("output_schema","schema://documents/output/v2");
                        child.put("output_bytes",19); child.put("output_omitted",false); child.put("output",Map.of("text","teaching"));
                        child.put("output_digest","d".repeat(64)); child.put("instruction_trust","untrusted_data");
                        var group = new LinkedHashMap<String,Object>();
                        group.put("version","agent-group-result/v1"); group.put("parent_run_id","resume-run");
                        group.put("operation_key","teaching-support"); group.put("instruction_trust","untrusted_data");
                        group.put("status","completed"); group.put("terminal",true); group.put("outputs_complete",true);
                        group.put("completed",1); group.put("failed",0); group.put("cancelled",0); group.put("pending",0);
                        group.put("outputs_omitted",0); group.put("children",List.of(child)); result=Map.of("group",group);
                    } else if (path.endsWith("/harness-policy")) {
                        result=Map.of("version","harness-policy/v1","policy_hash","a".repeat(64),"server_time_ms",now*1000,
                            "limits",Map.of("max_rounds",8,"max_tool_calls",16,"max_repeated_calls",1,"max_elapsed_seconds",300,"limit_behavior","incomplete"));
                    } else if (path.endsWith("/checkpoint")) {
                        result=new LinkedHashMap<>(); result.put("state_key","b".repeat(64)); result.put("checkpoint",null);
                    } else if (path.endsWith("/context/prepare")) {
                        contexts.incrementAndGet(); byte[] body=JSON.writeValueAsBytes(Map.of("error_code","FIXTURE_AFTER_START"));
                        exchange.sendResponseHeaders(403,body.length); exchange.getResponseBody().write(body);return;
                    } else throw new java.io.IOException("unexpected teaching fixture operation");
                    byte[] body=JSON.writeValueAsBytes(Map.of("data",result)); exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);
                } catch (Exception error) { throw new java.io.IOException("continuation fixture failed",error); }
                finally { exchange.close(); }
            }); platform.start();
            try {
                var client=new CapabilityClient(config(platform),request("resume"));
                if(groupResume) {
                    var handoff=new ExecutionContract.AgentGroupHandoff("agent-group-handoff/v1","resume-run",3,"a".repeat(64),"c".repeat(64),client.businessInputFingerprint(),"run","teaching-group","teaching-support",0,Map.of(),List.of("c".repeat(64)));
                    var binding=new AgentGroupResumeBinding(handoff,"d".repeat(64)); client.bindAgentGroupResume(binding);
                    client.authorizeAgentGroupInvocation("teaching-group","teaching-support","d".repeat(64));
                    client.markAgentGroupResumeCheckpointVerified(binding);
                    client.gatherAgentChildren("teaching-support",List.of(new CapabilityClient.AgentChildBinding("c".repeat(64),"schema://documents/output/v2")));
                    assertFalse(client.isAgentGroupResume());
                }
                var error=assertThrows(CapabilityClient.Failure.class,()->client.runHarness(Map.of("messages",List.of(Map.of("role","user","content","teaching")),"idempotency_key","after-group"),new HarnessRunner.Options("after-group",3,4)));
                assertEquals(groupResume ? "FIXTURE_AFTER_START" : "HARNESS_STATE_REJECTED",error.code());
                assertEquals(groupResume ? 1 : 0,contexts.get(),"only a consumed verified Gather may start a new Harness");
            } finally { platform.stop(0); }
        }
    }

}
