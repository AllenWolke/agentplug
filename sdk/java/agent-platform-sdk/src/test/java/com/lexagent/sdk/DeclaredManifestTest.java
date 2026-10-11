package com.lexagent.sdk;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPairGenerator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class DeclaredManifestTest {
    private final ObjectMapper json = new ObjectMapper();

    private ServerConfig configuration(String manifest) throws Exception {
        return ServerConfig.builder().publicKey(KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic())
                .issuer("platform").audience("runtime").agentId("test-agent").agentVersion("0.1.1")
                .store(new MemoryRunStore()).capabilities(List.of("invoke"))
                .invoke((request, capabilities) -> Map.of()).manifest(manifest).build();
    }

    private ObjectNode declaration() throws Exception {
        return (ObjectNode) json.readTree("""
            {"manifest_version":"agent-manifest/v1","agent_id":"test-agent","version":"0.1.1",
             "execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],
             "schemas":{"input":"schema://test-agent/input/v2","output":"schema://test-agent/output/v17"},
             "runtime":{"transport":"http","isolation":"container","health_path":"/health/ready",
                        "run_store":"memory-dev-only(L2/L3 forbidden)"},"metadata":{"business":"demonstration"}}
            """);
    }

    @Test void servesCompleteDeclaration() throws Exception {
        var expected = declaration();
        var execution = new ExecutionServer(configuration(expected.toString()));
        var http = execution.start(new InetSocketAddress("127.0.0.1", 0));
        try {
            var response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"
                    + http.getAddress().getPort() + "/.well-known/agent-manifest.json")).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode());
            assertEquals(expected, json.readTree(response.body()));
        } finally { http.stop(0); execution.stop(); }
    }

    @Test void refusesInconsistentDeclarations() throws Exception {
        for (String mutation : List.of(
                "identity", "version", "capabilities", "durability",
                "schema-zero", "schema-leading-zero", "schema-foreign-agent",
                "schema-extra-path", "schema-fragment", "schema-query")) {
            var root = declaration();
            var schemas = (ObjectNode) root.get("schemas");
            switch (mutation) {
                case "identity" -> root.put("agent_id", "other-agent");
                case "version" -> root.put("version", "0.0.0");
                case "capabilities" -> root.putArray("capabilities").add("invoke").add("run");
                case "durability" -> ((ObjectNode)root.get("runtime")).put("run_store", "durable");
                case "schema-zero" -> schemas.put("input", "schema://test-agent/input/v0");
                case "schema-leading-zero" -> schemas.put("output", "schema://test-agent/output/v01");
                case "schema-foreign-agent" -> schemas.put("input", "schema://other-agent/input/v2");
                case "schema-extra-path" -> schemas.put("output", "schema://test-agent/output/v17/extra");
                case "schema-fragment" -> schemas.put("input", "schema://test-agent/input/v2#fragment");
                case "schema-query" -> schemas.put("output", "schema://test-agent/output/v17?version=17");
            }
            var cfg = configuration(root.toString());
            assertThrows(ServerConfig.ServerConfigError.class, () -> new ExecutionServer(cfg), mutation);
        }
    }
}
