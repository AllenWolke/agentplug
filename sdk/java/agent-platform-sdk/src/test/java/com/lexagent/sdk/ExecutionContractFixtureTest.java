package com.lexagent.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

final class ExecutionContractFixtureTest {
    private final ObjectMapper mapper = new ObjectMapper()
        .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
        .findAndRegisterModules();

    @Test
    void resumeDecisionChangesTheSignedDigest() {
        // Never sign only the original input while ignoring the review decision.
        // 不得只签原始输入而遗漏审核恢复决策。
        var scope = new ExecutionContract.ScopeKey("t", "d", "a", "i", "install", "agent", "v", "user", "u", "s", "r", 1, "trace", null, 0);
        var input = java.util.Map.<String, Object>of("question", "q");
        var approved = new ExecutionContract.ExecuteRequest("agent-execution/v2", "", scope, "resume", "key", "schema", input, java.util.Map.of("decision", "approve"));
        var rejected = new ExecutionContract.ExecuteRequest("agent-execution/v2", "", scope, "resume", "key", "schema", input, java.util.Map.of("decision", "reject"));
        var empty = new ExecutionContract.ExecuteRequest("agent-execution/v2", "", scope, "resume", "key", "schema", input, java.util.Map.of());
        var missing = new ExecutionContract.ExecuteRequest("agent-execution/v2", "", scope, "resume", "key", "schema", input);
        assertNotEquals(ContextVerifier.canonicalBodyHash(approved), ContextVerifier.canonicalBodyHash(rejected));
        assertNotEquals(ContextVerifier.canonicalBodyHash(empty), ContextVerifier.canonicalBodyHash(missing));
    }

    @Test
    void sharedResumeDigestMatchesPythonAndGo() throws Exception {
        Path fixture = Path.of("..", "..", "..", "contracts", "fixtures", "execution-v2-request.json");
        var original = mapper.readValue(Files.readAllBytes(fixture), ExecutionContract.ExecuteRequest.class);
        var resumed = new ExecutionContract.ExecuteRequest(original.protocolVersion(), original.contextToken(), original.scope(), "resume", original.idempotencyKey(), original.inputSchema(), original.input(), java.util.Map.of("decision", "approve", "reviewer_id", "reviewer-a"));
        assertEquals("b3b300c491c0e717dd493556b96cef294c30fcc93cd3eea53fb5beb986a1530a", ContextVerifier.canonicalBodyHash(resumed));
    }

    @Test
    void decodesAndReencodesSharedExecutionFixture() throws Exception {
        // Resolve the repository fixture instead of maintaining a Java-only copy.
        // 直接读取仓库公共 fixture，避免 Java 端形成第二套契约。
        Path fixture = Path.of("..", "..", "..", "contracts", "fixtures", "execution-v2-request.json");
        byte[] raw = Files.readAllBytes(fixture);
        ExecutionContract.ExecuteRequest request = mapper.readValue(raw, ExecutionContract.ExecuteRequest.class);

        assertEquals(ExecutionContract.PROTOCOL_VERSION, request.protocolVersion());
        assertEquals(3L, request.scope().authorizationEpoch());
        assertEquals("run", request.operation());
        assertEquals(mapper.readTree(raw), mapper.readTree(mapper.writeValueAsBytes(request)));
    }

    @Test
    void canonicalBodyHashMatchesTheSharedCapabilityFixture() throws Exception {
        // The shared Ed25519 fixture is signed once; every language SDK must recompute
        // the same body hash byte for byte. / 该公共夹具一次性签名；各语言
        // SDK 必须逐字节重算出同一正文哈希。
        Path fixture = Path.of("..", "..", "..", "contracts", "fixtures", "execution-v2-capability.json");
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.exists(fixture), "shared capability fixture not present");
        var root = mapper.readTree(Files.readAllBytes(fixture));
        ExecutionContract.ExecuteRequest request = mapper.treeToValue(root.get("request"),
                ExecutionContract.ExecuteRequest.class);
        assertEquals(root.get("body_hash").asText(), ContextVerifier.canonicalBodyHash(request));
    }
}
