package com.lexagent.sdk;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EvaluationParentCapabilityTest {
    private static String token(KeyPair key, ExecutionContract.ExecuteRequest request, String parent) throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", "platform"); claims.put("aud", "agent-runtime");
        claims.put("subject_type", "user"); claims.put("sub", "owner");
        claims.put("tenant_id", "tenant"); claims.put("application_id", "app");
        claims.put("agent_instance_id", "instance"); claims.put("installation_id", "installation");
        claims.put("authorization_epoch", 4); claims.put("actions", List.of("invoke"));
        claims.put("policy_snapshot_hash", "policy-v1");
        claims.put("body_hash", ContextVerifier.canonicalBodyHash(request));
        claims.put("iat", 1000); claims.put("exp", 1120); claims.put("parent_run_id", parent);
        var encoder = Base64.getUrlEncoder().withoutPadding();
        String message = encoder.encodeToString("{\"alg\":\"EdDSA\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8))
                + "." + encoder.encodeToString(new ObjectMapper().writeValueAsBytes(claims));
        var signer = Signature.getInstance("Ed25519"); signer.initSign(key.getPrivate());
        signer.update(message.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return message + "." + encoder.encodeToString(signer.sign());
    }
    @Test void signedEvaluationParentIsDecodedAndBound() throws Exception {
        var key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var scope = new ExecutionContract.ScopeKey("tenant", "department", "app", "instance", "installation",
                "agent", "version", "user", "owner", "session", "run", 4, "trace", "evaluation-parent", 0);
        var input = Map.<String, Object>of("policy_snapshot", Map.of("content_hash", "policy-v1"));
        var original = new ExecutionContract.ExecuteRequest("agent-execution/v2", "", scope, "invoke", "key", "schema", input);
        var request = new ExecutionContract.ExecuteRequest(original.protocolVersion(), token(key, original, "evaluation-parent"),
                scope, "invoke", "key", "schema", input);
        var verifier = new ContextVerifier(() -> 1001L);
        assertEquals("evaluation-parent", verifier.verify(request, key.getPublic(), "platform", "agent-runtime").parentRunId());
        var mismatched = new ExecutionContract.ExecuteRequest(original.protocolVersion(), token(key, original, "another-parent"),
                scope, "invoke", "key", "schema", input);
        assertThrows(SecurityException.class, () -> verifier.verify(mismatched, key.getPublic(), "platform", "agent-runtime"));
    }
}
