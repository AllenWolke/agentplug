package com.lexagent.sdk.spring;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.lexagent.sdk.ContextVerifier;
import com.lexagent.sdk.ExecutionContract;
import com.lexagent.sdk.ExecutionContract.CapabilityClaims;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/** Interceptor tests over real MockMvc: the cached-body filter + the capability
 * interceptor enforce the same fail-closed ladder as the SDK transport.
 * 真实 MockMvc 拦截器测试：缓存正文过滤器 + 能力拦截器执行与 SDK 传输层一致的
 * 失败闭合阶梯。
 */
final class CapabilityVerifierInterceptorTest {
    private static final ObjectMapper JSON = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .findAndRegisterModules();
    private static final String ISSUER = "platform-runtime-gateway";
    private static final String AUDIENCE = "mvc-agent";

    private final KeyPair pair = keyPair();
    private final ContextVerifier verifier = new ContextVerifier();
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.standaloneSetup(new EchoController())
                .addFilters(new CachedBodyFilter())
                .addInterceptors(new CapabilityVerifierInterceptor(pair.getPublic(), ISSUER, AUDIENCE))
                .build();
    }

    private static KeyPair keyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    @RestController
    static final class EchoController {
        @PostMapping("/internal/agent-execution/v2/invoke")
        Map<String, Object> invoke(@org.springframework.web.bind.annotation.RequestBody
                Map<String, Object> body, jakarta.servlet.http.HttpServletRequest request) {
            CapabilityClaims claims = (CapabilityClaims) request.getAttribute(
                    CapabilityVerifierInterceptor.TRUSTED_CLAIMS);
            return Map.of("subject", claims.subjectId(), "input", body.get("input"));
        }
    }

    private Map<String, Object> envelope() {
        Map<String, Object> scope = new LinkedHashMap<>();
        scope.put("tenant_id", "tenant-a");
        scope.put("department_id", "business-department");
        scope.put("application_id", "business-app");
        scope.put("agent_instance_id", "instance-a");
        scope.put("installation_id", "installation-a");
        scope.put("agent_id", AUDIENCE);
        scope.put("agent_version_id", "v2");
        scope.put("principal_type", "user");
        scope.put("principal_id", "user-a");
        scope.put("session_id", "session-a");
        scope.put("run_id", "run-mvc");
        scope.put("authorization_epoch", 1);
        scope.put("trace_id", "0".repeat(32));
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("protocol_version", ExecutionContract.PROTOCOL_VERSION);
        envelope.put("scope", scope);
        envelope.put("operation", "invoke");
        envelope.put("idempotency_key", "idem-key-0001");
        envelope.put("input_schema", "schema://example/input/v1");
        envelope.put("input", Map.of("policy_snapshot", Map.of("content_hash", "a".repeat(64))));
        return envelope;
    }

    private String token(Map<String, Object> envelope, List<String> actions, KeyPair signWith) throws Exception {
        ExecutionContract.ExecuteRequest request = JSON.convertValue(envelope,
                ExecutionContract.ExecuteRequest.class);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", ISSUER);
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
        claims.put("body_hash", ContextVerifier.canonicalBodyHash(request));
        long now = Instant.now().getEpochSecond();
        claims.put("iat", now);
        claims.put("exp", now + 120);
        return sign(claims, signWith);
    }

    private String sign(Map<String, Object> claims, KeyPair signWith) throws Exception {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString(JSON.writeValueAsBytes(Map.of("alg", "EdDSA", "typ", "JWT")));
        String payload = encoder.encodeToString(JSON.writeValueAsBytes(claims));
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(signWith.getPrivate());
        signature.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
        return header + "." + payload + "." + encoder.encodeToString(signature.sign());
    }

    @Test
    void verifiedCallersReachTheControllerWithTrustedClaims() throws Exception {
        Map<String, Object> envelope = envelope();
        String token = token(envelope, List.of("invoke"), pair);
        envelope.put("context_token", token);
        mvc.perform(post("/internal/agent-execution/v2/invoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + token)
                        .content(JSON.writeValueAsString(envelope)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("user-a"));
    }

    @Test
    void forgedKeysAndStolenHeadersAreRejected() throws Exception {
        KeyPair forged = keyPair();
        Map<String, Object> envelope = envelope();
        String token = token(envelope, List.of("invoke"), forged);
        envelope.put("context_token", token);
        mvc.perform(post("/internal/agent-execution/v2/invoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + token)
                        .content(JSON.writeValueAsString(envelope)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("CAPABILITY_INVALID"));

        // A stolen header cannot be paired with a different body.
        // 窃取的头部无法与别的正文配对。
        envelope = envelope();
        token = token(envelope, List.of("invoke"), pair);
        envelope.put("context_token", token);
        mvc.perform(post("/internal/agent-execution/v2/invoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer forged")
                        .content(JSON.writeValueAsString(envelope)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tamperedBodiesAndUndelegatedActionsAreRejected() throws Exception {
        Map<String, Object> envelope = envelope();
        String token = token(envelope, List.of("invoke"), pair);
        envelope.put("context_token", token);
        // Tamper the body AFTER minting so the body hash no longer matches;
        // the envelope maps are immutable, so copy first. / 铸造后篡改正文，使
        // 正文哈希不再匹配；信封里的 Map 不可变，先复制再改。
        Map<String, Object> input = new LinkedHashMap<>(cast(envelope.get("input")));
        input.put("injected", "value");
        envelope.put("input", input);
        mvc.perform(post("/internal/agent-execution/v2/invoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + token)
                        .content(JSON.writeValueAsString(envelope)))
                .andExpect(status().isUnauthorized());

        envelope = envelope();
        token = token(envelope, List.of(), pair);
        envelope.put("context_token", token);
        mvc.perform(post("/internal/agent-execution/v2/invoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + token)
                        .content(JSON.writeValueAsString(envelope)))
                .andExpect(status().isUnauthorized());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> cast(Object value) {
        return (Map<String, Object>) value;
    }
}
