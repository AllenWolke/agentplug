package generated;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.lexagent.sdk.ContextVerifier;
import com.lexagent.sdk.ExecutionContract.ExecuteRequest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;

/**
 * Runnable self-check for the vendored PEP: it verifies the shared
 * Go-SDK-signed capability fixture, recomputes the canonical body hash and shows
 * that forged, tampered and mis-scoped capabilities are rejected. Unlike the
 * historical hand-rolled check it exercises the REAL platform SDK, so it also
 * proves the vendored copy behaves like the source of truth.
 *
 * vendored PEP 的可运行自检：校验由 Go SDK 一次性签名的共享能力夹具、重算规范化
 * 正文哈希，并证明伪造/篡改/越权令牌被拒绝。与旧的手写检查不同，它驱动的是真实
 * 平台 SDK，因此也证明 vendored 副本与事实源行为一致。
 */
public final class CapabilitySelfCheck {
    private static final ObjectMapper JSON = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .findAndRegisterModules();

    private CapabilitySelfCheck() {}

    public static void main(String[] args) throws Exception {
        Path fixture = Path.of(args.length > 0 ? args[0]
                : "../../../contracts/fixtures/execution-v2-capability.json");
        var root = JSON.readTree(Files.readAllBytes(fixture));
        String expectedHash = root.get("body_hash").asText();
        String issuer = root.get("issuer").asText();
        String audience = root.get("audience").asText();
        PublicKey key = PlatformKey.publicKeyFromBase64(root.get("public_key_b64").asText());
        require(key != null, "the fixture public key did not decode");

        ExecuteRequest request = JSON.treeToValue(root.get("request"), ExecuteRequest.class);

        // 1. Canonicalization must match the signature produced by the Go SDK.
        String hash = ContextVerifier.canonicalBodyHash(request);
        require(hash.equals(expectedHash), "canonical body hash drifted: " + hash + " != " + expectedHash);

        // The fixture pins its own timestamp; the injected clock verifies it
        // deterministically instead of depending on the wall clock.
        // 夹具钉死时间戳；注入时钟使其确定性校验，而不依赖真实时钟。
        long now = root.get("now").asLong();

        // 2. A Gateway-signed capability is accepted.
        ContextVerifier verifier = new ContextVerifier(() -> now);
        verifier.verify(request, key, issuer, audience);

        // 3. Forged, tampered and mis-scoped capabilities are rejected.
        reject(verifier, key, issuer, audience, withToken(request, "0123456789abcdef0123456789abcdef"),
                "length-only token");
        reject(verifier, key, issuer, audience, tamperedBody(request), "tampered body");
        reject(verifier, key, issuer, audience, otherIdempotency(request), "tampered idempotency");
        reject(verifier, key, issuer, audience, otherOperation(request), "undelegated action");
        reject(verifier, key, issuer, "another-agent", request, "wrong audience");
        reject(new ContextVerifier(() -> now + 3600), key, issuer, audience, request, "expired lifetime");

        System.out.println("capability self-check: OK (" + hash.substring(0, 16) + "...)");
    }

    private static ExecuteRequest withToken(ExecuteRequest request, String token) {
        return new ExecuteRequest(request.protocolVersion(), token, request.scope(), request.operation(),
                request.idempotencyKey(), request.inputSchema(), request.input());
    }

    private static ExecuteRequest tamperedBody(ExecuteRequest request) {
        var input = new java.util.LinkedHashMap<>(request.input());
        input.put("injected", "value");
        return copy(request, request.idempotencyKey(), request.operation(), input);
    }

    private static ExecuteRequest otherIdempotency(ExecuteRequest request) {
        return copy(request, "other-key", request.operation(), request.input());
    }

    private static ExecuteRequest otherOperation(ExecuteRequest request) {
        return copy(request, request.idempotencyKey(), "run", request.input());
    }

    private static ExecuteRequest copy(ExecuteRequest request, String idempotency, String operation,
            java.util.Map<String, Object> input) {
        return new ExecuteRequest(request.protocolVersion(), request.contextToken(), request.scope(),
                operation, idempotency, request.inputSchema(), input);
    }

    private static void reject(ContextVerifier verifier, PublicKey key, String issuer, String audience,
            ExecuteRequest request, String label) {
        try {
            verifier.verify(request, key, issuer, audience);
        } catch (SecurityException expected) {
            return;
        }
        throw new AssertionError(label + " was accepted");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
