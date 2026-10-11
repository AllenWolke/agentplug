package generated;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.lexagent.sdk.ContextVerifier;
import com.lexagent.sdk.ExecutionContract.ExecuteRequest;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/** Cross-language capability fixture test: the Go SDK signed this token once and
 * every language template must recompute the identical canonical body hash and
 * accept the token with a pinned clock.
 * 跨语言能力夹具测试：该令牌由 Go SDK 一次性签名，各语言模板必须重算出逐字节
 * 一致的规范化正文哈希，并在钉住时钟下接受该令牌。
 */
final class CapabilityFixtureTest {
    private final ObjectMapper mapper = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .findAndRegisterModules();

    @Test
    void canonicalBodyHashMatchesTheSharedCapabilityFixture() throws Exception {
        Path fixture = Path.of("..", "..", "contracts", "fixtures", "execution-v2-capability.json");
        assumeTrue(Files.exists(fixture), "shared capability fixture not present (standalone generated project)");
        var root = mapper.readTree(Files.readAllBytes(fixture));
        ExecuteRequest request = mapper.treeToValue(root.get("request"), ExecuteRequest.class);
        assertEquals(root.get("body_hash").asText(), ContextVerifier.canonicalBodyHash(request));
    }

    @Test
    void gatewaySignedCapabilityVerifiesWithAPinnedClock() throws Exception {
        Path fixture = Path.of("..", "..", "contracts", "fixtures", "execution-v2-capability.json");
        assumeTrue(Files.exists(fixture), "shared capability fixture not present (standalone generated project)");
        var root = mapper.readTree(Files.readAllBytes(fixture));
        ExecuteRequest request = mapper.treeToValue(root.get("request"), ExecuteRequest.class);
        long now = root.get("now").asLong();
        var claims = new ContextVerifier(() -> now).verify(request,
                PlatformKey.publicKeyFromBase64(root.get("public_key_b64").asText()),
                root.get("issuer").asText(), root.get("audience").asText());
        assertEquals("user-a", claims.subjectId());
    }
}
