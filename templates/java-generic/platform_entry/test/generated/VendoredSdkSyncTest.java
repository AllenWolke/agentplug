package generated;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.lexagent.sdk.ExecutionServer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Vendored SDK sync check, mirroring the Go and Python templates' sync tests.
 *
 * 钉住单一事实源规则：vendored 平台 SDK 副本必须与 sdk/java/agent-platform-sdk
 * 逐字节一致。生成项目独立存在（SDK 兄弟目录缺失）时跳过。
 */
final class VendoredSdkSyncTest {
    private static final Path VENDOR = Path.of("platform_entry", "com", "lexagent", "sdk");
    private static final Path SDK_ROOT = Path.of("..", "..", "sdk", "java", "agent-platform-sdk",
            "src", "main", "java", "com", "lexagent", "sdk");
    private static final List<String> FILES = List.of(
            "ContextVerifier.java", "ExecutionContract.java", "Lifecycle.java", "MemoryRunStore.java",
            "ServerConfig.java", "ExecutionServer.java", "ExecutionTracker.java", "Tracing.java", "CapabilityClient.java");

    @Test
    void vendoredSdkStaysInSyncWithTheSourceOfTruth() throws Exception {
        assumeTrue(Files.isDirectory(SDK_ROOT), "platform SDK sibling not present (standalone generated project)");
        for (String name : FILES) {
            byte[] source = Files.readAllBytes(SDK_ROOT.resolve(name));
            byte[] vendored = Files.readAllBytes(VENDOR.resolve(name));
            assertEquals(new String(source), new String(vendored),
                    "vendored " + name + " drifted from the platform SDK; re-vendor it");
        }
        // The template must drive the SDK transport, never a parallel one.
        // 模板必须驱动 SDK 传输层，绝不是并行实现。
        assertEquals("com.lexagent.sdk", ExecutionServer.class.getPackageName());
    }
}
