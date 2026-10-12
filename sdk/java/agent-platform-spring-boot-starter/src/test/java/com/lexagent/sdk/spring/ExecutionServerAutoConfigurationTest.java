package com.lexagent.sdk.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.lexagent.sdk.ExecutionServer;
import com.lexagent.sdk.Tracing.NoopTracer;
import com.lexagent.sdk.Tracing.Tracer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.web.server.context.ServerPortInfoApplicationContextInitializer;

/** Auto-configuration tests: fail closed without platform material, wire the
 * full surface when it is present. / 自动装配测试：平台材料缺失即失败闭合；
 * 齐备时装配完整接口面。
 */
final class ExecutionServerAutoConfigurationTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(new ServerPortInfoApplicationContextInitializer())
            .withConfiguration(AutoConfigurations.of(ExecutionServerAutoConfiguration.class));

    private String rawKeyBase64() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        // Extract the raw 32 bytes from the X.509 form the JDK hands out.
        // 从 JDK 给出的 X.509 形式中提取原始 32 字节。
        byte[] spki = pair.getPublic().getEncoded();
        byte[] raw = new byte[32];
        System.arraycopy(spki, spki.length - 32, raw, 0, 32);
        return Base64.getEncoder().encodeToString(raw);
    }

    @Test
    void missingPlatformMaterialFailsClosed() {
        runner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasMessageContaining("agent-platform");
        });
    }

    @Test
    void configuresTheFullSurfaceWhenMaterialIsPresent() throws Exception {
        String key = rawKeyBase64();
        runner.withPropertyValues(
                "agent-platform.audience=spring-agent",
                "agent-platform.public-key-base64=" + key,
                "agent-platform.port=0")
                .run(context -> {
                    assertThat(context).hasSingleBean(ExecutionServer.class);
                    assertThat(context.getBean(Tracer.class)).isInstanceOf(NoopTracer.class);
                    // The boundary never binds the manifest port until the
                    // lifecycle starts; port 0 keeps tests conflict-free.
                    // 生命周期启动前不绑定；port 0 避免测试冲突。
                    assertThat(context).hasBean("executionServerLifecycle");
                });
    }

    @Test
    void blankOtlpEndpointYieldsTheNoopTracer() throws Exception {
        runner.withPropertyValues(
                "agent-platform.audience=spring-agent",
                "agent-platform.public-key-base64=" + rawKeyBase64(),
                "agent-platform.port=0",
                "agent-platform.otlp-endpoint=")
                .run(context -> assertThat(context.getBean(Tracer.class)).isInstanceOf(NoopTracer.class));
    }
}
