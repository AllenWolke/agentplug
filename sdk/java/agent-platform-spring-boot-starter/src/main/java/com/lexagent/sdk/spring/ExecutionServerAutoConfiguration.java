package com.lexagent.sdk.spring;

import com.lexagent.sdk.ExecutionServer;
import com.lexagent.sdk.Lifecycle;
import com.lexagent.sdk.MemoryRunStore;
import com.lexagent.sdk.ServerConfig;
import com.lexagent.sdk.ServerConfig.InvokeHandler;
import com.lexagent.sdk.ServerConfig.RunHandler;
import com.lexagent.sdk.Tracing.Tracer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.annotation.Bean;

/** Auto-configures the platform boundary for Spring Boot applications.
 *
 * The SDK ExecutionServer (invoke plus the run/resume/cancel/events lifecycle)
 * starts with the application and fails closed when the platform-injected public
 * key is absent. The memory run store is development-only; production supplies
 * its own durable RunStore bean.
 *
 * 为 Spring Boot 应用自动装配平台边界：SDK ExecutionServer（invoke 与
 * run/resume/cancel/events 生命周期）随应用启动，公钥缺失即失败闭合；内存运行
 * 存储仅限开发，生产必须提供自己的持久化 RunStore Bean。
 */
@AutoConfiguration
@ConditionalOnClass(ExecutionServer.class)
@ConditionalOnProperty(prefix = "agent-platform", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AgentPlatformProperties.class)
public class ExecutionServerAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(Lifecycle.RunStore.class)
    Lifecycle.RunStore runStore() {
        // NOT FOR L2/L3: development default only; production registers a
        // scoped durable RunStore bean instead. / 不可用于 L2/L3：仅开发默认；
        // 生产注册带 Scope 的持久化 RunStore Bean 取而代之。
        return new MemoryRunStore();
    }

    @Bean
    @ConditionalOnMissingBean(Tracer.class)
    Tracer platformTracer(AgentPlatformProperties properties) {
        // An empty endpoint yields the no-op tracer; a configured endpoint with
        // missing OTel classes fails loudly inside Telemetry.setup.
        // 空端点返回 no-op tracer；配置了端点但缺 OTel 类时 Telemetry.setup 大声失败。
        return Telemetry.setup(agentId(properties), properties.getOtlpEndpoint()).tracer();
    }

    @Bean
    @ConditionalOnMissingBean(InvokeHandler.class)
    InvokeHandler invokeHandler() {
        return (request, capabilities) -> request.input();
    }

    @Bean
    @ConditionalOnMissingBean(RunHandler.class)
    RunHandler runHandler() {
        return (request, events, signals, capabilities) -> {
            events.append(Lifecycle.EVENT_PROGRESS, java.util.Map.of("stage", "business"));
            return request.input();
        };
    }

    @Bean
    ExecutionServer executionServer(AgentPlatformProperties properties, Lifecycle.RunStore store,
            Tracer tracer, InvokeHandler invoke, RunHandler run) throws Exception {
        return new ExecutionServer(ServerConfig.builder()
                .publicKey(publicKey(properties))
                .issuer(properties.getIssuer())
                .audience(audience(properties))
                .agentId(agentId(properties))
                .store(store)
                .capabilities(properties.getCapabilities())
                .tracer(tracer)
                .capability(com.lexagent.sdk.CapabilityClient.Config.fromEnvironment())
                .invoke(invoke)
                .run(run)
                .build());
    }

    @Bean
    SmartLifecycle executionServerLifecycle(ExecutionServer server, AgentPlatformProperties properties) {
        return new ExecutionServerLifecycle(server, properties.getPort());
    }

    /** MVC edge PEP for apps that expose the execution paths through their own
     * controllers. / 供通过自有控制器暴露执行路径的应用使用的 MVC 边 PEP。 */
    @Bean
    @org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication(
            type = org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnMissingBean
    CapabilityVerifierInterceptor capabilityVerifierInterceptor(AgentPlatformProperties properties) throws Exception {
        return new CapabilityVerifierInterceptor(publicKey(properties), properties.getIssuer(),
                audience(properties));
    }

    @Bean
    @org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication(
            type = org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnMissingBean
    org.springframework.boot.web.servlet.FilterRegistrationBean<CachedBodyFilter> cachedBodyFilter() {
        org.springframework.boot.web.servlet.FilterRegistrationBean<CachedBodyFilter> registration =
                new org.springframework.boot.web.servlet.FilterRegistrationBean<>(new CachedBodyFilter());
        registration.addUrlPatterns("/internal/agent-execution/v2/*");
        registration.setOrder(org.springframework.core.Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }

    private static String audience(AgentPlatformProperties properties) {
        if (properties.getAudience() == null || properties.getAudience().isBlank()) {
            throw new IllegalStateException("agent-platform.audience is required");
        }
        return properties.getAudience();
    }

    private static String agentId(AgentPlatformProperties properties) {
        if (properties.getAgentId() != null && !properties.getAgentId().isBlank()) {
            return properties.getAgentId();
        }
        return audience(properties);
    }

    /** Load the platform-injected Ed25519 public key; absent material fails
     * closed instead of serving an unverified surface. / 加载平台注入的
     * Ed25519 公钥；材料缺失即失败闭合，绝不以未验证状态服务。
     */
    private static PublicKey publicKey(AgentPlatformProperties properties) throws Exception {
        String value = properties.getPublicKeyBase64();
        if ((value == null || value.isBlank()) && properties.getPublicKeyFile() != null
                && !properties.getPublicKeyFile().isBlank()) {
            value = Files.readString(Path.of(properties.getPublicKeyFile())).trim();
        }
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("agent-platform.public-key-base64 is required");
        }
        byte[] raw = decode(value);
        if (raw.length == 32) {
            // Wrap the raw key into its X.509 SubjectPublicKeyInfo form so the
            // JDK KeyFactory accepts it. / 把原始密钥包成 X.509 SPKI 形式，
            // 供 JDK KeyFactory 使用。
            byte[] spki = new byte[12 + 32];
            System.arraycopy(hex("302a300506032b6570032100"), 0, spki, 0, 12);
            System.arraycopy(raw, 0, spki, 12, 32);
            raw = spki;
        }
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(raw));
    }

    private static byte[] decode(String value) {
        String padded = value + "=".repeat((4 - value.length() % 4) % 4);
        for (Base64.Decoder decoder : java.util.List.of(Base64.getUrlDecoder(), Base64.getDecoder())) {
            try {
                return decoder.decode(padded);
            } catch (IllegalArgumentException ignored) {
                // try the next alphabet / 尝试下一种字母表
            }
        }
        throw new IllegalStateException("agent-platform.public-key-base64 must be an Ed25519 public key");
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    /** Binds the JDK HTTP server lifecycle to the Spring context. / 把 JDK HTTP
     * 服务器生命周期挂到 Spring 上下文。 */
    static final class ExecutionServerLifecycle implements SmartLifecycle {
        private final ExecutionServer server;
        private final int port;
        private volatile com.sun.net.httpserver.HttpServer httpd;
        private volatile boolean running;

        ExecutionServerLifecycle(ExecutionServer server, int port) {
            this.server = server;
            this.port = port;
        }

        @Override
        public void start() {
            try {
                httpd = server.start(new java.net.InetSocketAddress("0.0.0.0", port));
                running = true;
            } catch (IOException exception) {
                throw new IllegalStateException("cannot bind the execution server to port " + port, exception);
            }
        }

        @Override
        public void stop() {
            running = false;
            server.stop();
            if (httpd != null) {
                httpd.stop(0);
            }
        }

        @Override
        public boolean isRunning() {
            return running;
        }

        @Override
        public int getPhase() {
            // Start late so business beans are wired first. / 晚启动，业务 Bean
            // 先完成接线。
            return Integer.MAX_VALUE;
        }
    }
}
