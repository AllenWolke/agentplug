package generated;

import java.util.Map;
import com.lexagent.sdk.ExecutionServer;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Spring entrypoint for the agent-execution/v2 boundary.
 *
 * The context is intentionally non-web: the SDK ExecutionServer is the only
 * HTTP surface (manifest, readiness and the five execution entries), while
 * Spring provides DI for the Spring AI workflow. Without platform-injected
 * verification material the process refuses to start.
 *
 * agent-execution/v2 边界的 Spring 入口：刻意采用非 web 上下文——SDK
 * ExecutionServer 是唯一 HTTP 接口面（manifest、就绪探针与五个执行入口），
 * Spring 只为 Spring AI 工作流提供 DI。没有平台注入的校验材料时拒绝启动。
 */
@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        // The boundary must boot without model credentials: black-box conformance
        // only exercises HTTP and never calls a model. Spring AI's OpenAI client
        // is wired only when the deployment supplies a real key (relaxed binding
        // maps OPENAI_API_KEY to spring.ai.openai.api-key).
        // / 边界必须在无模型凭证时可启动：黑盒一致性只打 HTTP 从不调用模型；
        // 仅当部署提供真实密钥时才装配 OpenAI 客户端。
        String apiKey = System.getenv("OPENAI_API_KEY");
        if (apiKey == null || apiKey.isBlank()) {
            System.setProperty("spring.autoconfigure.exclude", String.join(",",
                    "org.springframework.ai.model.openai.autoconfigure.OpenAiChatAutoConfiguration",
                    "org.springframework.ai.model.openai.autoconfigure.OpenAiAudioSpeechAutoConfiguration",
                    "org.springframework.ai.model.openai.autoconfigure.OpenAiAudioTranscriptionAutoConfiguration",
                    "org.springframework.ai.model.openai.autoconfigure.OpenAiImageAutoConfiguration",
                    "org.springframework.ai.model.openai.autoconfigure.OpenAiEmbeddingAutoConfiguration",
                    "org.springframework.ai.model.openai.autoconfigure.OpenAiModerationAutoConfiguration"));
        }
        new SpringApplicationBuilder(Application.class)
                .web(WebApplicationType.NONE)
                .run(args);
    }

    @Bean
    public Workflow workflow(ObjectProvider<ChatModel> chatModel) {
        ChatModel model = chatModel.getIfAvailable();
        if (model == null) {
            // Deterministic echo keeps conformance green without a model.
            // 无模型时以确定性回显保持一致性测试全绿。
            return Workflow.echoFallback();
        }
        return new Workflow(ChatClient.builder(model).build(), Map.of(
                "data_retention", "Regulatory data must be retained for 5 years and then deleted.",
                "cross_border_transfer", "Cross-border transfers require a recorded legal basis."));
    }

    /** Load the platform-injected Ed25519 public key; absent material fails
     * closed instead of serving an unverified surface. / 加载平台注入的
     * Ed25519 公钥；材料缺失即失败闭合，绝不以未验证状态服务。
     */
    @Bean
    public java.security.PublicKey platformPublicKey() throws Exception {
        return PlatformKey.fromEnv();
    }

    @Bean
    public SmartLifecycle executionBoundary(Environment environment,
            org.springframework.beans.factory.ObjectProvider<java.security.PublicKey> publicKey,
            Workflow workflow) {
        return new ExecutionBoundaryLifecycle(environment, publicKey.getIfAvailable(), workflow);
    }

    /** Binds the vendored SDK ExecutionServer to the Spring lifecycle.
     * 将 vendored SDK ExecutionServer 挂到 Spring 生命周期。
     */
    static final class ExecutionBoundaryLifecycle implements SmartLifecycle {
        private final Environment environment;
        private final java.security.PublicKey publicKey;
        private final Workflow workflow;
        private com.sun.net.httpserver.HttpServer httpd;
        private volatile boolean running;

        ExecutionBoundaryLifecycle(Environment environment, java.security.PublicKey publicKey,
                Workflow workflow) {
            this.environment = environment;
            this.publicKey = publicKey;
            this.workflow = workflow;
        }

        @Override
        public void start() {
            // Fail closed: without platform-injected verification material the
            // Agent refuses to start rather than accepting unverified callers.
            // 失败闭合：没有平台注入的校验材料时拒绝启动，绝不接受未验证调用方。
            if (publicKey == null) {
                throw new IllegalStateException("AGENT_PLATFORM_PUBLIC_KEY_BASE64 is required");
            }
            String agentId = environment.getProperty("AGENT_PLATFORM_AGENT_ID",
                    ExecutionBoundary.DEFAULT_AUDIENCE);
            int port = Integer.parseInt(environment.getProperty("PORT", "8080"));
            ExecutionServer server = ExecutionBoundary.server(publicKey, agentId, null, workflow);
            try {
                httpd = server.start(ExecutionBoundary.bindAddress(port));
            } catch (java.io.IOException exception) {
                throw new IllegalStateException("cannot bind the execution server to port " + port, exception);
            }
            running = true;
        }

        @Override
        public void stop() {
            running = false;
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
            return Integer.MAX_VALUE;
        }
    }
}
