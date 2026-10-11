package com.lexagent.examples.tickets;

import com.lexagent.sdk.CapabilityClient;
import com.lexagent.sdk.ExecutionServer;
import com.lexagent.sdk.MemoryRunStore;
import com.lexagent.sdk.ServerConfig;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CountDownLatch;

public final class TicketAgent {
    public static final String AGENT_ID = "example-java-tickets";

    public static ExecutionServer server(PublicKey key, String issuer, String audience, CapabilityClient.Config capability) {
        if (capability == null || capability.workloadClientId().isBlank()) {
            throw new IllegalArgumentException("platform capability gateway and Agent machine identity are required");
        }
        var business = new TicketAssistant();
        return new ExecutionServer(ServerConfig.builder().publicKey(key).issuer(issuer).audience(audience)
                .agentId(AGENT_ID).agentVersion("0.2.7").manifest(publishedManifest()).store(new MemoryRunStore())
                .capabilities(List.of("invoke", "run", "resume", "cancel", "events"))
                .capability(capability).invoke(business::invoke).run(business::run)
                .recoveryCheckpointSelector(business::recoveryPlan).build());
    }

    private static String publishedManifest() {
        try (var input = TicketAgent.class.getResourceAsStream("/manifest.json")) {
            if (input == null) throw new IllegalStateException("published manifest is missing");
            return new String(input.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (java.io.IOException error) {
            throw new IllegalStateException("published manifest cannot be read", error);
        }
    }

    public static void main(String[] args) {
        try {
            var execution = server(publicKey(), env("AGENT_PLATFORM_ISSUER", "platform"),
                    env("AGENT_PLATFORM_AUDIENCE", "agent-runtime"), CapabilityClient.Config.fromEnvironment());
            var http = execution.start(new InetSocketAddress(env("AGENT_HTTP_HOST", "0.0.0.0"), Integer.parseInt(env("PORT", "8080"))));
            Runtime.getRuntime().addShutdownHook(new Thread(() -> { http.stop(1); execution.stop(); }, "ticket-agent-shutdown"));
            new CountDownLatch(1).await();
        } catch (Exception ignored) {
            System.err.println("Java ticket Agent configuration or startup failed; credentials suppressed");
            System.exit(1);
        }
    }

    private static PublicKey publicKey() throws Exception {
        String value = env("AGENT_PLATFORM_PUBLIC_KEY_BASE64", "");
        if (value.isBlank()) value = env("PLATFORM_CONTEXT_PUBLIC_KEY", "");
        if (value.isBlank()) value = Files.readString(Path.of(env("AGENT_PLATFORM_PUBLIC_KEY_FILE", ""))).trim();
        byte[] raw;
        try { raw = Base64.getDecoder().decode(value); }
        catch (IllegalArgumentException ignored) { raw = Base64.getUrlDecoder().decode(value); }
        if (raw.length == 32) {
            byte[] wrapped = new byte[44];
            System.arraycopy(HexFormat.of().parseHex("302a300506032b6570032100"), 0, wrapped, 0, 12);
            System.arraycopy(raw, 0, wrapped, 12, 32); raw = wrapped;
        }
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(raw));
    }

    private static String env(String key, String fallback) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? fallback : value.trim();
    }
}
