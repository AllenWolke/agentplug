package com.lexagent.sdk.spring;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Configuration for the auto-configured platform boundary. / 自动装配的平台
 * 边界配置：公钥缺失即失败闭合，绝不以未验证状态启动。
 */
@ConfigurationProperties(prefix = "agent-platform")
public class AgentPlatformProperties {

    /** Whether the SDK execution server starts with the application. */
    private boolean enabled = true;

    /** Platform issuer; must match the gateway's token issuer. */
    private String issuer = "platform-runtime-gateway";

    /** The audience is this Agent's id; the gateway signs tokens for exactly it. */
    private String audience;

    /** Defaults to the audience when blank. */
    private String agentId;

    /** Port for the SDK execution server. */
    private int port = 8080;

    /** Advertised capabilities; the lifecycle entries travel together. */
    private List<String> capabilities = List.of("invoke", "run", "resume", "cancel", "events");

    /** Raw Ed25519 public key (base64, standard or url-safe). */
    private String publicKeyBase64;

    /** File holding the public key, alternative to the inline value. */
    private String publicKeyFile;

    /** OTLP endpoint; blank means no telemetry leaves the process. */
    private String otlpEndpoint = "";

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getAgentId() {
        return agentId;
    }

    public void setAgentId(String agentId) {
        this.agentId = agentId;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public List<String> getCapabilities() {
        return capabilities;
    }

    public void setCapabilities(List<String> capabilities) {
        this.capabilities = capabilities;
    }

    public String getPublicKeyBase64() {
        return publicKeyBase64;
    }

    public void setPublicKeyBase64(String publicKeyBase64) {
        this.publicKeyBase64 = publicKeyBase64;
    }

    public String getPublicKeyFile() {
        return publicKeyFile;
    }

    public void setPublicKeyFile(String publicKeyFile) {
        this.publicKeyFile = publicKeyFile;
    }

    public String getOtlpEndpoint() {
        return otlpEndpoint;
    }

    public void setOtlpEndpoint(String otlpEndpoint) {
        this.otlpEndpoint = otlpEndpoint;
    }
}
