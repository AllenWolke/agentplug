package com.lexagent.sdk.spring;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.lexagent.sdk.ContextVerifier;
import com.lexagent.sdk.ExecutionContract;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.PublicKey;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.HandlerInterceptor;

/** Spring MVC capability interceptor: the PEP at the controller edge.
 *
 * It binds the bearer token to the cached request body, verifies the gateway
 * signature, the delegated actions and the lifetime, and publishes the trusted
 * claims as a request attribute. Controllers never parse tokens themselves.
 *
 * Spring MVC 能力拦截器：控制器边上的 PEP。将 Bearer 令牌绑定到缓存的请求正文，
 * 校验网关签名、被委派动作与时效，并把已验证声明发布为请求属性；控制器绝不
 * 自行解析令牌。
 */
public final class CapabilityVerifierInterceptor implements HandlerInterceptor {

    /** Request attribute carrying the verified capability claims. / 承载已验证
     * 能力声明的请求属性。 */
    public static final String TRUSTED_CLAIMS = "agentPlatform.trustedClaims";

    private final ContextVerifier verifier = new ContextVerifier();
    private final ObjectMapper json = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .findAndRegisterModules();
    private final PublicKey publicKey;
    private final String issuer;
    private final String audience;

    public CapabilityVerifierInterceptor(PublicKey publicKey, String issuer, String audience) {
        this.publicKey = publicKey;
        this.issuer = issuer;
        this.audience = audience;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        byte[] body = (byte[]) request.getAttribute(CachedBodyFilter.CACHED_BODY);
        if (body == null) {
            // The caching filter did not run for this path; fail closed rather
            // than verifying nothing. / 缓存过滤器未在该路径运行；失败闭合，
            // 绝不空校验。
            reject(response);
            return false;
        }
        JsonNode tree;
        try {
            tree = json.readTree(body);
        } catch (IOException exception) {
            reject(response);
            return false;
        }
        String token = tree.path("context_token").asText("");
        // Bind the envelope token to the request credential so a stolen header
        // cannot be paired with a different body.
        // 将信封令牌与请求凭证绑定，窃取的头部无法与别的正文配对。
        if (token.isEmpty() || !("Bearer " + token).equals(request.getHeader("Authorization"))) {
            reject(response);
            return false;
        }
        try {
            ExecutionContract.CapabilityClaims claims = tree.has("operation")
                    ? verifier.verify(json.readValue(body, ExecutionContract.ExecuteRequest.class),
                            publicKey, issuer, audience)
                    : verifier.verifyEvent(json.readValue(body, ExecutionContract.EventRequest.class),
                            publicKey, issuer, audience);
            request.setAttribute(TRUSTED_CLAIMS, claims);
            return true;
        } catch (RuntimeException exception) {
            // The failure reason is never echoed back; it may reveal tenant or
            // claim details. / 不回显失败原因，避免泄漏租户或声明细节。
            reject(response);
            return false;
        }
    }

    private void reject(HttpServletResponse response) throws IOException {
        // Constant-shape rejection body, identical to the SDK transport.
        // 与 SDK 传输层一致的常量形态拒绝体。
        byte[] body = json.writeValueAsBytes(new ExecutionContract.AppError(
                "CAPABILITY_INVALID", "execution capability is invalid", false, java.util.Map.of()));
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
        response.getOutputStream().flush();
    }
}
