package com.lexagent.sdk.spring;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import org.springframework.web.filter.OncePerRequestFilter;

/** Caches the execution request body so the PEP can bind the capability token to
 * the exact bytes before any controller reads them.
 * 缓存执行请求正文，使 PEP 能在控制器读取前把能力令牌绑定到确切字节。
 */
public final class CachedBodyFilter extends OncePerRequestFilter {

    /** Request attribute carrying the cached body bytes. / 承载缓存正文的请求属性。 */
    public static final String CACHED_BODY = "agentPlatform.cachedBody";

    private static final Set<String> EXECUTION_PREFIXES = Set.of(
            "/internal/agent-execution/v2/invoke", "/internal/agent-execution/v2/runs");

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !EXECUTION_PREFIXES.stream().anyMatch(path::startsWith);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        byte[] body = request.getInputStream().readAllBytes();
        request.setAttribute(CACHED_BODY, body);
        chain.doFilter(new CachedRequest(request, body), response);
    }

    /** Re-readable request so controllers still see the same bytes the PEP
     * verified. / 正文可重复读取，控制器看到的与 PEP 校验的是同一字节。
     */
    private static final class CachedRequest extends HttpServletRequestWrapper {
        private final byte[] body;

        CachedRequest(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream buffer = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override
                public boolean isFinished() {
                    return buffer.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener listener) {
                    // synchronous reads only / 仅同步读取
                }

                @Override
                public int read() {
                    return buffer.read();
                }
            };
        }

        @Override
        public java.io.BufferedReader getReader() {
            return new java.io.BufferedReader(new java.io.InputStreamReader(
                    new ByteArrayInputStream(body), StandardCharsets.UTF_8));
        }
    }
}
