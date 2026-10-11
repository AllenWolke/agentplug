package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const sessionCookie = "lexagent_session"

type userClaims struct {
	Username       string   `json:"username"`
	DisplayName    string   `json:"display_name"`
	TenantID       string   `json:"tenant_id"`
	DepartmentID   string   `json:"department_id"`
	DepartmentName string   `json:"department_name"`
	ApplicationID  string   `json:"application_id"`
	Roles          []string `json:"roles"`
	TokenVersion   uint64   `json:"token_version,omitempty"`
	SessionID      string   `json:"session_id,omitempty"`
}

type demoUser struct {
	Password string
	Claims   userClaims
}

// Browser authentication uses Identity credentials. The empty legacy map has
// no runtime accounts; isolated tests supply their own fixture identities.
var demoClaims = map[string]userClaims{}

func loadDemoUsers() map[string]demoUser {
	users := make(map[string]demoUser, len(demoClaims))
	for username, claims := range demoClaims {
		envName := "DEMO_PASSWORD_" + strings.NewReplacer(".", "_", "-", "_").Replace(strings.ToUpper(username))
		users[username] = demoUser{Password: strings.TrimSpace(os.Getenv(envName)), Claims: claims}
	}
	return users
}

type session struct {
	User      userClaims
	ExpiresAt time.Time
	Family    string
	Used      bool
}

type sessionStore struct {
	mu      sync.RWMutex
	items   map[string]session
	revoked map[string]bool
}

func (s *sessionStore) create(user userClaims) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	s.mu.Lock()
	if s.revoked == nil {
		s.revoked = map[string]bool{}
	}
	hash := gatewayRefreshHash(token)
	s.items[hash] = session{User: user, ExpiresAt: time.Now().Add(refreshTokenTTL), Family: hash}
	s.mu.Unlock()
	return token, nil
}

func (s *sessionStore) get(token string) (userClaims, bool) {
	s.mu.RLock()
	value, ok := s.items[gatewayRefreshHash(token)]
	revoked := s.revoked[value.Family]
	s.mu.RUnlock()
	if !ok || value.Used || revoked || !time.Now().Before(value.ExpiresAt) {
		if ok {
			s.remove(token)
		}
		return userClaims{}, false
	}
	return value.User, true
}

func (s *sessionStore) remove(token string) {
	s.mu.Lock()
	if value, ok := s.items[gatewayRefreshHash(token)]; ok {
		s.revoked[value.Family] = true
	}
	s.mu.Unlock()
}

type gateway struct {
	platformTarget *url.URL
	staticRoot     string
	platformToken  string
	secureCookie   bool
	sessions       *sessionStore
	demoUsers      map[string]demoUser
	httpClient     *http.Client
	authMode       string
	oidcTrusted    bool
	oidcAuthURL    string
	oidcProxyAuth  string
	oidcIssuer     string
	authClient     *http.Client
	accessSigner   *accessTokenSigner
	oidcStepUp     *oidcStepUpProvider
}

func main() {
	listenAddr := envOr("LISTEN_ADDR", ":80")
	if len(os.Getenv("PLATFORM_GATEWAY_TOKEN")) < 32 {
		log.Fatal("PLATFORM_GATEWAY_TOKEN requires an independent gateway credential of at least 32 bytes")
	}
	// The presentation gateway has one upstream: the modular platform process.
	// 展示网关只有模块化平台这一个上游，不再保留 Backend 回退配置。
	handler, err := newHandlerWithConfig(envOr("PLATFORM_URL", "http://platform-app:8080"), ".", os.Getenv("PLATFORM_GATEWAY_TOKEN"), strings.EqualFold(envOr("COOKIE_SECURE", "false"), "true"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("LexAgent React gateway listening on %s", listenAddr)
	server := &http.Server{Addr: listenAddr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}

func newHandler(platformURL, staticRoot string) (http.Handler, error) {
	return newHandlerWithConfig(platformURL, staticRoot, "dev-api-key", false)
}

func newHandlerWithConfig(platformURL, staticRoot, platformToken string, secureCookie bool) (http.Handler, error) {
	platformURL = strings.TrimSpace(envOr("PLATFORM_URL", platformURL))
	platformToken = envOr("PLATFORM_GATEWAY_TOKEN", platformToken)
	platformTarget, err := url.Parse(platformURL)
	if err != nil || (platformTarget.Scheme != "http" && platformTarget.Scheme != "https") {
		return nil, errors.New("platform URL must use http or https")
	}
	authMode := strings.ToLower(envOr("FRONTEND_AUTH_MODE", "demo"))
	if authMode != "demo" && authMode != "local" && authMode != "oidc" {
		return nil, errors.New("FRONTEND_AUTH_MODE must be demo, local or oidc")
	}
	oidcTrusted := strings.EqualFold(envOr("OIDC_PROXY_TRUSTED", "false"), "true")
	oidcProxyAuth := strings.TrimSpace(os.Getenv("OIDC_PROXY_AUTH_URL"))
	oidcIssuer := strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL"))
	if authMode == "oidc" {
		proxyURL, parseErr := url.Parse(oidcProxyAuth)
		if parseErr != nil || proxyURL.Scheme != "http" || proxyURL.Host == "" || proxyURL.Path != "/oauth2/auth" || proxyURL.User != nil || proxyURL.RawQuery != "" || proxyURL.Fragment != "" {
			return nil, errors.New("OIDC_PROXY_AUTH_URL must be an internal http /oauth2/auth endpoint")
		}
		issuerURL, parseErr := url.Parse(oidcIssuer)
		if parseErr != nil || issuerURL.Scheme != "https" || issuerURL.Host == "" || issuerURL.User != nil || issuerURL.RawQuery != "" || issuerURL.Fragment != "" {
			return nil, errors.New("OIDC_ISSUER_URL must be an HTTPS issuer")
		}
	}
	environment := strings.ToLower(strings.TrimSpace(envOr("APP_ENV", "development")))
	signingKey := strings.TrimSpace(os.Getenv("ACCESS_TOKEN_SIGNING_KEY"))
	if (environment == "production" || environment == "prod") && signingKey == "" {
		return nil, errors.New("production frontend requires a dedicated ACCESS_TOKEN_SIGNING_KEY")
	}
	accessSigner, err := newAccessTokenSigner(signingKey)
	if err != nil {
		return nil, err
	}
	accessSigner.authMode = authMode
	if environment == "production" || environment == "prod" {
		if !secureCookie {
			return nil, errors.New("production frontend requires secure cookies")
		}
		if authMode != "oidc" || !oidcTrusted {
			return nil, errors.New("production frontend requires trusted OIDC proxy authentication")
		}
		if !validProductionToken(platformToken) {
			return nil, errors.New("production frontend requires a non-placeholder platform token with at least 32 bytes")
		}
	}
	g := &gateway{
		platformTarget: platformTarget, staticRoot: staticRoot,
		platformToken: platformToken, secureCookie: secureCookie,
		sessions:      &sessionStore{items: map[string]session{}},
		accessSigner:  accessSigner,
		httpClient:    &http.Client{Timeout: 2 * time.Second},
		authMode:      authMode,
		oidcTrusted:   oidcTrusted,
		oidcAuthURL:   strings.TrimSpace(os.Getenv("OIDC_AUTH_URL")),
		oidcProxyAuth: oidcProxyAuth,
		oidcIssuer:    oidcIssuer,
		authClient:    &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	g.demoUsers = loadDemoUsers()
	if authMode == "oidc" {
		g.oidcStepUp, err = loadOIDCStepUpProvider(oidcIssuer)
		if err != nil {
			return nil, err
		}
	}
	return http.HandlerFunc(g.serveHTTP), nil
}

func (g *gateway) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/healthz":
		writeText(w, http.StatusOK, "ok")
	case r.URL.Path == "/auth/login" && r.Method == http.MethodPost:
		g.login(w, r)
	case r.URL.Path == "/auth/refresh" && r.Method == http.MethodPost:
		g.refresh(w, r)
	case r.URL.Path == "/auth/workspace" && r.Method == http.MethodPost:
		g.switchWorkspace(w, r)
	case r.URL.Path == "/auth/step-up/method" && r.Method == http.MethodGet:
		g.stepUpMethod(w, r)
	case r.URL.Path == "/auth/step-up/oidc/start" && r.Method == http.MethodPost:
		g.beginOIDCStepUp(w, r)
	case r.URL.Path == oidcStepUpCallback && r.Method == http.MethodGet:
		g.completeOIDCStepUp(w, r)
	case r.URL.Path == "/auth/register" && r.Method == http.MethodPost:
		g.register(w, r)
	case r.URL.Path == "/auth/registration-agent-catalog" && r.Method == http.MethodGet:
		g.proxyPublicIdentity(w, r, "/registration-agent-catalog")
	case strings.HasPrefix(r.URL.Path, "/auth/registrations/"):
		g.proxyPublicRegistration(w, r)
	case r.URL.Path == "/auth/me" && r.Method == http.MethodGet:
		g.me(w, r)
	case r.URL.Path == "/auth/logout" && r.Method == http.MethodPost:
		g.logout(w, r)
	case r.URL.Path == "/ops/status" && r.Method == http.MethodGet:
		g.opsStatus(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/modules/conversation/shares/") && r.Method == http.MethodGet:
		g.proxyPublicConversationShare(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/v1/shared/conversations/"):
		// The legacy Backend share endpoint is retired; all new shares are owned
		// by the platform Conversation module.
		// 旧 Backend 分享入口已退役；新分享统一由平台 Conversation 模块管理。
		http.NotFound(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/modules/"):
		if module, ok := publicPlatformModule(strings.TrimPrefix(r.URL.Path, "/api/modules/")); ok {
			g.proxyPlatformModule(w, r, module)
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "平台模块不存在"})
	case strings.HasPrefix(r.URL.Path, "/api/"):
		// No implicit Backend proxy remains. Only allowlisted platform modules
		// are routable; retired /api/v1 and product paths fail closed.
		// 不保留隐式 Backend 代理；仅白名单平台模块可访问，旧路径闭合拒绝。
		http.NotFound(w, r)
	default:
		g.serveStatic(w, r)
	}
}

// publicPlatformModule validates the first path segment before forwarding it
// to the platform registry.  The usage-cost module keeps its domain name in
// the platform registry; "usage" is the stable browser-facing alias.
// publicPlatformModule 在转发前校验第一个路径段，避免把任意 /api/modules
// 路径当作平台业务入口；usage 是浏览器稳定别名，平台内部仍叫 usage-cost。
func publicPlatformModule(path string) (string, bool) {
	segment := strings.TrimSpace(strings.SplitN(path, "/", 2)[0])
	switch segment {
	case "identity", "catalog", "conversation", "execution", "evaluation-product", "agent-factory", "audit", "notification", "model-governance", "policyasset", "model-billing", "tool-approvals", "skills", "knowledge":
		return segment, true
	case "usage", "usage-cost":
		return segment, true
	default:
		return "", false
	}
}

// proxyConversation forwards only the new platform conversation contract.
// The browser never supplies tenant or principal headers; this gateway derives
// them from the authenticated HttpOnly session and uses the server-owned
// internal token for the platform boundary.
// proxyConversation 只转发平台新会话契约；浏览器不能伪造 Scope，网关从会话
// 派生作用域并使用服务端内部令牌访问平台。
func (g *gateway) proxyConversation(w http.ResponseWriter, r *http.Request) {
	g.proxyPlatformModule(w, r, "conversation")
}

// proxyPlatformModule forwards authenticated browser requests to a named
// platform module while deriving every Scope field from the HttpOnly session.
// proxyPlatformModule 将浏览器请求转发到指定平台模块，并从 HttpOnly 会话派生
// 全部 Scope 字段，浏览器不能自行提交租户或主体身份。
func (g *gateway) proxyPlatformModule(w http.ResponseWriter, r *http.Request, module string) {
	if !safeBrowserMethod(r.Method) && !g.sameBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"message": "请求来源不受信任"})
		return
	}
	user, ok := g.authenticate(r)
	if !ok {
		w.Header().Set("X-Authentication-Error", "access_token_invalid")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "请先登录智能体中台"})
		return
	}
	publicModule := strings.Trim(module, "/")
	platformModule := publicModule
	if publicModule == "usage" {
		platformModule = "usage-cost"
	}
	if publicModule == "model-billing" {
		platformModule = "capability"
	}
	if publicModule == "tool-approvals" {
		platformModule = "capability"
	}
	if publicModule == "skills" {
		platformModule = "capability"
	}
	prefix := "/api/modules/" + publicModule
	path := strings.TrimPrefix(r.URL.Path, prefix)
	if path == "" {
		path = "/"
	}
	if publicModule == "skills" {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		switch path {
		case "/inspect", "/register", "/review", "/publish":
		default:
			http.NotFound(w, r)
			return
		}
		path = "/skills" + path
	}
	if publicModule == "tool-approvals" {
		switch path {
		case "/pending", "/preview", "/step-up", "/approve", "/revoke", "/resume":
		default:
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		path = "/tool-approvals" + path
	}
	if publicModule == "model-billing" {
		// Only the human billing endpoint is browser accessible, not capabilities.
		// 仅开放人工计费入口，不向浏览器开放模型/工具等内部能力接口。
		if path != "/reconciliations" {
			http.NotFound(w, r)
			return
		}
		path = "/billing" + path
	}
	endpoint := *g.platformTarget
	endpoint.Path = "/modules/" + platformModule + path
	endpoint.RawQuery = r.URL.RawQuery
	request, err := http.NewRequestWithContext(r.Context(), r.Method, endpoint.String(), r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "无法访问会话服务"})
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Internal-Token", g.platformToken)
	request.Header.Set("X-Tenant-ID", user.TenantID)
	request.Header.Set("X-Department-ID", user.DepartmentID)
	request.Header.Set("X-Application-ID", user.ApplicationID)
	request.Header.Set("X-Principal-Type", "user")
	request.Header.Set("X-Principal-ID", user.Username)
	requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if requestID == "" || len(requestID) > 128 {
		requestID = newRequestID()
	}
	request.Header.Set("X-Trace-ID", requestID)
	// Trace context is correlation metadata, never an authorization input. Only
	// forward a valid W3C parent; do not forward arbitrary browser baggage.
	// 追踪上下文仅用于关联，不参与授权；只透传合法 W3C parent，不透传浏览器 baggage。
	if parent := strings.TrimSpace(r.Header.Get("traceparent")); validTraceparent(parent) {
		request.Header.Set("traceparent", parent)
	}
	// Preserve the caller's command idempotency key across the trusted browser
	// gateway. Without this, platform commands that require durable replay
	// protection (for example remediation transitions) fail with HTTP 400.
	// 将调用方的命令幂等键透传过可信浏览器网关；否则整改等要求持久化
	// 重放保护的平台命令会因缺少幂等键而返回 HTTP 400。
	if idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key")); idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	// Mark the request as browser-originated so modules do not mistake the
	// gateway's service credential for the user's authorization decision.
	// 标记浏览器来源，避免模块把网关服务令牌误当成用户授权结论。
	request.Header.Set("X-Browser-Module", "1")
	request.Header.Set("X-Authentication-Revision", strconv.FormatUint(user.TokenVersion, 10))
	request.Header.Set("X-Authentication-Session", user.SessionID)
	if publicModule == "execution" {
		// The execution module resolves the remaining run scope from its durable
		// record; the browser gateway only forwards the authenticated owner.
		// 执行模块从持久化 Run 解析其余作用域，浏览器网关只转发可信登录主体。
	}
	// Streaming has no whole-response deadline; disconnect cancels upstream.
	// 事件流不使用普通请求的总时限；浏览器断开通过 Context 取消上游。
	client := g.httpClient
	if publicModule == "evaluation-product" && r.Method == http.MethodGet && path == "/agents" {
		// Discovery bounds its parallel health probes to 20s and rechecks IAM
		// afterwards. Let an offline Agent become a discovery item instead of
		// racing the ordinary 2s gateway deadline. Authentication retains its
		// separate short timeout; client disconnect still cancels this request.
		discoveryClient := *client
		discoveryClient.Timeout = 25 * time.Second
		discoveryClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &discoveryClient
	}
	stream := publicModule == "execution" && r.Method == http.MethodGet && (strings.HasSuffix(path, "/events") || strings.HasSuffix(path, "/agent-events"))
	if stream {
		streamClient := *client
		streamClient.Timeout = 0
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if configured, ok := client.Transport.(*http.Transport); ok {
			transport = configured.Clone()
		}
		transport.ResponseHeaderTimeout = 10 * time.Second
		if strings.HasSuffix(path, "/agent-events") {
			// The platform bounds an Agent snapshot to 15s, including authority
			// checks before the first byte. Allow its stable error to arrive.
			transport.ResponseHeaderTimeout = 20 * time.Second
		}
		streamClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		streamClient.Transport = transport
		defer transport.CloseIdleConnections()
		client = &streamClient
	}
	response, err := client.Do(request)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "平台模块暂不可用"})
		return
	}
	defer response.Body.Close()
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	if stream && strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		controller := http.NewResponseController(w)
		if err := controller.Flush(); err != nil {
			panic(http.ErrAbortHandler)
		}
		buffer := make([]byte, 32*1024)
		for {
			n, readErr := response.Body.Read(buffer)
			if n > 0 {
				if _, err := w.Write(buffer[:n]); err != nil {
					panic(http.ErrAbortHandler)
				}
				if err := controller.Flush(); err != nil {
					panic(http.ErrAbortHandler)
				}
			}
			if readErr == io.EOF {
				return
			}
			// Never disguise an upstream truncation as a clean EOF.
			// 上游异常中断不能被包装为正常结束。
			if readErr != nil {
				panic(http.ErrAbortHandler)
			}
		}
	}
	_, _ = io.Copy(w, response.Body)
}

// validTraceparent accepts the fixed-length W3C version 00 format and rejects
// all-zero IDs. A malformed browser header must not become an upstream parent.
// 仅接受固定长度的 W3C 00 格式并拒绝全零 ID；损坏的浏览器头不能成为上游父级。
func validTraceparent(value string) bool {
	parts := strings.Split(value, "-")
	if len(value) != 55 || len(parts) != 4 || parts[0] != "00" || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return false
	}
	for _, field := range parts[1:] {
		if _, err := hex.DecodeString(field); err != nil || strings.ToLower(field) != field {
			return false
		}
	}
	return parts[1] != strings.Repeat("0", 32) && parts[2] != strings.Repeat("0", 16)
}

func (g *gateway) proxyPublicRegistration(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "注册凭证必须通过请求头提交"})
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/auth/registrations/"), "/")
	if len(parts) != 2 || !safeIdentityPathSegment(parts[0]) || (parts[1] != "verify-contact" && parts[1] != "status" && parts[1] != "withdraw") {
		http.NotFound(w, r)
		return
	}
	if (parts[1] == "status" && r.Method != http.MethodGet) || (parts[1] != "status" && r.Method != http.MethodPost) {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "方法不允许"})
		return
	}
	var body io.Reader
	if r.Method == http.MethodPost {
		limitedBody, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
		if readErr != nil {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"message": "注册请求过大"})
			return
		}
		body = bytes.NewReader(limitedBody)
	}
	endpoint := *g.platformTarget
	endpoint.Path = "/modules/identity/registrations/" + parts[0] + "/" + parts[1]
	request, err := http.NewRequestWithContext(r.Context(), r.Method, endpoint.String(), body)
	if err != nil {
		writeJSON(w, 500, map[string]string{"message": "无法访问注册服务"})
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Internal-Token", g.platformToken)
	if clientIP := internalClientIP(r); clientIP != "" {
		request.Header.Set("X-Internal-Client-IP", clientIP)
	}
	if token := r.Header.Get("X-Registration-Token"); token != "" {
		request.Header.Set("X-Registration-Token", token)
	}
	response, err := g.httpClient.Do(request)
	if err != nil {
		writeJSON(w, 503, map[string]string{"message": "注册服务暂不可用"})
		return
	}
	defer response.Body.Close()
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	for key, values := range response.Header {
		if strings.EqualFold(key, "Set-Cookie") || strings.EqualFold(key, "Cache-Control") {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(response.Body, 1<<20))
}

// proxyPublicIdentity permits only intentionally public Identity operations.
// The registration catalog contains requestable metadata, never tenant data
// or administrative controls. The public request has no caller-controlled
// scope headers; the platform resolves its registration scope from server-side
// configuration.
// proxyPublicIdentity 只放行明确公开的 Identity 操作；注册目录仅含可申请的
// 非敏感元数据，不包含租户数据或管理操作，作用域由平台服务端配置解析。
func (g *gateway) proxyPublicIdentity(w http.ResponseWriter, r *http.Request, modulePath string) {
	if r.Method != http.MethodGet || (modulePath != "/registration-agent-catalog" && modulePath != "/registrations/agent-catalog") {
		http.NotFound(w, r)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "query parameters are not accepted", http.StatusBadRequest)
		return
	}
	endpoint := *g.platformTarget
	endpoint.Path = "/modules/identity" + modulePath
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint.String(), nil)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "无法访问注册目录"})
		return
	}
	request.Header.Set("X-Internal-Token", g.platformToken)
	if clientIP := internalClientIP(r); clientIP != "" {
		request.Header.Set("X-Internal-Client-IP", clientIP)
	}
	response, err := g.httpClient.Do(request)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "注册目录暂不可用"})
		return
	}
	defer response.Body.Close()
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(response.Body, 1<<20))
}

func safeIdentityPathSegment(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// internalClientIP is derived only from the socket peer. Never forward a
// caller-supplied forwarding header as the trusted registration/login rate key.
// internalClientIP 只取 TCP 对端地址，不信任客户端自行提交的转发头。
func internalClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	if net.ParseIP(strings.TrimSpace(r.RemoteAddr)) != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return ""
}

// proxyPublicConversationShare is the only unauthenticated browser route into
// a platform module. Its authority is a 256-bit URL capability; the platform
// stores only the capability hash and enforces expiry/revocation.
// proxyPublicConversationShare 是唯一无需浏览器登录的模块路由；授权来自
// 256 位 URL 能力令牌，平台仅保存令牌哈希并强制检查过期/撤销。
func (g *gateway) proxyPublicConversationShare(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/api/modules/conversation/shares/")
	query, queryErr := url.ParseQuery(r.URL.RawQuery)
	if !validPublicShareToken(token) || queryErr != nil {
		http.NotFound(w, r)
		return
	}
	for key, values := range query {
		if (key != "page" && key != "page_size") || len(values) != 1 {
			http.NotFound(w, r)
			return
		}
	}
	endpoint := *g.platformTarget
	endpoint.Path = "/modules/conversation/shares/" + token
	endpoint.RawQuery = r.URL.RawQuery
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint.String(), nil)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "无法访问会话分享服务"})
		return
	}
	request.Header.Set("X-Internal-Token", g.platformToken)
	response, err := g.httpClient.Do(request)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "会话分享服务暂不可用"})
		return
	}
	defer response.Body.Close()
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(response.Body, 8<<20))
}

func validPublicShareToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(raw) == 32
}

var errLoginRateLimited = errors.New("identity login rate limited")

func (g *gateway) login(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != "" && !g.sameBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"message": "请求来源不受信任"})
		return
	}
	if g.authMode == "oidc" {
		if !g.oidcTrusted || g.oidcAuthURL == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "OIDC 登录尚未配置"})
			return
		}
		http.Redirect(w, r, g.oidcAuthURL, http.StatusFound)
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	if err := decoder.Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "登录请求格式错误"})
		return
	}
	account, ok := g.demoUsers[strings.TrimSpace(input.Username)]
	valid := g.authMode == "demo" && ok && account.Password != "" && subtle.ConstantTimeCompare([]byte(account.Password), []byte(input.Password)) == 1
	if !valid {
		if dynamic, authErr := g.authenticateLocalUser(r, input.Username, input.Password); authErr == nil {
			account, valid = demoUser{Claims: dynamic}, true
		} else if errors.Is(authErr, errLoginRateLimited) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"code": "RATE_LIMITED", "message": "登录请求过于频繁，请稍后重试"})
			return
		}
	}
	if !valid {
		time.Sleep(120 * time.Millisecond)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "账号或密码错误"})
		return
	}
	if err := g.issueLoginTokens(w, r, account.Claims); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "无法创建登录会话"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, account.Claims)
}

func (g *gateway) authenticateLocalUser(r *http.Request, username, password string) (userClaims, error) {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	endpoint := *g.platformTarget
	endpoint.Path = "/modules/identity/internal/credentials/verify"
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return userClaims{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Internal-Token", g.platformToken)
	if clientIP := internalClientIP(r); clientIP != "" {
		request.Header.Set("X-Internal-Client-IP", clientIP)
	}
	response, err := g.httpClient.Do(request)
	if err != nil {
		return userClaims{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusTooManyRequests {
		return userClaims{}, errLoginRateLimited
	}
	if response.StatusCode != http.StatusOK {
		return userClaims{}, errors.New("identity credentials rejected")
	}
	var identity struct {
		Username      string   `json:"username"`
		DisplayName   string   `json:"display_name"`
		TenantID      string   `json:"tenant_id"`
		DepartmentID  string   `json:"department_id"`
		ApplicationID string   `json:"application_id"`
		Roles         []string `json:"roles"`
		AuthRevision  uint64   `json:"auth_revision"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&identity) != nil || identity.Username == "" || identity.TenantID == "" || identity.DepartmentID == "" || identity.ApplicationID == "" || identity.AuthRevision == 0 {
		return userClaims{}, errors.New("invalid identity credential response")
	}
	return userClaims{Username: identity.Username, DisplayName: identity.DisplayName, TenantID: identity.TenantID, DepartmentID: identity.DepartmentID, DepartmentName: identity.DepartmentID, ApplicationID: identity.ApplicationID, Roles: identity.Roles, TokenVersion: identity.AuthRevision}, nil
}

func (g *gateway) register(w http.ResponseWriter, r *http.Request) {
	var input map[string]any
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if decoder.Decode(&input) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "注册信息格式错误"})
		return
	}
	body, _ := json.Marshal(input)
	endpoint := *g.platformTarget
	endpoint.Path = "/modules/identity/registrations"
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		writeJSON(w, 500, map[string]string{"message": "无法提交注册申请"})
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Internal-Token", g.platformToken)
	if clientIP := internalClientIP(r); clientIP != "" {
		request.Header.Set("X-Internal-Client-IP", clientIP)
	}
	response, err := g.httpClient.Do(request)
	if err != nil {
		writeJSON(w, 503, map[string]string{"message": "注册服务暂不可用"})
		return
	}
	defer response.Body.Close()
	var envelope map[string]any
	if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&envelope) != nil {
		writeJSON(w, 502, map[string]string{"message": "注册服务响应异常"})
		return
	}
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	writeJSON(w, response.StatusCode, envelope)
}

func (g *gateway) me(w http.ResponseWriter, r *http.Request) {
	user, ok := g.authenticate(r)
	if ok && user.SessionID != "" {
		if err := g.validateBrowserSession(r, user); err != nil {
			if !errors.Is(err, errRemoteRefreshRejected) {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "认证服务暂不可用，请稍后重试"})
				return
			}
			ok = false
		}
	} else if ok && g.authMode != "oidc" && user.TokenVersion > 0 {
		ok = g.validateLocalSession(r, user)
	}
	if !ok {
		w.Header().Set("X-Authentication-Error", "access_token_invalid")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "登录会话无效或已过期"})
		return
	}
	if subject, _ := r.Context().Value(verifiedOIDCSubjectKey{}).(string); subject != "" {
		result, err := g.platformRefresh(r, "create", map[string]any{"issuer": g.oidcIssuer, "subject": subject})
		if err != nil || result.AuthenticationMethod != "oidc" || result.Identity.Username != user.Username || result.RefreshToken == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "无法创建持久登录会话"})
			return
		}
		user.TokenVersion = result.Identity.AuthRevision
		user.SessionID = result.SessionID
		if err := g.setTokenCookies(w, user, "oidc."+result.RefreshToken, result.ExpiresAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "无法签发访问凭证"})
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, user)
}

func (g *gateway) logout(w http.ResponseWriter, r *http.Request) {
	if !g.sameBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"message": "请求来源不受信任"})
		return
	}
	if cookie, err := r.Cookie(refreshCookie); err == nil {
		if strings.HasPrefix(cookie.Value, "demo.") {
			g.sessions.remove(strings.TrimPrefix(cookie.Value, "demo."))
		} else if strings.HasPrefix(cookie.Value, "local.") || strings.HasPrefix(cookie.Value, "oidc.") {
			_, raw, _ := strings.Cut(cookie.Value, ".")
			if _, err := g.platformRefresh(r, "revoke", map[string]any{"refresh_token": raw}); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "会话撤销暂不可用，请重试"})
				return
			}
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: g.secureCookie, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: refreshCookie, Value: "", Path: "/auth", HttpOnly: true, Secure: g.secureCookie, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	if g.authMode == "oidc" {
		// The browser must visit the proxy endpoint to clear its own session cookie.
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "logout_url": "/oauth2/sign_out"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func safeBrowserMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// Cookie-authenticated commands require the browser's own Origin. The
// externally requested Host is preserved by the production Ingress; forwarded
// host/protocol headers are deliberately ignored because clients may forge them.
func (g *gateway) sameBrowserOrigin(r *http.Request) bool {
	raw := r.Header.Get("Origin")
	if raw == "" || r.Host == "" {
		return false
	}
	origin, err := url.Parse(raw)
	if err != nil || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || !strings.EqualFold(origin.Host, r.Host) {
		return false
	}
	if g.secureCookie {
		return origin.Scheme == "https"
	}
	return origin.Scheme == "http"
}

func (g *gateway) authenticate(r *http.Request) (userClaims, bool) {
	if g.authMode == "oidc" {
		if !g.oidcTrusted {
			return userClaims{}, false
		}
		if cookie, err := r.Cookie(sessionCookie); err == nil {
			return g.accessSigner.verify(cookie.Value, time.Now())
		}
		return g.authenticateOIDC(r)
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return userClaims{}, false
	}
	user, ok := g.accessSigner.verify(cookie.Value, time.Now())
	if !ok {
		return userClaims{}, false
	}
	return user, true
}

// authenticateOIDC never trusts identity headers from the browser or ingress.
// The proxy validates the browser cookie, then the platform resolves the
// immutable issuer/subject pair to its current, server-owned access scope.
func (g *gateway) authenticateOIDC(r *http.Request) (userClaims, bool) {
	check, err := http.NewRequestWithContext(r.Context(), http.MethodGet, g.oidcProxyAuth, nil)
	if err != nil {
		return userClaims{}, false
	}
	check.Header.Set("Cookie", r.Header.Get("Cookie"))
	verified, err := g.authClient.Do(check)
	if err != nil {
		return userClaims{}, false
	}
	defer verified.Body.Close()
	if verified.StatusCode != http.StatusAccepted {
		return userClaims{}, false
	}
	subject := strings.TrimSpace(verified.Header.Get("X-Auth-Request-User"))
	if subject == "" || len(subject) > 512 || strings.ContainsAny(subject, "\r\n\x00") {
		return userClaims{}, false
	}
	body, _ := json.Marshal(map[string]string{"issuer": g.oidcIssuer, "subject": subject})
	endpoint := *g.platformTarget
	endpoint.Path = "/modules/identity/internal/oidc/resolve"
	resolve, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return userClaims{}, false
	}
	resolve.Header.Set("Content-Type", "application/json")
	resolve.Header.Set("X-Internal-Token", g.platformToken)
	response, err := g.authClient.Do(resolve)
	if err != nil {
		return userClaims{}, false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return userClaims{}, false
	}
	var user userClaims
	if json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&user) != nil || user.Username == "" || user.TenantID == "" || user.DepartmentID == "" || user.ApplicationID == "" {
		return userClaims{}, false
	}
	*r = *r.WithContext(context.WithValue(r.Context(), verifiedOIDCSubjectKey{}, subject))
	return user, true
}

func (g *gateway) validateLocalSession(r *http.Request, user userClaims) bool {
	body, _ := json.Marshal(map[string]any{"username": user.Username, "tenant_id": user.TenantID, "department_id": user.DepartmentID, "application_id": user.ApplicationID, "auth_revision": user.TokenVersion})
	endpoint := *g.platformTarget
	endpoint.Path = "/modules/identity/internal/sessions/validate"
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return false
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Internal-Token", g.platformToken)
	response, err := g.httpClient.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func (g *gateway) opsStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := g.authenticate(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "请先登录智能体中台"})
		return
	}
	if g.authMode != "demo" || user.TokenVersion > 0 {
		allowed, err := g.currentMonitorPermission(r, user)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "实时权限服务暂不可用"})
			return
		}
		if !allowed {
			writeJSON(w, http.StatusForbidden, map[string]string{"message": "没有运维中心访问权限"})
			return
		}
	} else if !contains(user.Roles, "admin") {
		writeJSON(w, http.StatusForbidden, map[string]string{"message": "仅系统管理员可查看运维中心"})
		return
	}
	// The modular Platform exposes separate liveness/readiness routes; operations
	// status must use readiness so a live but unready process is not reported green.
	// 模块化平台区分存活与就绪探针；运维状态必须读取 readiness，不能把未就绪进程报成健康。
	platform := g.probeHealth(r.Context(), g.platformTarget.String(), "/health/ready")
	writeJSON(w, http.StatusOK, map[string]any{
		"profile":    envOr("DEPLOYMENT_PROFILE", "modular-compose"),
		"model_mode": envOr("MODEL_MODE", "mock"),
		"gateway":    map[string]any{"status": "healthy", "version": "react-v2"},
		"platform":   platform,
		"components": []map[string]string{
			{"name": "Frontend Gateway", "status": "healthy", "endpoint": "/healthz"},
			{"name": "Platform", "status": platform.Status, "endpoint": g.platformTarget.Host},
		},
	})
}

type componentHealth struct {
	Status    string `json:"status"`
	Endpoint  string `json:"endpoint"`
	LatencyMs int64  `json:"latency_ms"`
}

// probeHealth reports only an observed readiness result. An unconfigured
// dependency is unknown, never inferred healthy from another component.
// probeHealth 只报告实际探测结果；未配置的依赖为 unknown，不借用其他组件状态。
func (g *gateway) probeHealth(ctx context.Context, rawURL, healthPath string) componentHealth {
	if strings.TrimSpace(rawURL) == "" {
		return componentHealth{Status: "unknown", Endpoint: "未配置探测地址"}
	}
	base, err := url.Parse(rawURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil {
		return componentHealth{Status: "unknown", Endpoint: "探测地址无效"}
	}
	endpoint := base.ResolveReference(&url.URL{Path: healthPath})
	result := componentHealth{Status: "unhealthy", Endpoint: base.Host}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return result
	}
	started := time.Now()
	response, err := g.httpClient.Do(request)
	result.LatencyMs = time.Since(started).Milliseconds()
	if err != nil {
		return result
	}
	defer response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		result.Status = "healthy"
	}
	return result
}

func (g *gateway) serveStatic(w http.ResponseWriter, r *http.Request) {
	// Entry HTML must always reference the current build after a deployment.
	// Browsers may otherwise heuristically cache a previous index.html and keep
	// requesting bundles which no longer exist in the new image.
	w.Header().Set("Cache-Control", "no-store")
	clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
	if clean == "." || strings.HasPrefix(clean, "..") {
		clean = "index.html"
	}
	candidate := filepath.Join(g.staticRoot, clean)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		http.ServeFile(w, r, candidate)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/assets/") {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(g.staticRoot, "index.html"))
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
func newRequestID() string {
	raw := make([]byte, 12)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeText(w http.ResponseWriter, status int, value string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(value))
}
func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func splitHeader(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// validProductionToken 拒绝短凭证、重复字符及已知占位值；部署方仍须使用密码学随机生成器。
func validProductionToken(value string) bool {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(value) < 32 || strings.Count(value, string(runes[0])) == len(runes) {
		return false
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"replace-", "change-me", "changeme", "placeholder", "dev-internal", "dev-signing"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}
