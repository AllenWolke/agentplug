package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOIDCLogoutClearsProxySessionThroughBrowser(t *testing.T) {
	t.Setenv("ACCESS_TOKEN_SIGNING_KEY", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")
	t.Setenv("APP_ENV", "production")
	t.Setenv("FRONTEND_AUTH_MODE", "oidc")
	t.Setenv("OIDC_PROXY_TRUSTED", "true")
	t.Setenv("OIDC_PROXY_AUTH_URL", "http://oauth2-proxy:4180/oauth2/auth")
	t.Setenv("OIDC_ISSUER_URL", "https://idp.example.com/realms/main")
	t.Setenv("PLATFORM_URL", "http://127.0.0.1:1")
	handler, err := newHandlerWithConfig("http://127.0.0.1:1", t.TempDir(), "server-owned-token-0123456789abcdef", true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	request.Host = "agent.example.com"
	request.Header.Set("Origin", "https://agent.example.com")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("logout status = %d", response.Code)
	}
	var result struct {
		OK        bool   `json:"ok"`
		LogoutURL string `json:"logout_url"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.LogoutURL != "/oauth2/sign_out" {
		t.Fatalf("OIDC logout must clear proxy session: %+v", result)
	}
	if !strings.Contains(response.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("local cookie was not cleared: %q", response.Header().Get("Set-Cookie"))
	}
}

func TestOIDCBrowserCommandsRejectCrossOriginAndMissingOrigin(t *testing.T) {
	t.Setenv("ACCESS_TOKEN_SIGNING_KEY", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")
	t.Setenv("APP_ENV", "production")
	t.Setenv("FRONTEND_AUTH_MODE", "oidc")
	t.Setenv("OIDC_PROXY_TRUSTED", "true")
	t.Setenv("OIDC_ISSUER_URL", "https://idp.example.com/realm")
	proxyChecks := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyChecks++
		if r.URL.Path != "/oauth2/auth" || r.Header.Get("Cookie") != "_oauth2_proxy=valid" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-Auth-Request-User", "stable-subject")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer proxy.Close()
	forwarded := 0
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/modules/identity/internal/oidc/resolve" {
			writeJSON(w, http.StatusOK, userClaims{Username: "bound-user", TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", Roles: []string{"operator"}})
			return
		}
		if r.URL.Path == "/modules/conversation/sessions" {
			forwarded++
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer platform.Close()
	t.Setenv("OIDC_PROXY_AUTH_URL", proxy.URL+"/oauth2/auth")
	handler, err := newHandlerWithConfig(platform.URL, t.TempDir(), "server-owned-token-0123456789abcdef", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"", "null", "http://agent.example.com", "https://evil.example.com", "https://sub.agent.example.com", "https://agent.example.com.evil.test"} {
		request := httptest.NewRequest(http.MethodPost, "/api/modules/conversation/sessions", strings.NewReader(`{}`))
		request.Host = "agent.example.com"
		request.Header.Set("Cookie", "_oauth2_proxy=valid")
		request.Header.Set("Origin", origin)
		request.Header.Set("X-Forwarded-Host", "evil.example.com")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden || proxyChecks != 0 || forwarded != 0 {
			t.Fatalf("origin %q reached authenticated command: status=%d proxy=%d forwarded=%d", origin, response.Code, proxyChecks, forwarded)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/api/modules/conversation/sessions", strings.NewReader(`{}`))
	request.Host = "agent.example.com"
	request.Header.Set("Cookie", "_oauth2_proxy=valid")
	request.Header.Set("Origin", "https://agent.example.com")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || proxyChecks != 1 || forwarded != 1 {
		t.Fatalf("same-origin command failed: status=%d proxy=%d forwarded=%d", response.Code, proxyChecks, forwarded)
	}
	logout := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	logout.Host = "agent.example.com"
	logout.Header.Set("Origin", "https://evil.example.com")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, logout)
	if response.Code != http.StatusForbidden || response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("cross-origin logout changed session: status=%d cookie=%q", response.Code, response.Header().Get("Set-Cookie"))
	}
}

func TestOIDCSessionIgnoresBrowserIdentityHeaders(t *testing.T) {
	t.Setenv("ACCESS_TOKEN_SIGNING_KEY", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")
	t.Setenv("APP_ENV", "production")
	t.Setenv("FRONTEND_AUTH_MODE", "oidc")
	t.Setenv("OIDC_PROXY_TRUSTED", "true")
	t.Setenv("OIDC_ISSUER_URL", "https://idp.example.com/realm")
	var proxyChecks, platformChecks atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyChecks.Add(1)
		if r.URL.Path != "/oauth2/auth" || r.Header.Get("Cookie") != "_oauth2_proxy=valid" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-Auth-Request-User", "stable-subject")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer proxy.Close()
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		platformChecks.Add(1)
		if r.URL.Path == "/modules/identity/internal/browser-sessions/validate" && r.Header.Get("X-Internal-Token") == "server-owned-token-0123456789abcdef" {
			writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
			return
		}
		if (r.URL.Path != "/modules/identity/internal/oidc/resolve" && r.URL.Path != "/modules/identity/internal/refresh-sessions") || r.Header.Get("X-Internal-Token") != "server-owned-token-0123456789abcdef" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var in struct {
			Issuer  string `json:"issuer"`
			Subject string `json:"subject"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Issuer != "https://idp.example.com/realm" || in.Subject != "stable-subject" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/modules/identity/internal/refresh-sessions" {
			writeJSON(w, http.StatusOK, map[string]any{"session_id": strings.Repeat("a", 64), "authentication_method": "oidc", "refresh_token": "oidc-test-refresh", "expires_at": time.Now().Add(refreshTokenTTL), "identity": map[string]any{"username": "bound-user", "auth_revision": 1}})
			return
		}
		_ = json.NewEncoder(w).Encode(userClaims{Username: "bound-user", TenantID: "bound-tenant", DepartmentID: "bound-department", ApplicationID: "bound-app", Roles: []string{"operator"}})
	}))
	defer platform.Close()
	t.Setenv("OIDC_PROXY_AUTH_URL", proxy.URL+"/oauth2/auth")
	handler, err := newHandlerWithConfig(platform.URL, t.TempDir(), "server-owned-token-0123456789abcdef", true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	request.Header.Set("X-Auth-Request-User", "attacker")
	request.Header.Set("X-Auth-Request-Roles", "admin")
	request.Header.Set("X-Auth-Request-Tenant", "other-tenant")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("forged headers without proxy cookie returned %d", response.Code)
	}
	request.Header.Set("Cookie", "_oauth2_proxy=valid")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("verified cookie returned %d: %s", response.Code, response.Body.String())
	}
	var user userClaims
	if err := json.Unmarshal(response.Body.Bytes(), &user); err != nil {
		t.Fatal(err)
	}
	if user.Username != "bound-user" || user.TenantID != "bound-tenant" || len(user.Roles) != 1 || user.Roles[0] != "operator" {
		t.Fatalf("browser identity headers influenced principal: %+v", user)
	}
	var access *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookie {
			access = cookie
		}
	}
	if access == nil {
		t.Fatal("OIDC login did not issue a short-lived access token")
	}
	signed := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	signed.AddCookie(access)
	signedResponse := httptest.NewRecorder()
	handler.ServeHTTP(signedResponse, signed)
	if signedResponse.Code != http.StatusOK || proxyChecks.Load() != 2 || platformChecks.Load() != 3 {
		t.Fatal("OIDC JWT repeated IdP authentication or skipped durable session check", signedResponse.Code, proxyChecks.Load(), platformChecks.Load())
	}
}

func TestGatewayAuthenticationAndIdentityInjection(t *testing.T) {
	t.Setenv("DEMO_PASSWORD_FIXTURE_ADMIN", "test-compliance-password")
	staticRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticRoot, "index.html"), []byte("<main>LexAgent React</main>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(staticRoot, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staticRoot, "assets", "app.js"), []byte("window.reactReady=true"), 0o600); err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/ready" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"tenant": r.Header.Get("X-Tenant-ID"), "department": r.Header.Get("X-Department-ID"),
			"application": r.Header.Get("X-Application-ID"), "user": r.Header.Get("X-Principal-ID"),
			"principal_type": r.Header.Get("X-Principal-Type"), "internal_token": r.Header.Get("X-Internal-Token"),
			"forged_api_key": r.Header.Get("X-Api-Key"), "forged_tenant": r.Header.Get("X-Mock-Tenant"),
		})
	}))
	defer upstream.Close()
	handler, err := newHandlerWithConfig(upstream.URL, staticRoot, "server-owned-key", false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	unauthorized, err := client.Get(server.URL + "/api/modules/identity/principals")
	if err != nil {
		t.Fatal(err)
	}
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", unauthorized.StatusCode)
	}
	_ = unauthorized.Body.Close()

	loginBody, _ := json.Marshal(map[string]string{"username": "fixture.admin", "password": "test-compliance-password"})
	login, err := client.Post(server.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	if login.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(login.Body)
		t.Fatalf("login: %d %s", login.StatusCode, body)
	}
	_ = login.Body.Close()

	request, _ := http.NewRequest(http.MethodGet, server.URL+"/api/modules/identity/principals", nil)
	request.Header.Set("X-Mock-Tenant", "forged")
	request.Header.Set("X-Api-Key", "forged")
	request.Header.Set("X-Tenant-ID", "attacker-tenant")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var projection map[string]string
	if err := json.NewDecoder(response.Body).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if projection["tenant"] != "tenant-demo" || projection["department"] != "dept-demo" || projection["application"] != "app-demo" {
		t.Fatalf("scope was not injected: %#v", projection)
	}
	if projection["user"] != "fixture.admin" || projection["principal_type"] != "user" || projection["internal_token"] != "server-owned-key" || projection["forged_api_key"] != "" || projection["forged_tenant"] != "" {
		t.Fatalf("identity was not protected: %#v", projection)
	}
	retired, err := client.Get(server.URL + "/api/v1/batches")
	if err != nil {
		t.Fatal(err)
	}
	defer retired.Body.Close()
	if retired.StatusCode != http.StatusNotFound {
		t.Fatalf("retired Backend path must fail closed: %d", retired.StatusCode)
	}
}

func TestRemediationDemoAccountsAreScopedAndLeastPrivileged(t *testing.T) {
	passwords := map[string]string{
		"DEMO_PASSWORD_FIXTURE_REQUESTER": "requester-test-password",
		"DEMO_PASSWORD_FIXTURE_REVIEWER":  "reviewer-test-password",
		"DEMO_PASSWORD_FIXTURE_OPERATOR":  "operator-test-password",
		"DEMO_PASSWORD_FIXTURE_VERIFIER":  "verifier-test-password",
	}
	for name, value := range passwords {
		t.Setenv(name, value)
	}
	handler, err := newHandlerWithConfig("http://127.0.0.1:1", t.TempDir(), "test-key", false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	actors := []struct {
		username string
		password string
		role     string
	}{
		{"fixture.requester", passwords["DEMO_PASSWORD_FIXTURE_REQUESTER"], "operator"},
		{"fixture.reviewer", passwords["DEMO_PASSWORD_FIXTURE_REVIEWER"], "reviewer"},
		{"fixture.operator", passwords["DEMO_PASSWORD_FIXTURE_OPERATOR"], "operator"},
		{"fixture.verifier", passwords["DEMO_PASSWORD_FIXTURE_VERIFIER"], "reviewer"},
	}
	for _, actor := range actors {
		body, _ := json.Marshal(map[string]string{"username": actor.username, "password": actor.password})
		response, requestErr := http.Post(server.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		var claims userClaims
		decodeErr := json.NewDecoder(response.Body).Decode(&claims)
		_ = response.Body.Close()
		if decodeErr != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("login %s status=%d err=%v", actor.username, response.StatusCode, decodeErr)
		}
		if claims.Username != actor.username || claims.TenantID != "tenant-demo" || claims.DepartmentID != "dept-demo" || claims.ApplicationID != "app-demo" || len(claims.Roles) != 1 || claims.Roles[0] != actor.role {
			t.Fatalf("identity %s is not scoped and least-privileged: %+v", actor.username, claims)
		}
		cookie := response.Header.Get("Set-Cookie")
		if !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "SameSite=Strict") {
			t.Fatalf("login %s did not receive protected session cookie: %q", actor.username, cookie)
		}
	}
}

func TestStaticFallbackAndSystemOpsAuthorization(t *testing.T) {
	t.Setenv("MODEL_MODE", "mock")
	t.Setenv("DEMO_PASSWORD_FIXTURE_ADMIN", "test-compliance-password")
	t.Setenv("DEMO_PASSWORD_SYSTEM_ADMIN", "test-system-password")
	staticRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticRoot, "index.html"), []byte("<main>LexAgent</main>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(staticRoot, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staticRoot, "assets", "index.js"), []byte("react"), 0o600); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	handler, _ := newHandler(upstream.URL, staticRoot)
	server := httptest.NewServer(handler)
	defer server.Close()

	for _, path := range []string{"/healthz", "/", "/apps/business-example", "/assets/index.js"} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d", path, response.StatusCode)
		}
		_ = response.Body.Close()
	}
	missing, _ := http.Get(server.URL + "/assets/missing.js")
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("missing asset should be 404, got %d", missing.StatusCode)
	}
	_ = missing.Body.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	loginBody, _ := json.Marshal(map[string]string{"username": "fixture.admin", "password": "test-compliance-password"})
	login, _ := client.Post(server.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
	_ = login.Body.Close()
	denied, _ := client.Get(server.URL + "/ops/status")
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("expected ops 403, got %d", denied.StatusCode)
	}
	_ = denied.Body.Close()

	systemJar, _ := cookiejar.New(nil)
	systemClient := &http.Client{Jar: systemJar}
	systemBody, _ := json.Marshal(map[string]string{"username": "system.admin", "password": "test-system-password"})
	systemLogin, _ := systemClient.Post(server.URL+"/auth/login", "application/json", bytes.NewReader(systemBody))
	_ = systemLogin.Body.Close()
	statusResponse, err := systemClient.Get(server.URL + "/ops/status")
	if err != nil {
		t.Fatal(err)
	}
	defer statusResponse.Body.Close()
	var status map[string]any
	if err := json.NewDecoder(statusResponse.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if statusResponse.StatusCode != http.StatusOK || status["model_mode"] != "mock" {
		t.Fatalf("unexpected ops status: code=%d payload=%#v", statusResponse.StatusCode, status)
	}
	if _, legacy := status["backend"]; legacy {
		t.Fatal("ops status must not report the retired Backend process")
	}
	if _, legacy := status["kubernetes"]; legacy {
		t.Fatal("ops status must not advertise a stale Kubernetes manifest/control-plane claim")
	}
	if platform, ok := status["platform"].(map[string]any); !ok || platform["status"] != "healthy" {
		t.Fatalf("ops status must probe the platform process: %#v", status["platform"])
	}
	components, ok := status["components"].([]any)
	if !ok || len(components) != 2 {
		t.Fatalf("ops status must report only deployed platform components: %#v", status["components"])
	}
}

func TestConversationProxyInjectsAuthenticatedPlatformScope(t *testing.T) {
	t.Setenv("DEMO_PASSWORD_FIXTURE_ADMIN", "test-compliance-password")
	t.Setenv("PLATFORM_GATEWAY_TOKEN", "platform-owned-token")
	seen := map[string]int{}
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/modules/conversation/sessions" {
			t.Fatalf("platform path = %s", r.URL.Path)
		}
		if r.Header.Get("X-Internal-Token") != "platform-owned-token" || r.Header.Get("X-Tenant-ID") != "tenant-demo" || r.Header.Get("X-Principal-ID") != "fixture.admin" {
			t.Fatalf("platform scope headers = %#v", r.Header)
		}
		seen[r.URL.Path]++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"total":0,"page":1,"page_size":5}`))
	}))
	defer platform.Close()
	t.Setenv("PLATFORM_URL", platform.URL)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer backend.Close()
	handler, err := newHandlerWithConfig(backend.URL, t.TempDir(), "backend-key", false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := &http.Client{Jar: mustCookieJar(t)}
	loginBody := strings.NewReader(`{"username":"fixture.admin","password":"test-compliance-password"}`)
	login, err := client.Post(server.URL+"/auth/login", "application/json", loginBody)
	if err != nil || login.StatusCode != http.StatusOK {
		t.Fatalf("login status=%v err=%v", login.StatusCode, err)
	}
	_ = login.Body.Close()
	response, err := client.Get(server.URL + "/api/modules/conversation/sessions?kind=qa&view=mine&page=1&page_size=5")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("conversation proxy status = %d", response.StatusCode)
	}
}

func TestConversationProxyForwardsOnlyValidTraceparent(t *testing.T) {
	t.Setenv("DEMO_PASSWORD_FIXTURE_ADMIN", "test-compliance-password")
	t.Setenv("PLATFORM_GATEWAY_TOKEN", "platform-owned-token")
	const parent = "00-11111111111111111111111111111111-2222222222222222-01"
	seen := make([]string, 0, 2)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("traceparent"))
		if r.Header.Get("baggage") != "" || r.Header.Get("tracestate") != "" {
			t.Fatal("untrusted browser trace baggage was forwarded")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"total":0}`))
	}))
	defer platform.Close()
	t.Setenv("PLATFORM_URL", platform.URL)
	handler, err := newHandlerWithConfig(platform.URL, t.TempDir(), "platform-owned-token", false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := &http.Client{Jar: mustCookieJar(t)}
	login, err := client.Post(server.URL+"/auth/login", "application/json", strings.NewReader(`{"username":"fixture.admin","password":"test-compliance-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = login.Body.Close()
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", login.StatusCode)
	}
	for _, candidate := range []string{parent, "00-00000000000000000000000000000000-2222222222222222-01"} {
		request, err := http.NewRequest(http.MethodGet, server.URL+"/api/modules/conversation/sessions", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("traceparent", candidate)
		request.Header.Set("baggage", "private-fixture-secret")
		request.Header.Set("tracestate", "private=fixture")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("proxy status = %d", response.StatusCode)
		}
	}
	if len(seen) != 2 || seen[0] != parent || seen[1] != "" {
		t.Fatalf("forwarded traceparents = %#v", seen)
	}
}

func TestPublicConversationShareUsesOnlyPlatformCapabilityRoute(t *testing.T) {
	t.Setenv("PLATFORM_GATEWAY_TOKEN", "platform-owned-token")
	token := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/modules/conversation/shares/"+token || r.URL.Query().Get("page") != "2" {
			t.Fatalf("public share upstream path/query = %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		if r.Header.Get("X-Internal-Token") != "platform-owned-token" || r.Header.Get("X-Tenant-ID") != "" || r.Header.Get("X-Principal-ID") != "" {
			t.Fatalf("public share forwarded caller identity: %#v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session_id":"s1","messages":[]}`))
	}))
	defer platform.Close()
	t.Setenv("PLATFORM_URL", platform.URL)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer backend.Close()
	handler, err := newHandlerWithConfig(backend.URL, t.TempDir(), "backend-key", false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	response, err := http.Get(server.URL + "/api/modules/conversation/shares/" + token + "?page=2")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store, private" {
		t.Fatalf("public share response status=%d headers=%v", response.StatusCode, response.Header)
	}
	_ = response.Body.Close()

	legacy, err := http.Get(server.URL + "/api/v1/shared/conversations/legacy-token")
	if err != nil {
		t.Fatal(err)
	}
	if legacy.StatusCode != http.StatusNotFound {
		t.Fatalf("legacy share endpoint status=%d, want 404", legacy.StatusCode)
	}
	_ = legacy.Body.Close()
}

func TestPublicEnrollmentGatewayUsesIdentityModuleOnly(t *testing.T) {
	t.Setenv("PLATFORM_GATEWAY_TOKEN", "platform-owned-token")
	seen := map[string]int{}
	var backendRequests int
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Token") != "platform-owned-token" {
			t.Fatalf("Identity internal token missing: %#v", r.Header)
		}
		if r.Header.Get("X-Tenant-ID") != "" || r.Header.Get("X-Principal-ID") != "" {
			t.Fatalf("public registration forwarded caller-controlled scope: %#v", r.Header)
		}
		clientIP := r.Header.Get("X-Internal-Client-IP")
		if net.ParseIP(clientIP) == nil || clientIP == "203.0.113.99" {
			t.Fatalf("Gateway must derive the trusted rate-limit IP from the socket peer: %q", clientIP)
		}
		seen[r.Method+" "+r.URL.Path]++
		switch r.URL.Path {
		case "/modules/identity/registration-agent-catalog":
			if r.Method != http.MethodGet {
				t.Fatalf("catalog method = %s", r.Method)
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": []any{map[string]any{"agent_id": "business-example-qa-agent", "agent_instance_id": "install-qa", "name": "文档助手"}}})
		case "/modules/identity/registrations":
			if r.Method != http.MethodPost {
				t.Fatalf("register method = %s", r.Method)
			}
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["username"] != "new.user" {
				t.Fatalf("registration body = %#v", body)
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"registration_id": "reg-1", "status": "contact_verification_pending", "status_token": "opaque-token"})
		case "/modules/identity/registrations/reg-1/verify-contact":
			if r.Method != http.MethodPost || r.Header.Get("X-Registration-Token") != "opaque-token" || r.URL.RawQuery != "" {
				t.Fatalf("verification request method/headers/query invalid: %s %#v?%s", r.Method, r.Header, r.URL.RawQuery)
			}
			writeJSON(w, http.StatusOK, map[string]any{"registration_id": "reg-1", "status": "pending_review"})
		default:
			t.Fatalf("unexpected Identity route: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer platform.Close()
	t.Setenv("PLATFORM_URL", platform.URL)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendRequests++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer backend.Close()
	handler, err := newHandlerWithConfig(backend.URL, t.TempDir(), "backend-key", false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	catalogRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/auth/registration-agent-catalog", nil)
	catalogRequest.Header.Set("X-Internal-Client-IP", "203.0.113.99")
	catalog, err := http.DefaultClient.Do(catalogRequest)
	if err != nil || catalog.StatusCode != http.StatusOK {
		t.Fatalf("catalog status=%v err=%v", catalog.StatusCode, err)
	}
	_ = catalog.Body.Close()

	registration, err := http.Post(server.URL+"/auth/register", "application/json", strings.NewReader(`{"username":"new.user","password":"long-test-password","requested_agent_ids":["business-example-qa-agent"]}`))
	if err != nil || registration.StatusCode != http.StatusAccepted {
		t.Fatalf("registration status=%v err=%v", registration.StatusCode, err)
	}
	_ = registration.Body.Close()

	verification, err := http.NewRequest(http.MethodPost, server.URL+"/auth/registrations/reg-1/verify-contact", strings.NewReader(`{"code":"123456"}`))
	if err != nil {
		t.Fatal(err)
	}
	verification.Header.Set("Content-Type", "application/json")
	verification.Header.Set("X-Registration-Token", "opaque-token")
	verified, err := http.DefaultClient.Do(verification)
	if err != nil || verified.StatusCode != http.StatusOK {
		t.Fatalf("verification status=%v err=%v", verified.StatusCode, err)
	}
	_ = verified.Body.Close()

	queryToken, err := http.Get(server.URL + "/auth/registrations/reg-1/status?registration_token=must-not-be-accepted")
	if err != nil || queryToken.StatusCode != http.StatusBadRequest {
		t.Fatalf("query token status=%v err=%v", queryToken.StatusCode, err)
	}
	_ = queryToken.Body.Close()
	if backendRequests != 0 {
		t.Fatalf("public enrollment called retired Backend %d times", backendRequests)
	}
	if seen["GET /modules/identity/registration-agent-catalog"] != 1 || seen["POST /modules/identity/registrations"] != 1 || seen["POST /modules/identity/registrations/reg-1/verify-contact"] != 1 {
		t.Fatalf("Identity route counts = %#v", seen)
	}
}

func TestDynamicLocalLoginPreservesRateLimitWithoutIssuingSession(t *testing.T) {
	t.Setenv("PLATFORM_GATEWAY_TOKEN", "rate-fixture-token")
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/modules/identity/internal/credentials/verify" {
			t.Error("rate-limited login attempted another identity operation")
		}
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "RATE_LIMITED"})
	}))
	defer platform.Close()
	t.Setenv("PLATFORM_URL", platform.URL)
	handler, err := newHandlerWithConfig(platform.URL, t.TempDir(), "test-only-backend", false)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"rate.fixture","password":"test-only-password"}`)))
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), `"code":"RATE_LIMITED"`) || len(w.Result().Cookies()) != 0 {
		t.Fatal("login rate limit was hidden or session issued", w.Code, w.Body.String())
	}
}

func TestDynamicLocalLoginAndSessionValidationUseIdentityModule(t *testing.T) {
	t.Setenv("PLATFORM_GATEWAY_TOKEN", "platform-owned-token")
	var backendRequests int
	seenVerify, seenValidate := 0, 0
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Token") != "platform-owned-token" {
			t.Fatalf("Identity internal token missing: %#v", r.Header)
		}
		switch r.URL.Path {
		case "/modules/identity/internal/credentials/verify":
			seenVerify++
			var request map[string]any
			if json.NewDecoder(r.Body).Decode(&request) != nil || request["username"] != "enrolled.user" || request["password"] != "user-password" {
				t.Fatalf("credential verification body = %#v", request)
			}
			writeJSON(w, http.StatusOK, map[string]any{"principal_id": "enrolled.user", "username": "enrolled.user", "display_name": "已注册用户", "tenant_id": "tenant-a", "department_id": "department-a", "application_id": "application-a", "roles": []string{"operator"}, "auth_revision": 3})
		case "/modules/identity/internal/refresh-sessions":
			writeJSON(w, http.StatusOK, map[string]any{"session_id": strings.Repeat("a", 64), "authentication_method": "local", "refresh_token": "test-refresh-token", "expires_at": time.Now().Add(refreshTokenTTL), "identity": map[string]any{"username": "enrolled.user", "auth_revision": 3}})
		case "/modules/identity/internal/browser-sessions/validate":
			seenValidate++
			var request map[string]any
			if json.NewDecoder(r.Body).Decode(&request) != nil || request["session_id"] != strings.Repeat("a", 64) || request["auth_revision"] != float64(3) {
				t.Fatalf("session validation body = %#v", request)
			}
			writeJSON(w, http.StatusOK, map[string]any{"active": true})
		default:
			t.Fatalf("unexpected Identity auth route: %s", r.URL.Path)
		}
	}))
	defer platform.Close()
	t.Setenv("PLATFORM_URL", platform.URL)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendRequests++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer backend.Close()
	handler, err := newHandlerWithConfig(backend.URL, t.TempDir(), "backend-key", false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := &http.Client{Jar: mustCookieJar(t)}
	login, err := client.Post(server.URL+"/auth/login", "application/json", strings.NewReader(`{"username":"enrolled.user","password":"user-password"}`))
	if err != nil || login.StatusCode != http.StatusOK {
		t.Fatalf("dynamic login status=%v err=%v", login.StatusCode, err)
	}
	_ = login.Body.Close()
	me, err := client.Get(server.URL + "/auth/me")
	if err != nil || me.StatusCode != http.StatusOK {
		t.Fatalf("session identity status=%v err=%v", me.StatusCode, err)
	}
	_ = me.Body.Close()
	if seenVerify != 1 || seenValidate != 1 || backendRequests != 0 {
		t.Fatalf("verify=%d validate=%d retired Backend requests=%d", seenVerify, seenValidate, backendRequests)
	}
}

func TestCatalogProxyInjectsAuthenticatedPlatformScope(t *testing.T) {
	t.Setenv("DEMO_PASSWORD_FIXTURE_ADMIN", "test-compliance-password")
	t.Setenv("PLATFORM_GATEWAY_TOKEN", "platform-owned-token")
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/modules/catalog/available" {
			t.Fatalf("platform path = %s", r.URL.Path)
		}
		if r.Header.Get("X-Internal-Token") != "platform-owned-token" || r.Header.Get("X-Tenant-ID") != "tenant-demo" || r.Header.Get("X-Principal-ID") != "fixture.admin" {
			t.Fatalf("platform scope headers = %#v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"total":0,"page":1,"page_size":20}`))
	}))
	defer platform.Close()
	t.Setenv("PLATFORM_URL", platform.URL)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer backend.Close()
	handler, err := newHandlerWithConfig(backend.URL, t.TempDir(), "backend-key", false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := &http.Client{Jar: mustCookieJar(t)}
	login, err := client.Post(server.URL+"/auth/login", "application/json", strings.NewReader(`{"username":"fixture.admin","password":"test-compliance-password"}`))
	if err != nil || login.StatusCode != http.StatusOK {
		t.Fatalf("login status=%v err=%v", login.StatusCode, err)
	}
	_ = login.Body.Close()
	response, err := client.Get(server.URL + "/api/modules/catalog/available?page=1&page_size=20")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("catalog proxy status = %d", response.StatusCode)
	}
}

func TestBrowserSSEFlushesAndSurvivesOrdinaryClientTimeout(t *testing.T) {
	t.Setenv("DEMO_PASSWORD_FIXTURE_ADMIN", "test-compliance-password")
	t.Setenv("PLATFORM_GATEWAY_TOKEN", "platform-owned-token")
	release := make(chan struct{})
	defer close(release)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: accepted\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-time.After(2200 * time.Millisecond):
		case <-r.Context().Done():
			return
		case <-release:
			return
		}
		_, _ = io.WriteString(w, "event: task_completed\ndata: {}\n\n")
	}))
	defer platform.Close()
	t.Setenv("PLATFORM_URL", platform.URL)
	handler, err := newHandlerWithConfig(platform.URL, t.TempDir(), "backend-key", false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := &http.Client{Jar: mustCookieJar(t), Timeout: 5 * time.Second}
	login, err := client.Post(server.URL+"/auth/login", "application/json", strings.NewReader(`{"username":"fixture.admin","password":"test-compliance-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	login.Body.Close()
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d", login.StatusCode)
	}
	started := time.Now()
	response, err := client.Get(server.URL + "/api/modules/execution/platform/runs/test/events")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	first, err := reader.ReadString('\n')
	if err != nil || first != "event: accepted\n" || time.Since(started) >= 2*time.Second {
		t.Fatalf("first event was buffered: %q err=%v", first, err)
	}
	rest, err := io.ReadAll(reader)
	if err != nil || !bytes.Contains(rest, []byte("event: task_completed")) {
		t.Fatalf("long stream truncated: %s err=%v", rest, err)
	}
}

func TestEvaluationDiscoverySurvivesOfflineHealthProbeDeadline(t *testing.T) {
	t.Setenv("DEMO_PASSWORD_FIXTURE_ADMIN", "test-compliance-password")
	t.Setenv("PLATFORM_GATEWAY_TOKEN", "platform-owned-token")
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/modules/evaluation-product/agents" || r.Header.Get("X-Principal-ID") != "fixture.admin" {
			t.Errorf("unexpected discovery path/identity")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		select {
		case <-time.After(2100 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"online": 0, "items": []map[string]any{{"health": "offline", "can_evaluate": false}}})
	}))
	defer platform.Close()
	t.Setenv("PLATFORM_URL", platform.URL)
	handler, err := newHandlerWithConfig(platform.URL, t.TempDir(), "backend-key", false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := &http.Client{Jar: mustCookieJar(t), Timeout: 5 * time.Second}
	login, err := client.Post(server.URL+"/auth/login", "application/json", strings.NewReader(`{"username":"fixture.admin","password":"test-compliance-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	login.Body.Close()
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d", login.StatusCode)
	}
	response, err := client.Get(server.URL + "/api/modules/evaluation-product/agents?page=1")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"offline"`)) {
		t.Fatalf("offline Agent must be returned as discovery item: status=%d err=%v", response.StatusCode, err)
	}
}

func TestPlatformModuleGatewayExposesRegistryModules(t *testing.T) {
	t.Setenv("DEMO_PASSWORD_FIXTURE_ADMIN", "test-compliance-password")
	t.Setenv("PLATFORM_GATEWAY_TOKEN", "platform-owned-token")
	seen := map[string]int{}
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Token") != "platform-owned-token" || r.Header.Get("X-Tenant-ID") != "tenant-demo" || r.Header.Get("X-Principal-ID") != "fixture.admin" {
			t.Fatalf("platform scope headers = %#v", r.Header)
		}
		if r.Header.Get("X-Browser-Module") != "1" {
			t.Fatalf("browser module marker missing: %#v", r.Header)
		}
		if r.Header.Get("X-Trace-ID") == "" {
			t.Fatal("gateway request trace missing")
		}
		if strings.Contains(r.URL.Path, "/remediation/") && r.Header.Get("Idempotency-Key") != "browser-command-123" {
			t.Fatalf("remediation idempotency key was not forwarded: %#v", r.Header)
		}
		seen[r.URL.Path]++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer platform.Close()
	t.Setenv("PLATFORM_URL", platform.URL)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer backend.Close()
	handler, err := newHandlerWithConfig(backend.URL, t.TempDir(), "backend-key", false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := &http.Client{Jar: mustCookieJar(t)}
	login, err := client.Post(server.URL+"/auth/login", "application/json", strings.NewReader(`{"username":"fixture.admin","password":"test-compliance-password"}`))
	if err != nil || login.StatusCode != http.StatusOK {
		t.Fatalf("login status=%v err=%v", login.StatusCode, err)
	}
	_ = login.Body.Close()
	cases := []struct {
		publicPath   string
		platformPath string
	}{
		{"identity/tenants", "/modules/identity/tenants"},
		{"catalog/available", "/modules/catalog/available"},
		{"catalog/definitions/agent-1", "/modules/catalog/definitions/agent-1"},
		{"conversation/sessions", "/modules/conversation/sessions"},
		{"execution/platform/runs/run-1/events", "/modules/execution/platform/runs/run-1/events"},
		{"evaluation-product/runs/run-1", "/modules/evaluation-product/runs/run-1"},
		{"usage/snapshots", "/modules/usage-cost/snapshots"},
		{"usage-cost/snapshots", "/modules/usage-cost/snapshots"},
		{"audit/events", "/modules/audit/events"},
		{"audit/runtime-steps", "/modules/audit/runtime-steps"},
		{"notification/events", "/modules/notification/events"},
		{"model-governance/providers", "/modules/model-governance/providers"},
		{"model-billing/reconciliations", "/modules/capability/billing/reconciliations"},
		{"policyasset/assets", "/modules/policyasset/assets"},
		{"knowledge/sources/docs", "/modules/knowledge/sources/docs"},
	}
	for _, tc := range cases {
		response, requestErr := client.Get(server.URL + "/api/modules/" + tc.publicPath)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status=%d", tc.publicPath, response.StatusCode)
		}
	}
	for _, tc := range cases {
		// Both browser aliases (`usage` and `usage-cost`) intentionally resolve to
		// the same platform module path.  Count the expected occurrences instead
		// of treating the alias pair as a duplicate forward.
		// 浏览器别名 usage 与 usage-cost 按契约映射到同一个平台模块路径，
		// 因此按预期次数断言，而不是把别名访问误判为重复转发。
		expected := 1
		if tc.platformPath == "/modules/usage-cost/snapshots" {
			expected = 2
		}
		if seen[tc.platformPath] != expected {
			t.Fatalf("platform path %s expected %d forwards (seen=%d)", tc.platformPath, expected, seen[tc.platformPath])
		}
	}
	blocked, err := client.Get(server.URL + "/api/modules/model-billing/internal/model/generate")
	if err != nil {
		t.Fatal(err)
	}
	_ = blocked.Body.Close()
	if blocked.StatusCode != http.StatusNotFound || seen["/modules/capability/billing/internal/model/generate"] != 0 {
		t.Fatal("billing alias exposed a private capability route")
	}
	command, err := http.NewRequest(http.MethodPost, server.URL+"/api/modules/execution/platform/runs/run-1/resume", strings.NewReader(`{"decision":"approve","expected_revision":1}`))
	if err != nil {
		t.Fatal(err)
	}
	command.Header.Set("Content-Type", "application/json")
	command.Header.Set("Origin", server.URL)
	command.Header.Set("Idempotency-Key", "browser-command-123")
	response, err := client.Do(command)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || seen["/modules/execution/platform/runs/run-1/resume"] != 1 {
		t.Fatalf("run review command proxy status=%d forwarded=%d", response.StatusCode, seen["/modules/execution/platform/runs/run-1/resume"])
	}
	for _, action := range []string{"preview", "step-up", "approve", "revoke"} {
		request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/modules/tool-approvals/"+action, strings.NewReader(`{}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", server.URL)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 200 || seen["/modules/capability/tool-approvals/"+action] != 1 {
			t.Fatal("approval alias not limited and routed", action)
		}
	}
	blocked, err = client.Get(server.URL + "/api/modules/tool-approvals/internal/tool/invoke")
	if err != nil {
		t.Fatal(err)
	}
	blocked.Body.Close()
	if blocked.StatusCode != 404 || seen["/modules/capability/tool-approvals/internal/tool/invoke"] != 0 {
		t.Fatal("approval alias exposed private tool gateway")
	}
}

func TestPlatformModuleGatewayRejectsUnknownModule(t *testing.T) {
	handler, err := newHandlerWithConfig("http://127.0.0.1:1", t.TempDir(), "backend-key", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, module := range []string{"not-a-module", "evaluation"} {
		request := httptest.NewRequest(http.MethodGet, "/api/modules/"+module+"/health", nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("retired or unknown module %q status=%d", module, recorder.Code)
		}
	}
}

func mustCookieJar(t *testing.T) *cookiejar.Jar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return jar
}
