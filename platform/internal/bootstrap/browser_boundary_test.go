package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBrowserBoundarySeparatesGatewayAndAgentAuthority(t *testing.T) {
	gatewayToken := "gateway-fixture-0123456789abcdef0123456789abcdef"
	runtimeToken := "runtime-fixture-0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name, path, token, browser string
		status                     int
	}{
		{"agent cannot impersonate browser", "/modules/identity/principals", runtimeToken, "1", 403},
		{"agent cannot omit browser marker", "/modules/identity/grants", runtimeToken, "", 403},
		{"agent cannot mint refresh", "/modules/identity/internal/refresh-sessions", runtimeToken, "", 403},
		{"agent cannot configure model", "/modules/model-governance/profiles", runtimeToken, "", 403},
		{"gateway authentication request", "/modules/identity/internal/credentials/verify", gatewayToken, "", 204},
		{"gateway OIDC fresh authentication challenge", "/modules/identity/internal/oidc/step-up:challenge", gatewayToken, "", 204},
		{"gateway OIDC fresh authentication completion", "/modules/identity/internal/oidc/step-up:complete", gatewayToken, "", 204},
		{"browser cannot complete OIDC authentication", "/modules/identity/internal/oidc/step-up:complete", gatewayToken, "1", 403},
		{"Agent cannot assert OIDC authentication", "/modules/identity/internal/oidc/step-up:complete", runtimeToken, "", 403},
		{"unknown OIDC internal route remains blocked", "/modules/identity/internal/oidc/step-up:other", gatewayToken, "", 403},
		{"gateway browser cannot mint refresh", "/modules/identity/internal/refresh-sessions", gatewayToken, "1", 403},
		{"gateway needs human context for grants", "/modules/identity/grants", gatewayToken, "", 403},
		{"human management transport", "/modules/catalog/definitions", gatewayToken, "1", 204},
		{"machine exchange uses own credentials", "/modules/identity/oauth/token", "", "", 204},
		{"execution delegates machine authorization", "/modules/execution/runs", runtimeToken, "", 204},
		{"shared secret cannot create as an arbitrary caller", "/modules/execution/platform/runs", runtimeToken, "", 403},
		{"shared secret cannot mutate an arbitrary Run", "/modules/execution/platform/runs/known/transition", runtimeToken, "", 403},
		{"missing credential cannot use local provider", "/modules/execution/platform/runs", "", "", 403},
		{"machine entry validates its bearer", "/modules/execution/agent-runs", runtimeToken, "", 204},
		{"capability delegates signed context", "/modules/capability/knowledge/search", runtimeToken, "", 204},
		{"gateway cannot impersonate service", "/modules/execution/runs", gatewayToken, "", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := BrowserBoundary(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if tc.token == gatewayToken && r.Header.Get("X-Internal-Token") != runtimeToken {
					t.Fatal("gateway token leaked to module")
				}
				w.WriteHeader(204)
			}), gatewayToken, runtimeToken)
			r := httptest.NewRequest(http.MethodPost, tc.path, nil)
			r.Header.Set("X-Internal-Token", tc.token)
			r.Header.Set("X-Browser-Module", tc.browser)
			for key, value := range map[string]string{"X-Principal-Type": "user", "X-Principal-ID": "alice", "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a"} {
				r.Header.Set(key, value)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || called != (tc.status == 204) {
				t.Fatalf("status=%d downstream=%v", w.Code, called)
			}
			if r.Header.Get("X-Internal-Token") != tc.token {
				t.Fatal("middleware mutated incoming request")
			}
		})
	}
}

func TestBrowserBoundaryPublicShareReadOnly(t *testing.T) {
	gateway := "gateway-fixture-0123456789abcdef0123456789abcdef"
	runtime := "runtime-fixture-0123456789abcdef0123456789abcdef"
	valid := "/modules/conversation/shares/" + strings.Repeat("A", 43)
	for _, tc := range []struct {
		method, path, token string
		status              int
	}{
		{http.MethodGet, valid, gateway, 204},
		{http.MethodGet, valid, runtime, 403},
		{http.MethodPost, valid, gateway, 403},
		{http.MethodGet, valid + "/revoke", gateway, 403},
		{http.MethodGet, valid + "/", gateway, 403},
		{http.MethodGet, "/modules/conversation/shares/invalid", gateway, 403},
	} {
		h := BrowserBoundary(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), gateway, runtime)
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.Header.Set("X-Internal-Token", tc.token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("method=%s path=%s status=%d want=%d", tc.method, tc.path, w.Code, tc.status)
		}
	}
}

func TestBrowserBoundaryMissingGatewayCredentialFailsClosed(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("missing gateway configuration reached IAM") })
	for _, key := range []string{"", "shared-fixture-0123456789abcdef0123456789abcdef"} {
		h := BrowserBoundary(next, key, "shared-fixture-0123456789abcdef0123456789abcdef")
		r := httptest.NewRequest(http.MethodGet, "/modules/identity/principals", nil)
		r.Header.Set("X-Internal-Token", key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 503 && w.Code != 403 {
			t.Fatal("unsafe configuration allowed", w.Code)
		}
	}
}

func TestGatewayConfigurationRejectsSharedRuntimeCredential(t *testing.T) {
	config := productionCredentialFixture()
	for _, token := range []string{"", config.InternalToken, "short"} {
		config.BrowserGatewayToken = token
		if config.Validate() == nil {
			t.Fatal("invalid gateway credential admitted")
		}
	}
	config.Environment = "development"
	config.BrowserGatewayToken = config.InternalToken
	if config.Validate() == nil {
		t.Fatal("development gateway shares Agent credential")
	}
}
