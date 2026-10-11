package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceSwitchUsesSignedActorAndRotatesBothCookies(t *testing.T) {
	calls := 0
	status := http.StatusOK
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var input map[string]any
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			t.Fatal("invalid request")
		}
		if r.URL.Path != "/modules/identity/internal/refresh-sessions:workspace" || input["username"] != "alice" || input["auth_revision"] != float64(4) || input["refresh_token"] != "fixture-refresh" || r.Header.Get("X-Internal-Token") != "gateway-token" {
			t.Errorf("untrusted switch request: path=%s input=%v", r.URL.Path, input)
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			result := platformRefreshResult{SessionID: strings.Repeat("a", 64), AuthenticationMethod: "local", RefreshToken: "fixture-next", ExpiresAt: time.Now().Add(time.Hour)}
			result.Identity.Username = "alice"
			result.Identity.DisplayName = "Alice"
			result.Identity.AuthRevision = 4
			result.Identity.TenantID = "t"
			result.Identity.DepartmentID = "d"
			result.Identity.ApplicationID = "b"
			json.NewEncoder(w).Encode(result)
		}
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newAccessTokenSigner("")
	if err != nil {
		t.Fatal(err)
	}
	signer.authMode = "local"
	g := &gateway{platformTarget: targetURL, platformToken: "gateway-token", authMode: "local", httpClient: upstream.Client(), accessSigner: signer}
	h := http.HandlerFunc(g.serveHTTP)
	access, err := g.accessSigner.sign(userClaims{Username: "alice", TenantID: "t", DepartmentID: "d", ApplicationID: "a", TokenVersion: 4}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(origin, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "http://gateway/auth/workspace", strings.NewReader(body))
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Principal-ID", "attacker")
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: access})
		r.AddCookie(&http.Cookie{Name: refreshCookie, Value: "local.fixture-refresh"})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	body := `{"tenant_id":"t","department_id":"d","application_id":"b"}`
	if response := invoke("http://evil", body); response.Code != http.StatusForbidden || calls != 0 {
		t.Fatal("CSRF switch reached upstream")
	}
	if response := invoke("http://gateway", `{"tenant_id":"t","department_id":"d","application_id":"b","username":"attacker"}`); response.Code != http.StatusBadRequest || calls != 0 {
		t.Fatal("browser selected principal")
	}
	response := invoke("http://gateway", body)
	if response.Code != http.StatusOK {
		t.Fatal(response.Code, response.Body.String())
	}
	var sawAccess, sawRefresh bool
	for _, c := range response.Result().Cookies() {
		if c.Name == sessionCookie {
			claims, ok := g.accessSigner.verify(c.Value, time.Now())
			sawAccess = ok && claims.Username == "alice" && claims.ApplicationID == "b" && claims.SessionID == strings.Repeat("a", 64) && c.HttpOnly && c.MaxAge == 900
		}
		if c.Name == refreshCookie {
			sawRefresh = c.Value == "local.fixture-next" && c.Path == "/auth" && c.HttpOnly
		}
	}
	if !sawAccess || !sawRefresh {
		t.Fatal("switch failed to renew both cookies")
	}
	for _, code := range []int{http.StatusForbidden, http.StatusUnauthorized, http.StatusServiceUnavailable} {
		status = code
		response = invoke("http://gateway", body)
		if response.Code != code || len(response.Result().Cookies()) != 0 {
			t.Fatalf("failure replaced valid cookies: upstream=%d response=%d", code, response.Code)
		}
	}
}
