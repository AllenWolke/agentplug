package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDemoRefreshRotationAndCookieIsolation(t *testing.T) {
	t.Setenv("DEMO_PASSWORD_FIXTURE_USER", "test-password")
	handler, err := newHandler("http://127.0.0.1:1", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest(http.MethodPost, "http://gateway/auth/login", strings.NewReader(`{"username":"fixture.user","password":"test-password"}`)))
	if login.Code != http.StatusOK {
		t.Fatal(login.Code, login.Body.String())
	}
	var refresh, access *http.Cookie
	for _, cookie := range login.Result().Cookies() {
		if cookie.Name == refreshCookie {
			refresh = cookie
		}
		if cookie.Name == sessionCookie {
			access = cookie
		}
	}
	if refresh == nil || access == nil || refresh.Path != "/auth" || access.MaxAge != 900 || !refresh.HttpOnly || !access.HttpOnly {
		t.Fatal("token cookie constraints")
	}
	request := func(cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "http://gateway/auth/refresh", nil)
		r.Header.Set("Origin", origin)
		r.AddCookie(cookie)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		return response
	}
	if got := request(refresh, "http://evil"); got.Code != http.StatusForbidden {
		t.Fatal("CSRF accepted")
	}
	next := request(refresh, "http://gateway")
	if next.Code != http.StatusOK {
		t.Fatal(next.Code, next.Body.String())
	}
	var nextRefresh *http.Cookie
	for _, cookie := range next.Result().Cookies() {
		if cookie.Name == refreshCookie {
			nextRefresh = cookie
		}
	}
	if nextRefresh == nil || nextRefresh.Value == refresh.Value {
		t.Fatal("refresh did not rotate")
	}
	if got := request(refresh, "http://gateway"); got.Code != http.StatusUnauthorized {
		t.Fatal("replay accepted")
	}
	if got := request(nextRefresh, "http://gateway"); got.Code != http.StatusUnauthorized {
		t.Fatal("replayed family survived")
	}
	// Revoking refresh does not pretend to revoke a stateless access assertion.
	r := httptest.NewRequest(http.MethodGet, "http://gateway/auth/me", nil)
	r.AddCookie(access)
	me := httptest.NewRecorder()
	handler.ServeHTTP(me, r)
	if me.Code != http.StatusOK {
		t.Fatal("unexpired signature rejected unexpectedly")
	}
	var user userClaims
	if json.Unmarshal(me.Body.Bytes(), &user) != nil || user.Username != "fixture.user" {
		t.Fatal("invalid access identity")
	}
}

func TestDemoRefreshNeverPersistsBearerAndDoesNotExtendLifetime(t *testing.T) {
	s := &sessionStore{items: map[string]session{}}
	token, err := s.create(demoClaims["fixture.user"])
	if err != nil {
		t.Fatal(err)
	}
	if _, found := s.items[token]; found {
		t.Fatal("refresh stored in plaintext")
	}
	expires := s.items[gatewayRefreshHash(token)].ExpiresAt
	next, _, nextExpires, err := s.rotate(token)
	if err != nil || nextExpires != expires {
		t.Fatal("rotation extended absolute expiry", err)
	}
	value := s.items[gatewayRefreshHash(next)]
	value.ExpiresAt = time.Now()
	s.items[gatewayRefreshHash(next)] = value
	if _, _, _, err := s.rotate(next); err == nil {
		t.Fatal("expired refresh accepted")
	}
}

func TestLocalModeNeverFallsBackToStaticDemoPassword(t *testing.T) {
	t.Setenv("FRONTEND_AUTH_MODE", "local")
	t.Setenv("DEMO_PASSWORD_FIXTURE_USER", "configured-demo-password")
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer platform.Close()
	handler, err := newHandler(platform.URL, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://gateway/auth/login", strings.NewReader(`{"username":"fixture.user","password":"configured-demo-password"}`)))
	if response.Code != http.StatusUnauthorized || len(response.Result().Cookies()) != 0 {
		t.Fatal("local authentication used demo fallback")
	}
}

func TestDurableRefreshOutageIsUnavailableAndPreservesCookies(t *testing.T) {
	t.Setenv("FRONTEND_AUTH_MODE", "local")
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer platform.Close()
	handler, err := newHandler(platform.URL, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://gateway/auth/refresh", nil)
	request.Header.Set("Origin", "http://gateway")
	request.AddCookie(&http.Cookie{Name: refreshCookie, Value: "local." + strings.Repeat("a", 43)})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || len(response.Result().Cookies()) != 0 {
		t.Fatal("outage invalidated browser session")
	}
}

func TestOperationsChecksCurrentPolicyInsteadOfCachedAdministratorClaims(t *testing.T) {
	t.Setenv("FRONTEND_AUTH_MODE", "local")
	var checked atomic.Bool
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checked.Store(true)
		if r.URL.Path != "/modules/identity/permissions:explain" || r.Header.Get("X-Browser-Module") != "1" || r.Header.Get("X-Principal-ID") != "alice" {
			t.Error("live authorization did not receive trusted identity")
		}
		writeJSON(w, http.StatusOK, map[string]bool{"allowed": false})
	}))
	defer platform.Close()
	t.Setenv("ACCESS_TOKEN_SIGNING_KEY", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")
	handler, err := newHandler(platform.URL, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := newAccessTokenSigner("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")
	signer.authMode = "local"
	token, err := signer.sign(userClaims{Username: "alice", TenantID: "t", DepartmentID: "d", ApplicationID: "a", Roles: []string{"admin"}, TokenVersion: 1}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://gateway/ops/status", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, r)
	if response.Code != http.StatusForbidden || !checked.Load() {
		t.Fatal("cached JWT admin bypassed live role revocation")
	}
}
