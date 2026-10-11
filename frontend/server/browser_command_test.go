package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLocalBrowserCommandsRequireSameOrigin(t *testing.T) {
	for _, mode := range []string{"demo", "local"} {
		t.Run(mode, func(t *testing.T) {
			forwarded := 0
			platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded++
				if r.Header.Get("X-Principal-ID") != "alice" || r.Header.Get("X-Browser-Module") != "1" {
					t.Error("trusted browser context missing")
				}
				if r.Header.Get("X-Authentication-Session") != strings.Repeat("a", 64) || r.Header.Get("X-Authentication-Revision") != "2" {
					t.Error("signed authentication session metadata missing or forged")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer platform.Close()
			target, err := url.Parse(platform.URL)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := newAccessTokenSigner("")
			if err != nil {
				t.Fatal(err)
			}
			signer.authMode = mode
			g := &gateway{platformTarget: target, platformToken: "gateway-fixture-0123456789abcdef0123456789abcdef", authMode: mode, httpClient: platform.Client(), accessSigner: signer}
			access, err := signer.sign(userClaims{Username: "alice", TenantID: "t", DepartmentID: "d", ApplicationID: "a", TokenVersion: 2, SessionID: strings.Repeat("a", 64)}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
				for _, origin := range []string{"", "null", "http://evil", "https://gateway", "http://gateway.evil.test", "http://gateway/path"} {
					r := httptest.NewRequest(method, "http://gateway/api/modules/conversation/sessions", strings.NewReader(`{}`))
					r.Header.Set("Origin", origin)
					r.Header.Set("X-Forwarded-Host", "evil")
					r.AddCookie(&http.Cookie{Name: sessionCookie, Value: access})
					w := httptest.NewRecorder()
					g.serveHTTP(w, r)
					if w.Code != http.StatusForbidden || forwarded != 0 {
						t.Fatalf("method=%s origin=%q status=%d forwarded=%d", method, origin, w.Code, forwarded)
					}
				}
			}
			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
				r := httptest.NewRequest(method, "http://gateway/api/modules/conversation/sessions", strings.NewReader(`{}`))
				r.Header.Set("Origin", "http://gateway")
				r.Header.Set("X-Principal-ID", "attacker")
				r.Header.Set("X-Authentication-Session", "forged-session")
				r.Header.Set("X-Authentication-Revision", "999")
				r.AddCookie(&http.Cookie{Name: sessionCookie, Value: access})
				w := httptest.NewRecorder()
				g.serveHTTP(w, r)
				if w.Code != http.StatusNoContent {
					t.Fatalf("same-origin %s failed: status=%d", method, w.Code)
				}
			}
			if forwarded != 4 {
				t.Fatalf("expected four authenticated commands, got %d", forwarded)
			}
		})
	}
}
