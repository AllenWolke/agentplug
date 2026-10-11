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

func TestCurrentBrowserSessionChecksDurableFamilyAndPreservesCookiesOnOutage(t *testing.T) {
	for _, mode := range []string{"local", "oidc"} {
		t.Run(mode, func(t *testing.T) {
			status := http.StatusOK
			calls := 0
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var input struct {
					Scope     map[string]string `json:"scope"`
					SessionID string            `json:"session_id"`
					Revision  uint64            `json:"auth_revision"`
				}
				if json.NewDecoder(r.Body).Decode(&input) != nil || input.Scope["PrincipalID"] != "alice" || input.SessionID != strings.Repeat("a", 64) || input.Revision != 4 || r.URL.Path != "/modules/identity/internal/browser-sessions/validate" || r.Header.Get("X-Internal-Token") != "gateway-fixture" || r.Header.Get("X-Browser-Module") != "" {
					t.Error("invalid trusted authentication validation request")
				}
				w.WriteHeader(status)
			}))
			defer upstream.Close()
			target, _ := url.Parse(upstream.URL)
			signer, err := newAccessTokenSigner("")
			if err != nil {
				t.Fatal(err)
			}
			signer.authMode = mode
			g := &gateway{platformTarget: target, platformToken: "gateway-fixture", authMode: mode, oidcTrusted: true, httpClient: upstream.Client(), accessSigner: signer}
			access, err := signer.sign(userClaims{Username: "alice", TenantID: "t", DepartmentID: "d", ApplicationID: "a", TokenVersion: 4, SessionID: strings.Repeat("a", 64)}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []int{200, 503, 401} {
				status = want
				r := httptest.NewRequest(http.MethodGet, "http://gateway/auth/me", nil)
				r.Header.Set("X-Authentication-Session", "attacker")
				r.AddCookie(&http.Cookie{Name: sessionCookie, Value: access})
				w := httptest.NewRecorder()
				g.serveHTTP(w, r)
				if w.Code != want || w.Header().Get("Set-Cookie") != "" || (w.Header().Get("X-Authentication-Error") == "access_token_invalid") != (want == 401) {
					t.Fatalf("status=%d want=%d changed session/authentication classification", w.Code, want)
				}
			}
			if calls != 3 {
				t.Fatal("session validation skipped", calls)
			}
		})
	}
}
