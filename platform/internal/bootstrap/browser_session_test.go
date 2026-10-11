package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBrowserSessionBoundaryRejectsStaleSessionAndPreservesOutage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		allowed bool
		err     error
		status  int
	}{
		{"current", true, nil, 204},
		{"revoked", false, nil, 401},
		{"outage", false, errors.New("database unavailable"), 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := 0
			h := BrowserSessionBoundary(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++; w.WriteHeader(204) }), func(context.Context, *http.Request) (bool, error) { return tc.allowed, tc.err })
			r := httptest.NewRequest(http.MethodGet, "/modules/identity/me/permissions", nil)
			r.Header.Set("X-Browser-Module", "1")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || (called == 1) != tc.allowed {
				t.Fatalf("status=%d downstream=%d", w.Code, called)
			}
			if (w.Header().Get("X-Authentication-Error") == "access_token_invalid") != (tc.status == 401) || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("outage/session error changed cookies or authentication semantics")
			}
		})
	}
}

func TestBrowserSessionBoundaryRunsOnlyAfterGatewayProof(t *testing.T) {
	checks := 0
	h := BrowserBoundary(BrowserSessionBoundary(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), func(context.Context, *http.Request) (bool, error) { checks++; return true, nil }), "gateway-fixture-0123456789abcdef0123456789abcdef", "runtime-fixture-0123456789abcdef0123456789abcdef")
	r := httptest.NewRequest(http.MethodGet, "/modules/identity/me/permissions", nil)
	r.Header.Set("X-Browser-Module", "1")
	r.Header.Set("X-Internal-Token", "runtime-fixture-0123456789abcdef0123456789abcdef")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || checks != 0 {
		t.Fatal("untrusted caller reached authentication session store")
	}
}
