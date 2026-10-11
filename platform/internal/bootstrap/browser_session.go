package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type BrowserSessionCheck func(context.Context, *http.Request) (bool, error)

// Install inside BrowserBoundary so the callback only receives an independently
// authenticated gateway assertion. Database failure must not become a logout.
func BrowserSessionBoundary(next http.Handler, check BrowserSessionCheck) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/modules/") && r.Header.Get("X-Browser-Module") == "1" {
			allowed, err := check(r.Context(), r)
			if err != nil || !allowed {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				status, code := http.StatusUnauthorized, "AUTHENTICATION_SESSION_REJECTED"
				if err != nil {
					status, code = http.StatusServiceUnavailable, "AUTHENTICATION_SESSION_UNAVAILABLE"
				} else {
					w.Header().Set("X-Authentication-Error", "access_token_invalid")
				}
				w.WriteHeader(status)
				json.NewEncoder(w).Encode(map[string]string{"error": code})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
