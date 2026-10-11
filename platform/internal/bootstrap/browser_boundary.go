package bootstrap

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

// BrowserBoundary separates the gateway's authentication authority from Agent
// runtime credentials. Identity and management modules remain responsible for
// the human's current permissions after this transport-level check.
func BrowserBoundary(next http.Handler, gatewayToken, runtimeToken string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/modules/") {
			next.ServeHTTP(w, r)
			return
		}
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/modules/"), "/", 2)
		module := parts[0]
		path := "/"
		if len(parts) == 2 {
			path += parts[1]
		}
		browser := r.Header.Get("X-Browser-Module") != ""
		supplied := r.Header.Get("X-Internal-Token")
		gateway := len(gatewayToken) >= 32 && gatewayToken != runtimeToken && subtle.ConstantTimeCompare([]byte(gatewayToken), []byte(supplied)) == 1
		deny := func(status int, code string) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]string{"error": code})
		}
		// The Local Run Provider is an in-process platform contract. A shared
		// transport secret cannot authenticate the caller represented in its
		// request body. Public callers use the human or machine entry points.
		if module == "execution" && (path == "/platform/runs" || strings.HasPrefix(path, "/platform/runs/")) && !browser {
			deny(http.StatusForbidden, "AUTHENTICATED_RUN_ENTRY_REQUIRED")
			return
		}
		// These public machine entry points validate their own client_credentials or
		// machine bearer identity. A runtime token alone is not a human identity.
		machine := module == "identity" && path == "/oauth/token"
		human := module != "execution" && module != "capability" && !machine
		if browser || human || gateway {
			if !gateway {
				if len(gatewayToken) < 32 {
					deny(http.StatusServiceUnavailable, "GATEWAY_AUTHENTICATION_UNAVAILABLE")
				} else {
					deny(http.StatusForbidden, "GATEWAY_CREDENTIAL_REQUIRED")
				}
				return
			}
			if browser {
				if r.Header.Get("X-Browser-Module") != "1" || r.Header.Get("X-Principal-Type") != "user" || strings.TrimSpace(r.Header.Get("X-Principal-ID")) == "" || r.Header.Get("X-Tenant-ID") == "" || r.Header.Get("X-Department-ID") == "" || r.Header.Get("X-Application-ID") == "" {
					deny(http.StatusForbidden, "TRUSTED_USER_CONTEXT_REQUIRED")
					return
				}
				if module == "identity" && strings.HasPrefix(path, "/internal/") {
					deny(http.StatusForbidden, "AUTHENTICATION_GATEWAY_ONLY")
					return
				}
			} else {
				if !(module == "identity" && gatewayIdentityEndpoint(path)) && !gatewayPublicShare(r.Method, module, path) {
					deny(http.StatusForbidden, "TRUSTED_USER_CONTEXT_REQUIRED")
					return
				}
			}
			// Translate only after proving the independent gateway credential. Modules
			// retain one local service-auth port, and never receive the gateway secret.
			r = r.Clone(r.Context())
			r.Header.Set("X-Internal-Token", runtimeToken)
		}
		next.ServeHTTP(w, r)
	})
}

// Public shares use an opaque, revocable share credential rather than a user
// context. Permit only the existing read operation through the trusted gateway.
func gatewayPublicShare(method, module, path string) bool {
	if method != http.MethodGet || module != "conversation" || !strings.HasPrefix(path, "/shares/") {
		return false
	}
	token := strings.TrimPrefix(path, "/shares/")
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == token
}

func gatewayIdentityEndpoint(path string) bool {
	switch path {
	case "/internal/oidc/step-up:challenge", "/internal/oidc/step-up:complete":
		return true
	case "/internal/credentials/verify", "/internal/sessions/validate", "/internal/browser-sessions/validate", "/internal/oidc/resolve", "/internal/refresh-sessions", "/internal/refresh-sessions:rotate", "/internal/refresh-sessions:workspace", "/internal/refresh-sessions:revoke", "/registration-agent-catalog", "/registrations":
		return true
	}
	return strings.HasPrefix(path, "/registrations/")
}
