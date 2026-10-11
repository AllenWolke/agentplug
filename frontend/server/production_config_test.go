package main

import (
	"strings"
	"testing"
)

func TestProductionAliasesRejectDemoAndInsecureCookies(t *testing.T) {
	for _, environment := range []string{"production", "prod"} {
		t.Run(environment, func(t *testing.T) {
			t.Setenv("ACCESS_TOKEN_SIGNING_KEY", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")
			t.Setenv("APP_ENV", environment)
			t.Setenv("FRONTEND_AUTH_MODE", "demo")
			if _, err := newHandlerWithConfig("http://127.0.0.1:1", t.TempDir(), "test-0123456789abcdef0123456789abcdef", true); err == nil {
				t.Fatal("production alias accepted demo identity")
			}
			t.Setenv("FRONTEND_AUTH_MODE", "oidc")
			t.Setenv("OIDC_PROXY_TRUSTED", "true")
			t.Setenv("OIDC_PROXY_AUTH_URL", "http://oauth2-proxy:4180/oauth2/auth")
			t.Setenv("OIDC_ISSUER_URL", "https://idp.example.com/realm")
			if _, err := newHandlerWithConfig("http://127.0.0.1:1", t.TempDir(), "test-0123456789abcdef0123456789abcdef", false); err == nil {
				t.Fatal("production alias accepted insecure cookie")
			}
			for _, token := range []string{"", "short", "placeholder-0123456789abcdef0123456789abcdef", "dev-internal-0123456789abcdef0123456789abcdef", strings.Repeat("x", 32), strings.Repeat("密", 11), "replace-" + strings.Repeat("0123456789abcdef", 3)} {
				if _, err := newHandlerWithConfig("http://127.0.0.1:1", t.TempDir(), token, true); err == nil || (token != "" && strings.Contains(err.Error(), token)) {
					t.Fatal("unsafe token accepted or echoed")
				}
			}
			if _, err := newHandlerWithConfig("http://127.0.0.1:1", t.TempDir(), "test-0123456789abcdef0123456789abcdef", true); err != nil {
				t.Fatalf("valid production configuration rejected: %v", err)
			}
		})
	}
}
