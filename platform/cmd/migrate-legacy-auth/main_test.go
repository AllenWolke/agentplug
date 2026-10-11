package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/identity"
)

func TestLegacyAuthenticationVerifierMatchesIdentityAndCleansSession(t *testing.T) {
	logouts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/logout" {
			if _, err := r.Cookie("fixture"); err != nil {
				t.Error("verification cookie missing")
			}
			logouts++
			w.WriteHeader(204)
			return
		}
		var credentials map[string]string
		json.NewDecoder(r.Body).Decode(&credentials)
		if credentials["password"] != "fixture-secret" {
			t.Error("credentials lost")
		}
		http.SetCookie(w, &http.Cookie{Name: "fixture", Value: "temporary", Path: "/"})
		json.NewEncoder(w).Encode(map[string]string{"username": "selected.admin", "tenant_id": "tenant", "department_id": "department", "application_id": "application"})
	}))
	defer server.Close()
	verify, err := authenticationVerifier(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	r := identity.LegacyLocalAuthenticationMigration{PrincipalID: "selected.admin", TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", ConfigurationDigest: strings.Repeat("a", 64), Password: "fixture-secret"}
	e, err := verify(context.Background(), r)
	if err != nil || !e.Authenticated || logouts != 1 {
		t.Fatal("actual response proof or cleanup missing", err)
	}
	r.ApplicationID = "forged-application"
	if _, err := verify(context.Background(), r); err == nil || logouts != 2 {
		t.Fatal("mismatched scope accepted or session leaked")
	}
	for _, origin := range []string{"http://example.com", "http://localhost", "https://user:password@example.com", "https://example.com?secret=value"} {
		if _, err := authenticationVerifier(origin); err == nil {
			t.Fatal("unsafe origin accepted")
		}
	}
}

func TestLegacyAuthenticationInputRejectsUserSuppliedProof(t *testing.T) {
	valid := `{"accounts":[{"request":{"principal_id":"selected.admin"},"password":"fixture-secret"}]}`
	file, digest, err := readInput(strings.NewReader(valid))
	if err != nil || len(digest) != 64 || file.Accounts[0].Request.Password != "fixture-secret" {
		t.Fatal("input rejected", err)
	}
	for _, raw := range []string{valid + ` {}`, strings.Replace(valid, `"principal_id":"selected.admin"`, `"principal_id":"selected.admin","authenticated":true`, 1), strings.Replace(valid, `"principal_id":"selected.admin"`, `"principal_id":"selected.admin","configuration_digest":"pretend"`, 1)} {
		if _, _, err := readInput(strings.NewReader(raw)); err == nil {
			t.Fatal("untrusted proof accepted")
		}
	}
}
