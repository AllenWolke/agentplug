package identity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLegacyAuthenticationEvidenceMustMatchFreshApprovedSubject(t *testing.T) {
	now := time.Now().UTC()
	r := LegacyLocalAuthenticationMigration{PrincipalID: "system.admin", TenantID: "t", DepartmentID: "d", ApplicationID: "a", ConfigurationDigest: strings.Repeat("a", 64), AppointFirstSuperAdministrator: true, Password: "private-source-password"} // secret-scan: allow -- synthetic test-only credential, never a deployed account password
	e := LegacyAuthenticationEvidence{PrincipalID: r.PrincipalID, TenantID: r.TenantID, DepartmentID: r.DepartmentID, ApplicationID: r.ApplicationID, ConfigurationDigest: r.ConfigurationDigest, Authenticated: true, VerifiedAt: now}
	if !validLegacyAuthenticationEvidence(r, e, now) {
		t.Fatal("matching fresh evidence rejected")
	}
	for _, mutate := range []func(*LegacyAuthenticationEvidence){func(e *LegacyAuthenticationEvidence) { e.PrincipalID = "other" }, func(e *LegacyAuthenticationEvidence) { e.ApplicationID = "other" }, func(e *LegacyAuthenticationEvidence) { e.ConfigurationDigest = "wrong" }, func(e *LegacyAuthenticationEvidence) { e.Authenticated = false }, func(e *LegacyAuthenticationEvidence) { e.VerifiedAt = now.Add(-6 * time.Minute) }, func(e *LegacyAuthenticationEvidence) { e.VerifiedAt = now.Add(time.Minute) }} {
		changed := e
		mutate(&changed)
		if validLegacyAuthenticationEvidence(r, changed, now) {
			t.Fatal("invalid authentication evidence accepted")
		}
	}
	r.AppointFirstSuperAdministrator = false
	e.Authenticated = false
	if !validLegacyAuthenticationEvidence(r, e, now) {
		t.Fatal("verified inactive configuration cannot be preserved")
	}
	raw, err := json.Marshal(r)
	if err != nil || strings.Contains(string(raw), r.Password) || strings.Contains(string(raw), "Password") {
		t.Fatal("secret escaped into metadata", err)
	}
}
