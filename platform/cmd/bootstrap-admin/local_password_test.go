package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPrivateLocalAdministratorConfiguration(t *testing.T) {
	config := fixtureConfiguration(t)
	config.Issuer, config.Subject = "", ""
	config.LocalPassword = "fixture-local-password-0123456789"
	raw, _ := json.Marshal(config)
	if _, err := loadConfiguration(writeConfig(t, raw)); err != nil {
		t.Fatal("real local password configuration rejected", err)
	}
	for _, kind := range []string{"mixed", "short", "missing", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			candidate := config
			switch kind {
			case "mixed":
				candidate.Issuer = "https://idp.fixture.internal"
				candidate.Subject = "actual-subject"
			case "short":
				candidate.LocalPassword = "short"
			case "missing":
				candidate.LocalPassword = ""
			case "oversize":
				candidate.LocalPassword = strings.Repeat("x", 129)
			}
			raw, _ := json.Marshal(candidate)
			if _, err := loadConfiguration(writeConfig(t, raw)); err == nil {
				t.Fatal("invalid auth source accepted")
			}
		})
	}
}
