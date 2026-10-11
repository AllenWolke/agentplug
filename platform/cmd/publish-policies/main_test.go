package main

import (
	"strings"
	"testing"
)

func TestPublicationInputNeverAcceptsIncompleteBundle(t *testing.T) {
	for _, body := range []string{`{}`, `{"operator_password":"fixture-secret","publications":[]}`, `{"operator_password":"fixture-secret","publications":[{"installation_id":"fixture","scope":{},"assets":[]}]}`, `{"operator_password":"fixture-secret","actor_roles":["super_admin"],"publications":[]}`} {
		if _, _, err := readInput(strings.NewReader(body), "fixture-admin"); err == nil {
			t.Fatal("unsafe publication input accepted")
		}
	}
}
