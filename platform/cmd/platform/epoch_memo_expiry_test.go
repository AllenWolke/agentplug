package main

import (
	"testing"
	"time"

	"github.com/lexagent/platform/internal/identity"
)

func TestEpochMemoRechecksEffectiveSourceBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	boundary := now.Add(time.Minute)
	for _, kind := range []string{"membership", "role", "grant", "delegation", "assignment"} {
		for _, starting := range []bool{false, true} {
			validity := identity.Validity{ExpiresAt: &boundary}
			if starting {
				validity = identity.Validity{StartsAt: &boundary}
			}
			snapshot := identity.PermissionSnapshot{}
			switch kind {
			case "membership":
				snapshot.Memberships = []identity.Membership{{ID: "source", Status: "active", Validity: validity}}
			case "role":
				snapshot.Bindings = []identity.RoleBinding{{ID: "source", Status: "active", Validity: validity}}
			case "grant":
				snapshot.Grants = []identity.Grant{{ID: "source", Status: "active", Effect: "allow", Validity: validity}}
			case "delegation":
				snapshot.Delegations = []identity.Delegation{{ID: "source", Status: "active", Validity: validity}}
			case "assignment":
				snapshot.Assignments = []identity.TaskAssignment{{ID: "source", Status: "active", Validity: validity}}
			}
			digest, err := identity.EffectivePermissionSnapshotDigest(snapshot, now)
			if err != nil {
				t.Fatal(err)
			}
			entry := epochMemoEntry{epoch: 7, snapshot: snapshot, digest: digest}
			if !entry.current(now) || !entry.current(boundary.Add(-time.Nanosecond)) || entry.current(boundary) {
				t.Fatal("same-transaction memo crossed a natural source boundary", kind, starting)
			}
		}
	}
}
