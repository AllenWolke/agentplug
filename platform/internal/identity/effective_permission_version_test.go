package identity

import (
	"testing"
	"time"
)

func TestEffectivePermissionFingerprintChangesAtTemporalBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	start, expiry := now.Add(time.Minute), now.Add(2*time.Minute)
	valid := Validity{StartsAt: &start, ExpiresAt: &expiry}
	for _, kind := range []string{"membership", "binding", "grant", "delegation"} {
		t.Run(kind, func(t *testing.T) {
			snapshot := PermissionSnapshot{Mode: "v2"}
			switch kind {
			case "membership":
				snapshot.Memberships = []Membership{{ID: "fact", Status: "active", Validity: valid}}
			case "binding":
				snapshot.Bindings = []RoleBinding{{ID: "fact", Status: "active", Validity: valid}}
			case "grant":
				snapshot.Grants = []Grant{{ID: "fact", Status: "active", Validity: valid}}
			case "delegation":
				snapshot.Delegations = []Delegation{{ID: "fact", Status: "active", Validity: valid}}
			}
			digest := func(at time.Time) string {
				t.Helper()
				value, err := EffectivePermissionSnapshotDigest(snapshot, at)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			before, active, after := digest(now), digest(start), digest(expiry)
			if before == active || after == active || before != after {
				t.Fatal("temporal source state was not bound")
			}
			if digest(start.Add(time.Second)) != active || digest(now.Add(time.Second)) != before {
				t.Fatal("clock ticks needlessly churn authorization versions")
			}
			base, err := PermissionSnapshotDigest(snapshot)
			if err != nil || base == "" {
				t.Fatal("persistent preview/CAS digest changed contract", err)
			}
		})
	}
}

func TestEffectivePermissionFingerprintOrderingStable(t *testing.T) {
	now := time.Now()
	snapshot := PermissionSnapshot{Grants: []Grant{{ID: "a", Status: "active"}, {ID: "b", Status: "active"}}}
	one, err := EffectivePermissionSnapshotDigest(snapshot, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Grants[0], snapshot.Grants[1] = snapshot.Grants[1], snapshot.Grants[0]
	two, err := EffectivePermissionSnapshotDigest(snapshot, now)
	if err != nil || one != two {
		t.Fatal("ordering changed effective fingerprint", err)
	}
}
