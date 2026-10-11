package identity

import (
	"slices"
	"testing"
	"time"
)

func TestPermissionExplanationMatchesDelegatedManagementCapability(t *testing.T) {
	snapshot, query := permissionFixture()
	snapshot.Bindings[0].RoleCode = "permission_admin"
	query.ResourceID, query.ResourceType = "", ""
	for _, action := range []string{"authorization.change", "access_request.decide", "principal.disable", "membership.manage"} {
		query.Action = action
		snapshot.Delegations = nil
		out, err := explainPermissionSnapshot(snapshot, query)
		if err != nil || out.Allowed || out.Reason != "DELEGATION_REQUIRED" {
			t.Fatal("permission-admin role alone explained as mutation authority", action, out, err)
		}
		snapshot.Delegations = []Delegation{{ID: "matching-delegation", SubjectID: snapshot.Principal.ID, Scope: query.Scope, Status: "active", ManagementActions: []string{action}}}
		out, err = explainPermissionSnapshot(snapshot, query)
		if err != nil || !out.Allowed || !slices.Contains(out.DelegationIDs, "matching-delegation") || len(out.Delegations) != 1 || len(out.Bindings) != 1 {
			t.Fatal("current delegated capability missing from explanation", action, out, err)
		}
		snapshot.Delegations[0].ExpiresAt = &query.Now
		out, err = explainPermissionSnapshot(snapshot, query)
		if err != nil || out.Allowed || out.Reason != "DELEGATION_REQUIRED" || len(out.Delegations) != 0 || !slices.Contains(out.DiagnosticReasons, "DELEGATION_EXPIRED") {
			t.Fatal("expired delegated mutation explained as allowed", action, out, err)
		}
	}
}

func TestPermissionExplanationSourcesVersionsAndTimeBoundaries(t *testing.T) {
	s, q := permissionFixture()
	s.Principal.Revision = 42
	s.Bindings[0].PresetCode, s.Bindings[0].PresetVersion = "operator", 1
	s.Grants[0].DelegationID = "bounded-source"
	g := s.Grants[0]
	g.ID = "other-source"
	g.SourceID = "independent"
	g.DelegationID = ""
	s.Grants = append(s.Grants, g)
	o, err := explainPermissionSnapshot(s, q)
	if err != nil || !o.Allowed || len(o.Grants) != 2 || len(o.Bindings) != 1 || o.SubjectRevision != 42 || o.Bindings[0].PresetVersion != 1 || !o.ComputedAt.Equal(q.Now) || len(o.EffectiveVersion) != 64 || !slices.Equal(o.DelegationIDs, []string{"bounded-source"}) {
		t.Fatalf("incomplete explanation: %+v %v", o, err)
	}
	initial := o.EffectiveVersion
	future := q.Now.Add(time.Minute)
	s.Grants[0].ExpiresAt = &future
	o, err = explainPermissionSnapshot(s, q)
	if err != nil {
		t.Fatal(err)
	}
	beforeExpiry := o.EffectiveVersion
	q.Now = future
	o, err = explainPermissionSnapshot(s, q)
	if err != nil || !o.Allowed || len(o.Grants) != 1 || !slices.Contains(o.DiagnosticReasons, "GRANT_EXPIRED") || o.EffectiveVersion == beforeExpiry || o.EffectiveVersion == initial {
		t.Fatal("natural expiry explanation/version mismatch", o, err)
	}
	s.Grants[1].Effect = "deny"
	o, err = explainPermissionSnapshot(s, q)
	if err != nil || o.Allowed || o.Reason != "EXPLICIT_DENY" || len(o.Grants) != 1 || o.Grants[0].Effect != "deny" {
		t.Fatal("deny source hidden or bypassed", o, err)
	}
	s.Grants[1].ApplicationID = "outside"
	o, err = explainPermissionSnapshot(s, q)
	if err != nil || o.Allowed || len(o.Grants) != 0 || slices.Contains(o.DiagnosticReasons, "RESOURCE_SCOPE_MISMATCH") {
		t.Fatal("out-of-scope source disclosed", o, err)
	}
}
