package identity

import (
	"testing"
)

func TestAuthorizationFingerprintBindsActualRevisionsAndIsOrderIndependent(t *testing.T) {
	p := Principal{ID: "actor", Type: PrincipalUser, TenantID: "tenant", IsActive: true, Revision: 1}
	g1 := Grant{ID: "a", Revision: 1, Status: GrantActive, Effect: "allow"}
	g2 := Grant{ID: "b", Revision: 1, Status: GrantRevoked, Effect: "deny"}
	fingerprint, err := authorizationFingerprint(p, []Grant{g1, g2}, []uint64{1, 1, 1})
	if err != nil {
		t.Fatal(err)
	}
	reordered, _ := authorizationFingerprint(p, []Grant{g2, g1}, []uint64{1, 1, 1})
	if reordered != fingerprint {
		t.Fatal("row ordering changed IAM version")
	}
	g2.Revision++
	changed, _ := authorizationFingerprint(p, []Grant{g1, g2}, []uint64{1, 1, 1})
	if changed == fingerprint {
		t.Fatal("revoked grant revision did not change authority fingerprint")
	}
	p.Revision++
	changed, _ = authorizationFingerprint(p, []Grant{g1}, []uint64{1, 1, 1})
	baseline, _ := authorizationFingerprint(Principal{ID: "actor", Type: PrincipalUser, TenantID: "tenant", IsActive: true, Revision: 1}, []Grant{g1}, []uint64{1, 1, 1})
	if changed == baseline {
		t.Fatal("principal revision not bound")
	}
}
