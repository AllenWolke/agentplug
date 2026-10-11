package sharedkernel

import "testing"

func TestScopeRequiresTrustBoundary(t *testing.T) {
	if err := (Scope{}).Validate(); err != ErrInvalidScope {
		t.Fatalf("expected ErrInvalidScope, got %v", err)
	}
	if err := (Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "p"}).Validate(); err != nil {
		t.Fatalf("valid scope rejected: %v", err)
	}
}
