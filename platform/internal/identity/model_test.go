package identity

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestIdentityPersistenceErrorMapsDuplicateKeyToConflict(t *testing.T) {
	duplicate := &pgconn.PgError{Code: "23505", Message: "duplicate key"}
	if err := identityPersistenceError("create identity tenant", duplicate); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("duplicate key should map to identity conflict, got %v", err)
	}
	other := errors.New("database unavailable")
	if err := identityPersistenceError("create identity tenant", other); !errors.Is(err, other) || errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("non-duplicate database error should remain distinguishable, got %v", err)
	}
}

func TestAccessContextSeparatesTenantAndAgentInstance(t *testing.T) {
	ctx := AccessContext{
		Scope:     sharedkernel.Scope{TenantID: "tenant-a", DepartmentID: "d", ApplicationID: "app", AgentInstanceID: "install-a", PrincipalID: "user-a"},
		Principal: Principal{Type: PrincipalUser, ID: "user-a", TenantID: "tenant-b", IsActive: true},
		Action:    "run",
	}
	if err := ctx.Validate(); err != ErrScopeMismatch {
		t.Fatalf("expected scope mismatch, got %v", err)
	}
}

func TestPrincipalRejectsInactiveOrUnknownType(t *testing.T) {
	for _, p := range []Principal{{Type: PrincipalUser, ID: "u", TenantID: "t"}, {Type: "unknown", ID: "u", TenantID: "t", IsActive: true}} {
		if err := p.Validate(); err != ErrInvalidPrincipal {
			t.Fatalf("expected invalid principal, got %v", err)
		}
	}
}

func TestGrantRejectsUnknownStatus(t *testing.T) {
	g := Grant{ID: "g", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "i", SubjectType: PrincipalUser, SubjectID: "u", Action: "run", Effect: "allow", Status: "pending", Revision: 1}
	if err := g.Validate(); err != ErrInvalidResource {
		t.Fatalf("unknown grant status must be rejected: %v", err)
	}
}
