package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLRefreshSessionLifecycle(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s := NewSQLStore(db)
	s.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, RefreshSessionEvent) error { return nil })
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("rt-%d", time.Now().UnixNano())
	scope := EnrollmentScope{TenantID: prefix, DepartmentID: prefix + "-d", ApplicationID: prefix + "-a"}
	id := prefix + "-user"
	for _, err := range []error{
		s.CreateTenant(ctx, Tenant{ID: scope.TenantID, Code: prefix, Name: "refresh fixture", Status: "active", Revision: 1}),
		s.CreateDepartment(ctx, Department{ID: scope.DepartmentID, TenantID: scope.TenantID, Code: prefix, Name: "refresh fixture", Status: "active", Revision: 1}),
		s.CreateApplication(ctx, Application{ID: scope.ApplicationID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, Code: prefix, Name: "refresh fixture", Status: "active", Revision: 1}),
		s.CreatePrincipal(ctx, Principal{Type: PrincipalUser, ID: id, TenantID: scope.TenantID, Roles: []string{"operator"}, IsActive: true}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	passwordHash, err := hashEnrollmentPassword("old-refresh-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_local_credential(principal_id,tenant_id,department_id,application_id,display_name,password_hash,auth_revision,active,created_at,updated_at) VALUES(?,?,?,?,?,?,1,TRUE,clock_timestamp(),clock_timestamp())`), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID, "refresh fixture", passwordHash); err != nil {
		t.Fatal(err)
	}
	create := func(t *testing.T) RefreshSessionResult {
		t.Helper()
		value, err := s.CreateRefreshSession(ctx, id, scope, 1)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	browser := sharedkernel.Scope{PrincipalType: "user", PrincipalID: id, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}
	assertSession := func(t *testing.T, session RefreshSessionResult, allowed bool) {
		t.Helper()
		err := s.ValidateBrowserSession(ctx, browser, session.SessionID, session.Identity.AuthRevision)
		if (err == nil) != allowed || (!allowed && !errors.Is(err, ErrRefreshSessionRejected)) {
			t.Fatalf("browser authentication allowed=%v error=%v", allowed, err)
		}
	}
	t.Run("browser assertions bind exact subject scope revision and durable family", func(t *testing.T) {
		first := create(t)
		assertSession(t, first, true)
		if len(first.SessionID) != 64 || first.SessionID == first.RefreshToken {
			t.Fatal("session correlation identifier invalid")
		}
		if err := s.ValidateBrowserSession(ctx, browser, "", 0); !errors.Is(err, ErrRefreshSessionRejected) {
			t.Fatal("database credential fell back to static demo identity", err)
		}
		for _, invalid := range []sharedkernel.Scope{
			{PrincipalType: "user", PrincipalID: "other", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID},
			{PrincipalType: "user", PrincipalID: id, TenantID: "foreign", DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID},
			{PrincipalType: "user", PrincipalID: id, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: "other"},
		} {
			if err := s.ValidateBrowserSession(ctx, invalid, first.SessionID, 1); !errors.Is(err, ErrRefreshSessionRejected) {
				t.Fatal("session escaped its signed subject or workspace", err)
			}
		}
		if err := s.ValidateBrowserSession(ctx, browser, first.SessionID, 2); !errors.Is(err, ErrRefreshSessionRejected) {
			t.Fatal("wrong authentication revision accepted", err)
		}
		next, err := s.RotateRefreshSession(ctx, first.RefreshToken)
		if err != nil || next.SessionID != first.SessionID {
			t.Fatal("rotation changed durable session identity", err)
		}
		assertSession(t, first, true)
		if err := s.RevokeRefreshSession(ctx, first.RefreshToken); err != nil {
			t.Fatal(err)
		}
		assertSession(t, first, false)
		assertSession(t, next, false)
	})

	t.Run("session recording failure rolls back creation and rotation", func(t *testing.T) {
		first := create(t)
		fault := errors.New("session audit unavailable")
		s.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, RefreshSessionEvent) error { return fault })
		defer s.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, RefreshSessionEvent) error { return nil })
		var before, after int
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_refresh_family WHERE principal_id=?`), id).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateRefreshSession(ctx, id, scope, 1); !errors.Is(err, fault) {
			t.Fatal("creation ignored audit failure", err)
		}
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_refresh_family WHERE principal_id=?`), id).Scan(&after); err != nil || after != before {
			t.Fatal("creation partially committed", err)
		}
		if _, err := s.RotateRefreshSession(ctx, first.RefreshToken); !errors.Is(err, fault) {
			t.Fatal("rotation ignored audit failure", err)
		}
		var used bool
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT used FROM platform_identity_refresh_token WHERE token_hash=?`), refreshHash(first.RefreshToken)).Scan(&used); err != nil || used {
			t.Fatal("rotation partially committed", err)
		}
		if err := s.RevokeRefreshSession(ctx, first.RefreshToken); !errors.Is(err, fault) {
			t.Fatal("logout ignored audit failure", err)
		}
		var revoked bool
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT f.revoked FROM platform_identity_refresh_family f JOIN platform_identity_refresh_token t ON t.family_id=f.id WHERE t.token_hash=?`), refreshHash(first.RefreshToken)).Scan(&revoked); err != nil || revoked {
			t.Fatal("logout partially committed", err)
		}
	})
	t.Run("hash-only durable rotation and replay revocation", func(t *testing.T) {
		first := create(t)
		var stored string
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT token_hash FROM platform_identity_refresh_token WHERE token_hash=?`), refreshHash(first.RefreshToken)).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if stored == first.RefreshToken || len(stored) != 64 {
			t.Fatal("bearer persisted")
		}
		restarted := NewSQLStore(db)
		restarted.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, RefreshSessionEvent) error { return nil })
		next, err := restarted.RotateRefreshSession(ctx, first.RefreshToken)
		if err != nil || next.RefreshToken == first.RefreshToken || next.Identity.Username != id || next.ExpiresAt.Sub(first.ExpiresAt) > time.Microsecond {
			t.Fatalf("rotation: %#v %v", next.Identity, err)
		}
		if _, err := s.RotateRefreshSession(ctx, first.RefreshToken); !errors.Is(err, ErrRefreshSessionRejected) {
			t.Fatal("replay accepted", err)
		}
		if _, err := s.RotateRefreshSession(ctx, next.RefreshToken); !errors.Is(err, ErrRefreshSessionRejected) {
			t.Fatal("successor survived replay", err)
		}
		assertSession(t, next, false)
	})
	t.Run("logout revokes successor through old token", func(t *testing.T) {
		first := create(t)
		next, err := s.RotateRefreshSession(ctx, first.RefreshToken)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeRefreshSession(ctx, first.RefreshToken); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RotateRefreshSession(ctx, next.RefreshToken); !errors.Is(err, ErrRefreshSessionRejected) {
			t.Fatal("logout not durable", err)
		}
	})
	t.Run("absolute family expiry", func(t *testing.T) {
		first := create(t)
		expired := first.ExpiresAt
		s.clock = func() time.Time { return expired }
		defer func() { s.clock = time.Now }()
		assertSession(t, first, false)
		if _, err := s.RotateRefreshSession(ctx, first.RefreshToken); !errors.Is(err, ErrRefreshSessionRejected) {
			t.Fatal("expiry accepted", err)
		}
	})
	t.Run("concurrent refresh is single use", func(t *testing.T) {
		first := create(t)
		var wg sync.WaitGroup
		results := make(chan error, 6)
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _, err := s.RotateRefreshSession(ctx, first.RefreshToken); results <- err }()
		}
		wg.Wait()
		close(results)
		success := 0
		for err := range results {
			if err == nil {
				success++
			} else if !errors.Is(err, ErrRefreshSessionRejected) {
				t.Fatal(err)
			}
		}
		if success != 1 {
			t.Fatalf("successful rotations=%d", success)
		}
	})
	t.Run("disabled identity cannot refresh", func(t *testing.T) {
		first := create(t)
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE principal_type='user' AND id=?`), id); err != nil {
			t.Fatal(err)
		}
		defer db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=TRUE WHERE principal_type='user' AND id=?`), id)
		assertSession(t, first, false)
		if _, err := s.RotateRefreshSession(ctx, first.RefreshToken); !errors.Is(err, ErrRefreshSessionRejected) {
			t.Fatal("disabled identity accepted", err)
		}
	})
	t.Run("bounded cleanup preserves active replay evidence", func(t *testing.T) {
		first := create(t)
		active := create(t)
		// Session expiry uses the injected application authority clock. Docker's
		// database clock may be slightly ahead of the host; do not mix the two.
		// Freeze a microsecond-exact boundary to prove <=, not a timing delay.
		cutoff := s.clock().UTC().Add(-time.Second).Truncate(time.Microsecond)
		previousClock := s.clock
		s.clock = func() time.Time { return cutoff }
		defer func() { s.clock = previousClock }()
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_refresh_family f SET expires_at=? FROM platform_identity_refresh_token t WHERE t.family_id=f.id AND t.token_hash=?`), cutoff, refreshHash(first.RefreshToken)); err != nil {
			t.Fatal(err)
		}
		if count, err := s.PurgeExpiredRefreshSessions(ctx, 100); err != nil || count < 1 {
			t.Fatal("cleanup", count, err)
		}
		var count int
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_refresh_token WHERE token_hash=?`), refreshHash(first.RefreshToken)).Scan(&count); err != nil || count != 0 {
			t.Fatal("expired hash retained", err)
		}
		if _, err := s.RotateRefreshSession(ctx, active.RefreshToken); err != nil {
			t.Fatal("cleanup touched valid session", err)
		}
	})
	t.Run("OIDC binding sessions rotate and revocation is atomic", func(t *testing.T) {
		actor := sharedkernel.Scope{PrincipalType: "user", PrincipalID: id, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}
		binding := OIDCBinding{Issuer: "https://fixture.example.test/issuer", Subject: prefix + "-sub", PrincipalID: id, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}
		s.SetOIDCBindingRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, OIDCBindingDecision) error { return nil })
		if err := s.CreateOIDCBinding(ctx, actor, binding); err != nil {
			t.Fatal(err)
		}
		first, err := s.CreateOIDCRefreshSession(ctx, binding.Issuer, binding.Subject)
		if err != nil {
			t.Fatal(err)
		}
		assertSession(t, first, true)
		if _, err := s.CreateOIDCRefreshSession(ctx, binding.Issuer, "other-subject"); !errors.Is(err, ErrRefreshSessionRejected) {
			t.Fatal("unbound OIDC session accepted", err)
		}
		next, err := s.RotateRefreshSession(ctx, first.RefreshToken)
		if err != nil || next.Identity.Username != id {
			t.Fatal("OIDC rotation", err)
		}
		fault := errors.New("OIDC audit unavailable")
		s.SetOIDCBindingRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, OIDCBindingDecision) error { return fault })
		if err := s.DisableOIDCBinding(ctx, actor, binding, 1); !errors.Is(err, fault) {
			t.Fatal("OIDC rollback fixture", err)
		}
		last, err := s.RotateRefreshSession(ctx, next.RefreshToken)
		if err != nil {
			t.Fatal("failed binding revocation invalidated session", err)
		}
		s.SetOIDCBindingRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, OIDCBindingDecision) error { return nil })
		if err := s.DisableOIDCBinding(ctx, actor, binding, 1); err != nil {
			t.Fatal(err)
		}
		assertSession(t, last, false)
		if _, err := s.RotateRefreshSession(ctx, last.RefreshToken); !errors.Is(err, ErrRefreshSessionRejected) {
			t.Fatal("disabled binding renewed", err)
		}
		var revoked bool
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT f.revoked FROM platform_identity_refresh_family f JOIN platform_identity_refresh_token t ON t.family_id=f.id WHERE t.token_hash=?`), refreshHash(last.RefreshToken)).Scan(&revoked); err != nil || !revoked {
			t.Fatal("binding revocation did not persist family revocation", err)
		}
	})
	t.Run("credential change and family revocation are atomic", func(t *testing.T) {
		first := create(t)
		newHash, err := hashEnrollmentPassword("new-refresh-password")
		if err != nil {
			t.Fatal(err)
		}
		actor := sharedkernel.Scope{PrincipalType: "user", PrincipalID: id, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}
		fault := errors.New("injected audit failure")
		s.SetCredentialLifecycleRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, CredentialLifecycleDecision) error { return fault })
		if _, err := s.ChangeOwnPassword(ctx, actor, "old-refresh-password", newHash); !errors.Is(err, fault) {
			t.Fatal("rollback fixture", err)
		}
		next, err := s.RotateRefreshSession(ctx, first.RefreshToken)
		if err != nil {
			t.Fatal("rollback revoked old session", err)
		}
		s.SetCredentialLifecycleRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, CredentialLifecycleDecision) error { return nil })
		if _, err := s.ChangeOwnPassword(ctx, actor, "old-refresh-password", newHash); err != nil {
			t.Fatal(err)
		}
		assertSession(t, next, false)
		if _, err := s.RotateRefreshSession(ctx, next.RefreshToken); !errors.Is(err, ErrRefreshSessionRejected) {
			t.Fatal("changed password accepted stale refresh", err)
		}
		if _, err := s.CreateRefreshSession(ctx, id, scope, 1); !errors.Is(err, ErrRefreshSessionRejected) {
			t.Fatal("stale credential revision accepted", err)
		}
	})
}
