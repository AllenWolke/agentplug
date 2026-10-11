package identity

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLOIDCBindingFollowsCurrentIAMState(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store := NewSQLStore(db)
	var recorded []OIDCBindingDecision
	store.SetOIDCBindingRecorder(func(_ context.Context, _ *sql.Tx, _ sharedkernel.Scope, decision OIDCBindingDecision) error {
		recorded = append(recorded, decision)
		return nil
	})
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	id := "oidc-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	binding := OIDCBinding{Issuer: "https://idp.example.com/realm", Subject: id + "-sub", PrincipalID: id + "-user", TenantID: id, DepartmentID: id + "-dept", ApplicationID: id + "-app"}
	actor := sharedkernel.Scope{TenantID: id, DepartmentID: binding.DepartmentID, ApplicationID: binding.ApplicationID, PrincipalType: "user", PrincipalID: id + "-admin"}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		for _, item := range []struct {
			query string
			args  []any
		}{
			{`DELETE FROM platform_identity_oidc_binding WHERE identity_key=?`, []any{oidcIdentityKey(binding.Issuer, binding.Subject)}},
			{`DELETE FROM platform_identity_principal WHERE id=?`, []any{binding.PrincipalID}},
			{`DELETE FROM platform_identity_application WHERE id=?`, []any{binding.ApplicationID}},
			{`DELETE FROM platform_identity_department WHERE id=?`, []any{binding.DepartmentID}},
			{`DELETE FROM platform_identity_tenant WHERE id=?`, []any{binding.TenantID}},
		} {
			if _, err := db.ExecContext(cleanup, sqlutil.Bind(item.query), item.args...); err != nil {
				t.Errorf("cleanup OIDC fixture: %v", err)
			}
		}
	})
	if err := store.CreateTenant(ctx, Tenant{ID: id, Code: id, Name: "OIDC fixture", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateDepartment(ctx, Department{ID: binding.DepartmentID, TenantID: id, Code: id, Name: "OIDC department", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateApplication(ctx, Application{ID: binding.ApplicationID, TenantID: id, DepartmentID: binding.DepartmentID, Code: id, Name: "OIDC app", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreatePrincipal(ctx, Principal{Type: PrincipalUser, ID: binding.PrincipalID, TenantID: id, Roles: []string{"operator"}, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	wrong := binding
	wrong.TenantID = "other-tenant"
	if err := store.CreateOIDCBinding(ctx, actor, wrong); !errors.Is(err, ErrOIDCBindingNotFound) {
		t.Fatalf("cross-tenant binding accepted: %v", err)
	}
	store.SetOIDCBindingRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, OIDCBindingDecision) error {
		return errors.New("audit unavailable")
	})
	if err := store.CreateOIDCBinding(ctx, actor, binding); err == nil {
		t.Fatal("binding created without audit")
	}
	if _, err := store.ResolveOIDC(ctx, binding.Issuer, binding.Subject); !errors.Is(err, ErrOIDCBindingNotFound) {
		t.Fatalf("audit failure did not roll back binding: %v", err)
	}
	store.SetOIDCBindingRecorder(func(_ context.Context, _ *sql.Tx, _ sharedkernel.Scope, decision OIDCBindingDecision) error {
		recorded = append(recorded, decision)
		return nil
	})
	if err := store.CreateOIDCBinding(ctx, actor, binding); err != nil {
		t.Fatal(err)
	}
	resolved, err := store.ResolveOIDC(ctx, binding.Issuer, binding.Subject)
	if err != nil || resolved.TenantID != id || len(resolved.Roles) != 1 || resolved.Roles[0] != "operator" {
		t.Fatalf("active binding: %+v %v", resolved, err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET roles_json='["reviewer"]' WHERE id=?`), binding.PrincipalID); err != nil {
		t.Fatal(err)
	}
	resolved, err = store.ResolveOIDC(ctx, binding.Issuer, binding.Subject)
	if err != nil || len(resolved.Roles) != 1 || resolved.Roles[0] != "reviewer" {
		t.Fatalf("role change not immediate: %+v %v", resolved, err)
	}
	store.SetOIDCBindingRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, OIDCBindingDecision) error {
		return errors.New("audit unavailable")
	})
	if err := store.DisableOIDCBinding(ctx, actor, binding, 1); err == nil {
		t.Fatal("binding revoked without audit")
	}
	if _, err := store.ResolveOIDC(ctx, binding.Issuer, binding.Subject); err != nil {
		t.Fatalf("audit failure did not roll back revocation: %v", err)
	}
	store.SetOIDCBindingRecorder(func(_ context.Context, _ *sql.Tx, _ sharedkernel.Scope, decision OIDCBindingDecision) error {
		recorded = append(recorded, decision)
		return nil
	})
	if err := store.DisableOIDCBinding(ctx, actor, binding, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResolveOIDC(ctx, binding.Issuer, binding.Subject); !errors.Is(err, ErrOIDCBindingNotFound) {
		t.Fatalf("revoked binding accepted: %v", err)
	}
	if err := store.DisableOIDCBinding(ctx, actor, binding, 1); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("stale revoke accepted: %v", err)
	}
	if len(recorded) != 2 || recorded[0].Status != "active" || recorded[1].Status != "disabled" {
		t.Fatalf("binding audit decisions: %+v", recorded)
	}
}
