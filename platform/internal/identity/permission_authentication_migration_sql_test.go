package identity

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLLegacyAuthenticationImportAndVerifiedExistingAdministrator(t *testing.T) {
	db := newEmptyMigrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s := NewSQLStore(db)
	outbox := notification.NewSQLStore(db)
	events := audit.NewSQLStoreWithOutbox(db, outbox)
	for _, ensure := range []func(context.Context) error{s.EnsureSchema, outbox.EnsureSchema, events.EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, err := range []error{
		s.CreateTenant(ctx, Tenant{ID: "legacy-tenant", Code: "legacy", Name: "fixture", Status: "active", Revision: 1}),
		s.CreateDepartment(ctx, Department{ID: "legacy-department", TenantID: "legacy-tenant", Code: "legacy", Name: "fixture", Status: "active", Revision: 1}),
		s.CreateApplication(ctx, Application{ID: "legacy-application", TenantID: "legacy-tenant", DepartmentID: "legacy-department", Code: "legacy", Name: "fixture", Status: "active", Revision: 1}),
		s.CreatePrincipal(ctx, Principal{Type: PrincipalUser, ID: "existing-admin", TenantID: "legacy-tenant", IsActive: true, Roles: []string{"admin", "auditor"}}),
		s.CreatePrincipal(ctx, Principal{Type: PrincipalUser, ID: "existing-disabled", TenantID: "legacy-tenant", IsActive: true, Roles: []string{"operator"}}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	// Creation accepts active subjects only; preserve a pre-existing disabled
	// subject as migration input without weakening the production invariant.
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE id='existing-disabled'`)); err != nil {
		t.Fatal(err)
	}
	actor := sharedkernel.Scope{TenantID: "legacy-tenant", DepartmentID: "legacy-department", ApplicationID: "legacy-application", PrincipalID: "existing-admin", PrincipalType: "user"}
	sources, err := s.InspectMigrationSources(ctx, actor.TenantID, []MigrationSubject{{Type: PrincipalUser, ID: actor.PrincipalID}, {Type: PrincipalUser, ID: "existing-disabled"}})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]MigrationSource{}
	for _, source := range sources.Sources {
		byID[source.Snapshot.Principal.ID] = source
	}
	request := LegacyLocalAuthenticationMigration{PrincipalID: actor.PrincipalID, TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, DisplayName: "Existing administrator", ExpectedSourceDigest: byID[actor.PrincipalID].SourceDigest, ConfigurationDigest: strings.Repeat("a", 64), ApprovalReference: "explicit-approved-auth-source", AppointFirstSuperAdministrator: true, Password: "source-credential-fixture"} // secret-scan: allow -- synthetic test-only credential, never a deployed account password
	verified := func(_ context.Context, r LegacyLocalAuthenticationMigration) (LegacyAuthenticationEvidence, error) {
		return LegacyAuthenticationEvidence{PrincipalID: r.PrincipalID, TenantID: r.TenantID, DepartmentID: r.DepartmentID, ApplicationID: r.ApplicationID, ConfigurationDigest: r.ConfigurationDigest, Authenticated: r.AppointFirstSuperAdministrator, VerifiedAt: time.Now().UTC()}, nil
	}
	fail := true
	s.SetAuthorizationChangeRecorder(func(_ context.Context, tx *sql.Tx, scope sharedkernel.Scope, r AuthorizationChangeReceipt) error {
		if err := events.RecordTx(tx, audit.Event{ID: r.ID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorID: r.ActorID, ActorType: "user", AggregateType: "identity_authentication_migration", AggregateID: r.SubjectID, Action: "authentication.migrated", Outcome: "success", Summary: r.Reason, CreatedAt: r.OccurredAt}); err != nil {
			return err
		}
		if fail {
			return errors.New("injected fault after actual audit/outbox")
		}
		return nil
	})
	if _, err := s.MigrateLegacyLocalAuthentication(ctx, actor, request, nil); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("missing verifier accepted", err)
	}
	if _, err := s.MigrateLegacyLocalAuthentication(ctx, actor, request, verified); err == nil {
		t.Fatal("audit fault ignored")
	}
	for _, query := range []string{`SELECT COUNT(*) FROM platform_identity_local_credential`, `SELECT COUNT(*) FROM platform_identity_role_binding`, `SELECT COUNT(*) FROM platform_identity_membership`, `SELECT COUNT(*) FROM platform_identity_authorization_change`, `SELECT COUNT(*) FROM platform_audit_event`, `SELECT COUNT(*) FROM platform_notification_outbox`} {
		var count int
		if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil || count != 0 {
			t.Fatal("bootstrap escaped rollback", count, err)
		}
	}
	fail = false
	receipt, err := s.MigrateLegacyLocalAuthentication(ctx, actor, request, verified)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.MigrateLegacyLocalAuthentication(ctx, actor, request, verified)
	if err != nil || replay.ID != receipt.ID {
		t.Fatal("bootstrap retry", err)
	}
	snapshot, err := s.PermissionSnapshot(ctx, PrincipalUser, actor.PrincipalID)
	if err != nil || snapshot.Mode != "v2" || !migrationEqual(snapshot.Principal.Roles, byID[actor.PrincipalID].Snapshot.Principal.Roles) || len(snapshot.Bindings) != 1 || snapshot.Bindings[0].RoleCode != "super_admin" || len(snapshot.Grants) != 0 {
		t.Fatal("source identity changed or business authority added", err)
	}
	var hash string
	var active bool
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT password_hash,active FROM platform_identity_local_credential WHERE principal_id=?`), actor.PrincipalID).Scan(&hash, &active); err != nil || !active || hash == request.Password || !verifyEnrollmentPassword(hash, request.Password) {
		t.Fatal("password import invalid", err)
	}
	inactive := request
	inactive.PrincipalID = "existing-disabled"
	inactive.ExpectedSourceDigest = byID[inactive.PrincipalID].SourceDigest
	inactive.ApprovalReference = "preserve-disabled-auth"
	inactive.AppointFirstSuperAdministrator = false
	inactive.DisplayName = "Existing inactive account"
	if _, err := s.MigrateLegacyLocalAuthentication(ctx, actor, inactive, verified); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT active FROM platform_identity_local_credential WHERE principal_id='existing-disabled'`)).Scan(&active); err != nil || active {
		t.Fatal("inactive credential enabled", err)
	}
	disabled, err := s.GetPrincipal(ctx, PrincipalUser, "existing-disabled")
	if err != nil || disabled.IsActive || !migrationEqual(disabled.Roles, byID[disabled.ID].Snapshot.Principal.Roles) {
		t.Fatal("disabled subject enabled", err)
	}
	var persisted string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT receipt FROM platform_identity_authorization_change WHERE id=?`), receipt.ID).Scan(&persisted); err != nil || strings.Contains(persisted, request.Password) {
		t.Fatal("secret persisted in receipt", err)
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT summary FROM platform_audit_event WHERE event_id=?`), receipt.ID).Scan(&persisted); err != nil || strings.Contains(persisted, request.Password) {
		t.Fatal("secret persisted in audit", err)
	}
	wrong := request
	wrong.Password = "different-source-secret"
	if _, err := s.MigrateLegacyLocalAuthentication(ctx, actor, wrong, verified); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("replay of different password accepted", err)
	}
}
