package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"testing"
	"time"
)

func TestSQLWorkspaceSwitchAndRefresh(t *testing.T) {
	f := newAdministratorFixture(t)
	actor := f.actors[2]
	s := f.store
	s.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, RefreshSessionEvent) error { return nil })
	target := EnrollmentScope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID + "-second"}
	if err := s.CreateApplication(f.ctx, Application{ID: target.ApplicationID, TenantID: target.TenantID, DepartmentID: target.DepartmentID, Code: "second", Name: "Second workspace", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	scope := ManagementScope{Type: "application", TenantID: target.TenantID, DepartmentID: target.DepartmentID, ApplicationID: target.ApplicationID}
	member := Membership{ID: "workspace-second-member", SubjectID: actor.PrincipalID, Scope: scope, Status: "active", Revision: 1}
	raw, _ := json.Marshal(member)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES(?,?,?,?,?,'active',1,?,?)`), member.ID, actor.PrincipalID, target.TenantID, target.DepartmentID, target.ApplicationID, string(raw), permissionHash([]byte(member.ID))); err != nil {
		t.Fatal(err)
	}
	home := EnrollmentScope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	first, err := s.CreateRefreshSession(f.ctx, actor.PrincipalID, home, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateBrowserSession(f.ctx, actor, first.SessionID, 1); err != nil {
		t.Fatal("home browser session rejected", err)
	}
	for _, input := range []struct {
		subject  string
		revision uint64
		scope    EnrollmentScope
	}{{"someone.else", 1, target}, {actor.PrincipalID, 2, target}, {actor.PrincipalID, 1, EnrollmentScope{TenantID: "foreign", DepartmentID: target.DepartmentID, ApplicationID: target.ApplicationID}}, {actor.PrincipalID, 1, EnrollmentScope{TenantID: target.TenantID, DepartmentID: target.DepartmentID, ApplicationID: "unjoined"}}} {
		if _, err := s.SwitchRefreshWorkspace(f.ctx, first.RefreshToken, input.subject, input.revision, input.scope); err == nil {
			t.Fatal("invalid workspace switch allowed", input)
		}
	}
	fault := errors.New("workspace audit unavailable")
	s.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, RefreshSessionEvent) error { return fault })
	if _, err := s.SwitchRefreshWorkspace(f.ctx, first.RefreshToken, actor.PrincipalID, 1, target); !errors.Is(err, fault) {
		t.Fatal("audit rollback missing", err)
	}
	s.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, RefreshSessionEvent) error { return nil })
	next, err := s.SwitchRefreshWorkspace(f.ctx, first.RefreshToken, actor.PrincipalID, 1, target)
	if err != nil || next.Identity.ApplicationID != target.ApplicationID || !next.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("switch or absolute lifetime incorrect", next, err)
	}
	if err := s.ValidateBrowserSession(f.ctx, actor, first.SessionID, 1); !errors.Is(err, ErrRefreshSessionRejected) {
		t.Fatal("old workspace assertion survived workspace switch", err)
	}
	switched := actor
	switched.ApplicationID = target.ApplicationID
	if err := s.ValidateBrowserSession(f.ctx, switched, next.SessionID, 1); err != nil {
		t.Fatal("current workspace assertion rejected", err)
	}
	if _, err := s.ValidateEnrollmentSession(f.ctx, actor.PrincipalID, target, 1); err != nil {
		t.Fatal("credential origin confused with active workspace", err)
	}
	workspaces, err := s.ListApplicationWorkspaces(f.ctx, actor.PrincipalID)
	if err != nil || len(workspaces) != 2 {
		t.Fatal("workspace member projection incorrect", workspaces, err)
	}
	restarted := NewSQLStore(f.db)
	restarted.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, RefreshSessionEvent) error { return nil })
	restarted.clock = s.clock
	renewed, err := restarted.RotateRefreshSession(f.ctx, next.RefreshToken)
	if err != nil || renewed.Identity.ApplicationID != target.ApplicationID || !renewed.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("workspace lost on restart or rotation", renewed, err)
	}
	decision, err := s.ResolvePermission(f.ctx, PrincipalUser, actor.PrincipalID, PermissionQuery{Action: "run", Scope: scope, ResourceType: "agent_installation", ResourceID: "missing-grant", Now: f.now})
	if err != nil || decision.Allowed {
		t.Fatal("workspace switching granted business access", decision, err)
	}
	expired := f.now.Add(-time.Second)
	member.Validity.ExpiresAt = &expired
	raw, _ = json.Marshal(member)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_membership SET expires_at=?,payload=? WHERE id=?`), expired, string(raw), member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateEnrollmentSession(f.ctx, actor.PrincipalID, target, 1); err == nil {
		t.Fatal("expired workspace accepted")
	}
	if err := s.ValidateBrowserSession(f.ctx, switched, renewed.SessionID, 1); !errors.Is(err, ErrRefreshSessionRejected) {
		t.Fatal("expired membership survived in access-token session", err)
	}
	if _, err := s.SwitchRefreshWorkspace(f.ctx, renewed.RefreshToken, actor.PrincipalID, 1, target); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("expired workspace switch accepted", err)
	}
	back, err := s.RotateRefreshSession(f.ctx, renewed.RefreshToken)
	if err != nil || back.Identity.ApplicationID != home.ApplicationID {
		t.Fatal("membership loss broke authentication or restored forbidden workspace", back, err)
	}
	var credentialApp string
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT application_id FROM platform_identity_local_credential WHERE principal_id=?`), actor.PrincipalID).Scan(&credentialApp); err != nil || credentialApp != home.ApplicationID {
		t.Fatal("workspace mutated authentication origin", err)
	}
	// Account security operations use the credential's origin and the current
	// workspace independently, including protected action-bound authentication.
	admin := f.actors[0]
	switchedAdmin := admin
	switchedAdmin.ApplicationID = target.ApplicationID
	member.ID, member.SubjectID, member.Validity = "workspace-admin-member", admin.PrincipalID, Validity{}
	raw, _ = json.Marshal(member)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES(?,?,?,?,?,'active',1,?,?)`), member.ID, admin.PrincipalID, target.TenantID, target.DepartmentID, target.ApplicationID, string(raw), permissionHash([]byte(member.ID))); err != nil {
		t.Fatal(err)
	}
	proof, err := s.CreateLocalStepUp(f.ctx, switchedAdmin, StepUpRequest{CurrentPassword: "fixture-administrator-password", Action: "delegation.manage", RequestDigest: permissionHash([]byte("switched-workspace-command"))})
	if err != nil || proof.Token == "" {
		t.Fatal("step-up confused credential origin", err)
	}
	adminFamily, err := s.CreateRefreshSession(f.ctx, admin.PrincipalID, home, 1)
	if err != nil {
		t.Fatal(err)
	}
	s.SetCredentialLifecycleRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, CredentialLifecycleDecision) error { return nil })
	newHash, err := hashEnrollmentPassword("workspace-changed-password")
	if err != nil {
		t.Fatal(err)
	}
	if revision, err := s.ChangeOwnPassword(f.ctx, switchedAdmin, "fixture-administrator-password", newHash); err != nil || revision != 2 {
		t.Fatal("password change in joined workspace failed", revision, err)
	}
	if _, err := s.RotateRefreshSession(f.ctx, adminFamily.RefreshToken); !errors.Is(err, ErrRefreshSessionRejected) {
		t.Fatal("switched password change failed to revoke original sessions", err)
	}
	if _, err := s.VerifyEnrollmentCredentials(f.ctx, admin.PrincipalID, "workspace-changed-password"); err != nil {
		t.Fatal("password rotated wrong authentication binding", err)
	}
}
