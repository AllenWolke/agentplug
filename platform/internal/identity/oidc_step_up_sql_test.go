package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
	"testing"
	"time"
)

type oidcStepUpFixture struct {
	administratorFixture
	session RefreshSessionResult
	binding OIDCBinding
}

func newOIDCStepUpFixture(t *testing.T) oidcStepUpFixture {
	return newOIDCStepUpFixtureForActor(t, 0)
}

func newOIDCStepUpFixtureForActor(t *testing.T, index int) oidcStepUpFixture {
	t.Helper()
	f := newAdministratorFixture(t)
	actor := f.actors[index]
	binding := OIDCBinding{Issuer: "https://fixture.example/realm", Subject: "immutable-administrator-subject", PrincipalID: actor.PrincipalID, TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, Status: "active", Revision: 1}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_oidc_binding(identity_key,issuer,subject,principal_id,tenant_id,department_id,application_id,status,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'active',1,?,?)`), oidcIdentityKey(binding.Issuer, binding.Subject), binding.Issuer, binding.Subject, actor.PrincipalID, actor.TenantID, actor.DepartmentID, actor.ApplicationID, f.now, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`DELETE FROM platform_identity_local_credential WHERE principal_id=?`), actor.PrincipalID); err != nil {
		t.Fatal(err)
	}
	f.store.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, RefreshSessionEvent) error { return nil })
	session, err := f.store.CreateOIDCRefreshSession(f.ctx, binding.Issuer, binding.Subject)
	if err != nil {
		t.Fatal(err)
	}
	notifications := notification.NewSQLStore(f.db)
	if err := notifications.EnsureSchema(f.ctx); err != nil {
		t.Fatal(err)
	}
	audits := audit.NewSQLStoreWithOutbox(f.db, notifications)
	if err := audits.EnsureSchema(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.store.SetAdministrativeRecorder(func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, event AdministrativeEvent) error {
		return audits.RecordTx(tx, audit.Event{ID: event.ID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: "user", ActorID: event.ActorID, AggregateType: "identity_administration", AggregateID: event.SubjectID, Action: event.Action, Outcome: "success", Summary: "bounded fixture administrative event", CreatedAt: event.OccurredAt})
	})
	f.store.SetAuthorizationChangeRecorder(func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, receipt AuthorizationChangeReceipt) error {
		return f.store.administrativeRecorder(ctx, tx, scope, AdministrativeEvent{ID: receipt.ID, ActorID: receipt.ActorID, SubjectID: receipt.SubjectID, Action: "authorization.changed", OccurredAt: receipt.OccurredAt})
	})
	return oidcStepUpFixture{administratorFixture: f, session: session, binding: binding}
}
func (f oidcStepUpFixture) request(command AdministratorCommand) OIDCStepUpRequest {
	digest, _ := AdministratorCommandDigest(command)
	return OIDCStepUpRequest{Scope: f.actors[0], SessionID: f.session.SessionID, AuthRevision: f.session.Identity.AuthRevision, Action: "administrator.appoint", RequestDigest: digest}
}
func (f oidcStepUpFixture) completion(t *testing.T, request OIDCStepUpRequest) OIDCStepUpCompletion {
	t.Helper()
	challenge, err := f.store.CreateOIDCStepUpChallenge(f.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	var storedHash, nonceHash string
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT token_hash,nonce_hash FROM platform_identity_oidc_step_up_challenge WHERE token_hash=?`), refreshHash(challenge.Token)).Scan(&storedHash, &nonceHash); err != nil || storedHash == challenge.Token || nonceHash == challenge.Nonce {
		t.Fatal("challenge bearer values persisted", err)
	}
	return OIDCStepUpCompletion{OIDCStepUpRequest: request, ChallengeToken: challenge.Token, Issuer: challenge.Issuer, Subject: challenge.Subject, Nonce: challenge.Nonce, AuthenticatedAt: f.now.Truncate(time.Second)}
}

func TestSQLOIDCStepUpAppointmentAndOneUse(t *testing.T) {
	f := newOIDCStepUpFixture(t)
	command := f.command(2, "oidc-appointed")
	completion := f.completion(t, f.request(command))
	proof, err := f.store.CompleteOIDCStepUp(f.ctx, completion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CompleteOIDCStepUp(f.ctx, completion); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal("challenge reuse accepted", err)
	}
	command.StepUpToken = proof.Token
	receipt, err := f.store.AppointAdministrator(f.ctx, f.actors[0], command)
	if err != nil || receipt.Revision != 2 || receipt.Command.StepUpToken != "" {
		t.Fatal("OIDC-only administrator could not appoint", receipt, err)
	}
	if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], command); err != nil {
		t.Fatal("qualified accepted command retry denied", err)
	}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := consumeStepUp(f.ctx, tx, f.actors[0], proof.Token, completion.Action, completion.RequestDigest, f.now); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal("consumed exact proof reused", err)
	}
	var audits, outbox int
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event`)).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_notification_outbox`)).Scan(&outbox); err != nil || audits != 3 || outbox != 3 {
		t.Fatal("OIDC start/proof/appointment audit and outbox mismatch", audits, outbox, err)
	}
}

func TestSQLOIDCStepUpChallengeBindingAndFreshness(t *testing.T) {
	f := newOIDCStepUpFixture(t)
	completion := f.completion(t, f.request(f.command(2, "oidc-binding")))
	for _, name := range []string{"nonce", "issuer", "subject", "scope", "session", "revision", "digest", "action", "old-authentication", "future-authentication"} {
		t.Run(name, func(t *testing.T) {
			c := completion
			switch name {
			case "nonce":
				c.Nonce = strings.Repeat("a", 43)
			case "issuer":
				c.Issuer = "https://other.example/realm"
			case "subject":
				c.Subject = "other-subject"
			case "scope":
				c.Scope.ApplicationID = "other-app"
			case "session":
				c.SessionID = strings.Repeat("b", 64)
			case "revision":
				c.AuthRevision++
			case "digest":
				c.RequestDigest = strings.Repeat("c", 64)
			case "action":
				c.Action = "delegation.manage"
			case "old-authentication":
				c.AuthenticatedAt = f.now.Truncate(time.Second).Add(-time.Second)
			case "future-authentication":
				c.AuthenticatedAt = f.now.Add(time.Minute)
			}
			if _, err := f.store.CompleteOIDCStepUp(f.ctx, c); err == nil {
				t.Fatal("unbound or stale OIDC assertion accepted")
			}
		})
	}
	var proofs int
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_step_up`)).Scan(&proofs); err != nil || proofs != 0 {
		t.Fatal("rejected assertions minted proofs", proofs, err)
	}
	if _, err := f.store.CompleteOIDCStepUp(f.ctx, completion); err != nil {
		t.Fatal("rejected assertions consumed challenge", err)
	}
}

func TestSQLOIDCStepUpAuditRollbackAndExpirationCleanup(t *testing.T) {
	f := newOIDCStepUpFixture(t)
	command := f.command(2, "oidc-rollback")
	completion := f.completion(t, f.request(command))
	original := f.store.administrativeRecorder
	fault := errors.New("injected OIDC audit failure")
	f.store.SetAdministrativeRecorder(func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, event AdministrativeEvent) error {
		if err := original(ctx, tx, scope, event); err != nil {
			return err
		}
		return fault
	})
	if _, err := f.store.CompleteOIDCStepUp(f.ctx, completion); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	var used bool
	var proofs, audits, outbox int
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT used FROM platform_identity_oidc_step_up_challenge WHERE token_hash=?`), refreshHash(completion.ChallengeToken)).Scan(&used); err != nil || used {
		t.Fatal("failed audit consumed challenge", err)
	}
	for query, destination := range map[string]*int{`SELECT COUNT(*) FROM platform_identity_step_up`: &proofs, `SELECT COUNT(*) FROM platform_audit_event`: &audits, `SELECT COUNT(*) FROM platform_notification_outbox`: &outbox} {
		if err := f.db.QueryRowContext(f.ctx, query).Scan(destination); err != nil {
			t.Fatal(err)
		}
	}
	if proofs != 0 || audits != 1 || outbox != 1 {
		t.Fatal("failed proof/audit/outbox escaped rollback", proofs, audits, outbox)
	}
	f.store.SetAdministrativeRecorder(original)
	proof, err := f.store.CompleteOIDCStepUp(f.ctx, completion)
	if err != nil {
		t.Fatal(err)
	}
	command.StepUpToken = proof.Token
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return fault })
	if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], command); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT used FROM platform_identity_step_up WHERE token_hash=?`), refreshHash(proof.Token)).Scan(&used); err != nil || used {
		t.Fatal("failed appointment consumed OIDC proof", err)
	}
	f.store.SetAdministrativeRecorder(original)
	end := proof.ExpiresAt
	f.store.clock = func() time.Time { return end }
	if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], command); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal("expired OIDC proof accepted", err)
	}
	if _, err := f.store.PurgeExpiredRefreshSessions(f.ctx, 100); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{`SELECT COUNT(*) FROM platform_identity_step_up`, `SELECT COUNT(*) FROM platform_identity_oidc_step_up_proof`} {
		var count int
		if err := f.db.QueryRowContext(f.ctx, query).Scan(&count); err != nil || count != 0 {
			t.Fatal("expired proof metadata retained", count, err)
		}
	}
	// The challenge has its own absolute lifetime and is removed after it.
	f.store.clock = func() time.Time { return f.now.Add(StepUpLifetime) }
	if _, err := f.store.PurgeExpiredRefreshSessions(f.ctx, 100); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_oidc_step_up_challenge`)).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired challenge retained", count, err)
	}
}

func TestSQLOIDCStepUpRevocationAndQualification(t *testing.T) {
	for _, name := range []string{"binding-disabled", "family-revoked", "member-removed", "workspace-changed", "principal-disabled", "qualification-revoked"} {
		t.Run(name, func(t *testing.T) {
			f := newOIDCStepUpFixture(t)
			command := f.command(2, "oidc-revoked")
			completion := f.completion(t, f.request(command))
			proof, err := f.store.CompleteOIDCStepUp(f.ctx, completion)
			if err != nil {
				t.Fatal(err)
			}
			command.StepUpToken = proof.Token
			switch name {
			case "binding-disabled":
				f.store.SetOIDCBindingRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, OIDCBindingDecision) error { return nil })
				if err := f.store.DisableOIDCBinding(f.ctx, f.actors[1], f.binding, 1); err != nil {
					t.Fatal(err)
				}
			case "family-revoked":
				if err := f.store.RevokeRefreshSession(f.ctx, f.session.RefreshToken); err != nil {
					t.Fatal(err)
				}
			case "member-removed":
				actor := f.actors[0]
				change := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: actor.PrincipalID, ExpectedRevision: 1, IdempotencyKey: "remove-oidc-member", Reason: "remove existing application membership", Memberships: []MembershipMutation{{ID: actor.PrincipalID + "-member", ExpectedRevision: 1, Scope: ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}, Status: "revoked"}}}
				plan, err := f.store.PreviewAuthorizationChange(f.ctx, f.actors[1], change)
				if err != nil {
					t.Fatal(err)
				}
				change.PlanDigest, change.PlanExpiresAt = plan.Digest, plan.ExpiresAt
				if _, err := f.store.CommitAuthorizationChange(f.ctx, f.actors[1], change); err != nil {
					t.Fatal(err)
				}
			case "workspace-changed":
				actor := f.actors[0]
				target := EnrollmentScope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID + "-other"}
				if err := f.store.CreateApplication(f.ctx, Application{ID: target.ApplicationID, TenantID: target.TenantID, DepartmentID: target.DepartmentID, Code: "other", Name: "other", Status: "active", Revision: 1}); err != nil {
					t.Fatal(err)
				}
				tx, err := f.db.BeginTx(f.ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				member := Membership{ID: actor.PrincipalID + "-other-member", SubjectID: actor.PrincipalID, Scope: ManagementScope{Type: "application", TenantID: target.TenantID, DepartmentID: target.DepartmentID, ApplicationID: target.ApplicationID}, Status: "active", Revision: 1}
				if err := persistMembershipMutation(f.ctx, tx, member, 0); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.SwitchRefreshWorkspace(f.ctx, f.session.RefreshToken, actor.PrincipalID, f.session.Identity.AuthRevision, target); err != nil {
					t.Fatal(err)
				}
			case "principal-disabled":
				if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE principal_type='user' AND id=?`), f.actors[0].PrincipalID); err != nil {
					t.Fatal(err)
				}
			case "qualification-revoked":
				var binding RoleBinding
				var raw []byte
				if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT payload FROM platform_identity_role_binding WHERE id=?`), f.bindings[0]).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(raw, &binding); err != nil {
					t.Fatal(err)
				}
				binding.Status = "revoked"
				raw, _ = json.Marshal(binding)
				if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_role_binding SET status='revoked',payload=? WHERE id=?`), string(raw), binding.ID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], command); err == nil {
				t.Fatal("revoked OIDC administrative proof accepted")
			}
			_, err = f.store.CreateOIDCStepUpChallenge(f.ctx, f.request(command))
			if name == "member-removed" {
				// Business membership removal invalidates the old proof, but a
				// retained administrator can authenticate again for management.
				if err != nil {
					t.Fatal("qualified administrator could not reauthenticate", err)
				}
			} else if err == nil {
				t.Fatal("revoked OIDC administrator started challenge")
			}
		})
	}
}
