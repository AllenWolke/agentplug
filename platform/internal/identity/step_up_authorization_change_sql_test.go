package identity

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLAuthorizationChangeInvalidatesStepUpAtomically(t *testing.T) {
	for _, mode := range []string{"local", "oidc"} {
		t.Run(mode, func(t *testing.T) {
			var f administratorFixture
			var oidc oidcStepUpFixture
			var pending OIDCStepUpCompletion
			var command AdministratorCommand
			if mode == "oidc" {
				oidc = newOIDCStepUpFixture(t)
				f = oidc.administratorFixture
				command = f.command(2, "reauthenticate-after-change")
				completion := oidc.completion(t, oidc.request(command))
				proof, err := f.store.CompleteOIDCStepUp(f.ctx, completion)
				if err != nil {
					t.Fatal(err)
				}
				command.StepUpToken = proof.Token
				pending = oidc.completion(t, oidc.request(command))
			} else {
				f = newAdministratorFixture(t)
				command = f.authenticate(t, 0, f.command(2, "reauthenticate-after-change"))
				f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
			}
			otherCommand := f.authenticate(t, 1, f.command(2, "other-administrator-proof"))
			actor := f.actors[0]
			change := AuthorizationChangeCommand{
				SubjectType: PrincipalUser, SubjectID: actor.PrincipalID, ExpectedRevision: 1,
				IdempotencyKey: "remove-membership-with-step-up", Reason: "remove business membership while retaining administrator management",
				Memberships: []MembershipMutation{{ID: actor.PrincipalID + "-member", ExpectedRevision: 1, Scope: ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}, Status: "revoked"}},
			}
			plan, err := f.store.PreviewAuthorizationChange(f.ctx, f.actors[1], change)
			if err != nil {
				t.Fatal(err)
			}
			change.PlanDigest, change.PlanExpiresAt = plan.Digest, plan.ExpiresAt
			recorder := f.store.authorizationChangeRecorder
			fault := errors.New("authorization audit unavailable")
			f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return fault })
			if _, err := f.store.CommitAuthorizationChange(f.ctx, f.actors[1], change); !errors.Is(err, fault) {
				t.Fatal("audit failure did not roll back authorization change", err)
			}
			assertProofUsed := func(token string, want bool) {
				var used bool
				if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT used FROM platform_identity_step_up WHERE token_hash=?`), refreshHash(token)).Scan(&used); err != nil || used != want {
					t.Fatal("step-up invalidation escaped transaction or affected another subject", used, want, err)
				}
			}
			assertChallengeUsed := func(want bool) {
				if mode != "oidc" {
					return
				}
				var used bool
				if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT used FROM platform_identity_oidc_step_up_challenge WHERE token_hash=?`), refreshHash(pending.ChallengeToken)).Scan(&used); err != nil || used != want {
					t.Fatal("unfinished challenge invalidation escaped transaction", used, want, err)
				}
			}
			assertProofUsed(command.StepUpToken, false)
			assertChallengeUsed(false)
			f.store.SetAuthorizationChangeRecorder(recorder)
			if _, err := f.store.CommitAuthorizationChange(f.ctx, f.actors[1], change); err != nil {
				t.Fatal(err)
			}
			assertProofUsed(command.StepUpToken, true)
			assertProofUsed(otherCommand.StepUpToken, false)
			assertChallengeUsed(true)
			if _, err := f.store.AppointAdministrator(f.ctx, actor, command); !errors.Is(err, ErrStepUpRequired) {
				t.Fatal("pre-change administrative proof remained usable", err)
			}
			if mode == "oidc" {
				if _, err := f.store.CompleteOIDCStepUp(f.ctx, pending); !errors.Is(err, ErrStepUpRequired) {
					t.Fatal("pre-change OIDC challenge issued a new proof", err)
				}
				completion := oidc.completion(t, oidc.request(command))
				proof, err := f.store.CompleteOIDCStepUp(f.ctx, completion)
				if err != nil {
					t.Fatal("qualified administrator could not reauthenticate", err)
				}
				command.StepUpToken = proof.Token
			} else {
				command = f.authenticate(t, 0, command)
			}
			if _, err := f.store.AppointAdministrator(f.ctx, actor, command); err != nil {
				t.Fatal("fresh proof could not authorize the retained management role", err)
			}
		})
	}
}
