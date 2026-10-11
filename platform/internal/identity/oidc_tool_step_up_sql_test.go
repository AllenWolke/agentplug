package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLOIDCToolStepUpExactSessionAndOperation(t *testing.T) {
	for _, action := range []string{"tool.approval.approve", "tool.approval.revoke"} {
		t.Run(action, func(t *testing.T) {
			f := newOIDCStepUpFixtureForActor(t, 2) // Member without any administrator role or local password.
			actor := f.actors[2]
			request := OIDCStepUpRequest{Scope: actor, SessionID: f.session.SessionID, AuthRevision: f.session.Identity.AuthRevision, Action: action, RequestDigest: strings.Repeat("b", 64)}
			management := request
			management.Action = "administrator.appoint"
			if _, err := f.store.CreateOIDCStepUpChallenge(f.ctx, management); err == nil {
				t.Fatal("business identity acquired administrator authentication")
			}
			completion := f.completion(t, request)
			for _, name := range []string{"subject", "nonce", "scope", "session", "revision", "digest", "action", "old-authentication", "future-authentication"} {
				t.Run("challenge-"+name, func(t *testing.T) {
					changed := completion
					switch name {
					case "subject":
						changed.Subject = "other-user"
					case "nonce":
						changed.Nonce = strings.Repeat("z", 43)
					case "scope":
						changed.Scope.ApplicationID = "other-application"
					case "session":
						changed.SessionID = strings.Repeat("c", 64)
					case "revision":
						changed.AuthRevision++
					case "digest":
						changed.RequestDigest = strings.Repeat("c", 64)
					case "action":
						if action == "tool.approval.approve" {
							changed.Action = "tool.approval.revoke"
						} else {
							changed.Action = "tool.approval.approve"
						}
					case "old-authentication":
						changed.AuthenticatedAt = f.now.Add(-time.Minute)
					case "future-authentication":
						changed.AuthenticatedAt = f.now.Add(time.Minute)
					}
					if _, err := f.store.CompleteOIDCStepUp(f.ctx, changed); err == nil {
						t.Fatal("unbound business authentication accepted")
					}
				})
			}
			proof, err := f.store.CompleteOIDCStepUp(f.ctx, completion)
			if err != nil {
				t.Fatal("OIDC-only member authentication", err)
			}
			if _, err := f.store.CompleteOIDCStepUp(f.ctx, completion); err == nil {
				t.Fatal("challenge replay accepted")
			}
			other, err := f.store.CreateOIDCRefreshSession(f.ctx, f.binding.Issuer, f.binding.Subject)
			if err != nil {
				t.Fatal(err)
			}
			consume := func(scope sharedkernel.Scope, session string, revision uint64, operation, digest string, commit bool) error {
				tx, err := f.db.BeginTx(f.ctx, nil)
				if err != nil {
					return err
				}
				defer tx.Rollback()
				if err := f.store.ConsumeToolStepUpTx(f.ctx, tx, scope, session, revision, proof.Token, operation, digest); err != nil {
					return err
				}
				if commit {
					return tx.Commit()
				}
				return nil
			}
			if err := consume(actor, other.SessionID, request.AuthRevision, action, request.RequestDigest, true); err == nil {
				t.Fatal("same-user other active login accepted proof")
			}
			if err := consume(actor, request.SessionID, request.AuthRevision+1, action, request.RequestDigest, true); err == nil {
				t.Fatal("different authentication revision accepted proof")
			}
			if err := consume(f.actors[1], request.SessionID, request.AuthRevision, action, request.RequestDigest, true); err == nil {
				t.Fatal("different user accepted proof")
			}
			if err := consume(actor, request.SessionID, request.AuthRevision, action, strings.Repeat("c", 64), true); err == nil {
				t.Fatal("different operation digest accepted proof")
			}
			if err := consume(actor, request.SessionID, request.AuthRevision, "administrator.appoint", request.RequestDigest, true); err == nil {
				t.Fatal("business proof used for management")
			}
			if err := consume(actor, request.SessionID, request.AuthRevision, action, request.RequestDigest, false); err != nil {
				t.Fatal("proof consumption rollback", err)
			}
			if err := consume(actor, request.SessionID, request.AuthRevision, action, request.RequestDigest, true); err != nil {
				t.Fatal("original exact proof after rejected and rolled-back requests", err)
			}
			if err := consume(actor, request.SessionID, request.AuthRevision, action, request.RequestDigest, true); err == nil {
				t.Fatal("proof replay accepted")
			}
		})
	}
}

func TestSQLOIDCToolStepUpMembershipRevocation(t *testing.T) {
	f := newOIDCStepUpFixtureForActor(t, 2)
	actor := f.actors[2]
	request := OIDCStepUpRequest{Scope: actor, SessionID: f.session.SessionID, AuthRevision: f.session.Identity.AuthRevision, Action: "tool.approval.approve", RequestDigest: strings.Repeat("b", 64)}
	proof, err := f.store.CompleteOIDCStepUp(f.ctx, f.completion(t, request))
	if err != nil {
		t.Fatal(err)
	}
	pending := f.completion(t, request)
	change := AuthorizationChangeCommand{
		SubjectType: PrincipalUser, SubjectID: actor.PrincipalID, ExpectedRevision: 1,
		IdempotencyKey: "remove-oidc-tool-membership", Reason: "remove member access after business fresh authentication",
		Memberships: []MembershipMutation{{ID: actor.PrincipalID + "-member", ExpectedRevision: 1, Scope: ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}, Status: "revoked"}},
	}
	plan, err := f.store.PreviewAuthorizationChange(f.ctx, f.actors[0], change)
	if err != nil {
		t.Fatal(err)
	}
	change.PlanDigest, change.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	if _, err := f.store.CommitAuthorizationChange(f.ctx, f.actors[0], change); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateOIDCStepUpChallenge(f.ctx, request); err == nil {
		t.Fatal("removed member started business authentication")
	}
	if _, err := f.store.CompleteOIDCStepUp(f.ctx, pending); err == nil {
		t.Fatal("removed member completed pending authentication")
	}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := f.store.ConsumeToolStepUpTx(f.ctx, tx, actor, request.SessionID, request.AuthRevision, proof.Token, request.Action, request.RequestDigest); err == nil {
		t.Fatal("removed member consumed issued authentication proof")
	}
}
