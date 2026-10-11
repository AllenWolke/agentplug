package identity

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLToolStepUpExactActionAndTransaction(t *testing.T) {
	f := newAdministratorFixture(t)
	actor := f.actors[2] // Ordinary member, no admin role.
	request := StepUpRequest{CurrentPassword: "fixture-administrator-password", Action: "tool.approval.approve", RequestDigest: strings.Repeat("b", 64)}
	authorize := func(_ context.Context, tx *sql.Tx, scope sharedkernel.Scope, action, digest string) error {
		if tx == nil || scope.PrincipalID != actor.PrincipalID || action != request.Action || digest != request.RequestDigest {
			return ErrPermissionDenied
		}
		return nil
	}
	if _, err := f.store.CreateToolStepUp(f.ctx, actor, request, nil); err == nil {
		t.Fatal("missing tool permission authorizer accepted")
	}
	if _, err := f.store.CreateLocalStepUp(f.ctx, actor, request); err == nil {
		t.Fatal("management endpoint accepted business proof")
	}
	wrong := request
	wrong.CurrentPassword = "wrong"
	if _, err := f.store.CreateToolStepUp(f.ctx, actor, wrong, authorize); !errors.Is(err, ErrCurrentPasswordInvalid) {
		t.Fatal("wrong password accepted", err)
	}
	if _, err := f.store.CreateToolStepUp(f.ctx, actor, request, func(context.Context, *sql.Tx, sharedkernel.Scope, string, string) error { return ErrPermissionDenied }); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("password bypassed resource permission")
	}
	proof, err := f.store.CreateToolStepUp(f.ctx, actor, request, authorize)
	if err != nil {
		t.Fatal("ordinary member step-up failed", err)
	}
	consume := func(action, digest string, commit bool) error {
		tx, err := f.db.BeginTx(f.ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err = f.store.ConsumeToolStepUpTx(f.ctx, tx, actor, strings.Repeat("a", 64), 1, proof.Token, action, digest); err != nil {
			return err
		}
		if commit {
			return tx.Commit()
		}
		return nil
	}
	if err = consume("tool.approval.revoke", request.RequestDigest, true); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal("cross-action proof accepted", err)
	}
	if err = consume(request.Action, strings.Repeat("c", 64), true); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal("changed operation proof accepted", err)
	}
	if err = consume(request.Action, request.RequestDigest, false); err != nil {
		t.Fatal("consume rollback failed", err)
	}
	if err = consume(request.Action, request.RequestDigest, true); err != nil {
		t.Fatal("rollback consumed proof", err)
	}
	if err = consume(request.Action, request.RequestDigest, true); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal("proof replay accepted", err)
	}
	proof, err = f.store.CreateToolStepUp(f.ctx, actor, request, authorize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Exec(sqlutil.Bind(`UPDATE platform_identity_local_credential SET auth_revision=auth_revision+1 WHERE principal_id=?`), actor.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if err = consume(request.Action, request.RequestDigest, true); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal("credential rotation retained proof", err)
	}
}
