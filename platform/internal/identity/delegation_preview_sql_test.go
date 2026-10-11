package identity

import (
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"testing"
	"time"
)

func TestSQLDelegationPreviewValidatesCurrentBoundaryWithoutWrites(t *testing.T) {
	f := newAdministratorFixture(t)
	appointment := f.command(2, "preview-permission-admin")
	d := Delegation{ID: "preview-bounded-delegation", SubjectID: f.actors[2].PrincipalID, Scope: appointment.Scope, Roles: []string{"operator"}, ManagementActions: []string{"authorization.change"}, MaxDurationSeconds: 3600, AllowPermanent: true, Status: "active", Revision: 1}
	command := DelegationCommand{SubjectID: d.SubjectID, ExpectedRevision: 1, IdempotencyKey: "preview-bounded", Reason: "limit grant-making authority", Delegation: &d}
	if _, err := f.store.PreviewDelegation(f.ctx, f.actors[0], command); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("preview accepted target without permission-admin qualification", err)
	}
	appointment = f.authenticate(t, 0, appointment)
	if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], appointment); err != nil {
		t.Fatal(err)
	}
	command.ExpectedRevision = 2
	command.StepUpToken = "must-not-enter-preview"
	preview, err := f.store.PreviewDelegation(f.ctx, f.actors[0], command)
	if err != nil || preview.Command.StepUpToken != "" || preview.StepUpAction != "delegation.manage" {
		t.Fatal("valid preview rejected or echoed proof", preview, err)
	}
	digest, err := DelegationCommandDigest(command)
	if err != nil || preview.RequestDigest != digest {
		t.Fatal("preview changed action digest", err)
	}
	preview.Command.Delegation.Roles[0] = "reviewer"
	if command.Delegation.Roles[0] != "operator" {
		t.Fatal("preview collections alias caller command")
	}
	for _, name := range []string{"stale-revision", "target-disabled", "foreign-scope", "admin-role", "wildcard", "duplicate-management", "expired", "missing-resource", "missing-resolver", "unknown-revoke", "permission-admin-issuer", "machine-issuer", "foreign-actor-tenant"} {
		t.Run(name, func(t *testing.T) {
			c := command
			v := d
			c.Delegation = &v
			actor := f.actors[0]
			switch name {
			case "stale-revision":
				c.ExpectedRevision = 1
			case "target-disabled":
				if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE principal_type='user' AND id=?`), d.SubjectID); err != nil {
					t.Fatal(err)
				}
				defer f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=TRUE WHERE principal_type='user' AND id=?`), d.SubjectID)
			case "foreign-scope":
				v.Scope.TenantID = "foreign"
			case "admin-role":
				v.Roles = []string{"super_admin"}
			case "wildcard":
				v.Roles = []string{"*"}
			case "duplicate-management":
				v.ManagementActions = []string{"authorization.change", "authorization.change"}
			case "expired":
				expired := f.now.Add(-time.Second)
				v.AllowPermanent = false
				v.ExpiresAt = &expired
			case "missing-resource":
				v.Actions = []string{"run"}
				v.DataScopeTypes = []string{"owner"}
			case "missing-resolver":
				v.Actions = []string{"run"}
				v.DataScopeTypes = []string{"owner"}
				v.Resources = []string{"unresolved-installation"}
			case "unknown-revoke":
				c.Delegation = nil
				c.RevokeDelegationID = "nonexistent-delegation"
			case "permission-admin-issuer":
				actor = f.actors[2]
			case "machine-issuer":
				actor.PrincipalType = "service_principal"
			case "foreign-actor-tenant":
				actor.TenantID = "foreign"
			}
			if _, err := f.store.PreviewDelegation(f.ctx, actor, c); err == nil {
				t.Fatal("invalid delegation preview accepted")
			}
		})
	}
	for _, table := range []string{"platform_identity_delegation", "platform_identity_authorization_change", "platform_identity_step_up"} {
		var count int
		if err := f.db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		expected := 1
		if table == "platform_identity_delegation" {
			expected = 0
		}
		if count != expected {
			t.Fatal("preview caused a durable mutation", table, count, expected)
		}
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, d.SubjectID)
	if err != nil || snapshot.Principal.Revision != 2 {
		t.Fatal("preview advanced target revision", snapshot, err)
	}
}
