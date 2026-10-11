package identity

import (
	"context"
	"database/sql"
	"time"
)

// Idempotency receipts are scoped management metadata. A previously accepted
// request does not retain access after the actor's current authority is revoked.
func authorizeReceiptRead(ctx context.Context, tx *sql.Tx, owner PermissionSnapshot, receipt AuthorizationChangeReceipt, now time.Time) error {
	if owner.Mode != "v2" || !owner.Principal.IsActive {
		return ErrPermissionDenied
	}
	target, err := loadPermissionSnapshot(ctx, tx, receipt.Change.SubjectType, receipt.SubjectID)
	if err != nil {
		return err
	}
	scopes := []ManagementScope{}
	for _, assignment := range receipt.Change.Assignments {
		scopes = append(scopes, assignment.Scope)
	}
	for _, id := range receipt.Change.RevokeAssignmentIDs {
		found := false
		for _, assignment := range target.Assignments {
			if assignment.ID == id {
				scopes = append(scopes, assignment.Scope)
				found = true
				break
			}
		}
		if !found {
			return ErrPermissionDenied
		}
	}
	for _, b := range receipt.Change.Bindings {
		scopes = append(scopes, b.Scope)
	}
	for _, g := range receipt.Change.Grants {
		scopes = append(scopes, ManagementScope{Type: "application", TenantID: g.TenantID, DepartmentID: g.DepartmentID, ApplicationID: g.ApplicationID})
	}
	for _, m := range receipt.Memberships {
		scopes = append(scopes, m.Scope)
	}
	for _, id := range receipt.Change.RevokeBindingIDs {
		found := false
		for _, b := range target.Bindings {
			if b.ID == id {
				scopes = append(scopes, b.Scope)
				found = true
				break
			}
		}
		if !found {
			return ErrPermissionDenied
		}
	}
	for _, id := range receipt.Change.RevokeGrantIDs {
		found := false
		for _, g := range target.Grants {
			if g.ID == id {
				scopes = append(scopes, ManagementScope{Type: "application", TenantID: g.TenantID, DepartmentID: g.DepartmentID, ApplicationID: g.ApplicationID})
				found = true
				break
			}
		}
		if !found {
			return ErrPermissionDenied
		}
	}
	if len(scopes) == 0 {
		return ErrPermissionDenied
	}
	memberOnly := len(receipt.Change.Memberships) > 0 && len(receipt.Change.Bindings) == 0 && len(receipt.Change.Grants) == 0 && len(receipt.Change.Assignments) == 0
	for _, scope := range scopes {
		if err := validatePermissionScope(ctx, tx, scope); err != nil {
			return err
		}
		decision, err := EvaluatePermission(owner, PermissionQuery{Action: "authorization.read", Scope: scope, Now: now})
		if err != nil {
			return err
		}
		if !decision.Allowed && memberOnly {
			decision, err = EvaluatePermission(owner, PermissionQuery{Action: "membership.manage", Scope: scope, Now: now})
			if err != nil {
				return err
			}
		}
		if !decision.Allowed {
			return ErrPermissionDenied
		}
	}
	return nil
}
