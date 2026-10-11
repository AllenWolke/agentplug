package identity

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// AuthorizeManagementTx joins a protected control-plane commit to current IAM.
// The common shared continuity lock remains held until that commit finishes;
// authorization mutations use the exclusive side of this same lock.
func (s *SQLStore) AuthorizeManagementTx(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, query PermissionQuery) error {
	if s == nil || tx == nil || actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) || query.Scope.TenantID != actor.TenantID {
		return ErrPermissionDenied
	}
	management := false
	for _, action := range BuiltinPermissionActions() {
		if action.Code == query.Action {
			management = action.Management
			break
		}
	}
	if !management {
		return ErrPermissionDenied
	}
	if err := s.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return err
	}
	if err := validatePermissionScope(ctx, tx, query.Scope); err != nil {
		return err
	}
	snapshot, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return err
	}
	if snapshot.Mode != "v2" {
		return ErrPermissionDenied
	}
	// The transaction's start time can precede a lock wait and natural expiry.
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&query.Now); err != nil {
		return err
	}
	decision, err := EvaluatePermission(snapshot, query)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return ErrPermissionDenied
	}
	return nil
}
