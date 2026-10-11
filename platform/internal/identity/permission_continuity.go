package identity

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"time"
)

var ErrLastAdministrator = errors.New("last authenticated permanent super administrator cannot be disabled")

// AcquirePermissionReadContinuity joins a caller-owned transaction on the
// modular monolith database. IAM mutations acquire this row exclusively before
// modifying authorization facts; a protected business commit holds it shared.
func (s *SQLStore) AcquirePermissionReadContinuity(ctx context.Context, tx *sql.Tx) error {
	if s == nil || s.db == nil || tx == nil {
		return ErrInvalidResource
	}
	var revision uint64
	return tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_continuity_guard WHERE id=1 FOR SHARE`)).Scan(&revision)
}

// Callers hold the common continuity mutex before locking principals or
// authentication bindings. A count outside that transaction is insufficient.
func protectPermissionAdministrator(ctx context.Context, tx *sql.Tx, subject, excludePrincipal, excludeOIDCKey string, now time.Time) error {
	var affected int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_role_binding WHERE subject_id=? AND role_code='super_admin' AND status='active' AND (starts_at IS NULL OR starts_at<=?) AND (expires_at IS NULL OR expires_at>?)`), subject, now, now).Scan(&affected); err != nil {
		return err
	}
	if affected == 0 {
		return nil
	}
	return ensurePermanentAdministrator(ctx, tx, excludePrincipal, excludeOIDCKey, now)
}

func ensurePermanentAdministrator(ctx context.Context, tx *sql.Tx, excludePrincipal, excludeOIDCKey string, now time.Time) error {
	var available int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(DISTINCT p.id) FROM platform_identity_principal p
		JOIN platform_identity_role_binding b ON b.subject_id=p.id
		JOIN platform_identity_policy_migration m ON m.subject_id=p.id AND m.principal_type=p.principal_type
		WHERE p.principal_type='user' AND p.active=TRUE AND p.id<>? AND m.policy_mode='v2'
		AND b.role_code='super_admin' AND b.status='active' AND b.expires_at IS NULL AND (b.starts_at IS NULL OR b.starts_at<=?)
		AND (b.payload->'scope'->>'scope_type')='global'
		AND (EXISTS (SELECT 1 FROM platform_identity_local_credential c WHERE c.principal_id=p.id AND c.tenant_id=p.tenant_id AND c.active=TRUE)
		OR EXISTS (SELECT 1 FROM platform_identity_oidc_binding o WHERE o.principal_id=p.id AND o.tenant_id=p.tenant_id AND o.status='active' AND o.identity_key<>?))`), excludePrincipal, now, excludeOIDCKey).Scan(&available); err != nil {
		return err
	}
	if available == 0 {
		return ErrLastAdministrator
	}
	return nil
}
