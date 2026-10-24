package identity

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// ValidateBrowserSession checks current authentication facts. SessionID is a
// correlation identifier inside a signed gateway assertion, never a bearer
// credential. Business permissions remain the responsibility of each module.
func (s *SQLStore) ValidateBrowserSession(ctx context.Context, scope sharedkernel.Scope, sessionID string, revision uint64) error {
	if scope.Validate() != nil || scope.PrincipalType != string(PrincipalUser) {
		return ErrRefreshSessionRejected
	}
	if sessionID == "" && revision == 0 {
		// Transitional demo authentication is allowed only for explicitly
		// unmigrated subjects, never as a fallback for a migrated credential.
		var count int
		err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_principal p
			JOIN platform_identity_tenant t ON t.id=p.tenant_id AND t.status='active'
			JOIN platform_identity_department d ON d.tenant_id=p.tenant_id AND d.id=? AND d.status='active'
			JOIN platform_identity_application a ON a.tenant_id=p.tenant_id AND a.department_id=d.id AND a.id=? AND a.status='active'
			LEFT JOIN platform_identity_policy_migration m ON m.principal_type=p.principal_type AND m.subject_id=p.id
			WHERE p.principal_type='user' AND p.id=? AND p.tenant_id=? AND p.active=TRUE
			AND COALESCE(m.policy_mode,'legacy') IN ('legacy','shadow')
			AND NOT EXISTS (SELECT 1 FROM platform_identity_local_credential c WHERE c.principal_id=p.id AND c.tenant_id=p.tenant_id)
			AND NOT EXISTS (SELECT 1 FROM platform_identity_oidc_binding b WHERE b.principal_id=p.id AND b.tenant_id=p.tenant_id)`), scope.DepartmentID, scope.ApplicationID, scope.PrincipalID, scope.TenantID).Scan(&count)
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrRefreshSessionRejected
		}
		return nil
	}
	raw, err := hex.DecodeString(sessionID)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != sessionID || revision == 0 {
		return ErrRefreshSessionRejected
	}
	if bound, joined, joinError := sqlutil.ContinuityTransaction(ctx, s.db); joined {
		if joinError != nil {
			return joinError
		}
		return s.validateBrowserSessionFacts(ctx, bound, scope, sessionID, revision)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.validateBrowserSessionFacts(ctx, tx, scope, sessionID, revision); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) validateBrowserSessionFacts(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, sessionID string, revision uint64) error {
	var id string
	now := s.clock().UTC()
	var err error
	var originDepartment, originApplication, policyMode string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT f.id,
		CASE WHEN o.family_id IS NULL THEN c.department_id ELSE b.department_id END,
		CASE WHEN o.family_id IS NULL THEN c.application_id ELSE b.application_id END,
		COALESCE(m.policy_mode,'legacy') FROM platform_identity_refresh_family f
		JOIN platform_identity_principal p ON p.principal_type='user' AND p.id=f.principal_id AND p.tenant_id=f.tenant_id AND p.active=TRUE
		JOIN platform_identity_tenant t ON t.id=f.tenant_id AND t.status='active'
		JOIN platform_identity_department d ON d.id=f.department_id AND d.tenant_id=f.tenant_id AND d.status='active'
		JOIN platform_identity_application a ON a.id=f.application_id AND a.tenant_id=f.tenant_id AND a.department_id=f.department_id AND a.status='active'
		LEFT JOIN platform_identity_policy_migration m ON m.principal_type='user' AND m.subject_id=f.principal_id
		LEFT JOIN platform_identity_refresh_oidc_binding o ON o.family_id=f.id
		LEFT JOIN platform_identity_oidc_binding b ON b.identity_key=o.binding_key
		LEFT JOIN platform_identity_local_credential c ON c.principal_id=f.principal_id AND c.tenant_id=f.tenant_id
		WHERE f.id=? AND f.principal_id=? AND f.tenant_id=? AND f.department_id=? AND f.application_id=?
		AND f.auth_revision=? AND f.revoked=FALSE AND f.expires_at>?
		AND EXISTS (SELECT 1 FROM platform_identity_refresh_token rt WHERE rt.family_id=f.id AND rt.used=FALSE)
		AND ((o.family_id IS NULL AND c.active=TRUE AND c.auth_revision=f.auth_revision)
		 OR (o.family_id IS NOT NULL AND b.status='active' AND b.revision=o.binding_revision AND b.revision=f.auth_revision AND b.principal_id=f.principal_id AND b.tenant_id=f.tenant_id))
		AND EXISTS (SELECT 1 FROM platform_identity_department od JOIN platform_identity_application oa ON oa.department_id=od.id AND oa.tenant_id=od.tenant_id AND oa.status='active'
		 WHERE od.status='active' AND od.tenant_id=f.tenant_id AND od.id=CASE WHEN o.family_id IS NULL THEN c.department_id ELSE b.department_id END AND oa.id=CASE WHEN o.family_id IS NULL THEN c.application_id ELSE b.application_id END)
		AND COALESCE(m.policy_mode,'legacy') IN ('legacy','shadow','v2')`), sessionID, scope.PrincipalID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, revision, now).Scan(&id, &originDepartment, &originApplication, &policyMode)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRefreshSessionRejected
	}
	if err != nil {
		return err
	}
	if policyMode == "v2" {
		target := EnrollmentScope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}
		if scope.DepartmentID == originDepartment && scope.ApplicationID == originApplication {
			// The credential origin remains an authentication context, even when
			// a qualified administrator has no delegation to handle cases there.
			err = validateWorkspace(ctx, tx, scope.PrincipalID, target, now)
		} else {
			err = validateWorkspaceSelection(ctx, tx, scope.PrincipalID, target, now)
		}
		if errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrScopeMismatch) {
			return ErrRefreshSessionRejected
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLStore) ValidateBrowserSessionTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, sessionID string, revision uint64) error {
	if s == nil || tx == nil || scope.Validate() != nil || scope.PrincipalType != string(PrincipalUser) || sessionID == "" || revision == 0 {
		return ErrRefreshSessionRejected
	}
	var id string
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id FROM platform_identity_refresh_family WHERE id=? AND principal_id=? AND tenant_id=? AND department_id=? AND application_id=? AND auth_revision=? AND revoked=FALSE AND expires_at>? FOR SHARE`), sessionID, scope.PrincipalID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, revision, s.clock().UTC()).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRefreshSessionRejected
	}
	if err != nil {
		return err
	}
	return s.ValidateBrowserSession(sqlutil.WithContinuityTransaction(ctx, s.db, tx), scope, sessionID, revision)
}
