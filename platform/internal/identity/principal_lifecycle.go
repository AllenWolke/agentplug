package identity

// Principal lifecycle changes are atomic with credential invalidation and the
// durable audit/outbox record. They remain behind ports so a later service
// split can replace SQLStore without changing the HTTP contract.
// Principal 生命周期变更与凭据失效、审计/Outbox 记录保持原子，并通过端口隔离持久化实现。

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

var (
	ErrPrincipalLifecycleRecorderUnavailable = errors.New("principal lifecycle recorder is required")
	ErrPrincipalLifecycleSelfDisable         = errors.New("principal cannot disable its own identity")
)

type PrincipalLifecycleDecision struct {
	PrincipalType PrincipalType
	PrincipalID   string
	Status        string
	Revision      uint64
	OccurredAt    time.Time
}

// PrincipalLifecycleRecorder persists audit/integration facts with the same
// database transaction that disables the identity and credentials.
// PrincipalLifecycleRecorder 在同一事务中写入审计/集成事实。
type PrincipalLifecycleRecorder func(context.Context, *sql.Tx, sharedkernel.Scope, PrincipalLifecycleDecision) error

func (s *SQLStore) SetPrincipalLifecycleRecorder(recorder PrincipalLifecycleRecorder) {
	if s != nil {
		s.principalLifecycleRecorder = recorder
	}
}

// DisablePrincipal atomically disables the Principal, revokes local or machine
// credentials, increments their revisions, and records the decision. Existing
// grants are retained for audit/history but cannot authorize an inactive
// Principal because access evaluation validates Principal.IsActive.
// DisablePrincipal 原子停用主体并撤销其凭据；Grant 留存作审计，但停用主体不能通过授权校验。
func (s *SQLStore) DisablePrincipal(ctx context.Context, actorScope sharedkernel.Scope, principalID string, expectedRevision uint64) (Principal, error) {
	if s == nil || s.db == nil {
		return Principal{}, errors.New("identity database is required")
	}
	if err := actorScope.Validate(); err != nil || actorScope.PrincipalType != string(PrincipalUser) || strings.TrimSpace(principalID) == "" || expectedRevision == 0 {
		return Principal{}, ErrInvalidPrincipal
	}
	if actorScope.PrincipalID == principalID {
		return Principal{}, ErrPrincipalLifecycleSelfDisable
	}
	if s.principalLifecycleRecorder == nil {
		return Principal{}, ErrPrincipalLifecycleRecorderUnavailable
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Principal{}, fmt.Errorf("begin principal lifecycle transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return Principal{}, err
	}
	if err := protectPermissionAdministrator(ctx, tx, principalID, principalID, "", s.clock().UTC()); err != nil {
		return Principal{}, err
	}

	var principal Principal
	var rolesJSON, groupsJSON string
	var active bool
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,principal_type,tenant_id,roles_json,groups_json,active,revision
		FROM platform_identity_principal WHERE principal_type=? AND id=? AND tenant_id=? FOR UPDATE`), PrincipalUser, principalID, actorScope.TenantID).
		Scan(&principal.ID, &principal.Type, &principal.TenantID, &rolesJSON, &groupsJSON, &active, &principal.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrPrincipalNotFound
	}
	if err != nil {
		return Principal{}, fmt.Errorf("load principal for lifecycle change: %w", err)
	}
	if !active || principal.Revision != expectedRevision {
		return Principal{}, ErrIdentityConflict
	}
	principal.Roles = unmarshalStrings(rolesJSON)
	principal.Groups = unmarshalStrings(groupsJSON)

	now := s.clock().UTC()
	// Browser authentication verifies the actor before this method is called.
	// Re-read v2 authority under the common IAM continuity lock so a revoked
	// company role cannot disable a target using an earlier HTTP decision.
	// Internal legacy service calls retain their existing trusted contract.
	owner, ownerErr := loadPermissionSnapshot(ctx, tx, PrincipalUser, actorScope.PrincipalID)
	if ownerErr != nil && !errors.Is(ownerErr, ErrPrincipalNotFound) {
		return Principal{}, ownerErr
	}
	if ownerErr == nil && owner.Mode == "v2" {
		if owner.Principal.TenantID != actorScope.TenantID {
			return Principal{}, ErrPermissionDenied
		}
		scope := ManagementScope{Type: "tenant", TenantID: principal.TenantID}
		decision, err := EvaluatePermission(owner, PermissionQuery{Action: "principal.disable", Scope: scope, Now: now})
		if err != nil || !decision.Allowed {
			return Principal{}, ErrPermissionDenied
		}
		if requireSuperAdministrator(owner, "principal.disable", now) != nil {
			target, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, principal.ID)
			if err != nil {
				return Principal{}, err
			}
			if target.Mode != "v2" && containsIdentityRole(target.Principal.Roles, "system_admin", "admin", "platform_admin") {
				return Principal{}, ErrPermissionDenied
			}
			for _, binding := range target.Bindings {
				if binding.Status == "active" && binding.Effective(now) && protectedAdministratorBinding(binding) {
					return Principal{}, ErrPermissionDenied
				}
			}
		}
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal
		SET active=FALSE,revision=revision+1 WHERE principal_type=? AND id=? AND tenant_id=? AND active=TRUE AND revision=?`), principal.Type, principal.ID, principal.TenantID, expectedRevision)
	if err != nil {
		return Principal{}, fmt.Errorf("disable identity principal: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Principal{}, fmt.Errorf("read principal lifecycle update: %w", err)
	}
	if rows != 1 {
		return Principal{}, ErrIdentityConflict
	}

	// Increment the credential revision as well as disabling the row so any
	// already-issued browser session or machine token becomes immediately stale.
	if principal.Type == PrincipalUser {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_local_credential
			SET active=FALSE,auth_revision=auth_revision+1,updated_at=? WHERE principal_id=? AND tenant_id=? AND active=TRUE`), now, principal.ID, principal.TenantID); err != nil {
			return Principal{}, fmt.Errorf("revoke principal local credentials: %w", err)
		}
	} else if principal.Type == PrincipalServicePrincipal {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_machine_credential
			SET status='disabled',revision=revision+1,updated_at=? WHERE principal_id=? AND tenant_id=? AND status='active'`), now, principal.ID, principal.TenantID); err != nil {
			return Principal{}, fmt.Errorf("revoke principal machine credentials: %w", err)
		}
	}

	principal.IsActive = false
	if err := revokePrincipalRefreshSessions(ctx, tx, principal.ID, principal.TenantID); err != nil {
		return Principal{}, fmt.Errorf("revoke refresh sessions: %w", err)
	}
	if err := invalidateAuthorizationStepUp(ctx, tx, principal.Type, principal.ID); err != nil {
		return Principal{}, fmt.Errorf("invalidate principal step-up: %w", err)
	}
	principal.Revision++
	decision := PrincipalLifecycleDecision{PrincipalType: principal.Type, PrincipalID: principal.ID, Status: "disabled", Revision: principal.Revision, OccurredAt: now}
	if err := s.principalLifecycleRecorder(ctx, tx, actorScope, decision); err != nil {
		return Principal{}, fmt.Errorf("record principal lifecycle decision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Principal{}, fmt.Errorf("commit principal lifecycle transaction: %w", err)
	}
	return principal, nil
}

var _ PrincipalLifecycleStore = (*SQLStore)(nil)
