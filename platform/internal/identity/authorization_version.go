package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// AuthorizationVersionPort returns the current IAM version, never a Catalog
// deployment revision or credential revision masquerading as an IAM epoch.
// AuthorizationVersionPort 返回当前 IAM 版本，禁止使用部署/凭据 revision 冒充授权版本。
type AuthorizationVersionPort interface {
	CurrentAuthorizationEpoch(context.Context, sharedkernel.Scope, string) (uint64, error)
}

func authorizationFingerprint(principal Principal, grants []Grant, hierarchy []uint64) (string, error) {
	ordered := append([]Grant(nil), grants...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	encoded, err := json.Marshal(struct {
		Principal Principal
		Grants    []Grant
		Hierarchy []uint64
	}{principal, ordered, hierarchy})
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:]), nil
}

func (s *SQLStore) CurrentAuthorizationEpoch(ctx context.Context, scope sharedkernel.Scope, action string) (uint64, error) {
	return s.currentAuthorizationEpoch(ctx, scope, action, "")
}

// An explanation pins its IAM snapshot. A changed or naturally expired source
// must not pair an old decision with a newer runtime epoch.
func (s *SQLStore) currentAuthorizationEpoch(ctx context.Context, scope sharedkernel.Scope, action, expectedDigest string) (uint64, error) {
	if s == nil || s.db == nil {
		return 0, ErrInvalidResource
	}
	if tx, joined, err := sqlutil.ContinuityTransaction(ctx, s.db); joined {
		if err != nil {
			return 0, err
		}
		if err := s.AcquirePermissionReadContinuity(ctx, tx); err != nil {
			return 0, err
		}
		return s.authorizationEpochFactsTx(ctx, tx, scope, action, expectedDigest, nil, false)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	epoch, err := s.currentAuthorizationEpochTx(ctx, tx, scope, action, expectedDigest)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return epoch, nil
}

// CurrentAuthorizationEpochTx binds new execution admission to the same source
// locks and authorization version transaction as the caller's Run creation.
func (s *SQLStore) CurrentAuthorizationEpochTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, action string) (uint64, error) {
	return s.currentAuthorizationEpochTx(ctx, tx, scope, action, "")
}

func (s *SQLStore) currentAuthorizationEpochTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, action, expectedDigest string) (uint64, error) {
	if s == nil || s.db == nil {
		return 0, ErrInvalidResource
	}
	if bound, joined, err := sqlutil.ContinuityTransaction(ctx, s.db); joined {
		if err != nil {
			return 0, err
		}
		if tx != bound {
			return 0, ErrInvalidResource
		}
		if err := s.AcquirePermissionReadContinuity(ctx, tx); err != nil {
			return 0, err
		}
		return s.authorizationEpochFactsTx(ctx, tx, scope, action, expectedDigest, nil, false)
	}
	return s.currentAuthorizationEpochFactsTx(ctx, tx, scope, action, expectedDigest, nil)
}

// WithCurrentAuthorizationSnapshot supplies the facts already used to validate
// the epoch to an immediate resource check. The shared IAM mutation fence stays
// held through that read-only check. No permission snapshot/decision survives
// this call; the callback must never execute a business effect.
func (s *SQLStore) WithCurrentAuthorizationSnapshot(ctx context.Context, scope sharedkernel.Scope, action string, check func(uint64, PermissionSnapshot) error) error {
	if check == nil {
		return ErrInvalidResource
	}
	return s.WithCurrentAuthorizationSnapshotContext(ctx, scope, action,
		func(_ context.Context, epoch uint64, snapshot PermissionSnapshot) error {
			return check(epoch, snapshot)
		})
}

// WithCurrentAuthorizationSnapshotContext supplies the current snapshot while
// holding the IAM mutation fence through an immediate read-only resource check.
// The callback context is bound to the same transaction, so related identity
// reads join this fence instead of opening nested transactions behind a queued
// IAM writer. The callback must never execute a business effect.
func (s *SQLStore) WithCurrentAuthorizationSnapshotContext(ctx context.Context, scope sharedkernel.Scope, action string,
	check func(context.Context, uint64, PermissionSnapshot) error) error {
	if s == nil || s.db == nil || ctx == nil || check == nil {
		return ErrInvalidResource
	}
	if tx, joined, err := sqlutil.ContinuityTransaction(ctx, s.db); joined {
		if err != nil {
			return err
		}
		if err := s.AcquirePermissionReadContinuity(ctx, tx); err != nil {
			return err
		}
		var snapshot PermissionSnapshot
		epoch, err := s.authorizationEpochFactsTx(ctx, tx, scope, action, "", &snapshot, false)
		if err != nil {
			return err
		}
		return check(sqlutil.WithContinuityTransaction(ctx, s.db, tx), epoch, snapshot)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return err
	}
	var snapshot PermissionSnapshot
	epoch, err := s.currentAuthorizationEpochFactsTx(ctx, tx, scope, action, "", &snapshot)
	if err != nil {
		return err
	}
	bound := sqlutil.WithContinuityTransaction(ctx, s.db, tx)
	checkErr := check(bound, epoch, snapshot)
	// The ordinary epoch API commits its monotonic observation even if the
	// subsequent resource check denies access. Preserve that boundary: rolling
	// it back could let a later reverted policy resurrect an older Run epoch.
	if err := tx.Commit(); err != nil {
		return errors.Join(checkErr, err)
	}
	return checkErr
}

func (s *SQLStore) currentAuthorizationEpochFactsTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, action, expectedDigest string, capture *PermissionSnapshot) (uint64, error) {
	return s.authorizationEpochFactsTx(ctx, tx, scope, action, expectedDigest, capture, true)
}

// A protected transaction revalidates a previously committed version. It never
// creates or advances an epoch. Changed/missing versions fail closed and must
// be observed by the ordinary standalone API, which commits independently of
// resource denial or a subsequent business rollback.
func (s *SQLStore) authorizationEpochFactsTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, action, expectedDigest string, capture *PermissionSnapshot, advance bool) (uint64, error) {
	if s == nil || s.db == nil || tx == nil || scope.Validate() != nil || scope.AgentInstanceID == "" || scope.PrincipalID == "" || action == "" {
		return 0, ErrInvalidResource
	}
	ctx = s.withPermissionDecode(ctx)
	encoded, err := json.Marshal([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentInstanceID, scope.InstallationID, scope.AgentID, scope.AgentVersionID, scope.PrincipalType, scope.PrincipalID, action})
	if err != nil {
		return 0, err
	}
	scopeHash := sha256.Sum256(encoded)
	key := hex.EncodeToString(scopeHash[:])
	// A persisted observation is not a current authorization snapshot. IAM
	// writers can change facts before another observer advances that epoch;
	// validity can also expire while the continuity read lock is held. Always
	// reload source facts and recompute their effective temporal fingerprint.
	// Only pure parsing of freshly read authoritative bytes is reused.
	principal, grants, hierarchy, err := readAuthorizationBasisTx(ctx, tx, scope, action)
	if err != nil {
		return 0, err
	}
	snapshot, err := loadPermissionSnapshot(ctx, tx, principal.Type, principal.ID)
	if err != nil {
		return 0, err
	}
	managedLegacyCancel := false
	if snapshot.Mode != "v2" {
		managed := departmentAgentPolicyFor(snapshot, ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: scope.AgentInstanceID}) != nil
		if managed && action != "cancel" {
			return 0, ErrPermissionDenied
		}
		if expectedDigest != "" {
			return 0, ErrPermissionExplanationStale
		}
		var decision AccessDecision
		if managed {
			decision, err = evaluateManagedLegacyCancellation(snapshot, scope, s.clock().UTC())
			managedLegacyCancel = true
		} else {
			decision, err = EvaluateAccess(AccessContext{Scope: scope, Principal: principal, Action: action}, grants)
		}
		if err != nil || !decision.Allowed {
			return 0, errors.New("current IAM access denied")
		}
	}
	fingerprint, err := authorizationFingerprint(principal, grants, hierarchy)
	if err != nil {
		return 0, err
	}
	if managedLegacyCancel {
		digest, err := EffectivePermissionSnapshotDigest(snapshot, s.clock().UTC())
		if err != nil {
			return 0, err
		}
		fingerprint = permissionHash([]byte(fingerprint + ":managed-legacy-cancel:" + digest))
	}
	if snapshot.Mode == "v2" {
		now := s.clock().UTC()
		if err := lockExecutionAgentPackages(ctx, tx, snapshot, scope); err != nil {
			return 0, err
		}
		decision, err := EvaluatePermission(snapshot, PermissionQuery{
			Action: action, Scope: ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: scope.AgentInstanceID},
			ResourceType: "agent_installation", ResourceID: scope.AgentInstanceID, Now: now, PublishedAgentVersionID: scope.AgentVersionID, RequirePublishedVersion: true,
		})
		if err != nil || !decision.Allowed {
			return 0, errors.New("current v2 IAM access denied")
		}
		digest, err := EffectivePermissionSnapshotDigest(snapshot, now)
		if err != nil {
			return 0, err
		}
		if expectedDigest != "" && digest != expectedDigest {
			return 0, ErrPermissionExplanationStale
		}
		fingerprint = permissionHash([]byte(fingerprint + ":" + digest))
	}
	// Source rows remain share-locked until the version is committed. Changes
	// to grants or identity cannot race a version snapshot in this transaction.
	// 源记录共享锁保持到版本提交，授权/身份更新不能与本事务的快照竞态。
	// An unchanged version is a read fence, not a write. Heartbeats and
	// coordinated child admission must be able to share this fence without
	// waiting for one another's transaction to finish. Only take an exclusive
	// version lock when its fingerprint actually needs to be created/changed.
	var unchangedEpoch uint64
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT epoch FROM platform_identity_authorization_version WHERE scope_key=? AND fingerprint=? FOR SHARE`), key, fingerprint).Scan(&unchangedEpoch)
	if err == nil {
		if capture != nil {
			*capture = snapshot
		}
		return unchangedEpoch, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if !advance {
		return 0, ErrPermissionExplanationStale
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_authorization_version(scope_key,fingerprint,epoch) VALUES (?,?,1) ON CONFLICT (scope_key) DO UPDATE SET scope_key=EXCLUDED.scope_key`), key, fingerprint); err != nil {
		return 0, err
	}
	var saved string
	var epoch uint64
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT fingerprint,epoch FROM platform_identity_authorization_version WHERE scope_key=? FOR UPDATE`), key).Scan(&saved, &epoch); err != nil {
		return 0, err
	}
	if saved != fingerprint {
		// JSON/JavaScript consumers must compare the integer without rounding.
		// 限制在 JSON/JavaScript 精确整数范围，避免跨语言授权版本失真。
		if epoch >= (1<<53)-1 {
			return 0, errors.New("IAM authorization epoch exhausted")
		}
		epoch++
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_authorization_version SET fingerprint=?,epoch=? WHERE scope_key=?`), fingerprint, epoch, key); err != nil {
			return 0, err
		}
	}
	if capture != nil {
		*capture = snapshot
	}
	return epoch, nil
}
