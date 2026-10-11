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
	if s == nil || s.db == nil || tx == nil || scope.Validate() != nil || scope.AgentInstanceID == "" || scope.PrincipalID == "" || action == "" {
		return 0, ErrInvalidResource
	}
	encoded, err := json.Marshal([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentInstanceID, scope.InstallationID, scope.AgentID, scope.AgentVersionID, scope.PrincipalType, scope.PrincipalID, action})
	if err != nil {
		return 0, err
	}
	scopeHash := sha256.Sum256(encoded)
	key := hex.EncodeToString(scopeHash[:])
	var principal Principal
	principal.ID, principal.Type, principal.TenantID = scope.PrincipalID, PrincipalType(scope.PrincipalType), scope.TenantID
	var roles, groups string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT roles_json,groups_json,active,revision FROM platform_identity_principal WHERE principal_type=? AND id=? AND tenant_id=? FOR SHARE`), scope.PrincipalType, scope.PrincipalID, scope.TenantID).Scan(&roles, &groups, &principal.IsActive, &principal.Revision); err != nil {
		return 0, err
	}
	if json.Unmarshal([]byte(roles), &principal.Roles) != nil || json.Unmarshal([]byte(groups), &principal.Groups) != nil {
		return 0, errors.New("identity principal data is invalid")
	}
	var tenantRev, departmentRev, applicationRev uint64
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT t.revision,d.revision,a.revision FROM platform_identity_tenant t JOIN platform_identity_department d ON d.tenant_id=t.id JOIN platform_identity_application a ON a.tenant_id=t.id AND a.department_id=d.id WHERE t.id=? AND d.id=? AND a.id=? AND t.status='active' AND d.status='active' AND a.status='active' FOR SHARE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID).Scan(&tenantRev, &departmentRev, &applicationRev); err != nil {
		return 0, err
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision FROM platform_identity_grant WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_instance_id=? AND subject_type=? AND subject_id=? AND action=? ORDER BY id FOR SHARE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentInstanceID, scope.PrincipalType, scope.PrincipalID, action)
	if err != nil {
		return 0, err
	}
	grants := []Grant{}
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.ID, &g.TenantID, &g.DepartmentID, &g.ApplicationID, &g.AgentInstanceID, &g.SubjectType, &g.SubjectID, &g.Action, &g.Effect, &g.Status, &g.Revision); err != nil {
			rows.Close()
			return 0, err
		}
		grants = append(grants, g)
	}
	rowErr := rows.Err()
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if rowErr != nil {
		return 0, rowErr
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
	fingerprint, err := authorizationFingerprint(principal, grants, []uint64{tenantRev, departmentRev, applicationRev})
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
		decision, err := EvaluatePermission(snapshot, PermissionQuery{
			Action: action, Scope: ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: scope.AgentInstanceID},
			ResourceType: "agent_installation", ResourceID: scope.AgentInstanceID, Now: now,
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
		return unchangedEpoch, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
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
	return epoch, nil
}
