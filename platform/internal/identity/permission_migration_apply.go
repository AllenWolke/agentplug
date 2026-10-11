package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// CommitMigrationMapping is a trusted migration-tool port, not a browser API.
// Administrator appointments are deliberately excluded; they use their existing
// verified authentication/continuity workflow before this port is invoked.
func (s *SQLStore) CommitMigrationMapping(ctx context.Context, actor sharedkernel.Scope, batchID string, mapping MigrationMapping) (AuthorizationChangeReceipt, error) {
	// A Serializable snapshot can precede the continuity lock wait. A concurrent
	// identical commit may therefore surface a unique conflict before SSI detects
	// serialization. Retry the entire rolled-back transaction; every attempt still
	// checks current authority, the exact idempotency digest and source CAS.
	for attempt := 0; ; attempt++ {
		receipt, err := s.commitMigrationMappingAttempt(ctx, actor, batchID, mapping)
		state := sqlutil.SQLState(err)
		if err == nil || attempt >= 7 || (state != "40001" && state != "40P01" && !errors.Is(err, ErrIdentityConflict)) {
			return receipt, err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return AuthorizationChangeReceipt{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *SQLStore) commitMigrationMappingAttempt(ctx context.Context, actor sharedkernel.Scope, batchID string, mapping MigrationMapping) (AuthorizationChangeReceipt, error) {
	if s == nil || s.db == nil || s.authorizationChangeRecorder == nil {
		return AuthorizationChangeReceipt{}, ErrPermissionRecorderUnavailable
	}
	if actor.Validate() != nil || actor.PrincipalType != "user" || batchID == "" || len(batchID) > 128 || strings.TrimSpace(batchID) != batchID || strings.ContainsAny(batchID, "\x00\r\n") || !validPermissionDigest(mapping.ExpectedSourceDigest) {
		return AuthorizationChangeReceipt{}, ErrInvalidResource
	}
	raw, err := json.Marshal(mapping)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	requestDigest := permissionHash(raw)
	principal := mapping.Target.Principal
	key := permissionHash([]byte("migration\x00" + actor.PrincipalID + "\x00" + batchID + "\x00" + string(principal.Type) + "\x00" + principal.ID))
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := authorizeMigrationWriter(ctx, tx, actor, s.clock().UTC()); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	var savedDigest string
	var saved []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,receipt FROM platform_identity_authorization_change WHERE idempotency_hash=?`), key).Scan(&savedDigest, &saved)
	if err == nil {
		if savedDigest != requestDigest {
			return AuthorizationChangeReceipt{}, ErrIdentityConflict
		}
		var receipt AuthorizationChangeReceipt
		if err := json.Unmarshal(saved, &receipt); err != nil {
			return receipt, err
		}
		if receipt.ActorID != actor.PrincipalID || receipt.SubjectID != principal.ID || receipt.Change.SubjectType != principal.Type {
			return receipt, ErrInvalidResource
		}
		if err := tx.Commit(); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AuthorizationChangeReceipt{}, err
	}
	source := MigrationSource{}
	source.Snapshot, err = loadPermissionSnapshot(ctx, tx, principal.Type, principal.ID)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if source.Snapshot.Principal.TenantID != actor.TenantID {
		return AuthorizationChangeReceipt{}, ErrPermissionDenied
	}
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,epoch FROM platform_identity_policy_migration WHERE principal_type=? AND subject_id=?`), principal.Type, principal.ID).Scan(&source.PolicyRevision, &source.PermissionEpoch)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return AuthorizationChangeReceipt{}, err
	}
	source.AuthenticationDigest, err = migrationAuthenticationDigest(ctx, tx, MigrationSubject{Type: principal.Type, ID: principal.ID}, principal.TenantID)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	source.SourceDigest, err = migrationSourceDigest(source)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if source.SourceDigest != mapping.ExpectedSourceDigest {
		return AuthorizationChangeReceipt{}, ErrPermissionPlanStale
	}
	preview, err := PreviewMigrationMapping(source, mapping, nil, s.clock().UTC())
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if len(preview.Issues) != 0 {
		return AuthorizationChangeReceipt{}, ErrPermissionDenied
	}
	if err := validateMigrationFactTransitions(source.Snapshot, preview.Target); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := s.validateMigrationTargetResources(ctx, tx, preview.Target); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := persistMigrationFacts(ctx, tx, source.Snapshot, preview.Target, s.clock().UTC()); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET revision=revision+1 WHERE principal_type=? AND id=? AND revision=?`), principal.Type, principal.ID, principal.Revision)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := migrationExactlyOne(result); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch,batch_id,source_digest) VALUES(?,?,'v2',?,?,?,?) ON CONFLICT (principal_type,subject_id) DO UPDATE SET policy_mode='v2',revision=EXCLUDED.revision,epoch=EXCLUDED.epoch,batch_id=EXCLUDED.batch_id,source_digest=EXCLUDED.source_digest`), principal.Type, principal.ID, source.PolicyRevision+1, source.PermissionEpoch+1, batchID, source.SourceDigest)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := invalidateAuthorizationStepUp(ctx, tx, principal.Type, principal.ID); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	receipt := AuthorizationChangeReceipt{ID: "migration-" + key, ActorID: actor.PrincipalID, SubjectID: principal.ID, Revision: principal.Revision + 1, PlanDigest: preview.Digest, Reason: "Reviewed migration: " + mapping.Basis, OccurredAt: s.clock().UTC(), Change: AuthorizationChangeCommand{SubjectType: principal.Type, SubjectID: principal.ID, ExpectedRevision: principal.Revision, IdempotencyKey: "migration:" + batchID, Reason: mapping.Basis, Bindings: preview.Target.Bindings, Grants: preview.Target.Grants}, Memberships: preview.Target.Memberships}
	if err := s.authorizationChangeRecorder(ctx, tx, actor, receipt); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	// Natural expiry and provider publication may change without IAM mutation.
	if err := authorizeMigrationWriter(ctx, tx, actor, s.clock().UTC()); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := s.validateMigrationTargetResources(ctx, tx, preview.Target); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	authenticationDigest, err := migrationAuthenticationDigest(ctx, tx, MigrationSubject{Type: principal.Type, ID: principal.ID}, principal.TenantID)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if authenticationDigest != source.AuthenticationDigest {
		return AuthorizationChangeReceipt{}, ErrPermissionPlanStale
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_authorization_change(id,actor_id,subject_id,idempotency_hash,request_digest,receipt,created_at) VALUES(?,?,?,?,?,?,?)`), receipt.ID, actor.PrincipalID, principal.ID, key, requestDigest, string(encoded), receipt.OccurredAt); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	return receipt, nil
}

func authorizeMigrationWriter(ctx context.Context, reader permissionReader, actor sharedkernel.Scope, now time.Time) error {
	owner, err := loadPermissionSnapshot(ctx, reader, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return err
	}
	if owner.Mode != "v2" || !owner.Principal.IsActive || owner.Principal.TenantID != actor.TenantID {
		return ErrPermissionDenied
	}
	d, err := EvaluatePermission(owner, PermissionQuery{Action: "authorization.change", Scope: ManagementScope{Type: "global"}, Now: now})
	if err != nil {
		return err
	}
	if !d.Allowed {
		return ErrPermissionDenied
	}
	return nil
}

func (s *SQLStore) validateMigrationTargetResources(ctx context.Context, reader permissionReader, target PermissionSnapshot) error {
	for _, m := range target.Memberships {
		if m.Status == "active" {
			if err := validatePermissionScope(ctx, reader, m.Scope); err != nil {
				return err
			}
		}
	}
	for _, b := range target.Bindings {
		if b.Status == "active" {
			if b.Scope.Type == "agent_installation" {
				if err := s.validateMigrationScope(ctx, b.Scope); err != nil {
					return err
				}
			} else if err := validatePermissionScope(ctx, reader, b.Scope); err != nil {
				return err
			}
		}
	}
	for _, g := range target.Grants {
		if g.Status == "active" {
			if err := validatePermissionScope(ctx, reader, ManagementScope{Type: "application", TenantID: g.TenantID, DepartmentID: g.DepartmentID, ApplicationID: g.ApplicationID}); err != nil {
				return err
			}
			if err := s.validateGrantResource(ctx, g); err != nil {
				return err
			}
		}
	}
	return nil
}

// Preserve every old ID, including revoked facts. Identity/owner coordinates
// never move in place; a different scope or role requires a new fact ID.
func validateMigrationFactTransitions(before, after PermissionSnapshot) error {
	members := map[string]Membership{}
	bindings := map[string]RoleBinding{}
	grants := map[string]Grant{}
	for _, v := range after.Memberships {
		if _, ok := members[v.ID]; ok {
			return ErrInvalidResource
		}
		members[v.ID] = v
	}
	for _, v := range after.Bindings {
		if _, ok := bindings[v.ID]; ok {
			return ErrInvalidResource
		}
		bindings[v.ID] = v
	}
	for _, v := range after.Grants {
		if _, ok := grants[v.ID]; ok {
			return ErrInvalidResource
		}
		grants[v.ID] = v
	}
	for _, old := range before.Memberships {
		next, ok := members[old.ID]
		if !ok || !migrationEqual(old.Scope, next.Scope) || !migrationFactRevision(old.Revision, next.Revision, migrationEqual(old, next)) || (old.Status != "active" && !migrationEqual(old, next)) {
			return ErrInvalidResource
		}
		delete(members, old.ID)
	}
	for _, old := range before.Bindings {
		next, ok := bindings[old.ID]
		if !ok || old.RoleCode != next.RoleCode || old.RoleVersion != next.RoleVersion || old.SourceID != next.SourceID || !migrationEqual(old.Scope, next.Scope) || !migrationFactRevision(old.Revision, next.Revision, migrationEqual(old, next)) || (old.Status != "active" && !migrationEqual(old, next)) {
			return ErrInvalidResource
		}
		delete(bindings, old.ID)
	}
	for _, old := range before.Grants {
		next, ok := grants[old.ID]
		if !ok || old.TenantID != next.TenantID || old.DepartmentID != next.DepartmentID || old.ApplicationID != next.ApplicationID || old.AgentInstanceID != next.AgentInstanceID || old.Effect != next.Effect || !(migrationFactRevision(old.Revision, next.Revision, migrationEqual(old, next)) || ((before.Mode == "legacy" || before.Mode == "shadow") && old.Effect == "deny" && migrationDenyPreserved(before.Mode, old, next))) {
			return ErrInvalidResource
		}
		delete(grants, old.ID)
	}
	for _, v := range members {
		if v.Revision != 1 {
			return ErrInvalidResource
		}
	}
	for _, v := range bindings {
		if v.Revision != 1 {
			return ErrInvalidResource
		}
	}
	for _, v := range grants {
		if v.Revision != 1 {
			return ErrInvalidResource
		}
	}
	return nil
}

func migrationFactRevision(old, next uint64, equal bool) bool {
	return (equal && old == next) || (!equal && next == old+1)
}
func migrationExactlyOne(result sql.Result) error {
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrIdentityConflict
	}
	return nil
}

func persistMigrationFacts(ctx context.Context, tx *sql.Tx, before, after PermissionSnapshot, now time.Time) error {
	members := map[string]Membership{}
	bindings := map[string]RoleBinding{}
	grants := map[string]Grant{}
	for _, v := range before.Memberships {
		members[v.ID] = v
	}
	for _, v := range before.Bindings {
		bindings[v.ID] = v
	}
	for _, v := range before.Grants {
		grants[v.ID] = v
	}
	for _, v := range after.Memberships {
		old, exists := members[v.ID]
		if exists && migrationEqual(old, v) {
			continue
		}
		if err := persistMembershipMutation(ctx, tx, v, old.Revision); err != nil {
			return err
		}
	}
	for _, v := range after.Bindings {
		old, exists := bindings[v.ID]
		if exists && migrationEqual(old, v) {
			continue
		}
		if !exists {
			if err := insertRoleBinding(ctx, tx, v); err != nil {
				return err
			}
			continue
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_role_binding SET status=?,revision=?,starts_at=?,expires_at=?,payload=? WHERE id=? AND subject_id=? AND revision=?`), v.Status, v.Revision, v.StartsAt, v.ExpiresAt, string(raw), v.ID, v.SubjectID, old.Revision)
		if err != nil {
			return err
		}
		if err := migrationExactlyOne(result); err != nil {
			return err
		}
	}
	for _, v := range after.Grants {
		old, exists := grants[v.ID]
		if exists && migrationEqual(old, v) {
			continue
		}
		if !exists {
			if err := insertPermissionGrant(ctx, tx, v, now); err != nil {
				return err
			}
			continue
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET action=?,status=?,revision=?,grant_key_hash=?,permission_json=? WHERE id=? AND subject_type=? AND subject_id=? AND revision=?`), v.Action, v.Status, v.Revision, grantKeyHash(v), string(raw), v.ID, v.SubjectType, v.SubjectID, old.Revision)
		if err != nil {
			return err
		}
		if err := migrationExactlyOne(result); err != nil {
			return err
		}
	}
	return nil
}
