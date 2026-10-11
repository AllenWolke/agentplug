package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func (s *SQLStore) EnsurePermissionBatchSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrInvalidResource
	}
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_identity_permission_batch (
		id VARCHAR(128) PRIMARY KEY, actor_id VARCHAR(128) NOT NULL,
		actor_tenant_id VARCHAR(128) NOT NULL, tenant_id VARCHAR(128) NOT NULL,
		request_digest VARCHAR(64) NOT NULL, payload JSONB NOT NULL,
		created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL)`)
	return err
}

func permissionBatchID(actor sharedkernel.Scope, key string) string {
	return "permission-batch-" + permissionHash([]byte(actor.PrincipalID+"\x00"+key))
}

func readPermissionBatch(ctx context.Context, reader permissionReader, id string, locked bool) (PermissionBatch, error) {
	var row *sql.Row
	if locked {
		row = reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT actor_id,actor_tenant_id,request_digest,payload FROM platform_identity_permission_batch WHERE id=? FOR UPDATE`), id)
	} else {
		row = reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT actor_id,actor_tenant_id,request_digest,payload FROM platform_identity_permission_batch WHERE id=?`), id)
	}
	var actor, tenant, digest string
	var raw []byte
	if err := row.Scan(&actor, &tenant, &digest, &raw); err != nil {
		return PermissionBatch{}, err
	}
	var batch PermissionBatch
	if err := json.Unmarshal(raw, &batch); err != nil {
		return PermissionBatch{}, err
	}
	if batch.ID != id || batch.ActorID != actor || batch.ActorTenantID != tenant || batch.RequestDigest != digest || len(batch.Items) == 0 || len(batch.Items) > permissionBatchLimit || len(batch.Items) != len(batch.Command.Items) || !validPermissionDigest(digest) {
		return PermissionBatch{}, ErrInvalidResource
	}
	for index, item := range batch.Items {
		if item.Index != index || !slices.Contains([]string{"pending", "blocked", "succeeded", "failed", "cancelled"}, item.Status) || item.Status == "succeeded" && item.Authorization == nil && item.Decision == nil {
			return PermissionBatch{}, ErrInvalidResource
		}
		if batch.Command.Kind == "authorization" && (item.Command.Authorization == nil || item.Command.Decision != nil || item.SubjectID != item.Command.Authorization.SubjectID) || batch.Command.Kind == "decision" && (item.Command.Decision == nil || item.Command.Authorization != nil) {
			return PermissionBatch{}, ErrInvalidResource
		}
		if item.Status == "succeeded" && (batch.Command.Kind == "authorization" && (item.Authorization == nil || item.Decision != nil || item.Authorization.SubjectID != item.SubjectID) || batch.Command.Kind == "decision" && (item.Decision == nil || item.Authorization != nil || item.Decision.Request.ID != item.Command.Decision.RequestID || item.Decision.Request.SubjectID != item.SubjectID)) {
			return PermissionBatch{}, ErrInvalidResource
		}
	}
	prepared := batch.Command
	prepared.Items = make([]PermissionBatchItemCommand, len(batch.Items))
	for index, item := range batch.Items {
		prepared.Items[index] = item.Command
	}
	storedActor := sharedkernel.Scope{TenantID: batch.ActorTenantID, DepartmentID: "stored-batch", ApplicationID: "stored-batch", PrincipalID: batch.ActorID, PrincipalType: "user"}
	_, semantic, err := normalizedPermissionBatchCommand(storedActor, prepared)
	_, originalSemantic, originalErr := normalizedPermissionBatchCommand(storedActor, batch.Command)
	if err != nil || originalErr != nil || semantic != digest || originalSemantic != digest || batch.ID != permissionBatchID(storedActor, batch.Command.IdempotencyKey) {
		return PermissionBatch{}, ErrInvalidResource
	}
	return batch, nil
}

func (s *SQLStore) authorizeStoredPermissionBatch(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, batch PermissionBatch) error {
	if batch.ActorID != actor.PrincipalID || batch.ActorTenantID != actor.TenantID {
		return ErrPermissionDenied
	}
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return err
	}
	if err := authorizePermissionBatch(owner, actor, batch.Command, s.clock().UTC()); err != nil {
		return err
	}
	return validatePermissionScope(ctx, tx, batch.Command.Scope)
}

func (s *SQLStore) CreatePermissionBatch(ctx context.Context, actor sharedkernel.Scope, command PermissionBatchCommand) (PermissionBatch, error) {
	if s == nil || s.db == nil || s.administrativeRecorder == nil || s.authorizationChangeRecorder == nil {
		return PermissionBatch{}, ErrPermissionRecorderUnavailable
	}
	normalized, digest, err := normalizedPermissionBatchCommand(actor, command)
	if err != nil {
		return PermissionBatch{}, err
	}
	id := permissionBatchID(actor, normalized.IdempotencyKey)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return PermissionBatch{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return PermissionBatch{}, err
	}
	prior, err := readPermissionBatch(ctx, tx, id, true)
	if err == nil {
		if prior.RequestDigest != digest {
			return PermissionBatch{}, ErrIdentityConflict
		}
		return prior, s.authorizeStoredPermissionBatch(ctx, tx, actor, prior)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return PermissionBatch{}, err
	}
	plan, err := s.planPermissionBatch(ctx, tx, actor, normalized, command.PlanExpiresAt)
	if err != nil {
		return PermissionBatch{}, err
	}
	if command.PlanDigest == "" || command.PlanDigest != plan.Digest {
		return PermissionBatch{}, ErrPermissionPlanStale
	}
	if !slices.ContainsFunc(plan.Items, func(item PermissionBatchItem) bool { return item.Status == "pending" }) {
		return PermissionBatch{}, ErrPermissionDenied
	}
	now := s.clock().UTC()
	batch := PermissionBatch{ID: id, ActorID: actor.PrincipalID, ActorTenantID: actor.TenantID, RequestDigest: digest, Command: plan.Change, Items: plan.Items, CreatedAt: now, UpdatedAt: now}
	if !plan.ExpiresAt.After(now) {
		return PermissionBatch{}, ErrPermissionPlanStale
	}
	if err := s.authorizeStoredPermissionBatch(ctx, tx, actor, batch); err != nil {
		return PermissionBatch{}, err
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		return PermissionBatch{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_permission_batch(id,actor_id,actor_tenant_id,tenant_id,request_digest,payload,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`), id, actor.PrincipalID, actor.TenantID, command.Scope.TenantID, digest, string(raw), now, now); err != nil {
		return PermissionBatch{}, err
	}
	if err := s.administrativeRecorder(ctx, tx, actor, AdministrativeEvent{ID: "prepared-" + id, ActorID: actor.PrincipalID, SubjectID: id, Action: "identity.permission_batch.prepare", Reason: command.Reason, DetailsDigest: plan.Digest, Revision: 1, OccurredAt: now}); err != nil {
		return PermissionBatch{}, err
	}
	return batch, tx.Commit()
}

// Cancelling a batch only abandons pending items. Successful permissions and
// decisions remain visible and require a separately reviewed change to undo.
func (s *SQLStore) CancelPermissionBatch(ctx context.Context, actor sharedkernel.Scope, originalKey string) (PermissionBatch, error) {
	if s == nil || s.db == nil || s.administrativeRecorder == nil {
		return PermissionBatch{}, ErrPermissionRecorderUnavailable
	}
	if !validPermissionBatchKey(originalKey) || actor.Validate() != nil || actor.PrincipalType != "user" {
		return PermissionBatch{}, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PermissionBatch{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return PermissionBatch{}, err
	}
	batch, err := readPermissionBatch(ctx, tx, permissionBatchID(actor, originalKey), true)
	if err != nil {
		return PermissionBatch{}, err
	}
	if err := s.authorizeStoredPermissionBatch(ctx, tx, actor, batch); err != nil {
		return PermissionBatch{}, err
	}
	changed := false
	for index := range batch.Items {
		if batch.Items[index].Status == "pending" {
			batch.Items[index].Status = "cancelled"
			changed = true
		}
	}
	if !changed {
		return batch, nil
	}
	batch.UpdatedAt = s.clock().UTC()
	raw, err := json.Marshal(batch)
	if err != nil {
		return PermissionBatch{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_permission_batch SET payload=?,updated_at=? WHERE id=?`), string(raw), batch.UpdatedAt, batch.ID); err != nil {
		return PermissionBatch{}, err
	}
	if err := s.administrativeRecorder(ctx, tx, actor, AdministrativeEvent{ID: "cancelled-" + batch.ID, ActorID: actor.PrincipalID, SubjectID: batch.ID, Action: "identity.permission_batch.cancel", Reason: "Abandon pending items; completed authority remains unchanged", DetailsDigest: permissionHash(raw), Revision: 1, OccurredAt: batch.UpdatedAt}); err != nil {
		return PermissionBatch{}, err
	}
	return batch, tx.Commit()
}

func (s *SQLStore) GetPermissionBatch(ctx context.Context, actor sharedkernel.Scope, originalKey string) (PermissionBatch, error) {
	if s == nil || s.db == nil || !validPermissionBatchKey(originalKey) || actor.Validate() != nil || actor.PrincipalType != "user" {
		return PermissionBatch{}, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return PermissionBatch{}, err
	}
	defer tx.Rollback()
	batch, err := readPermissionBatch(ctx, tx, permissionBatchID(actor, originalKey), false)
	if err != nil {
		return PermissionBatch{}, err
	}
	return batch, s.authorizeStoredPermissionBatch(ctx, tx, actor, batch)
}

// Exactly one pending operation is committed per transaction. The result row,
// IAM writes, request decision, audit and outbox share that transaction. A crash
// or an unknown commit outcome is recovered by reading the original batch.
func (s *SQLStore) ContinuePermissionBatch(ctx context.Context, actor sharedkernel.Scope, originalKey string) (PermissionBatch, error) {
	if s == nil || s.db == nil || s.administrativeRecorder == nil || s.authorizationChangeRecorder == nil {
		return PermissionBatch{}, ErrPermissionRecorderUnavailable
	}
	if !validPermissionBatchKey(originalKey) || actor.Validate() != nil || actor.PrincipalType != "user" {
		return PermissionBatch{}, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return PermissionBatch{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return PermissionBatch{}, err
	}
	batch, err := readPermissionBatch(ctx, tx, permissionBatchID(actor, originalKey), true)
	if err != nil {
		return PermissionBatch{}, err
	}
	if err := s.authorizeStoredPermissionBatch(ctx, tx, actor, batch); err != nil {
		return PermissionBatch{}, err
	}
	index := slices.IndexFunc(batch.Items, func(item PermissionBatchItem) bool { return item.Status == "pending" })
	if index < 0 {
		return batch, nil
	}
	item := &batch.Items[index]
	if _, err := tx.ExecContext(ctx, `SAVEPOINT permission_batch_operation`); err != nil {
		return PermissionBatch{}, err
	}
	ids := []string{actor.PrincipalID, item.SubjectID}
	slices.Sort(ids)
	for _, id := range slices.Compact(ids) {
		var revision uint64
		err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_principal WHERE principal_type='user' AND id=? FOR UPDATE`), id).Scan(&revision)
		if err != nil {
			break
		}
	}
	if err == nil && batch.Command.Kind == "authorization" {
		command := *item.Command.Authorization
		semantic := command
		semantic.PlanDigest, semantic.PlanExpiresAt = "", time.Time{}
		raw, marshalErr := json.Marshal(semantic)
		if marshalErr != nil {
			return PermissionBatch{}, marshalErr
		}
		key := permissionHash([]byte(actor.PrincipalID + "\x00" + command.IdempotencyKey))
		var receipt AuthorizationChangeReceipt
		receipt, err = s.commitPermissionBatchAuthorizationTx(ctx, tx, actor, command, key, permissionHash(raw))
		if err == nil {
			item.Authorization = &receipt
		}
	} else if err == nil {
		var receipt PermissionRequestDecisionReceipt
		receipt, err = s.decidePermissionRequestTx(ctx, tx, actor, *item.Command.Decision)
		if err == nil {
			item.Decision = &receipt
		}
	}
	if err != nil {
		code := permissionBatchFailureCode(err)
		if code == "" {
			return PermissionBatch{}, err // Keep pending after infrastructure faults.
		}
		if _, rollbackErr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT permission_batch_operation`); rollbackErr != nil {
			return PermissionBatch{}, rollbackErr
		}
		item.Status, item.FailureCode = "failed", code
	} else {
		item.Status = "succeeded"
	}
	if _, err := tx.ExecContext(ctx, `RELEASE SAVEPOINT permission_batch_operation`); err != nil {
		return PermissionBatch{}, err
	}
	batch.UpdatedAt = s.clock().UTC()
	raw, err := json.Marshal(batch)
	if err != nil {
		return PermissionBatch{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_permission_batch SET payload=?,updated_at=? WHERE id=?`), string(raw), batch.UpdatedAt, batch.ID); err != nil {
		return PermissionBatch{}, err
	}
	return batch, tx.Commit()
}

func (s *SQLStore) commitPermissionBatchAuthorizationTx(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, command AuthorizationChangeCommand, key, digest string) (AuthorizationChangeReceipt, error) {
	var priorDigest string
	var raw []byte
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,receipt FROM platform_identity_authorization_change WHERE idempotency_hash=?`), key).Scan(&priorDigest, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return s.commitAuthorizationChangeTx(ctx, tx, actor, command, key, digest)
	}
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if priorDigest != digest {
		return AuthorizationChangeReceipt{}, ErrIdentityConflict
	}
	var receipt AuthorizationChangeReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := authorizeReceiptRead(ctx, tx, owner, receipt, s.clock().UTC()); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	return receipt, nil
}
