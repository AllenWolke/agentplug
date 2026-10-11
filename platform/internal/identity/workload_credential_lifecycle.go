package identity

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// A credential affects every installation using the machine. An application
// administrator must therefore manage all its active installation scopes.
func authorizeWorkloadCredential(ctx context.Context, tx *sql.Tx, owner PermissionSnapshot, tenant, principal string, nowQuery PermissionQuery) error {
	if owner.Mode != "v2" || !owner.Principal.IsActive || owner.Principal.TenantID != tenant {
		return ErrPermissionDenied
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_identity_workload_binding WHERE tenant_id=? AND principal_id=? AND status='active'`), tenant, principal)
	if err != nil {
		return err
	}
	var scopes []ManagementScope
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var b WorkloadBinding
		if json.Unmarshal(raw, &b) != nil || b.TenantID != tenant || b.PrincipalID != principal || b.Status != "active" || b.Revision == 0 {
			rows.Close()
			return ErrInvalidResource
		}
		scopes = append(scopes, ManagementScope{Type: "application", TenantID: tenant, DepartmentID: b.DepartmentID, ApplicationID: b.ApplicationID})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(scopes) == 0 {
		scopes = []ManagementScope{{Type: "tenant", TenantID: tenant}}
	}
	for _, scope := range scopes {
		nowQuery.Action, nowQuery.Scope = "machine.manage", scope
		decision, err := EvaluatePermission(owner, nowQuery)
		if err != nil {
			return err
		}
		if !decision.Allowed {
			return ErrPermissionDenied
		}
	}
	return nil
}

// ChangePermissionMachineCredential keeps live authorization, credential CAS,
// epoch invalidation and audit/Outbox in one Identity-owned transaction.
func (s *SQLStore) ChangePermissionMachineCredential(ctx context.Context, actor sharedkernel.Scope, principal string, expected uint64, secretHash string, networks []string, disable bool) (uint64, error) {
	if s == nil || s.db == nil || s.administrativeRecorder == nil {
		return 0, ErrPermissionRecorderUnavailable
	}
	if actor.Validate() != nil || actor.PrincipalType != "user" || !validPermissionResourceID(principal) || expected == 0 || expected == ^uint64(0) {
		return 0, ErrInvalidResource
	}
	var cidrs []string
	if !disable {
		hash, err := hex.DecodeString(secretHash)
		if err != nil || len(hash) != 32 {
			return 0, ErrInvalidResource
		}
		cidrs, err = normalizeMachineCIDRs(networks)
		if err != nil {
			return 0, err
		}
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return 0, err
	}
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return 0, err
	}
	if err := authorizeWorkloadCredential(ctx, tx, owner, actor.TenantID, principal, PermissionQuery{Now: s.clock().UTC()}); err != nil {
		return 0, err
	}
	machine, err := loadPermissionSnapshot(ctx, tx, PrincipalServicePrincipal, principal)
	if err != nil {
		return 0, err
	}
	if machine.Mode != "v2" || machine.Principal.TenantID != actor.TenantID {
		return 0, ErrPermissionDenied
	}
	var revision uint64
	var status string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,status FROM platform_identity_machine_credential WHERE tenant_id=? AND principal_id=? FOR UPDATE`), actor.TenantID, principal).Scan(&revision, &status); err != nil {
		return 0, err
	}
	if revision != expected || status != "active" {
		return 0, ErrMachineCredentialConflict
	}
	now := s.clock().UTC()
	var changed sql.Result
	if disable {
		changed, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_machine_credential SET status='disabled',revision=revision+1,updated_at=? WHERE tenant_id=? AND principal_id=? AND revision=? AND status='active'`), now, actor.TenantID, principal, expected)
	} else {
		encoded, errJSON := json.Marshal(cidrs)
		if errJSON != nil {
			return 0, errJSON
		}
		changed, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_machine_credential SET secret_hash=?,network_cidrs_json=?,revision=revision+1,updated_at=? WHERE tenant_id=? AND principal_id=? AND revision=? AND status='active'`), secretHash, string(encoded), now, actor.TenantID, principal, expected)
	}
	if err != nil {
		return 0, err
	}
	count, err := changed.RowsAffected()
	if err != nil {
		return 0, err
	}
	if count != 1 {
		return 0, ErrMachineCredentialConflict
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET revision=revision+1 WHERE principal_type='service_principal' AND id=?`), principal); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_policy_migration SET revision=revision+1,epoch=epoch+1 WHERE principal_type='service_principal' AND subject_id=? AND policy_mode='v2'`), principal); err != nil {
		return 0, err
	}
	operation := "rotated"
	if disable {
		operation = "disabled"
	}
	event := AdministrativeEvent{SubjectType: PrincipalServicePrincipal, ID: "machine-credential-" + permissionHash([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s", actor.TenantID, principal, expected, operation))), ActorID: actor.PrincipalID, SubjectID: principal, Action: "machine.manage", Reason: "Machine credential " + operation, Revision: expected + 1, OccurredAt: now}
	if err := s.administrativeRecorder(ctx, tx, actor, event); err != nil {
		return 0, err
	}
	return expected + 1, tx.Commit()
}

func (s *SQLStore) ListPermissionMachineCredentials(ctx context.Context, actor sharedkernel.Scope) ([]MachineCredential, error) {
	if actor.Validate() != nil || actor.PrincipalType != "user" {
		return nil, ErrPermissionDenied
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return nil, err
	}
	if owner.Mode != "v2" || !owner.Principal.IsActive || owner.Principal.TenantID != actor.TenantID {
		return nil, ErrPermissionDenied
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT tenant_id,principal_id,network_cidrs_json,status,revision,created_at,updated_at FROM platform_identity_machine_credential WHERE tenant_id=? ORDER BY principal_id LIMIT 1001`), actor.TenantID)
	if err != nil {
		return nil, err
	}
	var candidates []MachineCredential
	for rows.Next() {
		var c MachineCredential
		var raw string
		if err := rows.Scan(&c.TenantID, &c.PrincipalID, &raw, &c.Status, &c.Revision, &c.CreatedAt, &c.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		if json.Unmarshal([]byte(raw), &c.NetworkCIDRs) != nil {
			rows.Close()
			return nil, ErrInvalidResource
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(candidates) > 1000 {
		return nil, ErrInvalidResource
	}
	result := []MachineCredential{}
	for _, c := range candidates {
		err := authorizeWorkloadCredential(ctx, tx, owner, actor.TenantID, c.PrincipalID, PermissionQuery{Now: s.clock().UTC()})
		if errors.Is(err, ErrPermissionDenied) {
			continue
		}
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, tx.Commit()
}
