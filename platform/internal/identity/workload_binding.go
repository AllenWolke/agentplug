package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
)

type WorkloadBinding struct {
	TenantID       string `json:"tenant_id"`
	DepartmentID   string `json:"department_id"`
	ApplicationID  string `json:"application_id"`
	InstallationID string `json:"installation_id"`
	AgentID        string `json:"agent_id"`
	AgentVersionID string `json:"agent_version_id"`
	PrincipalID    string `json:"principal_id"`
	Status         string `json:"status"`
	Revision       uint64 `json:"revision"`
}
type WorkloadBindingCommand struct {
	Binding          WorkloadBinding `json:"binding"`
	ExpectedRevision uint64          `json:"expected_revision"`
	IdempotencyKey   string          `json:"idempotency_key"`
	Reason           string          `json:"reason"`
	Revoke           bool            `json:"revoke"`
}
type WorkloadBindingReceipt struct {
	AdministrativeEvent
	Binding       WorkloadBinding `json:"binding"`
	RequestDigest string          `json:"request_digest"`
}
type WorkloadIdentityResolver interface {
	ResolveWorkloadIdentity(context.Context, sharedkernel.Scope) (WorkloadBinding, error)
}

func (s *SQLStore) EnsureWorkloadBindingSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE IF NOT EXISTS platform_identity_workload_binding (scope_hash VARCHAR(64) PRIMARY KEY,tenant_id VARCHAR(128) NOT NULL,department_id VARCHAR(128) NOT NULL,application_id VARCHAR(128) NOT NULL,installation_id VARCHAR(128) NOT NULL,principal_id VARCHAR(128) NOT NULL,status VARCHAR(24) NOT NULL,revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,payload JSON NOT NULL);
CREATE INDEX IF NOT EXISTS idx_workload_principal ON platform_identity_workload_binding (principal_id,status);`))
	return err
}
func workloadScopeHash(b WorkloadBinding) string {
	raw, _ := json.Marshal([]string{b.TenantID, b.DepartmentID, b.ApplicationID, b.InstallationID})
	return permissionHash(raw)
}
func (s *SQLStore) ResolveWorkloadIdentity(ctx context.Context, scope sharedkernel.Scope) (WorkloadBinding, error) {
	if scope.ValidateTrusted() != nil || scope.AgentInstanceID != scope.InstallationID {
		return WorkloadBinding{}, ErrInvalidResource
	}
	key := workloadScopeHash(WorkloadBinding{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, InstallationID: scope.InstallationID})
	var raw []byte
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_identity_workload_binding WHERE scope_hash=? AND status='active'`), key).Scan(&raw); err != nil {
		return WorkloadBinding{}, err
	}
	var b WorkloadBinding
	if json.Unmarshal(raw, &b) != nil || b.Revision == 0 || b.Status != "active" || b.TenantID != scope.TenantID || b.DepartmentID != scope.DepartmentID || b.ApplicationID != scope.ApplicationID || b.InstallationID != scope.InstallationID || b.AgentID != scope.AgentID || b.AgentVersionID != scope.AgentVersionID || b.PrincipalID == "" {
		return b, ErrPermissionDenied
	}
	return b, nil
}

// Binding authorizes no business capability. The executor still needs its own
// explicit resource Grants, checked independently from the original caller.
func (s *SQLStore) ChangeWorkloadBinding(ctx context.Context, actor sharedkernel.Scope, c WorkloadBindingCommand) (WorkloadBindingReceipt, error) {
	b := c.Binding
	if actor.Validate() != nil || actor.PrincipalType != "user" || c.IdempotencyKey == "" || len(c.IdempotencyKey) > 128 || strings.TrimSpace(c.Reason) == "" || len(c.Reason) > 2000 || b.Status != "" || b.Revision != 0 {
		return WorkloadBindingReceipt{}, ErrInvalidResource
	}
	for _, id := range []string{b.TenantID, b.DepartmentID, b.ApplicationID, b.InstallationID, b.AgentID, b.AgentVersionID, b.PrincipalID} {
		if !validPermissionResourceID(id) {
			return WorkloadBindingReceipt{}, ErrInvalidResource
		}
	}
	if s.administrativeRecorder == nil {
		return WorkloadBindingReceipt{}, ErrPermissionRecorderUnavailable
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return WorkloadBindingReceipt{}, err
	}
	digest := permissionHash(raw)
	retryKey := permissionHash([]byte("workload.bind\x00" + actor.PrincipalID + "\x00" + c.IdempotencyKey))
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return WorkloadBindingReceipt{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return WorkloadBindingReceipt{}, err
	}
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return WorkloadBindingReceipt{}, err
	}
	target := ManagementScope{Type: "application", TenantID: b.TenantID, DepartmentID: b.DepartmentID, ApplicationID: b.ApplicationID}
	if owner.Mode != "v2" || owner.Principal.TenantID != actor.TenantID {
		return WorkloadBindingReceipt{}, ErrPermissionDenied
	}
	decision, err := EvaluatePermission(owner, PermissionQuery{Action: "machine.manage", Scope: target, Now: s.clock().UTC()})
	if err != nil {
		return WorkloadBindingReceipt{}, err
	}
	if !decision.Allowed {
		return WorkloadBindingReceipt{}, ErrPermissionDenied
	}
	var priorDigest string
	var encoded []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,receipt FROM platform_identity_authorization_change WHERE idempotency_hash=?`), retryKey).Scan(&priorDigest, &encoded)
	if err == nil {
		if priorDigest != digest {
			return WorkloadBindingReceipt{}, ErrIdentityConflict
		}
		var prior WorkloadBindingReceipt
		err = json.Unmarshal(encoded, &prior)
		return prior, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return WorkloadBindingReceipt{}, err
	}
	if err := validatePermissionScope(ctx, tx, target); err != nil {
		return WorkloadBindingReceipt{}, err
	}
	key := workloadScopeHash(b)
	var currentRaw []byte
	var revision uint64
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,payload FROM platform_identity_workload_binding WHERE scope_hash=? FOR UPDATE`), key).Scan(&revision, &currentRaw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return WorkloadBindingReceipt{}, err
	}
	if revision != c.ExpectedRevision || c.Revoke && revision == 0 {
		return WorkloadBindingReceipt{}, ErrIdentityConflict
	}
	if revision > 0 {
		var current WorkloadBinding
		if json.Unmarshal(currentRaw, &current) != nil {
			return WorkloadBindingReceipt{}, ErrInvalidResource
		}
		if c.Revoke && (current.AgentID != b.AgentID || current.AgentVersionID != b.AgentVersionID) {
			return WorkloadBindingReceipt{}, ErrIdentityConflict
		}
		if current.PrincipalID != b.PrincipalID && (c.Revoke || current.Status != "revoked") {
			return WorkloadBindingReceipt{}, ErrIdentityConflict
		}
	}
	if !c.Revoke {
		machine, err := loadPermissionSnapshot(ctx, tx, PrincipalServicePrincipal, b.PrincipalID)
		if err != nil {
			return WorkloadBindingReceipt{}, err
		}
		if machine.Mode != "v2" || !machine.Principal.IsActive || machine.Principal.TenantID != b.TenantID || s.capabilityResourceResolver == nil {
			return WorkloadBindingReceipt{}, ErrPermissionDenied
		}
		var credentialStatus string
		var credentialRevision uint64
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,revision FROM platform_identity_machine_credential WHERE tenant_id=? AND principal_id=? FOR UPDATE`), b.TenantID, b.PrincipalID).Scan(&credentialStatus, &credentialRevision); err != nil {
			return WorkloadBindingReceipt{}, err
		}
		if credentialStatus != "active" || credentialRevision == 0 {
			return WorkloadBindingReceipt{}, ErrPermissionDenied
		}
		r, err := s.capabilityResourceResolver.ResolvePermissionResource(ctx, sharedkernel.Scope{TenantID: b.TenantID, DepartmentID: b.DepartmentID, ApplicationID: b.ApplicationID, InstallationID: b.InstallationID, AgentInstanceID: b.InstallationID, PrincipalID: b.PrincipalID, PrincipalType: "service_principal"}, "agent_installation", b.InstallationID)
		if err != nil {
			return WorkloadBindingReceipt{}, err
		}
		if r.Type != "agent_installation" || r.ID != b.InstallationID || r.InstallationID != b.InstallationID || r.TenantID != b.TenantID || r.DepartmentID != b.DepartmentID || r.ApplicationID != b.ApplicationID || r.AgentID != b.AgentID || r.AgentVersionID != b.AgentVersionID {
			return WorkloadBindingReceipt{}, ErrInvalidResource
		}
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET revision=revision+1 WHERE principal_type='service_principal' AND id=?`), b.PrincipalID); err != nil {
		return WorkloadBindingReceipt{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_policy_migration SET revision=revision+1,epoch=epoch+1 WHERE principal_type='service_principal' AND subject_id=? AND policy_mode='v2'`), b.PrincipalID); err != nil {
		return WorkloadBindingReceipt{}, err
	}
	b.Status = "active"
	if c.Revoke {
		b.Status = "revoked"
	}
	b.Revision = revision + 1
	raw, err = json.Marshal(b)
	if err != nil {
		return WorkloadBindingReceipt{}, err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_workload_binding(scope_hash,tenant_id,department_id,application_id,installation_id,principal_id,status,revision,payload) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT (scope_hash) DO UPDATE SET principal_id=EXCLUDED.principal_id,status=EXCLUDED.status,revision=EXCLUDED.revision,payload=EXCLUDED.payload`), key, b.TenantID, b.DepartmentID, b.ApplicationID, b.InstallationID, b.PrincipalID, b.Status, b.Revision, string(raw))
	if err != nil {
		return WorkloadBindingReceipt{}, err
	}
	event := AdministrativeEvent{SubjectType: PrincipalServicePrincipal, ID: "workload-change-" + retryKey, ActorID: actor.PrincipalID, SubjectID: b.PrincipalID, Action: "machine.manage", Reason: c.Reason, Revision: b.Revision, OccurredAt: s.clock().UTC(), DetailsDigest: permissionHash(raw)}
	if err := s.administrativeRecorder(ctx, tx, actor, event); err != nil {
		return WorkloadBindingReceipt{}, err
	}
	receipt := WorkloadBindingReceipt{AdministrativeEvent: event, Binding: b, RequestDigest: digest}
	encoded, err = json.Marshal(receipt)
	if err != nil {
		return receipt, err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_authorization_change(id,actor_id,subject_id,idempotency_hash,request_digest,receipt,created_at) VALUES(?,?,?,?,?,?,?)`), event.ID, actor.PrincipalID, b.PrincipalID, retryKey, digest, string(encoded), event.OccurredAt)
	if err != nil {
		return receipt, err
	}
	if err := tx.Commit(); err != nil {
		return receipt, err
	}
	return receipt, nil
}
