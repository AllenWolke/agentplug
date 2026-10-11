package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// WorkloadCreationCommand creates an unprivileged v2 machine, never a human
// account, role binding, installation binding or business Grant.
type WorkloadCreationCommand struct {
	PrincipalID    string          `json:"principal_id"`
	Scope          ManagementScope `json:"scope"`
	NetworkCIDRs   []string        `json:"network_cidrs"`
	IdempotencyKey string          `json:"idempotency_key"`
	Reason         string          `json:"reason"`
	ClientSecret   string          `json:"-"`
}

func (s *SQLStore) CreatePermissionWorkload(ctx context.Context, actor sharedkernel.Scope, c WorkloadCreationCommand) (AdministrativeEvent, error) {
	if s == nil || s.db == nil || s.administrativeRecorder == nil {
		return AdministrativeEvent{}, ErrPermissionRecorderUnavailable
	}
	if actor.Validate() != nil || actor.PrincipalType != "user" || !validPermissionResourceID(c.PrincipalID) || c.Scope.Type != "application" || c.Scope.Validate() != nil || c.Scope.TenantID != actor.TenantID || len(c.ClientSecret) < 32 || len(c.ClientSecret) > 512 || strings.TrimSpace(c.ClientSecret) != c.ClientSecret || strings.ContainsAny(c.ClientSecret, "\x00\r\n") || strings.TrimSpace(c.Reason) == "" || len(c.Reason) > 1000 || c.IdempotencyKey == "" || len(c.IdempotencyKey) > 128 {
		return AdministrativeEvent{}, ErrInvalidResource
	}
	cidrs, err := normalizeMachineCIDRs(c.NetworkCIDRs)
	if err != nil {
		return AdministrativeEvent{}, err
	}
	c.NetworkCIDRs = cidrs
	raw, err := json.Marshal(c)
	if err != nil {
		return AdministrativeEvent{}, err
	}
	digest := permissionHash(raw)
	key := permissionHash([]byte("workload.create\x00" + actor.PrincipalID + "\x00" + c.IdempotencyKey))
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return AdministrativeEvent{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return AdministrativeEvent{}, err
	}
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return AdministrativeEvent{}, err
	}
	decision, err := EvaluatePermission(owner, PermissionQuery{Action: "machine.manage", Scope: c.Scope, Now: s.clock().UTC()})
	if err != nil {
		return AdministrativeEvent{}, err
	}
	if owner.Mode != "v2" || !owner.Principal.IsActive || owner.Principal.TenantID != actor.TenantID || !decision.Allowed {
		return AdministrativeEvent{}, ErrPermissionDenied
	}
	if err := validatePermissionScope(ctx, tx, c.Scope); err != nil {
		return AdministrativeEvent{}, err
	}
	var priorDigest string
	var saved []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,receipt FROM platform_identity_authorization_change WHERE idempotency_hash=?`), key).Scan(&priorDigest, &saved)
	if err == nil {
		if priorDigest != digest {
			return AdministrativeEvent{}, ErrIdentityConflict
		}
		var event AdministrativeEvent
		if json.Unmarshal(saved, &event) != nil {
			return event, ErrIdentityConflict
		}
		var hash, status string
		err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT secret_hash,status FROM platform_identity_machine_credential WHERE tenant_id=? AND principal_id=?`), c.Scope.TenantID, c.PrincipalID).Scan(&hash, &status)
		if err != nil {
			return event, err
		}
		if status != "active" || hash != digestMachineValue(c.ClientSecret) {
			return event, ErrIdentityConflict
		}
		machine, err := loadPermissionSnapshot(ctx, tx, PrincipalServicePrincipal, c.PrincipalID)
		if err != nil {
			return event, err
		}
		if machine.Mode != "v2" || !machine.Principal.IsActive || machine.Principal.TenantID != c.Scope.TenantID {
			return event, ErrPermissionDenied
		}
		return event, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AdministrativeEvent{}, err
	}
	now := s.clock().UTC()
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_principal(id,principal_type,tenant_id,roles_json,groups_json,active,revision,created_at) VALUES(?,'service_principal',?,'[]','[]',TRUE,1,?)`), c.PrincipalID, c.Scope.TenantID, now)
	if err != nil {
		return AdministrativeEvent{}, identityPersistenceError("create permission workload", err)
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('service_principal',?,'v2',1,1)`), c.PrincipalID)
	if err != nil {
		return AdministrativeEvent{}, err
	}
	networkJSON, _ := json.Marshal(cidrs)
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_machine_credential(tenant_id,principal_id,secret_hash,network_cidrs_json,status,revision,created_at,updated_at) VALUES(?,?,?,?,'active',1,?,?)`), c.Scope.TenantID, c.PrincipalID, digestMachineValue(c.ClientSecret), string(networkJSON), now, now)
	if err != nil {
		return AdministrativeEvent{}, err
	}
	event := AdministrativeEvent{SubjectType: PrincipalServicePrincipal, ID: "workload-create-" + key, ActorID: actor.PrincipalID, SubjectID: c.PrincipalID, Action: "machine.manage", Reason: c.Reason, Revision: 1, OccurredAt: now, DetailsDigest: digest}
	if err := s.administrativeRecorder(ctx, tx, actor, event); err != nil {
		return AdministrativeEvent{}, err
	}
	receipt, err := json.Marshal(event)
	if err != nil {
		return event, err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_authorization_change(id,actor_id,subject_id,idempotency_hash,request_digest,receipt,created_at) VALUES(?,?,?,?,?,?,?)`), event.ID, actor.PrincipalID, c.PrincipalID, key, digest, string(receipt), now)
	if err != nil {
		return event, err
	}
	return event, tx.Commit()
}

func (m *Module) workloadPrincipal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, _, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	store, ok := m.store.(interface {
		CreatePermissionWorkload(context.Context, sharedkernel.Scope, WorkloadCreationCommand) (AdministrativeEvent, error)
	})
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "WORKLOAD_SERVICE_UNAVAILABLE")
		return
	}
	var request struct {
		WorkloadCreationCommand
		Secret string `json:"client_secret"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	request.ClientSecret = request.Secret
	event, err := store.CreatePermissionWorkload(r.Context(), actor.Scope, request.WorkloadCreationCommand)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	m.json(w, http.StatusOK, event)
}
