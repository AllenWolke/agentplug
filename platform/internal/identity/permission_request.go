package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type PermissionRequestItem struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	Scope          ManagementScope `json:"scope"`
	RoleCode       string          `json:"role_code,omitempty"`
	RoleVersion    uint64          `json:"role_version,omitempty"`
	ResourceID     string          `json:"resource_id,omitempty"`
	ResourceType   string          `json:"resource_type,omitempty"`
	InstallationID string          `json:"installation_id,omitempty"`
	Action         string          `json:"action,omitempty"`
	DataScope      DataScope       `json:"data_scope,omitempty"`
	Validity
	Outcome string `json:"outcome"`
}

type PermissionRequest struct {
	LegacySource *LegacyPermissionRequestSource `json:"legacy_source,omitempty"`
	ID           string                         `json:"id"`
	SubjectID    string                         `json:"subject_id"`
	Scope        ManagementScope                `json:"scope"`
	Items        []PermissionRequestItem        `json:"items"`
	Reason       string                         `json:"reason"`
	Status       string                         `json:"status"`
	Revision     uint64                         `json:"revision"`
	ReviewerID   string                         `json:"reviewer_id,omitempty"`
	Comment      string                         `json:"comment,omitempty"`
	CreatedAt    time.Time                      `json:"created_at"`
	UpdatedAt    time.Time                      `json:"updated_at"`
}

type PermissionRequestCreate struct {
	Scope          ManagementScope         `json:"scope"`
	Items          []PermissionRequestItem `json:"items"`
	Reason         string                  `json:"reason"`
	IdempotencyKey string                  `json:"idempotency_key"`
}

func (s *SQLStore) EnsurePermissionRequestSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE IF NOT EXISTS platform_identity_permission_request (
		id VARCHAR(128) PRIMARY KEY,subject_id VARCHAR(128) NOT NULL,tenant_id VARCHAR(128) NOT NULL,
		department_id VARCHAR(128) NOT NULL,application_id VARCHAR(128) NOT NULL,status VARCHAR(24) NOT NULL,
		revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,payload JSON NOT NULL,created_at TIMESTAMPTZ(6) NOT NULL,updated_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_permission_request_subject ON platform_identity_permission_request (subject_id,status,created_at,id);
CREATE INDEX IF NOT EXISTS idx_permission_request_scope ON platform_identity_permission_request (tenant_id,department_id,application_id,status,created_at,id);`))
	return err
}

func permissionRequestFromRow(row *sql.Row) (PermissionRequest, error) {
	var raw []byte
	if err := row.Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return PermissionRequest{}, ErrAccessRequestNotFound
	} else if err != nil {
		return PermissionRequest{}, err
	}
	var value PermissionRequest
	err := json.Unmarshal(raw, &value)
	return value, err
}

func permissionRequestOwner(ctx context.Context, reader permissionReader, actor sharedkernel.Scope) (PermissionSnapshot, error) {
	if actor.Validate() != nil || actor.PrincipalType != "user" {
		return PermissionSnapshot{}, ErrPermissionDenied
	}
	snapshot, err := loadPermissionSnapshot(ctx, reader, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return snapshot, err
	}
	if snapshot.Mode != "v2" || !snapshot.Principal.IsActive || snapshot.Principal.TenantID != actor.TenantID {
		return snapshot, ErrPermissionDenied
	}
	return snapshot, nil
}

func (s *SQLStore) validatePermissionRequest(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, c PermissionRequestCreate) (PermissionRequestCreate, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return c, err
	}
	var copied PermissionRequestCreate
	if err := json.Unmarshal(raw, &copied); err != nil {
		return c, err
	}
	c = copied
	owner, err := permissionRequestOwner(ctx, tx, actor)
	if err != nil {
		return c, err
	}
	now := s.clock().UTC()
	if administrationKind(owner, now) != "" {
		return c, ErrPermissionDenied
	}
	if c.Scope.Validate() != nil || !slices.Contains([]string{"tenant", "department", "application"}, c.Scope.Type) || c.Scope.TenantID != owner.Principal.TenantID || !membershipCovers(owner.Memberships, actor.PrincipalID, c.Scope, now) || len(c.Items) == 0 || len(c.Items) > 32 || strings.TrimSpace(c.Reason) == "" || len(c.Reason) > 1000 || c.IdempotencyKey == "" || len(c.IdempotencyKey) > 128 {
		return c, ErrInvalidResource
	}
	if err := validatePermissionScope(ctx, tx, c.Scope); err != nil {
		return c, err
	}
	seen := map[string]bool{}
	for i := range c.Items {
		item := &c.Items[i]
		if item.ID == "" || len(item.ID) > 64 || strings.TrimSpace(item.ID) != item.ID || strings.ContainsAny(item.ID, "*\x00") || seen[item.ID] || item.Scope.Validate() != nil || !c.Scope.Contains(item.Scope) || !membershipCovers(owner.Memberships, actor.PrincipalID, item.Scope, now) || item.Validity.Validate() != nil || item.ExpiresAt != nil && !item.ExpiresAt.After(now) || item.Outcome != "" {
			return c, ErrInvalidResource
		}
		seen[item.ID] = true
		if err := validatePermissionScope(ctx, tx, item.Scope); err != nil {
			return c, err
		}
		if item.Scope.Type == "agent_installation" {
			if s.permissionResourceResolver == nil {
				return c, ErrInvalidResource
			}
			if _, err := s.permissionResourceResolver.ResolveAgentInstallation(ctx, sharedkernel.Scope{TenantID: item.Scope.TenantID, DepartmentID: item.Scope.DepartmentID, ApplicationID: item.Scope.ApplicationID}, item.Scope.ResourceID); err != nil {
				return c, err
			}
		}
		switch item.Kind {
		case "role":
			if item.ResourceType != "" || item.InstallationID != "" {
				return c, ErrInvalidResource
			}
			if item.ResourceID != "" || item.Action != "" || item.DataScope.Type != "" || len(item.DataScope.IDs) != 0 || protectedAdministratorBinding(RoleBinding{RoleCode: item.RoleCode, RoleVersion: item.RoleVersion}) {
				return c, ErrInvalidResource
			}
			found := false
			for _, role := range owner.Roles {
				if role.Code == item.RoleCode && role.Version == item.RoleVersion && role.Assignable && slices.Contains(role.ScopeTypes, item.Scope.Type) {
					found = true
				}
			}
			if !found {
				return c, ErrInvalidResource
			}
		case "resource":
			if item.Scope.Type != "application" || item.RoleCode != "" || item.RoleVersion != 0 || item.ResourceID == "" || item.DataScope.Validate() != nil || s.permissionResourceResolver == nil {
				return c, ErrInvalidResource
			}
			grant, err := permissionRequestResourceGrant(*item, actor.PrincipalID)
			if err != nil {
				return c, err
			}
			if err := s.validateGrantResource(ctx, grant); err != nil {
				return c, err
			}
		default:
			return c, ErrInvalidResource
		}
	}
	return c, nil
}

func (s *SQLStore) savePermissionRequestEvent(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, request PermissionRequest, key, digest, action string) error {
	if s.administrativeRecorder == nil {
		return ErrPermissionRecorderUnavailable
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	event := AdministrativeEvent{ID: "request-event-" + key, ActorID: actor.PrincipalID, SubjectID: request.SubjectID, Action: action, Reason: request.Reason, Revision: request.Revision, OccurredAt: s.clock().UTC(), DetailsDigest: permissionHash(raw)}
	if err := s.administrativeRecorder(ctx, tx, actor, event); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_authorization_change(id,actor_id,subject_id,idempotency_hash,request_digest,receipt,created_at) VALUES(?,?,?,?,?,?,?)`), event.ID, actor.PrincipalID, request.SubjectID, key, digest, string(raw), event.OccurredAt)
	return err
}

func (s *SQLStore) CreatePermissionRequest(ctx context.Context, actor sharedkernel.Scope, c PermissionRequestCreate) (PermissionRequest, error) {
	if s == nil || s.db == nil || s.administrativeRecorder == nil {
		return PermissionRequest{}, ErrPermissionRecorderUnavailable
	}
	if c.IdempotencyKey == "" || len(c.IdempotencyKey) > 128 {
		return PermissionRequest{}, ErrInvalidResource
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return PermissionRequest{}, err
	}
	digest := permissionHash(raw)
	key := permissionHash([]byte("permission-request.create\x00" + actor.PrincipalID + "\x00" + c.IdempotencyKey))
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return PermissionRequest{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return PermissionRequest{}, err
	}
	if _, err := permissionRequestOwner(ctx, tx, actor); err != nil {
		return PermissionRequest{}, err
	}
	var priorDigest string
	var saved []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,receipt FROM platform_identity_authorization_change WHERE idempotency_hash=?`), key).Scan(&priorDigest, &saved)
	if err == nil {
		if digest != priorDigest {
			return PermissionRequest{}, ErrIdentityConflict
		}
		var request PermissionRequest
		if err := json.Unmarshal(saved, &request); err != nil {
			return PermissionRequest{}, err
		}
		return request, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return PermissionRequest{}, err
	}
	c, err = s.validatePermissionRequest(ctx, tx, actor, c)
	if err != nil {
		return PermissionRequest{}, err
	}
	now := s.clock().UTC()
	request := PermissionRequest{ID: "request-" + key, SubjectID: actor.PrincipalID, Scope: c.Scope, Items: c.Items, Reason: c.Reason, Status: "pending", Revision: 1, CreatedAt: now, UpdatedAt: now}
	for i := range request.Items {
		request.Items[i].Outcome = "pending"
	}
	raw, err = json.Marshal(request)
	if err != nil {
		return PermissionRequest{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_permission_request(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,created_at,updated_at) VALUES(?,?,?,?,?,'pending',1,?,?,?)`), request.ID, actor.PrincipalID, c.Scope.TenantID, c.Scope.DepartmentID, c.Scope.ApplicationID, string(raw), now, now); err != nil {
		return PermissionRequest{}, err
	}
	if err := s.savePermissionRequestEvent(ctx, tx, actor, request, key, digest, "identity.permission_request.created"); err != nil {
		return PermissionRequest{}, err
	}
	return request, tx.Commit()
}

func (s *SQLStore) readPermissionRequest(ctx context.Context, reader permissionReader, actor sharedkernel.Scope, id string) (PermissionRequest, error) {
	owner, err := permissionRequestOwner(ctx, reader, actor)
	if err != nil {
		return PermissionRequest{}, err
	}
	request, err := permissionRequestFromRow(reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_identity_permission_request WHERE id=?`), id))
	if err != nil {
		return request, err
	}
	if request.SubjectID == actor.PrincipalID {
		return request, nil
	}
	item := Enrollment{Username: request.SubjectID, TenantID: request.Scope.TenantID, DepartmentID: request.Scope.DepartmentID, ApplicationID: request.Scope.ApplicationID}
	// Requests at an organization scope use that exact scope, not an invented
	// application coordinate. Every subsequent approval also checks each fact.
	decision, err := EvaluatePermission(owner, PermissionQuery{Action: "access_request.decide", Scope: request.Scope, Now: s.clock().UTC()})
	if err != nil {
		return request, err
	}
	if !decision.Allowed || strings.EqualFold(item.Username, actor.PrincipalID) {
		return request, ErrPermissionDenied
	}
	return request, nil
}

func (s *SQLStore) GetPermissionRequest(ctx context.Context, actor sharedkernel.Scope, id string) (PermissionRequest, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return PermissionRequest{}, err
	}
	defer tx.Rollback()
	request, err := s.readPermissionRequest(ctx, tx, actor, id)
	if err != nil {
		return request, err
	}
	return request, tx.Commit()
}
