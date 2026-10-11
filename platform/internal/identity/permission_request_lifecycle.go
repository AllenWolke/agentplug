package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type PermissionRequestWithdrawal struct {
	RequestID        string `json:"request_id"`
	ExpectedRevision uint64 `json:"expected_revision"`
	IdempotencyKey   string `json:"idempotency_key"`
	Reason           string `json:"reason"`
}

func (s *SQLStore) WithdrawPermissionRequest(ctx context.Context, actor sharedkernel.Scope, c PermissionRequestWithdrawal) (PermissionRequest, error) {
	if s == nil || s.db == nil || s.administrativeRecorder == nil {
		return PermissionRequest{}, ErrPermissionRecorderUnavailable
	}
	if c.RequestID == "" || len(c.RequestID) > 128 || c.ExpectedRevision == 0 || c.IdempotencyKey == "" || len(c.IdempotencyKey) > 128 || strings.TrimSpace(c.Reason) == "" || len(c.Reason) > 1000 {
		return PermissionRequest{}, ErrInvalidResource
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return PermissionRequest{}, err
	}
	digest := permissionHash(raw)
	key := permissionHash([]byte("permission-request.withdraw\x00" + actor.PrincipalID + "\x00" + c.IdempotencyKey))
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
			return request, err
		}
		if request.SubjectID != actor.PrincipalID {
			return request, ErrPermissionDenied
		}
		return request, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return PermissionRequest{}, err
	}
	request, err := permissionRequestFromRow(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_identity_permission_request WHERE id=? FOR UPDATE`), c.RequestID))
	if err != nil {
		return request, err
	}
	if request.SubjectID != actor.PrincipalID {
		return request, ErrPermissionDenied
	}
	if request.Status != "pending" || request.Revision != c.ExpectedRevision {
		return request, ErrIdentityConflict
	}
	request.Status, request.Revision, request.Comment, request.UpdatedAt = "withdrawn", request.Revision+1, c.Reason, s.clock().UTC()
	for i := range request.Items {
		request.Items[i].Outcome = "withdrawn"
	}
	if err := updatePermissionRequestTx(ctx, tx, request, c.ExpectedRevision); err != nil {
		return request, err
	}
	if err := s.savePermissionRequestEvent(ctx, tx, actor, request, key, digest, "identity.permission_request.withdrawn"); err != nil {
		return request, err
	}
	return request, tx.Commit()
}

func (s *SQLStore) ListPermissionRequests(ctx context.Context, actor sharedkernel.Scope, scope ManagementScope, review bool, status string, page, size int) ([]PermissionRequest, int, error) {
	if page < 1 || size < 1 || size > 100 || scope.Validate() != nil || scope.Type == "global" || scope.Type == "agent_installation" || status != "" && status != "pending" && status != "approved" && status != "rejected" && status != "withdrawn" {
		return nil, 0, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	owner, err := permissionRequestOwner(ctx, tx, actor)
	if err != nil {
		return nil, 0, err
	}
	if err := validatePermissionScope(ctx, tx, scope); err != nil {
		return nil, 0, err
	}
	subject := actor.PrincipalID
	if review {
		decision, err := EvaluatePermission(owner, PermissionQuery{Action: "access_request.decide", Scope: scope, Now: s.clock().UTC()})
		if err != nil {
			return nil, 0, err
		}
		if !decision.Allowed {
			return nil, 0, ErrPermissionDenied
		}
		subject = ""
	} else if scope.TenantID != owner.Principal.TenantID {
		return nil, 0, ErrPermissionDenied
	}
	args := []any{scope.TenantID, scope.DepartmentID, scope.DepartmentID, scope.ApplicationID, scope.ApplicationID, subject, subject, status, status}
	var total int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_permission_request WHERE tenant_id=? AND (?='' OR department_id=?) AND (?='' OR application_id=?) AND (?='' OR subject_id=?) AND (?='' OR status=?)`), args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_identity_permission_request WHERE tenant_id=? AND (?='' OR department_id=?) AND (?='' OR application_id=?) AND (?='' OR subject_id=?) AND (?='' OR status=?) ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`), append(args, size, (page-1)*size)...)
	if err != nil {
		return nil, 0, err
	}
	items := []PermissionRequest{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, 0, err
		}
		var request PermissionRequest
		if err := json.Unmarshal(raw, &request); err != nil {
			rows.Close()
			return nil, 0, err
		}
		items = append(items, request)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, 0, err
	}
	rows.Close()
	return items, total, tx.Commit()
}
