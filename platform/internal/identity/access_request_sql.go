package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

var _ AgentAccessRequestRepository = (*SQLStore)(nil)

func (s *SQLStore) CreateAgentAccessRequest(ctx context.Context, request AgentAccessRequest) (AgentAccessRequest, error) {
	if s == nil || s.db == nil {
		return AgentAccessRequest{}, errors.New("identity database is required")
	}
	if err := validateAgentAccessRequest(request); err != nil {
		return AgentAccessRequest{}, err
	}
	actions, err := json.Marshal(request.Actions)
	if err != nil {
		return AgentAccessRequest{}, fmt.Errorf("encode agent access request actions: %w", err)
	}
	now := s.clock().UTC()
	request.CreatedAt, request.UpdatedAt = now, now
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AgentAccessRequest{}, fmt.Errorf("begin agent access request: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return AgentAccessRequest{}, err
	}
	if err := requireLegacyAccessRequestSubject(ctx, tx, request.SubjectID); err != nil {
		return AgentAccessRequest{}, err
	}
	var exists int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_identity_application WHERE id=? AND tenant_id=? AND department_id=? AND status=? FOR UPDATE`), request.ApplicationID, request.TenantID, request.DepartmentID, "active").Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AgentAccessRequest{}, ErrApplicationNotFound
		}
		return AgentAccessRequest{}, fmt.Errorf("validate agent access application: %w", err)
	}
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_identity_principal WHERE principal_type=? AND id=? AND tenant_id=? AND active=? FOR UPDATE`), request.SubjectType, request.SubjectID, request.TenantID, true).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AgentAccessRequest{}, ErrPrincipalNotFound
		}
		return AgentAccessRequest{}, fmt.Errorf("validate agent access requester: %w", err)
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_agent_access_request
		(id,tenant_id,department_id,application_id,agent_id,agent_instance_id,subject_type,subject_id,actions_json,reason,status,reviewer_id,comment,revision,pending_key_hash,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), request.ID, request.TenantID, request.DepartmentID, request.ApplicationID,
		request.AgentID, request.AgentInstanceID, request.SubjectType, request.SubjectID, string(actions), request.Reason,
		request.Status, request.ReviewerID, request.Comment, request.Revision, pendingAccessRequestKey(request), now, now)
	if err != nil {
		return AgentAccessRequest{}, identityPersistenceError("create agent access request", err)
	}
	if err := tx.Commit(); err != nil {
		return AgentAccessRequest{}, fmt.Errorf("commit agent access request: %w", err)
	}
	return request, nil
}

func (s *SQLStore) ListAgentAccessRequests(ctx context.Context, scope sharedkernel.Scope, subjectID, status string) ([]AgentAccessRequest, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("identity database is required")
	}
	if err := scope.Validate(); err != nil || scope.TenantID == "" || scope.DepartmentID == "" || scope.ApplicationID == "" {
		return nil, sharedkernel.ErrInvalidScope
	}
	query := `SELECT id,tenant_id,department_id,application_id,agent_id,agent_instance_id,subject_type,subject_id,actions_json,reason,status,reviewer_id,comment,revision,created_at,updated_at
		FROM platform_identity_agent_access_request WHERE tenant_id=? AND department_id=? AND application_id=?`
	args := []any{scope.TenantID, scope.DepartmentID, scope.ApplicationID}
	if subjectID != "" {
		query += ` AND subject_id=? AND subject_type=?`
		args = append(args, subjectID, PrincipalUser)
	}
	if status != "" {
		query += ` AND status=?`
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC,id DESC LIMIT 100`
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("list agent access requests: %w", err)
	}
	defer rows.Close()
	items := make([]AgentAccessRequest, 0)
	for rows.Next() {
		item, err := scanAgentAccessRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("scan agent access request: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate agent access requests: %w", err)
	}
	return items, nil
}

func (s *SQLStore) DecideAgentAccessRequest(ctx context.Context, scope sharedkernel.Scope, requestID, reviewerID, decision string, expectedRevision uint64, comment string) (AgentAccessRequest, error) {
	if s == nil || s.db == nil {
		return AgentAccessRequest{}, errors.New("identity database is required")
	}
	if err := scope.Validate(); err != nil || scope.TenantID == "" || scope.DepartmentID == "" || scope.ApplicationID == "" || strings.TrimSpace(requestID) == "" || strings.TrimSpace(reviewerID) == "" || expectedRevision == 0 || (decision != AgentAccessRequestApproved && decision != AgentAccessRequestRejected) || len(strings.TrimSpace(comment)) < 2 || len(comment) > 1000 {
		return AgentAccessRequest{}, ErrInvalidAccessRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AgentAccessRequest{}, fmt.Errorf("begin agent access decision: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return AgentAccessRequest{}, err
	}
	var mode string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT policy_mode FROM platform_identity_policy_migration WHERE principal_type='user' AND subject_id=?`), reviewerID).Scan(&mode)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return AgentAccessRequest{}, err
	}
	if err == nil && mode != "legacy" {
		return AgentAccessRequest{}, ErrPermissionDenied
	}
	request, err := scanAgentAccessRequest(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,tenant_id,department_id,application_id,agent_id,agent_instance_id,subject_type,subject_id,actions_json,reason,status,reviewer_id,comment,revision,created_at,updated_at
		FROM platform_identity_agent_access_request WHERE tenant_id=? AND department_id=? AND application_id=? AND id=? FOR UPDATE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, requestID))
	if errors.Is(err, sql.ErrNoRows) {
		return AgentAccessRequest{}, ErrAccessRequestNotFound
	}
	if err != nil {
		return AgentAccessRequest{}, fmt.Errorf("load agent access request for decision: %w", err)
	}
	if err := requireLegacyAccessRequestSubject(ctx, tx, request.SubjectID); err != nil {
		return AgentAccessRequest{}, err
	}
	var imported int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_permission_request WHERE id=?`), request.ID).Scan(&imported); err != nil {
		return AgentAccessRequest{}, err
	}
	if imported != 0 {
		return AgentAccessRequest{}, ErrPermissionDenied
	}
	if request.Status != AgentAccessRequestPending || request.Revision != expectedRevision {
		return AgentAccessRequest{}, ErrIdentityConflict
	}
	if request.SubjectID == reviewerID {
		return AgentAccessRequest{}, ErrAccessRequestSelfReview
	}
	if decision == AgentAccessRequestApproved {
		if err := s.applyAgentAccessRequestGrants(ctx, tx, request); err != nil {
			return AgentAccessRequest{}, err
		}
	}
	now := s.clock().UTC()
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_agent_access_request
		SET status=?,reviewer_id=?,comment=?,revision=revision+1,pending_key_hash=NULL,updated_at=?
		WHERE tenant_id=? AND department_id=? AND application_id=? AND id=? AND status=? AND revision=?`), decision, reviewerID, strings.TrimSpace(comment), now, scope.TenantID, scope.DepartmentID, scope.ApplicationID, requestID, AgentAccessRequestPending, expectedRevision)
	if err != nil {
		return AgentAccessRequest{}, fmt.Errorf("update agent access request decision: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return AgentAccessRequest{}, fmt.Errorf("read agent access decision rows: %w", err)
	}
	if rows != 1 {
		return AgentAccessRequest{}, ErrIdentityConflict
	}
	request.Status, request.ReviewerID, request.Comment = decision, reviewerID, strings.TrimSpace(comment)
	request.Revision++
	request.UpdatedAt = now
	if s.accessDecisionRecorder == nil {
		return AgentAccessRequest{}, ErrAccessDecisionRecorderUnavailable
	}
	if err := s.accessDecisionRecorder(ctx, tx, scope, request); err != nil {
		return AgentAccessRequest{}, fmt.Errorf("record agent access decision side effects: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return AgentAccessRequest{}, fmt.Errorf("commit agent access decision: %w", err)
	}
	return request, nil
}

func requireLegacyAccessRequestSubject(ctx context.Context, tx *sql.Tx, subjectID string) error {
	var mode string
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT policy_mode FROM platform_identity_policy_migration WHERE principal_type='user' AND subject_id=?`), subjectID).Scan(&mode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if mode != "legacy" && mode != "shadow" {
		return ErrPermissionDenied
	}
	return nil
}

func (s *SQLStore) applyAgentAccessRequestGrants(ctx context.Context, tx *sql.Tx, request AgentAccessRequest) error {
	var exists int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_identity_application WHERE id=? AND tenant_id=? AND department_id=? AND status=? FOR UPDATE`), request.ApplicationID, request.TenantID, request.DepartmentID, "active").Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrApplicationNotFound
		}
		return fmt.Errorf("validate access request application: %w", err)
	}
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_identity_principal WHERE principal_type=? AND id=? AND tenant_id=? AND active=? FOR UPDATE`), request.SubjectType, request.SubjectID, request.TenantID, true).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPrincipalNotFound
		}
		return fmt.Errorf("validate access request subject: %w", err)
	}
	for _, action := range request.Actions {
		var denyStatus string
		err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_identity_grant WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_instance_id=? AND subject_type=? AND subject_id=? AND action=? AND effect='deny' LIMIT 1 FOR UPDATE`), request.TenantID, request.DepartmentID, request.ApplicationID, request.AgentInstanceID, request.SubjectType, request.SubjectID, action).Scan(&denyStatus)
		if err == nil && denyStatus == GrantActive {
			return ErrIdentityConflict
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check deny grant before approval: %w", err)
		}
		var grantID, status string
		var revision uint64
		err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,status,revision FROM platform_identity_grant WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_instance_id=? AND subject_type=? AND subject_id=? AND action=? AND effect='allow' FOR UPDATE`), request.TenantID, request.DepartmentID, request.ApplicationID, request.AgentInstanceID, request.SubjectType, request.SubjectID, action).Scan(&grantID, &status, &revision)
		if err == nil {
			if status == GrantActive {
				continue
			}
			result, updateErr := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET status=?,revision=revision+1 WHERE id=? AND status=? AND revision=?`), GrantActive, grantID, GrantRevoked, revision)
			if updateErr != nil {
				return fmt.Errorf("reactivate agent grant: %w", updateErr)
			}
			updated, rowsErr := result.RowsAffected()
			if rowsErr != nil {
				return fmt.Errorf("read reactivated agent grant rows: %w", rowsErr)
			}
			if updated != 1 {
				return ErrIdentityConflict
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("find existing agent grant: %w", err)
		}
		grant := Grant{ID: accessRequestGrantID(request.ID, action), TenantID: request.TenantID, DepartmentID: request.DepartmentID, ApplicationID: request.ApplicationID, AgentInstanceID: request.AgentInstanceID, SubjectType: request.SubjectType, SubjectID: request.SubjectID, Action: action, Effect: "allow", Status: GrantActive, Revision: 1}
		if err := grant.Validate(); err != nil {
			return ErrInvalidAccessRequest
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_grant(id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision,grant_key_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`), grant.ID, grant.TenantID, grant.DepartmentID, grant.ApplicationID, grant.AgentInstanceID, grant.SubjectType, grant.SubjectID, grant.Action, grant.Effect, grant.Status, grant.Revision, grantKeyHash(grant), s.clock().UTC()); err != nil {
			return identityPersistenceError("create grant from access request", err)
		}
	}
	return nil
}

type agentAccessRequestScanner interface {
	Scan(...any) error
}

func scanAgentAccessRequest(scanner agentAccessRequestScanner) (AgentAccessRequest, error) {
	var request AgentAccessRequest
	var actionsJSON string
	err := scanner.Scan(&request.ID, &request.TenantID, &request.DepartmentID, &request.ApplicationID, &request.AgentID, &request.AgentInstanceID, &request.SubjectType, &request.SubjectID, &actionsJSON, &request.Reason, &request.Status, &request.ReviewerID, &request.Comment, &request.Revision, &request.CreatedAt, &request.UpdatedAt)
	if err != nil {
		return AgentAccessRequest{}, err
	}
	if err := json.Unmarshal([]byte(actionsJSON), &request.Actions); err != nil {
		return AgentAccessRequest{}, fmt.Errorf("decode stored agent access actions: %w", err)
	}
	return request, nil
}

func validateAgentAccessRequest(request AgentAccessRequest) error {
	if strings.TrimSpace(request.ID) == "" || strings.TrimSpace(request.TenantID) == "" || strings.TrimSpace(request.DepartmentID) == "" || strings.TrimSpace(request.ApplicationID) == "" || strings.TrimSpace(request.AgentID) == "" || strings.TrimSpace(request.AgentInstanceID) == "" || request.SubjectType != PrincipalUser || strings.TrimSpace(request.SubjectID) == "" || strings.TrimSpace(request.Reason) == "" || request.Status != AgentAccessRequestPending || request.Revision != 1 {
		return ErrInvalidAccessRequest
	}
	if _, ok := normalizeAgentAccessActions(request.Actions); !ok || len(request.Reason) < 10 || len(request.Reason) > 1000 {
		return ErrInvalidAccessRequest
	}
	return nil
}

func pendingAccessRequestKey(request AgentAccessRequest) string {
	key := strings.Join([]string{request.TenantID, request.DepartmentID, request.ApplicationID, request.AgentInstanceID, string(request.SubjectType), request.SubjectID}, "\x00")
	digest := sha256.Sum256([]byte(key))
	return hex.EncodeToString(digest[:])
}

func accessRequestGrantID(requestID, action string) string {
	digest := sha256.Sum256([]byte(requestID + "\x00" + action))
	return "iag_" + hex.EncodeToString(digest[:16])
}
