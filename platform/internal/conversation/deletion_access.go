package conversation

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
)

type DeletionAccessControl interface {
	DeletionReadPlan(context.Context, Scope) (HistoryAccessPlan, error)
}

type AuthorizedDeletionStore interface {
	ListDeletionRequestsAuthorized(context.Context, Scope, int, int, HistoryAccessPlan) ([]DeletionRequest, int64, error)
	ApproveDeletionAuthorized(context.Context, Scope, string, func(context.Context, SessionResource) error) (DeletionRequest, error)
}

var ErrDeletionRecorderUnavailable = errors.New("deletion approval recorder unavailable")

type DeletionApprovalRecorder func(context.Context, *sql.Tx, Scope, DeletionRequest) error

// Replay needs the immutable committed approval actor, never a browser-supplied identity.
type DeletionApprovalReplayChecker func(context.Context, *sql.Tx, Scope, DeletionRequest) (bool, error)

func (s *SQLStore) SetDeletionApprovalReplayChecker(check DeletionApprovalReplayChecker) {
	s.deletionReplay = check
}

func (s *SQLStore) replayDeletionApproval(ctx context.Context, tx *sql.Tx, scope Scope, item DeletionRequest, check func(context.Context, SessionResource) error) (DeletionRequest, error) {
	if s.deletionReplay == nil || item.ApprovedAt.IsZero() {
		return DeletionRequest{}, ErrForbidden
	}
	matched, err := s.deletionReplay(ctx, tx, scope, item)
	if err != nil {
		return DeletionRequest{}, err
	}
	if !matched {
		return DeletionRequest{}, ErrForbidden
	}
	var resource SessionResource
	var status string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,owner_id,principal_type,installation_id,agent_id,agent_version_id,status FROM platform_conversation_session WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND owner_id=? FOR UPDATE`), item.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, item.OwnerID).Scan(&resource.ID, &resource.OwnerID, &resource.PrincipalType, &resource.InstallationID, &resource.AgentID, &resource.AgentVersionID, &status)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && status != "deleted") {
		return DeletionRequest{}, ErrNotFound
	}
	if err != nil {
		return DeletionRequest{}, err
	}
	if err := check(ctx, resource); err != nil {
		return DeletionRequest{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeletionRequest{}, err
	}
	return item, nil
}

func (s *SQLStore) SetDeletionApprovalRecorder(recorder DeletionApprovalRecorder) {
	s.deletionRecorder = recorder
}

func (s *SQLStore) SetDeletionContinuityGuard(guard func(context.Context, *sql.Tx) error) {
	s.deletionGuard = guard
}

func (s *SQLStore) ApproveDeletionAuthorized(ctx context.Context, scope Scope, id string, check func(context.Context, SessionResource) error) (DeletionRequest, error) {
	if scope.PrincipalType != "user" || strings.TrimSpace(id) == "" || check == nil {
		return DeletionRequest{}, ErrForbidden
	}
	return s.approveDeletionWithCheck(ctx, scope, id, check)
}

func (s *SQLStore) ListDeletionRequestsAuthorized(ctx context.Context, scope Scope, page, size int, plan HistoryAccessPlan) ([]DeletionRequest, int64, error) {
	where, args, err := historyAccessWhere(scope, Query{}, plan)
	if err != nil {
		return nil, 0, err
	}
	page, size = maxPage(page), maxSize(size)
	filter := `tenant_id=? AND department_id=? AND application_id=? AND status='pending' AND owner_id<>? AND session_id IN (SELECT id FROM platform_conversation_session WHERE ` + where + `)`
	args = append([]any{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalID}, args...)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var total int64
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_deletion WHERE `+filter), args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT id,session_id,owner_id,reason,status,requested_at FROM platform_conversation_deletion WHERE `+filter+` ORDER BY requested_at DESC,id DESC LIMIT ? OFFSET ?`), append(args, size, (page-1)*size)...)
	if err != nil {
		return nil, 0, err
	}
	items := []DeletionRequest{}
	for rows.Next() {
		var item DeletionRequest
		if err := rows.Scan(&item.ID, &item.SessionID, &item.OwnerID, &item.Reason, &item.Status, &item.RequestedAt); err != nil {
			rows.Close()
			return nil, 0, err
		}
		items = append(items, item)
	}
	rowErr := rows.Err()
	if err := rows.Close(); err != nil {
		return nil, 0, err
	}
	if rowErr != nil {
		return nil, 0, rowErr
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (m *Module) deletionPlan(ctx context.Context, scope Scope) (HistoryAccessPlan, error) {
	if m.access == nil {
		return HistoryAccessPlan{Legacy: true}, nil
	}
	control, ok := m.access.(DeletionAccessControl)
	if !ok {
		return HistoryAccessPlan{}, ErrForbidden
	}
	return control.DeletionReadPlan(ctx, scope)
}
