package conversation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
)

func (s *SQLStore) GetSessionResource(ctx context.Context, scope Scope, id string) (SessionResource, error) {
	if scope.Validate() != nil || strings.TrimSpace(id) == "" {
		return SessionResource{}, ErrInvalidQuery
	}
	var resource SessionResource
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,owner_id,principal_type,installation_id,agent_id,agent_version_id,message_count FROM platform_conversation_session WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND status <> 'deleted'`), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID).Scan(&resource.ID, &resource.OwnerID, &resource.PrincipalType, &resource.InstallationID, &resource.AgentID, &resource.AgentVersionID, &resource.MessageCount)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionResource{}, ErrNotFound
	}
	return resource, err
}

// Fixed columns/operators only; resource, subject and selected IDs are bound.
// Task assignment to an execution/task does not authorize its whole session.
func historyAccessWhere(scope Scope, query Query, plan HistoryAccessPlan) (string, []any, error) {
	if scope.Validate() != nil || scope.PrincipalType != "user" || plan.Legacy {
		return "", nil, ErrForbidden
	}
	args := []any{scope.TenantID, scope.DepartmentID, scope.ApplicationID}
	compile := func(clauses []HistoryDataClause) (string, error) {
		parts := []string{}
		for _, clause := range clauses {
			if clause.InstallationID == "" || strings.ContainsAny(clause.InstallationID, "*\x00") {
				return "", ErrForbidden
			}
			selector := ""
			switch clause.Type {
			case "owner":
				if len(clause.IDs) != 0 {
					return "", ErrForbidden
				}
				selector = "owner_id=?"
			case "approved_organization":
				if len(clause.IDs) != 0 {
					return "", ErrForbidden
				}
				selector = "1=1"
			case "assigned_task":
				if len(clause.IDs) != 0 {
					return "", ErrForbidden
				}
				selector = "1=0"
			case "explicit_set":
				if len(clause.IDs) == 0 {
					return "", ErrForbidden
				}
				for _, id := range clause.IDs {
					if strings.TrimSpace(id) == "" || strings.ContainsAny(id, "*\x00") {
						return "", ErrForbidden
					}
				}
				selector = "id IN (" + strings.TrimSuffix(strings.Repeat("?,", len(clause.IDs)), ",") + ")"
			default:
				return "", ErrForbidden
			}
			parts = append(parts, "(installation_id=? AND ("+selector+"))")
			args = append(args, clause.InstallationID)
			if clause.Type == "owner" {
				args = append(args, scope.PrincipalID)
			}
			for _, id := range clause.IDs {
				args = append(args, id)
			}
		}
		if len(parts) == 0 {
			return "1=0", nil
		}
		return strings.Join(parts, " OR "), nil
	}
	allow, err := compile(plan.Allow)
	if err != nil {
		return "", nil, err
	}
	deny, err := compile(plan.Deny)
	if err != nil {
		return "", nil, err
	}
	where := `tenant_id=? AND department_id=? AND application_id=? AND principal_type='user' AND status <> 'deleted' AND (` + allow + `) AND NOT (` + deny + `)`
	if query.View == "mine" {
		where += ` AND owner_id=?`
		args = append(args, scope.PrincipalID)
	}
	if query.Kind != "" {
		where += ` AND kind=?`
		args = append(args, query.Kind)
	}
	if query.Text != "" {
		where += ` AND (title LIKE ? OR preview LIKE ?)`
		pattern := "%" + query.Text + "%"
		args = append(args, pattern, pattern)
	}
	return where, args, nil
}

func (s *SQLStore) ListAuthorized(ctx context.Context, scope Scope, query Query, plan HistoryAccessPlan) (Page, error) {
	query, err := query.Normalize()
	if err != nil {
		return Page{}, err
	}
	where, args, err := historyAccessWhere(scope, query, plan)
	if err != nil {
		return Page{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return Page{}, err
	}
	defer tx.Rollback()
	var total int64
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_session WHERE `+where), args...).Scan(&total); err != nil {
		return Page{}, fmt.Errorf("count authorized history: %w", err)
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT id,kind,agent_id,agent_version_id,installation_id,title,preview,owner_id,status,message_count,can_continue FROM platform_conversation_session WHERE `+where+` ORDER BY updated_at DESC,id DESC LIMIT ? OFFSET ?`), append(args, query.PageSize, (query.Page-1)*query.PageSize)...)
	if err != nil {
		return Page{}, err
	}
	items := []Summary{}
	for rows.Next() {
		var item Summary
		if err := rows.Scan(&item.ID, &item.Kind, &item.AgentID, &item.AgentVersionID, &item.InstallationID, &item.Title, &item.Preview, &item.OwnerID, &item.Status, &item.MessageCount, &item.CanContinue); err != nil {
			rows.Close()
			return Page{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Page{}, err
	}
	if err := rows.Close(); err != nil {
		return Page{}, err
	}
	if err := tx.Commit(); err != nil {
		return Page{}, err
	}
	return Page{Items: items, Total: total, Page: query.Page, Size: query.PageSize}, nil
}

// Resolve export provenance without selecting its sensitive payload.
func (s *SQLStore) GetExportSessionID(ctx context.Context, scope Scope, id string) (string, error) {
	if scope.Validate() != nil || strings.TrimSpace(id) == "" {
		return "", ErrInvalidQuery
	}
	var sessionID string
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT session_id FROM platform_conversation_export WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND principal_type=? AND owner_id=?`), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID).Scan(&sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return sessionID, err
}
