package audit

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"math"
	"strings"
)

func (s *SQLStore) ListMetadata(ctx context.Context, query MetadataQuery) (Page, error) {
	if query.Scope.Validate() != nil {
		return Page{}, ErrInvalidEvent
	}
	if query.Page < 1 {
		query.Page = 1
	}
	if query.PageSize < 1 {
		query.PageSize = 20
	}
	if query.PageSize > 100 {
		query.PageSize = 100
	}
	if int64(query.Page) > math.MaxInt64/int64(query.PageSize) {
		return Page{}, ErrInvalidEvent
	}
	where, args := "1=1", []any{}
	for _, axis := range []struct{ field, value string }{{"tenant_id", query.Scope.TenantID}, {"department_id", query.Scope.DepartmentID}, {"application_id", query.Scope.ApplicationID}} {
		if axis.value != "" {
			where += " AND " + axis.field + "=?"
			args = append(args, axis.value)
		}
	}
	task, trace := strings.TrimSpace(query.TaskID), strings.TrimSpace(query.TraceID)
	if task != "" && trace != "" {
		where += " AND (aggregate_id=? OR trace_id=?)"
		args = append(args, task, trace)
	} else if task != "" {
		where += " AND aggregate_id=?"
		args = append(args, task)
	} else if trace != "" {
		where += " AND trace_id=?"
		args = append(args, trace)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Page{}, err
	}
	defer tx.Rollback()
	result := Page{Items: []Event{}, Page: query.Page, PageSize: query.PageSize, MetadataOnly: true}
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event WHERE `+where), args...).Scan(&result.Total); err != nil {
		return Page{}, fmt.Errorf("count audit metadata: %w", err)
	}
	// Summary is deliberately absent: row-level metadata authority cannot read
	// arbitrary business text, including historically stored sensitive summaries.
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT event_id,tenant_id,department_id,application_id,actor_type,actor_id,trace_id,aggregate_type,aggregate_id,action,outcome,created_at FROM platform_audit_event WHERE `+where+` ORDER BY created_at DESC,event_id DESC LIMIT ? OFFSET ?`), append(args, query.PageSize, (int64(query.Page)-1)*int64(query.PageSize))...)
	if err != nil {
		return Page{}, fmt.Errorf("list audit metadata: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item Event
		if err := rows.Scan(&item.ID, &item.TenantID, &item.DepartmentID, &item.ApplicationID, &item.ActorType, &item.ActorID, &item.TraceID, &item.AggregateType, &item.AggregateID, &item.Action, &item.Outcome, &item.CreatedAt); err != nil {
			return Page{}, err
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return Page{}, err
	}
	if err := rows.Close(); err != nil {
		return Page{}, err
	}
	if err := tx.Commit(); err != nil {
		return Page{}, err
	}
	return result, nil
}

var _ MetadataReader = (*SQLStore)(nil)
