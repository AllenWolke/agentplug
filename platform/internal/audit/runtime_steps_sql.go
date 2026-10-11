package audit

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lexagent/platform/internal/sqlutil"
)

const runtimeAuditActionPlaceholders = "?,?,?,?,?,?,?"

var runtimeAuditActions = []string{
	"runtime.tool.executing",
	"runtime.tool.completed",
	"runtime.tool.failed",
	"runtime.tool.unknown",
	"runtime.tool.preparation_expired",
	"runtime.tool.execution_expired",
	"runtime.tool.receipt_reconciled",
}

type runtimeAuditCandidate struct {
	event       Event
	summarySize int64
}

type matchedRuntimeStep struct {
	candidate  runtimeAuditCandidate
	projection RuntimeExecutionAudit
}

func (s *SQLStore) ListRuntimeSteps(ctx context.Context, query RuntimeStepsQuery) (RuntimeStepsPage, error) {
	if s == nil || s.db == nil || validateRuntimeStepsQuery(query) != nil {
		return RuntimeStepsPage{}, ErrInvalidRuntimeSteps
	}
	page := RuntimeStepsPage{Items: []RuntimeExecutionAudit{}}
	afterTime, afterID, err := decodeRuntimeStepsCursor(query.Cursor, query)
	if err != nil {
		return RuntimeStepsPage{}, err
	}
	where := `tenant_id=? AND department_id=? AND application_id=? AND aggregate_type='run' AND aggregate_id=? AND action IN (` + runtimeAuditActionPlaceholders + `)`
	args := []any{query.Scope.TenantID, query.Scope.DepartmentID, query.Scope.ApplicationID, query.RunID}
	for _, action := range runtimeAuditActions {
		args = append(args, action)
	}
	if !afterTime.IsZero() {
		where += ` AND (created_at<? OR (created_at=? AND event_id<?))`
		args = append(args, afterTime, afterTime, afterID)
	}
	args = append(args, runtimeStepScanLimit+1)
	statement := `SELECT event_id,tenant_id,department_id,application_id,actor_type,actor_id,trace_id,aggregate_type,aggregate_id,action,outcome,CASE WHEN octet_length(summary)<=16384 THEN summary ELSE NULL END,octet_length(summary),created_at FROM platform_audit_event WHERE ` + where + ` ORDER BY created_at DESC,event_id DESC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(statement), args...)
	if err != nil {
		return RuntimeStepsPage{}, fmt.Errorf("list runtime audit steps: %w", err)
	}
	defer rows.Close()
	candidates := make([]runtimeAuditCandidate, 0, runtimeStepScanLimit+1)
	for rows.Next() {
		var item runtimeAuditCandidate
		var summary sql.NullString
		if err := rows.Scan(&item.event.ID, &item.event.TenantID, &item.event.DepartmentID, &item.event.ApplicationID,
			&item.event.ActorType, &item.event.ActorID, &item.event.TraceID, &item.event.AggregateType,
			&item.event.AggregateID, &item.event.Action, &item.event.Outcome, &summary,
			&item.summarySize, &item.event.CreatedAt); err != nil {
			return RuntimeStepsPage{}, fmt.Errorf("scan runtime audit metadata: %w", err)
		}
		if summary.Valid {
			item.event.Summary = summary.String
		}
		if item.event.TenantID != query.Scope.TenantID || item.event.DepartmentID != query.Scope.DepartmentID || item.event.ApplicationID != query.Scope.ApplicationID ||
			item.event.AggregateType != "run" || item.event.AggregateID != query.RunID || !runtimeToolAuditAction(item.event.Action) {
			return RuntimeStepsPage{}, ErrRuntimeStepCorrupt
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		return RuntimeStepsPage{}, fmt.Errorf("iterate runtime audit metadata: %w", err)
	}
	if err := rows.Close(); err != nil {
		return RuntimeStepsPage{}, fmt.Errorf("close runtime audit metadata: %w", err)
	}

	scanCount := min(runtimeStepScanLimit, len(candidates))
	matches := make([]matchedRuntimeStep, 0, min(query.PageSize+1, scanCount))
	for index := 0; index < scanCount; index++ {
		candidate := candidates[index]
		if candidate.summarySize < 0 || candidate.summarySize > runtimeStepSummaryMax || int64(len(candidate.event.Summary)) != candidate.summarySize {
			return RuntimeStepsPage{}, ErrRuntimeStepCorrupt
		}
		projection, err := decodeRuntimeAuditRecord(candidate.event, query.RunID)
		if err != nil {
			return RuntimeStepsPage{}, err
		}
		if query.StepID != "" && projection.StepID != query.StepID {
			continue
		}
		matches = append(matches, matchedRuntimeStep{candidate: candidate, projection: projection})
		if len(matches) > query.PageSize {
			page.Items = append(page.Items, projections(matches[:query.PageSize])...)
			cursor, err := encodeRuntimeStepsCursor(query, matches[query.PageSize-1].candidate.event)
			if err != nil {
				return RuntimeStepsPage{}, err
			}
			page.NextCursor = cursor
			return page, nil
		}
	}
	page.Items = append(page.Items, projections(matches)...)
	if len(candidates) > scanCount && scanCount > 0 {
		cursor, err := encodeRuntimeStepsCursor(query, candidates[scanCount-1].event)
		if err != nil {
			return RuntimeStepsPage{}, err
		}
		page.NextCursor = cursor
	}
	return page, nil
}

func projections(matches []matchedRuntimeStep) []RuntimeExecutionAudit {
	items := make([]RuntimeExecutionAudit, 0, len(matches))
	for _, match := range matches {
		items = append(items, match.projection)
	}
	return items
}

var _ RuntimeStepsReader = (*SQLStore)(nil)
