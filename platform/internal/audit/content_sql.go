package audit

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
)

func (s *SQLStore) GetEventMetadata(ctx context.Context, scope MetadataScope, id string) (Event, error) {
	if scope.Validate() != nil || scope.Type != "application" || !validEventID(id) {
		return Event{}, ErrInvalidEvent
	}
	var e Event
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT event_id,tenant_id,department_id,application_id,actor_type,actor_id,trace_id,aggregate_type,aggregate_id,action,outcome,created_at FROM platform_audit_event WHERE event_id=? AND tenant_id=? AND department_id=? AND application_id=?`), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID).Scan(&e.ID, &e.TenantID, &e.DepartmentID, &e.ApplicationID, &e.ActorType, &e.ActorID, &e.TraceID, &e.AggregateType, &e.AggregateID, &e.Action, &e.Outcome, &e.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Event{}, ErrNotFound
	}
	return e, err
}

func (s *SQLStore) GetEventContent(ctx context.Context, header Event) (Event, error) {
	if header.Validate() != nil || header.Summary != "" {
		return Event{}, ErrInvalidEvent
	}
	var summary string
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT summary FROM platform_audit_event WHERE event_id=? AND tenant_id=? AND department_id=? AND application_id=? AND aggregate_type=? AND aggregate_id=?`), header.ID, header.TenantID, header.DepartmentID, header.ApplicationID, header.AggregateType, header.AggregateID).Scan(&summary)
	if errors.Is(err, sql.ErrNoRows) {
		return Event{}, ErrNotFound
	}
	header.Summary = summary
	return header, err
}

var _ ContentReader = (*SQLStore)(nil)
