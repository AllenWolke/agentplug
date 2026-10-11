package audit

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
)

// MatchesCommittedActorTx verifies approval provenance without reading business
// content or requiring the retry to reuse the original request's trace ID.
func (s *SQLStore) MatchesCommittedActorTx(ctx context.Context, tx *sql.Tx, expected Event) (bool, error) {
	if s == nil || tx == nil || expected.ID == "" || expected.TenantID == "" || expected.DepartmentID == "" || expected.ApplicationID == "" || expected.ActorType == "" || expected.ActorID == "" || expected.AggregateType == "" || expected.AggregateID == "" || expected.Action == "" || expected.Outcome != "success" || expected.CreatedAt.IsZero() {
		return false, ErrInvalidEvent
	}
	var id string
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT event_id FROM platform_audit_event WHERE event_id=? AND tenant_id=? AND department_id=? AND application_id=? AND actor_type=? AND actor_id=? AND aggregate_type=? AND aggregate_id=? AND action=? AND outcome=? AND created_at=? FOR SHARE`), expected.ID, expected.TenantID, expected.DepartmentID, expected.ApplicationID, expected.ActorType, expected.ActorID, expected.AggregateType, expected.AggregateID, expected.Action, expected.Outcome, expected.CreatedAt.UTC()).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
