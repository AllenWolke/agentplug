package audit

import (
	"context"
	"database/sql"

	agenteval "github.com/lexagent/agent-evaluation"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// The caller must authorize current exact-Run history and metadata access
// before AND after reading. This port cannot enable application-wide browsing.
func (s *SQLStore) ReadPerformanceObservations(ctx context.Context, scope sharedkernel.Scope) ([]PerformanceObservation, bool, error) {
	return s.ReadPerformanceObservationsProfile(ctx, scope, "")
}

func (s *SQLStore) ReadPerformanceObservationsProfile(ctx context.Context, scope sharedkernel.Scope, profile string) ([]PerformanceObservation, bool, error) {
	limits, valid := agenteval.TrajectoryReadLimitsFor(profile)
	if s == nil || s.db == nil || scope.ValidateTrusted() != nil || !valid {
		return nil, false, ErrInvalidPerformanceObservation
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT event_id,action,outcome,actor_type,actor_id,
		CASE WHEN octet_length(summary)<=4096 THEN summary ELSE NULL END
		FROM platform_audit_event WHERE tenant_id=? AND department_id=? AND application_id=?
		AND aggregate_type='run' AND aggregate_id=? AND action IN ('runtime.performance.model_gateway','runtime.performance.knowledge_query')
		ORDER BY created_at,event_id LIMIT ?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.RunID, limits.Events+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	items := []PerformanceObservation{}
	complete := true
	for rows.Next() {
		if len(items) == limits.Events {
			complete = false
			break
		}
		var id, action, status, actorType, actorID string
		var summary sql.NullString
		if err := rows.Scan(&id, &action, &status, &actorType, &actorID, &summary); err != nil {
			return nil, false, err
		}
		if !summary.Valid || actorType != scope.PrincipalType || actorID != scope.PrincipalID {
			return nil, false, ErrInvalidPerformanceObservation
		}
		o, err := decodePerformanceObservation(summary.String, scope)
		if err != nil || o.StepID != id || action != "runtime.performance."+o.Kind || status != o.Status {
			return nil, false, ErrInvalidPerformanceObservation
		}
		items = append(items, o)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return items, complete, nil
}
