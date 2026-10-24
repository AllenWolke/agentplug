package capability

import (
	"context"
	"database/sql"
	"encoding/json"

	agenteval "github.com/lexagent/agent-evaluation"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

type ModelPerformanceEvidencePort interface {
	EvaluationModelPerformance(context.Context, sharedkernel.Scope) ([]audit.PerformanceObservation, bool, error)
}

type ModelPerformanceEvidenceProfilePort interface {
	EvaluationModelPerformanceProfile(context.Context, sharedkernel.Scope, string) ([]audit.PerformanceObservation, bool, error)
}

// Only native measurement metadata is extracted; model texts, functions and
// credentials never leave the invocation ledger through this read-only port.
// The composition root still authorizes the exact Run before and after reading.
func (s *SQLModelInvocationStore) EvaluationModelPerformance(ctx context.Context, scope sharedkernel.Scope) ([]audit.PerformanceObservation, bool, error) {
	return s.EvaluationModelPerformanceProfile(ctx, scope, "")
}

func (s *SQLModelInvocationStore) EvaluationModelPerformanceProfile(ctx context.Context, scope sharedkernel.Scope, profile string) ([]audit.PerformanceObservation, bool, error) {
	limits, valid := agenteval.TrajectoryReadLimitsFor(profile)
	if s == nil || s.db == nil || scope.ValidateTrusted() != nil || !valid {
		return nil, false, audit.ErrInvalidPerformanceObservation
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT idempotency_key,
CASE WHEN octet_length(response_json)<=4194304 THEN (response_json::jsonb->'performance_observation')::text ELSE NULL END,
CASE WHEN octet_length(response_json)<=4194304 THEN response_json::jsonb->>'model_version_id' ELSE NULL END,
COALESCE(octet_length(response_json)>4194304,FALSE)
FROM platform_model_invocation WHERE scope_hash IN (?,?) AND status IN ('completed','reconcile')
ORDER BY idempotency_key LIMIT ?`), modelEvidenceScopeHash(scope), modelSelectionScopeHash(scope), limits.ToolInputs+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	items, complete, count := []audit.PerformanceObservation{}, true, 0
	for rows.Next() {
		count++
		if count > limits.ToolInputs {
			complete = false
			break
		}
		var key string
		var raw, version sql.NullString
		var oversized bool
		if err := rows.Scan(&key, &raw, &version, &oversized); err != nil {
			return nil, false, err
		}
		if oversized {
			complete = false
			continue
		}
		if !raw.Valid {
			continue
		} // Historical absence is never reconstructed.
		var observation audit.PerformanceObservation
		if len(raw.String) > 4096 || json.Unmarshal([]byte(raw.String), &observation) != nil {
			return nil, false, audit.ErrInvalidPerformanceObservation
		}
		// Historical fixed-model keys cover a whole session. A receipt from
		// another Run is excluded using its native, original scope fingerprint.
		if !observation.BelongsTo(scope) {
			continue
		}
		step := usagecost.StableModelUsageStepID(usagecost.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID,
			ApplicationID: scope.ApplicationID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, RunID: scope.RunID}, key)
		if observation.Kind != "model_gateway" || !version.Valid || observation.ModelVersionID != version.String || step == nil || observation.UsageStepID != *step {
			return nil, false, audit.ErrInvalidPerformanceObservation
		}
		if observation.HasInconsistentWallDuration(scope) {
			// Old receipts can contain monotonic elapsed time alongside UTC wall
			// timestamps. Preserve the original receipt and known financial result;
			// this timing remains missing and cannot count toward complete samples.
			complete = false
			continue
		}
		if observation.Validate(scope) != nil {
			return nil, false, audit.ErrInvalidPerformanceObservation
		}
		items = append(items, observation)
	}
	return items, complete, rows.Err()
}
