package capability

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Historical model keys bind the entire original session, not just one run.
// Keep the legacy hash unchanged. An empty session is conservative proof for
// a terminal run; a prior session call prevents this proof, never implies zero.
func modelEvidenceScopeHash(scope sharedkernel.Scope) string {
	raw, _ := json.Marshal([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentInstanceID, scope.PrincipalType, scope.PrincipalID, scope.InstallationID, scope.AgentVersionID, scope.SessionID})
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// EvaluationUsedChatModel is a read-only qualification proof for an already
// verified case Run. It returns no model text or token payloads to its caller.
func (s *SQLModelInvocationStore) EvaluationUsedChatModel(ctx context.Context, scope sharedkernel.Scope, version string) (bool, error) {
	if s == nil || s.db == nil || scope.ValidateTrusted() != nil || strings.TrimSpace(version) == "" {
		return false, ErrModelInvocationConflict
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT status,COALESCE(response_json,'') FROM platform_model_invocation WHERE scope_hash IN (?,?) LIMIT 65`), modelEvidenceScopeHash(scope), modelSelectionScopeHash(scope))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	count, chat := 0, false
	for rows.Next() {
		count++
		var status, raw string
		if err := rows.Scan(&status, &raw); err != nil {
			return false, err
		}
		if status != "completed" || len(raw) > 4*1024*1024 || count > 64 {
			return false, nil
		}
		var receipt struct {
			ModelVersionID string          `json:"model_version_id"`
			Text           *string         `json:"text"`
			Vectors        json.RawMessage `json:"vectors"`
			Billing        *struct {
				CostMicros *int64 `json:"cost_micros"`
				Currency   string `json:"currency"`
			} `json:"billing"`
		}
		if json.Unmarshal([]byte(raw), &receipt) != nil || receipt.Billing == nil || receipt.Billing.CostMicros == nil || *receipt.Billing.CostMicros < 0 || receipt.Billing.Currency != "USD" {
			return false, nil
		}
		if len(receipt.Vectors) > 0 {
			continue
		} // Index embedding is a separate fixed target.
		if receipt.Text == nil || receipt.ModelVersionID != version {
			return false, nil
		}
		chat = true
	}
	return chat, rows.Err()
}

// Callers must first establish a currently authorized terminal run. Checking
// confirmed usage alone cannot establish that no model request was admitted.
type ModelEvaluationEvidencePort interface {
	EvaluationNoModelRequests(context.Context, sharedkernel.Scope) (bool, error)
}

func (s *SQLModelInvocationStore) EvaluationNoModelRequests(ctx context.Context, scope sharedkernel.Scope) (bool, error) {
	if s == nil || s.db == nil || scope.ValidateTrusted() != nil {
		return false, ErrModelInvocationConflict
	}
	var count int64
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_model_invocation WHERE scope_hash IN (?,?)`), modelEvidenceScopeHash(scope), modelSelectionScopeHash(scope)).Scan(&count); err != nil {
		return false, err
	}
	return count == 0, nil
}
