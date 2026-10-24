package capability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"

	agenteval "github.com/lexagent/agent-evaluation"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

const toolInputEvidenceMax = 16 << 10

// Optional immutable input evidence belongs to the protected invocation ledger,
// not public runtime audit metadata or logs. Historical calls remain unknown.
type ToolInputEvidence struct {
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func toolInputEvidence(payload map[string]any) *ToolInputEvidence {
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) > toolInputEvidenceMax {
		return nil
	}
	return &ToolInputEvidence{Arguments: raw}
}

type ToolEvaluationEvidence struct {
	StepID    string
	CallID    string
	ToolName  string
	Arguments map[string]any
}

// The composition root must check current history authorization before and
// after reading. This Port never offers application-wide or audit-role access.
type ToolEvaluationEvidencePort interface {
	EvaluationToolEvidence(context.Context, sharedkernel.Scope) ([]ToolEvaluationEvidence, bool, error)
}

type ToolEvaluationEvidenceV2Port interface {
	EvaluationToolEvidenceV2(context.Context, sharedkernel.Scope) ([]ToolEvaluationEvidence, bool, error)
}

// Optional capacity selection shares the protected ledger reader. Implementers
// must retain exact scope binding, fingerprints and per-record disclosure limits.
type ToolEvaluationEvidenceProfilePort interface {
	EvaluationToolEvidenceProfile(context.Context, sharedkernel.Scope, string, string) ([]ToolEvaluationEvidence, bool, error)
}

func decodeToolEvaluationEvidence(scope sharedkernel.Scope, callID, fingerprint, raw string) (ToolEvaluationEvidence, error) {
	return decodeToolEvaluationEvidenceProjection(scope, callID, fingerprint, raw, false)
}

func decodeToolEvaluationEvidenceProjection(scope sharedkernel.Scope, callID, fingerprint, raw string, partial bool) (ToolEvaluationEvidence, error) {
	var q ToolReceiptQuery
	if len(raw) > 65536 || json.Unmarshal([]byte(raw), &q) != nil || q.Scope.ValidateTrusted() != nil || ToolReceiptScopeHash(q.Scope) != ToolReceiptScopeHash(scope) || q.CallID != callID || q.Fingerprint != fingerprint || q.Name == "" {
		return ToolEvaluationEvidence{}, ErrToolInvocationConflict
	}
	step := sha256.Sum256([]byte(ToolReceiptScopeHash(scope) + "\x00" + callID))
	out := ToolEvaluationEvidence{StepID: fmt.Sprintf("runtime-%x", step), CallID: callID, ToolName: q.Name}
	if q.InputEvidence == nil || len(q.InputEvidence.Arguments) == 0 {
		return out, nil
	}
	if len(q.InputEvidence.Arguments) > toolInputEvidenceMax {
		return ToolEvaluationEvidence{}, ErrToolInvocationConflict
	}
	var arguments map[string]any
	d := json.NewDecoder(bytes.NewReader(q.InputEvidence.Arguments))
	d.UseNumber()
	if d.Decode(&arguments) != nil || arguments == nil || d.Decode(new(any)) != io.EOF {
		return ToolEvaluationEvidence{}, ErrToolInvocationConflict
	}
	expected, err := ToolCommandFingerprint(q.Name, arguments)
	if err != nil || expected != fingerprint {
		return ToolEvaluationEvidence{}, ErrToolInvocationConflict
	}
	// Source disclosure is redacted through the same public evaluation contract.
	// If anything was redacted/truncated, parameters stay unknown, not incorrect.
	safe := agenteval.Sanitize(arguments)
	encoded, err := json.Marshal(safe)
	original, originalErr := json.Marshal(arguments)
	if err == nil && originalErr == nil && (partial || bytes.Equal(encoded, original)) {
		out.Arguments, _ = safe.(map[string]any)
	}
	return out, nil
}

func (s *SQLToolInvocationStore) EvaluationToolEvidence(ctx context.Context, scope sharedkernel.Scope) ([]ToolEvaluationEvidence, bool, error) {
	return s.EvaluationToolEvidenceProfile(ctx, scope, "", "")
}

func (s *SQLToolInvocationStore) EvaluationToolEvidenceV2(ctx context.Context, scope sharedkernel.Scope) ([]ToolEvaluationEvidence, bool, error) {
	return s.EvaluationToolEvidenceProfile(ctx, scope, agenteval.ToolArgumentProjectionV2, "")
}

func (s *SQLToolInvocationStore) EvaluationToolEvidenceProfile(ctx context.Context, scope sharedkernel.Scope, projection, profile string) ([]ToolEvaluationEvidence, bool, error) {
	limits, valid := agenteval.TrajectoryReadLimitsFor(profile)
	if s == nil || s.db == nil || scope.ValidateTrusted() != nil || !valid || (projection != "" && projection != agenteval.ToolArgumentProjectionV2) {
		return nil, false, ErrToolInvocationConflict
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT call_id,fingerprint,recovery_query FROM platform_tool_invocation WHERE scope_hash=? ORDER BY created_at,call_id LIMIT ?`), ToolReceiptScopeHash(scope), limits.ToolInputs+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []ToolEvaluationEvidence{}
	bytesRead := 0
	rowsRead := 0
	complete := true
	for rows.Next() {
		var callID, fingerprint string
		var raw sql.NullString
		if err := rows.Scan(&callID, &fingerprint, &raw); err != nil {
			return nil, false, err
		}
		if rowsRead == limits.ToolInputs || bytesRead+len(raw.String) > limits.ToolInputBytes {
			complete = false
			break
		}
		bytesRead += len(raw.String)
		rowsRead++
		if !raw.Valid {
			continue // Old calls without recoverable input are not invented.
		}
		evidence, err := decodeToolEvaluationEvidenceProjection(scope, callID, fingerprint, raw.String, projection == agenteval.ToolArgumentProjectionV2)
		if err != nil {
			return nil, false, err
		}
		out = append(out, evidence)
	}
	return out, complete, rows.Err()
}
