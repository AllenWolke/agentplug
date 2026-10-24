package capability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// Optional read port for a batch's original platform-owned dispatch window.
// The timestamp comes from the durable generation journal, never an Agent clock.
type ExecutionWindowAuthority interface {
	PublishedExecutionWindow(context.Context, sharedkernel.Scope, string, string, string, int) (time.Time, time.Time, error)
}

// harnessPolicy only discloses the bounds of the already pinned runtime asset.
// It uses current caller/workload IAM and the live execution lease, creates no
// model call or charge, and permits no caller-supplied limits or policy ID.
func (m *Module) harnessPolicy(w http.ResponseWriter, r *http.Request) {
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	var input map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(op.Input))
	if decoder.Decode(&input) != nil || input == nil || decoder.Decode(new(any)) != io.EOF ||
		(len(input) != 0 && (len(input) != 1 || string(input["include_batch"]) != "true")) {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "only explicit batch disclosure may be requested", op.Context.TraceID)
		return
	}
	limits, err := op.Policy.Runtime.EffectiveHarnessPolicy()
	if err != nil {
		m.error(w, http.StatusForbidden, "POLICY_DENIED", "invalid published harness limits", op.Context.TraceID)
		return
	}
	encoded, err := json.Marshal(struct {
		Version  string `json:"version"`
		PolicyID string `json:"policy_id"`
		Runtime  any    `json:"runtime"`
	}{"harness-policy/v1", op.Policy.RuntimePolicyID, op.Policy.Runtime})
	if err != nil {
		m.error(w, http.StatusForbidden, "POLICY_DENIED", "harness policy unavailable", op.Context.TraceID)
		return
	}
	result := map[string]any{
		"version": "harness-policy/v1", "policy_hash": fmt.Sprintf("%x", sha256.Sum256(encoded)),
		"server_time_ms": time.Now().UTC().UnixMilli(), "limits": limits,
	}
	if len(input) == 1 {
		if op.Policy.Runtime.ValidateContext() != nil {
			m.error(w, http.StatusForbidden, "POLICY_DENIED", "invalid published execution limits", op.Context.TraceID)
			return
		}
		result["version"] = "harness-policy/v2"
		result["execution"] = map[string]any{"task_timeout_seconds": op.Policy.Runtime.TaskTimeoutSeconds, "batch": op.Policy.Runtime.Batch}
		if batch := op.Policy.Runtime.Batch; batch != nil {
			authority, supported := m.liveAuthority.(ExecutionWindowAuthority)
			claims, claimErr := signedExecutionClaims(op.Context)
			if !supported || claimErr != nil {
				m.error(w, http.StatusServiceUnavailable, "EXECUTION_WINDOW_UNAVAILABLE", "original processing window unavailable", op.Context.TraceID)
				return
			}
			windowCtx := sharedkernel.WithExecutionLease(r.Context(), claims.lease())
			start, deadline, err := authority.PublishedExecutionWindow(windowCtx, scopeFromHarness(op.Context), claims.Actions[0], claims.BodyHash, claims.PolicyHash, batch.ElapsedSeconds)
			if err != nil || start.IsZero() || deadline.Sub(start) != time.Duration(batch.ElapsedSeconds)*time.Second {
				m.error(w, http.StatusServiceUnavailable, "EXECUTION_WINDOW_UNAVAILABLE", "original processing window unavailable", op.Context.TraceID)
				return
			}
			result["execution"] = map[string]any{"task_timeout_seconds": op.Policy.Runtime.TaskTimeoutSeconds, "batch": batch,
				"window": map[string]int64{"started_ms": start.UnixMilli(), "deadline_ms": deadline.UnixMilli()}}
		}
	}
	m.currentResult(w, r, op, result)
}
