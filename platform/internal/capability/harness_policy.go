package capability

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

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
	if decoder.Decode(&input) != nil || input == nil || len(input) != 0 || decoder.Decode(new(any)) != io.EOF {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "harness policy input must be an empty object", op.Context.TraceID)
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
	m.currentResult(w, r, op, map[string]any{
		"version": "harness-policy/v1", "policy_hash": fmt.Sprintf("%x", sha256.Sum256(encoded)),
		"server_time_ms": time.Now().UTC().UnixMilli(), "limits": limits,
	})
}
