package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// AgentGroupHandoff proves only that the concrete SDK handler exited at a
// persisted group wait. It neither approves a Tool nor authorizes a child.
type AgentGroupHandoff struct {
	Version           string                      `json:"version"`
	RunID             string                      `json:"run_id"`
	ExecutionRevision uint64                      `json:"execution_revision"`
	BodyHash          string                      `json:"body_hash"`
	LeaseTokenHash    string                      `json:"lease_token_hash"`
	InputFingerprint  string                      `json:"input_fingerprint"`
	OriginOperation   string                      `json:"origin_operation"`
	GroupKey          string                      `json:"group_key"`
	OperationKey      string                      `json:"operation_key"`
	LastEventSeq      uint64                      `json:"last_event_seq"`
	Checkpoint        RecoveryCheckpointReference `json:"checkpoint"`
	ChildKeys         []string                    `json:"child_keys"`
}

func (h AgentGroupHandoff) Validate(runID string, revision uint64, bodyHash, leaseToken string) error {
	if h.ValidateStoredShape(runID, revision) != nil || h.BodyHash != bodyHash || leaseToken == "" {
		return fmt.Errorf("%w: agent group exit binding", ErrSchemaValidation)
	}
	digest := sha256.Sum256([]byte(leaseToken))
	if h.LeaseTokenHash != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("%w: agent group exit binding", ErrSchemaValidation)
	}
	return nil
}

// ValidateStoredShape checks bounded metadata only. It proves neither actual
// handler exit nor old lease possession; those are independently established
// by the execution store's committed waiting/queue transactions.
func (h AgentGroupHandoff) ValidateStoredShape(runID string, revision uint64) error {
	invalid := fmt.Errorf("%w: agent group exit binding", ErrSchemaValidation)
	if h.Version != "sdk-agent-group-exit/v1" || h.RunID != runID || !handoffIdentifier.MatchString(runID) ||
		h.ExecutionRevision == 0 || h.ExecutionRevision > (1<<33)-3 || h.ExecutionRevision != revision ||
		!handoffDigest.MatchString(h.BodyHash) ||
		!handoffDigest.MatchString(h.LeaseTokenHash) || !handoffDigest.MatchString(h.InputFingerprint) ||
		(h.OriginOperation != "invoke" && h.OriginOperation != "run") || !handoffKey.MatchString(h.GroupKey) ||
		!validGroupOperationKey(h.OperationKey) || h.Checkpoint.SchemaID != "schema://agentplug/agent-group/v1" ||
		h.Checkpoint.Validate(h.ExecutionRevision) != nil || len(h.ChildKeys) == 0 || len(h.ChildKeys) > 16 {
		return invalid
	}
	base := (h.ExecutionRevision - 1) * (1 << 20)
	if h.LastEventSeq <= base || h.LastEventSeq >= base+(1<<20) || h.LastEventSeq > MaxAgentEventSequence {
		return invalid
	}
	seen := map[string]bool{}
	for _, key := range h.ChildKeys {
		if !handoffDigest.MatchString(key) || seen[key] {
			return invalid
		}
		seen[key] = true
	}
	return nil
}

func validGroupOperationKey(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "*\x00\r\n")
}
