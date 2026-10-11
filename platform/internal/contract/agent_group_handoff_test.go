package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// These cases cover rejection of receipts replayed across generations and
// the independent group-wait boundary; shape alone never proves handler exit.
func TestAgentGroupHandoffGenerationBoundary(t *testing.T) {
	lease := "fixture-old-execution-lease"
	digest := sha256.Sum256([]byte(lease))
	const revision = uint64(5)
	base := (revision - 1) * (1 << 20)
	valid := AgentGroupHandoff{
		Version: "sdk-agent-group-exit/v1", RunID: "run-group-fixture", ExecutionRevision: revision,
		BodyHash: strings.Repeat("a", 64), LeaseTokenHash: hex.EncodeToString(digest[:]),
		InputFingerprint: strings.Repeat("b", 64), OriginOperation: "run",
		GroupKey: "document-coordination", OperationKey: "route:document:v1", LastEventSeq: base + 7,
		Checkpoint: RecoveryCheckpointReference{StateKey: strings.Repeat("c", 64), Revision: 2,
			SchemaID: "schema://agentplug/agent-group/v1", ContentHash: strings.Repeat("d", 64),
			ExecutionRevision: revision, ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)},
		ChildKeys: []string{strings.Repeat("e", 64), strings.Repeat("f", 64)},
	}
	if err := valid.Validate(valid.RunID, revision, valid.BodyHash, lease); err != nil {
		t.Fatalf("valid fixed group receipt rejected: %v", err)
	}
	for name, binding := range map[string]struct {
		run         string
		revision    uint64
		body, lease string
	}{
		"another run":    {"run-other", revision, valid.BodyHash, lease},
		"new generation": {valid.RunID, revision + 1, valid.BodyHash, lease},
		"another body":   {valid.RunID, revision, strings.Repeat("1", 64), lease},
		"new lease":      {valid.RunID, revision, valid.BodyHash, "fixture-new-execution-lease"},
	} {
		t.Run(name, func(t *testing.T) {
			if valid.Validate(binding.run, binding.revision, binding.body, binding.lease) == nil {
				t.Fatal("replayed exit receipt accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*AgentGroupHandoff){
		"old generation event":  func(h *AgentGroupHandoff) { h.LastEventSeq = base },
		"next generation event": func(h *AgentGroupHandoff) { h.LastEventSeq = base + (1 << 20) },
		"duplicate child":       func(h *AgentGroupHandoff) { h.ChildKeys = []string{h.ChildKeys[0], h.ChildKeys[0]} },
		"no children":           func(h *AgentGroupHandoff) { h.ChildKeys = nil },
		"future checkpoint":     func(h *AgentGroupHandoff) { h.Checkpoint.ExecutionRevision++ },
		"human tool checkpoint": func(h *AgentGroupHandoff) { h.Checkpoint.SchemaID = "schema://agentplug/harness-loop/v1" },
		"wildcard operation":    func(h *AgentGroupHandoff) { h.OperationKey = "route:*" },
		"human tool exit":       func(h *AgentGroupHandoff) { h.Version = "sdk-handler-exit/v1" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if candidate.Validate(valid.RunID, revision, valid.BodyHash, lease) == nil {
				t.Fatal("invalid group receipt accepted")
			}
		})
	}
}
