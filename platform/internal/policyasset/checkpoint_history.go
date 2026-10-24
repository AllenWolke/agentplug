package policyasset

import (
	"fmt"
	"github.com/lexagent/platform/internal/contract"
)

const DefaultCheckpointRevisions uint64 = 64
const MaximumCheckpointRevisions uint64 = contract.MaxCheckpointRevisions

// CheckpointHistoryPolicy is public State capacity, independent of any Agent
// framework or business domain. Absence keeps the historical revision limit.
type CheckpointHistoryPolicy struct {
	Version      string `json:"version"`
	MaxRevisions uint64 `json:"max_revisions"`
}

func (p MemoryPolicy) ValidateCheckpointHistory() error {
	if p.CheckpointHistory == nil {
		return nil
	}
	if p.CheckpointHistory.Version != "checkpoint-history/v1" || p.CheckpointHistory.MaxRevisions == 0 || p.CheckpointHistory.MaxRevisions > MaximumCheckpointRevisions {
		return fmt.Errorf("invalid published checkpoint history capacity")
	}
	return nil
}

func (p MemoryPolicy) CheckpointRevisionLimit() uint64 {
	if p.CheckpointHistory == nil {
		return DefaultCheckpointRevisions
	}
	return p.CheckpointHistory.MaxRevisions
}
