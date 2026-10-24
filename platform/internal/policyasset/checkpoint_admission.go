package policyasset

import "fmt"

// Optional quota admission separates resource reservation from State data.
// It grants no execution authority and carries no business-domain concepts.
type CheckpointAdmissionPolicy struct {
	Version string `json:"version"`
	Mode    string `json:"mode"`
}

func (p MemoryPolicy) ValidateCheckpointAdmission() error {
	if p.CheckpointAdmission == nil {
		return nil
	}
	if p.CheckpointAdmission.Version != "checkpoint-admission/v1" || p.CheckpointAdmission.Mode != "reserved_quota" {
		return fmt.Errorf("invalid published checkpoint admission")
	}
	return nil
}

func (p MemoryPolicy) ReservedCheckpointQuota() bool {
	return p.CheckpointAdmission != nil && p.ValidateCheckpointAdmission() == nil
}
