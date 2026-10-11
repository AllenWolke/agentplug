package usagecost

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// StableModelUsageStepID binds one model usage step to its trusted execution
// scope and request idempotency key without persisting or exposing that key.
// The length-prefixed fields make the digest unambiguous across delimiters.
func StableModelUsageStepID(scope Scope, requestID string) *string {
	fields := []string{
		"model-usage-step/v1",
		scope.TenantID,
		scope.DepartmentID,
		scope.ApplicationID,
		scope.AgentID,
		scope.AgentVersionID,
		scope.RunID,
		requestID,
	}
	for index, field := range fields {
		maxLength := 128
		if index == len(fields)-1 {
			maxLength = 255 // SQLModelInvocationStore's request key column bound.
		}
		if field == "" || len(field) > maxLength || strings.TrimSpace(field) != field || strings.ContainsAny(field, "\x00\r\n") {
			return nil
		}
	}
	var payload []byte
	for _, field := range fields {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		payload = append(payload, size[:]...)
		payload = append(payload, field...)
	}
	digest := sha256.Sum256(payload)
	stepID := "model-step-" + hex.EncodeToString(digest[:])
	return &stepID
}

func cloneStepID(stepID *string) *string {
	if stepID == nil {
		return nil
	}
	copy := *stepID
	return &copy
}

// A NULL historical step ID means the old row has no trustworthy step link.
// Treat that absence as compatible with a replay, but never fill it in.
func compatibleStepID(existing, incoming *string) bool {
	return existing == nil || incoming == nil || *existing == *incoming
}

// UsageEventsEqual compares the complete persisted usage event by value.
// Independently decoded legacy events with no step link compare equal, while
// a missing link never matches a present link in an authority decision.
func UsageEventsEqual(left, right Event) bool {
	if left.Validate() != nil || right.Validate() != nil {
		return false
	}
	if left.ID != right.ID || left.Scope != right.Scope || left.Provider != right.Provider || left.Model != right.Model ||
		left.InputTokens != right.InputTokens || left.OutputTokens != right.OutputTokens || left.CostMicros != right.CostMicros {
		return false
	}
	if left.StepID == nil || right.StepID == nil {
		return left.StepID == nil && right.StepID == nil
	}
	return *left.StepID == *right.StepID
}
