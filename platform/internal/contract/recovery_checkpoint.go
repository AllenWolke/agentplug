package contract

import (
	"fmt"
	"strings"
	"time"
)

// RecoveryCheckpointReference is bounded, non-secret metadata captured from
// the public State store. No business value or credential is included.
type RecoveryCheckpointReference struct {
	StateKey          string    `json:"state_key"`
	Revision          uint64    `json:"revision"`
	SchemaID          string    `json:"schema_id"`
	ContentHash       string    `json:"content_hash"`
	ExecutionRevision uint64    `json:"execution_revision"`
	ExpiresAt         time.Time `json:"expires_at"`
}

const MaxRecoveryCheckpoints = 128

// Absolute wire/storage bound. State admission still applies the pinned
// MemoryPolicy's capacity (64 for legacy policies).
const MaxCheckpointRevisions uint64 = 4096

func (r RecoveryCheckpointReference) Validate(stoppedRevision uint64) error {
	if !handoffDigest.MatchString(r.StateKey) || !handoffDigest.MatchString(r.ContentHash) ||
		r.Revision == 0 || r.Revision > MaxCheckpointRevisions || r.ExecutionRevision == 0 || r.ExecutionRevision > stoppedRevision ||
		len(r.SchemaID) <= len("schema://") || len(r.SchemaID) > 256 || !strings.HasPrefix(r.SchemaID, "schema://") ||
		strings.ContainsAny(r.SchemaID, "\x00\r\n\t* ") || r.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: recovery checkpoint reference", ErrSchemaValidation)
	}
	return nil
}
