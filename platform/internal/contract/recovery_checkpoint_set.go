package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// A large reference set contains only metadata. Its immutable digest binds
// every page to the signed stop generation; values remain in public State.
const MaxRecoveryCheckpointSet = 8192
const RecoveryCheckpointPageSize = 64
const MaxRecoveryReferenceBytes = 8 << 20

type RecoveryCheckpointSetReference struct {
	Version string `json:"version"`
	Count   int    `json:"count"`
	Digest  string `json:"digest"`
}

type RecoveryCheckpointReferencePage struct {
	Version    string                         `json:"version"`
	Set        RecoveryCheckpointSetReference `json:"set"`
	Offset     int                            `json:"offset"`
	References []RecoveryCheckpointReference  `json:"references"`
}

func (r RecoveryCheckpointSetReference) Validate() error {
	if r.Version != "recovery-checkpoint-set/v1" || r.Count <= MaxRecoveryCheckpoints || r.Count > MaxRecoveryCheckpointSet || !handoffDigest.MatchString(r.Digest) {
		return fmt.Errorf("%w: recovery checkpoint set", ErrSchemaValidation)
	}
	return nil
}

func RecoveryCheckpointSet(refs []RecoveryCheckpointReference) (RecoveryCheckpointSetReference, error) {
	if len(refs) <= MaxRecoveryCheckpoints || len(refs) > MaxRecoveryCheckpointSet {
		return RecoveryCheckpointSetReference{}, ErrSchemaValidation
	}
	// Array order, UTC timestamp spelling and Go's HTML escaping are part of
	// this new digest contract. They do not alter existing State hashes.
	items := make([][]any, len(refs))
	previous := ""
	for i, ref := range refs {
		if ref.Validate(ref.ExecutionRevision) != nil || ref.StateKey <= previous {
			return RecoveryCheckpointSetReference{}, ErrSchemaValidation
		}
		previous = ref.StateKey
		items[i] = []any{ref.StateKey, ref.Revision, ref.SchemaID, ref.ContentHash, ref.ExecutionRevision, ref.ExpiresAt.UTC().Format(time.RFC3339Nano)}
	}
	raw, err := json.Marshal(items)
	if err != nil || len(raw) > MaxRecoveryReferenceBytes {
		return RecoveryCheckpointSetReference{}, ErrSchemaValidation
	}
	digest := sha256.Sum256(raw)
	return RecoveryCheckpointSetReference{Version: "recovery-checkpoint-set/v1", Count: len(refs), Digest: hex.EncodeToString(digest[:])}, nil
}
