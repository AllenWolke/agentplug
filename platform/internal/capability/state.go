package capability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/sharedkernel"
)

var (
	ErrStateConflict       = errors.New("state revision or idempotency conflict")
	ErrStateDenied         = errors.New("state authorization or execution generation denied")
	ErrStateUnavailable    = errors.New("state continuity or persistence unavailable")
	ErrStateLimit          = errors.New("state quota or checkpoint history limit exceeded")
	ErrStateSchema         = errors.New("state schema does not match its checkpoint lineage")
	ErrStateContinuityLost = errors.New("checkpoint lineage exists but the requested state is no longer available")
)

type Checkpoint struct {
	Revision          uint64         `json:"revision"`
	SchemaID          string         `json:"schema_id"`
	Value             map[string]any `json:"value"`
	ContentHash       string         `json:"content_hash"`
	ExpiresAt         time.Time      `json:"expires_at"`
	ExecutionRevision uint64         `json:"execution_revision"`
}

type StateWrite struct {
	Scope                                    sharedkernel.Scope
	Lease                                    sharedkernel.ExecutionLeaseBinding
	Namespace, Key, SchemaID, IdempotencyKey string
	ExpectedRevision                         uint64
	Value                                    map[string]any
	TTLSeconds, MaxEntries                   int
	MaxRevisions                             uint64
	ReservedQuota                            bool
}

type CheckpointStore interface {
	Load(context.Context, sharedkernel.Scope, string, string, string, uint64) (Checkpoint, bool, error)
	Save(context.Context, StateWrite, func(context.Context) error) (Checkpoint, error)
}

// CheckpointReferenceReader loads a captured current head only when the
// opaque key belongs to the caller's full trusted scope and facts still match.
type CheckpointReferenceReader interface {
	LoadReference(context.Context, sharedkernel.Scope, contract.RecoveryCheckpointReference) (Checkpoint, error)
}

type RecoveryCheckpointPager interface {
	ReadRecoveryCheckpointPage(context.Context, sharedkernel.Scope, sharedkernel.ExecutionLeaseBinding, contract.RecoveryCheckpointSetReference, int, int) (contract.RecoveryCheckpointReferencePage, error)
}

func (m *Module) SetRecoveryCheckpointPager(pager RecoveryCheckpointPager) { m.recoveryPager = pager }

// CheckpointMaintenanceStore deletes expired payloads only. Lineage heads are
// retained so expiry cannot reset CAS versions or resurrect an old operation.
type CheckpointMaintenanceStore interface {
	PruneExpired(context.Context, int) (int64, error)
}

var stateName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

func stateKeys(scope sharedkernel.Scope, namespace, key string) (string, string, error) {
	prefix, id, err := sharedkernel.CheckpointIdentity(scope, namespace, key)
	if err != nil {
		return "", "", ErrStateDenied
	}
	return prefix, id, nil
}

func validStateSchema(schema string) bool {
	return len(schema) > len("schema://") && len(schema) <= 256 && strings.TrimSpace(schema) == schema && strings.HasPrefix(schema, "schema://") && !strings.ContainsAny(schema, "\x00\r\n\t* ")
}

func stateContentHash(schema string, value map[string]any) (string, error) {
	if !validStateSchema(schema) || value == nil {
		return "", ErrStateSchema
	}
	encoded, err := json.Marshal([]any{schema, value})
	if err != nil || len(encoded) > 256<<10 {
		return "", ErrStateLimit
	}
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:]), nil
}

func (m *Module) SetCheckpointStore(store CheckpointStore) { m.stateStore = store }
