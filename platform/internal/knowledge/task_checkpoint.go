package knowledge

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrCheckpointConflict = errors.New("knowledge task checkpoint revision conflict")
var ErrCheckpointUnavailable = errors.New("knowledge task checkpoint guard or recorder unavailable")
var ErrCheckpointNotFound = errors.New("knowledge task checkpoint not found")

type CheckpointReceipt struct {
	RunID          string `json:"run_id"`
	KnowledgeID    string `json:"knowledge_id"`
	Revision       int64  `json:"revision"`
	Digest         string `json:"digest"`
	SourceRevision int64  `json:"source_revision"`
}

type StoredCheckpoint struct {
	Receipt  CheckpointReceipt
	Payload  []byte
	Replayed bool
}

// This internal port stores body-free index work. Composition supplies BOTH
// current IAM and execution lease checks through GuardTx, in the same database
// transaction. Agents cannot read this table or supply arbitrary task owners.
type PostgresTaskCheckpoints struct {
	DB       *sql.DB
	GuardTx  func(context.Context, *sql.Tx, sharedkernel.Scope, string, uint64) error
	RecordTx func(context.Context, *sql.Tx, sharedkernel.Scope, CheckpointReceipt) error
}

func checkpointEnvelope(scope ProjectionScope, raw []byte) (indexCheckpoint, string, error) {
	var saved indexCheckpoint
	if !scope.valid() || len(raw) == 0 || len(raw) > 64*1024*1024 {
		return saved, "", ErrInvalidProjection
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&saved) != nil || decoder.Decode(new(any)) != io.EOF {
		return saved, "", ErrInvalidProjection
	}
	hash := saved.IntegrityHash
	saved.IntegrityHash = ""
	digest, err := sourceDigest(saved)
	if err != nil || hash == "" || digest != hash {
		return saved, "", ErrSourceCorrupt
	}
	if saved.Version != IndexCheckpointVersion || saved.Scope != scope || !saved.Config.valid() || saved.SourceRevision < 0 || saved.ActiveRevision < 0 || saved.SourceDigest == "" || saved.ConfigHash == "" {
		return saved, "", ErrInvalidProjection
	}
	for id, vector := range saved.Vectors {
		if id == "" {
			return saved, "", ErrInvalidProjection
		}
		if _, err := vectorLiteral(vector, saved.Config.Dimensions); err != nil {
			return saved, "", err
		}
	}
	return saved, hash, nil
}

func checkpointTaskScope(owner sharedkernel.Scope, knowledgeID string) ProjectionScope {
	return ProjectionScope{TenantID: owner.TenantID, DepartmentID: owner.DepartmentID, ApplicationID: owner.ApplicationID, KnowledgeID: knowledgeID}
}

func (s PostgresTaskCheckpoints) ready(owner sharedkernel.Scope, knowledgeID, token string, revision uint64) error {
	if s.DB == nil || s.GuardTx == nil || s.RecordTx == nil {
		return ErrCheckpointUnavailable
	}
	if owner.ValidateTrusted() != nil || !checkpointTaskScope(owner, knowledgeID).valid() || token == "" || revision == 0 {
		return ErrInvalidProjection
	}
	return nil
}

// Save uses an exact checkpoint CAS. An immediate identical retry returns the
// committed receipt without a second audit; old retries after newer work fail.
// Lease tokens are only passed to the guard and are never persisted here.
func (s PostgresTaskCheckpoints) Save(ctx context.Context, owner sharedkernel.Scope, knowledgeID, token string, runRevision uint64, expected int64, raw []byte) (StoredCheckpoint, error) {
	if err := s.ready(owner, knowledgeID, token, runRevision); err != nil {
		return StoredCheckpoint{}, err
	}
	if expected < 0 || expected == int64(^uint64(0)>>1) {
		return StoredCheckpoint{}, ErrCheckpointConflict
	}
	scope := checkpointTaskScope(owner, knowledgeID)
	saved, digest, err := checkpointEnvelope(scope, raw)
	if err != nil {
		return StoredCheckpoint{}, err
	}
	ownerDigest, err := sourceDigest(owner)
	if err != nil {
		return StoredCheckpoint{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return StoredCheckpoint{}, err
	}
	defer tx.Rollback()
	if err := s.GuardTx(ctx, tx, owner, token, runRevision); err != nil {
		return StoredCheckpoint{}, err
	}
	args := append(scope.args(), owner.RunID)
	receipt := CheckpointReceipt{RunID: owner.RunID, KnowledgeID: knowledgeID, Revision: expected + 1, Digest: digest, SourceRevision: saved.SourceRevision}
	inserted := false
	if expected == 0 {
		result, err := tx.ExecContext(ctx, `INSERT INTO platform_knowledge_task_checkpoint(tenant_id,department_id,application_id,knowledge_id,run_id,owner_digest,revision,checkpoint_digest,payload) VALUES($1,$2,$3,$4,$5,$6,1,$7,$8) ON CONFLICT(tenant_id,department_id,application_id,knowledge_id,run_id) DO NOTHING`, append(args, ownerDigest, digest, raw)...)
		if err != nil {
			return StoredCheckpoint{}, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return StoredCheckpoint{}, err
		}
		inserted = n == 1
	}
	var current, currentOwner, currentDigest string
	var currentRevision int64
	var payload []byte
	err = tx.QueryRowContext(ctx, `SELECT owner_digest,checkpoint_digest,revision,payload FROM platform_knowledge_task_checkpoint WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND run_id=$5 FOR UPDATE`, args...).Scan(&currentOwner, &currentDigest, &currentRevision, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredCheckpoint{}, ErrCheckpointConflict
	}
	if err != nil {
		return StoredCheckpoint{}, err
	}
	_, current, err = checkpointEnvelope(scope, payload)
	if err != nil || current != currentDigest {
		return StoredCheckpoint{}, ErrSourceCorrupt
	}
	if currentOwner != ownerDigest {
		return StoredCheckpoint{}, ErrCheckpointConflict
	}
	replayed := !inserted && currentDigest == digest && (currentRevision == expected+1 || currentRevision == expected)
	if replayed {
		// A restored worker may save the same complete state using the freshly
		// loaded CAS. Do not manufacture another revision/audit for that state.
		receipt.Revision = currentRevision
	}
	if !inserted && !replayed {
		if currentRevision != expected {
			return StoredCheckpoint{}, ErrCheckpointConflict
		}
		if _, err := tx.ExecContext(ctx, `UPDATE platform_knowledge_task_checkpoint SET revision=$6,checkpoint_digest=$7,payload=$8,updated_at=clock_timestamp() WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND run_id=$5`, append(args, receipt.Revision, digest, raw)...); err != nil {
			return StoredCheckpoint{}, err
		}
	}
	if !replayed {
		if err := s.RecordTx(ctx, tx, owner, receipt); err != nil {
			return StoredCheckpoint{}, err
		}
	}
	// Row locks or the recorder may have waited beyond a natural expiry.
	// Replayed writes also need this final current-authority/lease check.
	if err := s.GuardTx(ctx, tx, owner, token, runRevision); err != nil {
		return StoredCheckpoint{}, err
	}
	if err := tx.Commit(); err != nil {
		return StoredCheckpoint{}, err
	}
	return StoredCheckpoint{Receipt: receipt, Payload: append([]byte(nil), raw...), Replayed: replayed}, nil
}

func (s PostgresTaskCheckpoints) Load(ctx context.Context, owner sharedkernel.Scope, knowledgeID, token string, runRevision uint64) (StoredCheckpoint, error) {
	if err := s.ready(owner, knowledgeID, token, runRevision); err != nil {
		return StoredCheckpoint{}, err
	}
	scope := checkpointTaskScope(owner, knowledgeID)
	ownerDigest, err := sourceDigest(owner)
	if err != nil {
		return StoredCheckpoint{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return StoredCheckpoint{}, err
	}
	defer tx.Rollback()
	if err := s.GuardTx(ctx, tx, owner, token, runRevision); err != nil {
		return StoredCheckpoint{}, err
	}
	var actualOwner, digest string
	var revision int64
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT owner_digest,checkpoint_digest,revision,payload FROM platform_knowledge_task_checkpoint WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND run_id=$5 FOR SHARE`, append(scope.args(), owner.RunID)...).Scan(&actualOwner, &digest, &revision, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		// Do not turn an unrelated guard/resolver sql.ErrNoRows into a new job.
		return StoredCheckpoint{}, ErrCheckpointNotFound
	}
	if err != nil {
		return StoredCheckpoint{}, err
	}
	if actualOwner != ownerDigest {
		return StoredCheckpoint{}, ErrCheckpointConflict
	}
	saved, actualDigest, err := checkpointEnvelope(scope, raw)
	if err != nil || actualDigest != digest {
		return StoredCheckpoint{}, ErrSourceCorrupt
	}
	if err := s.GuardTx(ctx, tx, owner, token, runRevision); err != nil {
		return StoredCheckpoint{}, err
	}
	if err := tx.Commit(); err != nil {
		return StoredCheckpoint{}, err
	}
	return StoredCheckpoint{Receipt: CheckpointReceipt{RunID: owner.RunID, KnowledgeID: knowledgeID, Revision: revision, Digest: digest, SourceRevision: saved.SourceRevision}, Payload: raw}, nil
}
