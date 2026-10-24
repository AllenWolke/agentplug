package knowledge

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/sharedkernel"
)

const IndexCompensationProvider = "platform.knowledge.index"
const IndexCompensationVersion = "index-head-undo.v1"

// Additive migration only. Ordinary publishers obtain a fresh causal stamp,
// including a later publication of the same generation (ABA).
func MigrateIndexCompensation(ctx context.Context, db *sql.DB) error {
	if ctx == nil || db == nil {
		return compensation.ErrInvalid
	}
	_, err := db.ExecContext(ctx, `ALTER TABLE knowledge.active_generations ADD COLUMN IF NOT EXISTS effect_stamp VARCHAR(64) NOT NULL DEFAULT (md5(random()::text||clock_timestamp()::text)||md5(random()::text||clock_timestamp()::text));
CREATE OR REPLACE FUNCTION knowledge.index_effect_stamp() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.effect_stamp IS NOT DISTINCT FROM OLD.effect_stamp THEN
  NEW.effect_stamp=md5(random()::text||clock_timestamp()::text)||md5(random()::text||clock_timestamp()::text);
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS index_effect_stamp_trigger ON knowledge.active_generations;
CREATE TRIGGER index_effect_stamp_trigger BEFORE UPDATE ON knowledge.active_generations FOR EACH ROW EXECUTE FUNCTION knowledge.index_effect_stamp();`)
	return err
}

// The local owner restores only the activity pointer, never deletes generations,
// embeddings, source versions, authorization changes or incurred model fees.
type IndexCompensation struct {
	ledger compensation.LocalEffects
	record func(context.Context, *sql.Tx, sharedkernel.Scope, ProjectionScope, string) error
}
type IndexCancellation struct {
	owner *IndexCompensation
	scope sharedkernel.Scope
}
type indexBeforeImage struct {
	Collection        ProjectionScope `json:"collection"`
	Exists            bool            `json:"exists"`
	Generation        string          `json:"generation,omitempty"`
	Stamp             string          `json:"stamp,omitempty"`
	SourceRevision    int64           `json:"source_revision"`
	ForwardGeneration string          `json:"forward_generation"`
}

func NewIndexCompensation(ledger compensation.LocalEffects, record func(context.Context, *sql.Tx, sharedkernel.Scope, ProjectionScope, string) error) (*IndexCompensation, error) {
	if ledger == nil || record == nil {
		return nil, compensation.ErrInvalid
	}
	return &IndexCompensation{ledger: ledger, record: record}, nil
}
func (s *IndexCompensation) Bind(scope sharedkernel.Scope) (*IndexCancellation, error) {
	if s == nil || scope.ValidateTrusted() != nil {
		return nil, compensation.ErrInvalid
	}
	return &IndexCancellation{owner: s, scope: scope}, nil
}
func (s *IndexCompensation) Registration() (compensation.Registration, error) {
	if s == nil {
		return compensation.Registration{}, compensation.ErrInvalid
	}
	port, err := s.ledger.BindOwner(IndexCompensationProvider, IndexCompensationVersion, s)
	return compensation.Registration{Provider: IndexCompensationProvider, Version: IndexCompensationVersion, Timeout: 5 * time.Second, Port: port}, err
}
func indexEffectStep(owner sharedkernel.Scope, plan *IndexPlan, generation string) (compensation.Step, error) {
	if plan == nil || owner.ValidateTrusted() != nil || checkpointTaskScope(owner, plan.scope.KnowledgeID) != plan.scope {
		return compensation.Step{}, compensation.ErrInvalid
	}
	fp, err := sourceDigest([]any{plan.scope, generation, plan.snapshot.Revision, plan.configHash, plan.sourceDigest, plan.activeRevision})
	if err != nil {
		return compensation.Step{}, err
	}
	ref, err := sourceDigest(plan.scope)
	if err != nil {
		return compensation.Step{}, err
	}
	step := compensation.Step{Root: owner, Scope: owner, Kind: "index", Tool: "knowledge.index.publish", Provider: IndexCompensationProvider, ProviderVersion: IndexCompensationVersion, CallID: generation, Fingerprint: fp, Ref: ref}
	step.ID = compensation.StepID(owner, step.Kind, step.CallID)
	return step, step.Validate()
}
func indexForwardStamp(step compensation.Step) string {
	h := sha256.Sum256([]byte("index-forward/v1\x00" + step.Digest()))
	return hex.EncodeToString(h[:])
}
func (s *IndexCancellation) prepareTx(ctx context.Context, tx *sql.Tx, plan *IndexPlan, generation string) (string, error) {
	if s == nil || s.owner == nil {
		return "", compensation.ErrUnavailable
	}
	step, err := indexEffectStep(s.scope, plan, generation)
	if err != nil {
		return "", err
	}
	replayed, err := s.owner.ledger.AppliedTx(ctx, tx, step)
	if err != nil {
		return "", err
	}
	if replayed {
		return "", compensation.ErrConflict
	} // Exact replay is handled before this mutation path.
	before := indexBeforeImage{Collection: plan.scope, SourceRevision: plan.snapshot.Revision, ForwardGeneration: generation}
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT generation_id,revision,effect_stamp FROM knowledge.active_generations WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 FOR UPDATE`, plan.scope.args()...).Scan(&before.Generation, &revision, &before.Stamp)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	before.Exists = err == nil
	if revision != plan.activeRevision {
		return "", compensation.ErrConflict
	}
	raw, err := json.Marshal(before)
	if err != nil {
		return "", err
	}
	stamp := indexForwardStamp(step)
	return stamp, s.owner.ledger.RecordTx(ctx, tx, step, compensation.LocalEffect{Before: raw, ExpectedToken: stamp})
}
func (s *IndexCancellation) checkReplayTx(ctx context.Context, tx *sql.Tx, plan *IndexPlan, generation string) error {
	step, err := indexEffectStep(s.scope, plan, generation)
	if err != nil {
		return err
	}
	found, err := s.owner.ledger.AppliedTx(ctx, tx, step)
	if err != nil {
		return err
	}
	var stamp string
	if !found {
		return compensation.ErrConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT effect_stamp FROM knowledge.active_generations WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4`, plan.scope.args()...).Scan(&stamp); err != nil {
		return err
	}
	if stamp != indexForwardStamp(step) {
		return compensation.ErrConflict
	}
	return nil
}

func (s *IndexCompensation) RestoreEffectTx(ctx context.Context, tx *sql.Tx, step compensation.Step, effect compensation.LocalEffect) error {
	if s == nil || tx == nil || step.Validate() != nil || step.Kind != "index" || step.Tool != "knowledge.index.publish" || step.Provider != IndexCompensationProvider || step.ProviderVersion != IndexCompensationVersion {
		return compensation.ErrInvalid
	}
	var before indexBeforeImage
	if json.Unmarshal(effect.Before, &before) != nil || !before.Collection.valid() || before.SourceRevision < 0 || before.ForwardGeneration == "" || checkpointTaskScope(step.Scope, before.Collection.KnowledgeID) != before.Collection || (before.Exists && (before.Generation == "" || len(before.Stamp) != 64)) {
		return compensation.ErrConflict
	}
	ref, err := sourceDigest(before.Collection)
	if err != nil || ref != step.Ref || step.CallID != before.ForwardGeneration || effect.ExpectedToken != indexForwardStamp(step) {
		return compensation.ErrConflict
	}
	var sourceRevision int64
	if err = tx.QueryRowContext(ctx, `SELECT source_revision FROM platform_knowledge_source_head WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 FOR UPDATE`, before.Collection.args()...).Scan(&sourceRevision); err != nil {
		return err
	}
	if sourceRevision != before.SourceRevision {
		return compensation.ErrConflict
	}
	var activeGeneration, stamp string
	var activeRevision int64
	if err = tx.QueryRowContext(ctx, `SELECT generation_id,revision,effect_stamp FROM knowledge.active_generations WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 FOR UPDATE`, before.Collection.args()...).Scan(&activeGeneration, &activeRevision, &stamp); err != nil {
		return err
	}
	if stamp != effect.ExpectedToken || activeGeneration != before.ForwardGeneration || activeRevision == math.MaxInt64 {
		return compensation.ErrConflict
	}
	var changed sql.Result
	if before.Exists {
		// Preserve monotonic cache revision, while returning the causal stamp to
		// its predecessor so earlier owned publications can unwind in order.
		changed, err = tx.ExecContext(ctx, `UPDATE knowledge.active_generations SET generation_id=$5,revision=revision+1,effect_stamp=$6 WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND effect_stamp=$7`, append(before.Collection.args(), before.Generation, before.Stamp, effect.ExpectedToken)...)
	} else {
		changed, err = tx.ExecContext(ctx, `DELETE FROM knowledge.active_generations WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND effect_stamp=$5`, append(before.Collection.args(), effect.ExpectedToken)...)
	}
	if err != nil {
		return err
	}
	n, err := changed.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return compensation.ErrConflict
	}
	return s.record(ctx, tx, step.Scope, before.Collection, step.ID)
}
