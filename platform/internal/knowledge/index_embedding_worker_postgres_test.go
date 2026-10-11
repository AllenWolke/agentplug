package knowledge

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/execution"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type indexEmbeddingFixture struct {
	calls   int
	failAt  int
	invalid string
	after   func()
}

func (m *indexEmbeddingFixture) EmbedIndexChunks(_ context.Context, _ sharedkernel.Scope, version string, chunks []Chunk) (IndexEmbeddingBatch, error) {
	m.calls++
	if m.calls == m.failAt {
		return IndexEmbeddingBatch{}, errors.New("controlled embedding outage")
	}
	vectors := map[string][]float32{}
	for _, chunk := range chunks {
		vectors[chunk.ID] = []float32{1, .5}
	}
	if m.invalid == "version" {
		version = "unapproved-model"
	}
	if m.invalid == "vector" {
		vectors[chunks[0].ID] = []float32{0, 0}
	}
	if m.invalid == "count" {
		vectors["invented"] = []float32{1, .5}
	}
	// A provider must not be able to replace a captured source-plan chunk ID.
	chunks[0].ID = "model-mutated-id"
	if m.after != nil {
		m.after()
	}
	return IndexEmbeddingBatch{Vectors: vectors, Receipt: QueryStageReceipt{ModelVersionID: version, InvocationID: "fixture-model-receipt"}}, nil
}

func TestPostgresIndexEmbeddingWorkerCheckpointAndResume(t *testing.T) {
	for _, mode := range []string{"resume", "canceled", "source-changed", "invalid-version", "invalid-vector", "invalid-count", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			c, s, admin, config := indexFixture(t)
			ctx := context.Background()
			if err := execution.MigrateSchema(ctx, admin); err != nil {
				t.Fatal(err)
			}
			ex, err := execution.OpenSQLStore(ctx, "pgx", os.Getenv("KNOWLEDGE_TEST_POSTGRES_DSN"))
			if err != nil {
				t.Fatal(err)
			}
			defer ex.Close()
			owner := sharedkernel.Scope{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, PrincipalID: "source-admin", PrincipalType: "user", AgentInstanceID: "index-instance", InstallationID: "index-install", AgentID: "indexer", AgentVersionID: "v1", SessionID: s.TenantID, RunID: s.TenantID, TraceID: "embedding-worker", AuthorizationEpoch: 1}
			if _, err := ex.Create(platformruntime.CreateRequest{ID: owner.RunID, Scope: owner, AgentVersionID: owner.AgentVersionID, IdempotencyKey: "index", Fingerprint: "fixture"}); err != nil {
				t.Fatal(err)
			}
			claim, err := ex.AcquireLease(owner.RunID, "embedding-worker", time.Now().UTC(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			run, err := ex.TransitionLeased(owner.RunID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claim.Revision, claim.LeaseToken)
			if err != nil {
				t.Fatal(err)
			}
			command := sourceCommand("doc", "create", 0, 0)
			command.Body = "private-worker-body abcdefghijklmnopqrstuvwxyz"
			if _, err := c.Source.Change(ctx, s, command); err != nil {
				t.Fatal(err)
			}
			plan, err := c.Prepare(ctx, s, config, false)
			if err != nil {
				t.Fatal(err)
			}
			needed := len(plan.RequiredChunks())
			if needed < 3 {
				t.Fatal("insufficient batching fixture")
			}
			store := PostgresTaskCheckpoints{DB: c.Source.DB, GuardTx: ex.CheckTaskLeaseTx, RecordTx: func(context.Context, *sql.Tx, sharedkernel.Scope, CheckpointReceipt) error { return nil }}
			expected := int64(0)
			models := &indexEmbeddingFixture{}
			worker := IndexEmbeddingWorker{Models: models, BatchSize: 1, MaximumBatchBytes: 1 << 20, CheckCurrent: func(ctx context.Context, current sharedkernel.Scope, target ProjectionScope, model string, revision int64) error {
				if current != owner || target != s || model != config.EmbeddingModelVersion {
					return ErrInvalidProjection
				}
				tx, err := c.Source.DB.BeginTx(ctx, nil)
				if err != nil {
					return err
				}
				defer tx.Rollback()
				if err := ex.CheckTaskLeaseTx(ctx, tx, current, run.LeaseToken, run.Revision); err != nil {
					return err
				}
				snapshot, err := c.Source.Snapshot(ctx, s, config.MaximumDocuments)
				if err != nil {
					return err
				}
				if snapshot.Revision != revision {
					return ErrSourceConflict
				}
				return tx.Commit()
			}, SaveCheckpoint: func(ctx context.Context, current sharedkernel.Scope, target ProjectionScope, raw []byte) (CheckpointReceipt, error) {
				if target != s {
					return CheckpointReceipt{}, ErrInvalidProjection
				}
				saved, err := store.Save(ctx, current, s.KnowledgeID, run.LeaseToken, run.Revision, expected, raw)
				if err == nil {
					expected = saved.Receipt.Revision
				}
				return saved.Receipt, err
			}}
			switch mode {
			case "resume":
				models.failAt = 2
			case "canceled":
				models.after = func() {
					if _, err := ex.BeginCancellation(owner.RunID, run.Revision); err != nil {
						t.Fatal(err)
					}
				}
			case "source-changed":
				models.after = func() {
					changed := command
					changed.IdempotencyKey = "change"
					changed.ExpectedSourceRevision = 1
					changed.ExpectedDocumentVersion = 1
					changed.Body = "updated source"
					if _, err := c.Source.Change(ctx, s, changed); err != nil {
						t.Fatal(err)
					}
				}
			case "invalid-version":
				models.invalid = "version"
			case "invalid-vector":
				models.invalid = "vector"
			case "invalid-count":
				models.invalid = "count"
			case "oversized":
				worker.MaximumBatchBytes = 1
			}
			if progress, err := worker.Complete(ctx, owner, plan); err == nil || len(progress.Vectors) != 0 {
				t.Fatal("failed task returned successful work", err)
			}
			if mode == "oversized" && models.calls != 0 {
				t.Fatal("oversized input invoked model")
			}
			if mode == "resume" {
				loaded, err := store.Load(ctx, owner, s.KnowledgeID, run.LeaseToken, run.Revision)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(loaded.Payload, []byte("private-worker-body")) {
					t.Fatal("checkpoint leaked document body")
				}
				var checkpoint indexCheckpoint
				if json.Unmarshal(loaded.Payload, &checkpoint) != nil || len(checkpoint.Vectors) != 1 {
					t.Fatal("completed first batch not durable")
				}
				restarted, err := c.Restore(ctx, s, loaded.Payload)
				if err != nil {
					t.Fatal(err)
				}
				models.calls = 0
				models.failAt = 0
				work, err := worker.Complete(ctx, owner, restarted)
				if err != nil || work.ReusedChunks != 1 || work.EmbeddedChunks != needed-1 || models.calls != needed-1 {
					t.Fatal("completed vectors repeated after resume", err, models.calls)
				}
				if err := c.Build(ctx, restarted, "worker-resumed", work.Vectors); err != nil {
					t.Fatal(err)
				}
				if revision, err := c.Publish(ctx, restarted, "worker-resumed"); err != nil || revision != 1 {
					t.Fatal("complete shadow publication", revision, err)
				}
			} else {
				if _, _, err := (PostgresProjection{DB: c.Source.DB}).ActiveGeneration(ctx, s); !errors.Is(err, sql.ErrNoRows) {
					t.Fatal("failed task published generation", err)
				}
				var raw []byte
				if err := c.Source.DB.QueryRowContext(ctx, `SELECT payload FROM platform_knowledge_task_checkpoint WHERE tenant_id=$1 AND run_id=$2`, s.TenantID, owner.RunID).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var saved indexCheckpoint
				if json.Unmarshal(raw, &saved) != nil || len(saved.Vectors) != 0 {
					t.Fatal("failed batch persisted embeddings")
				}
			}
		})
	}
}
