package knowledge

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/execution"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestPostgresIndexTaskDriverRestartsFromDurableStages(t *testing.T) {
	for _, mode := range []string{"model-outage", "publication-ack-lost", "canceled-after-publication"} {
		t.Run(mode, func(t *testing.T) {
			c, scope, admin, config := indexFixture(t)
			ctx := context.Background()
			if err := execution.MigrateSchema(ctx, admin); err != nil {
				t.Fatal(err)
			}
			ex, err := execution.OpenSQLStore(ctx, "pgx", os.Getenv("KNOWLEDGE_TEST_POSTGRES_DSN"))
			if err != nil {
				t.Fatal(err)
			}
			defer ex.Close()
			owner := sharedkernel.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, PrincipalID: "source-admin", PrincipalType: "user", AgentInstanceID: "index-instance", InstallationID: "index-install", AgentID: "indexer", AgentVersionID: "v1", SessionID: scope.TenantID, RunID: scope.TenantID, TraceID: "task-driver", AuthorizationEpoch: 1}
			if _, err := ex.Create(platformruntime.CreateRequest{ID: owner.RunID, Scope: owner, AgentVersionID: owner.AgentVersionID, IdempotencyKey: "index-task", Fingerprint: "fixture"}); err != nil {
				t.Fatal(err)
			}
			claim, err := ex.AcquireLease(owner.RunID, "index-task", time.Now().UTC(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			run, err := ex.TransitionLeased(owner.RunID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claim.Revision, claim.LeaseToken)
			if err != nil {
				t.Fatal(err)
			}
			command := sourceCommand("doc", "create", 0, 0)
			command.Body = "task-driver-private-body abcdefghijklmnopqrstuvwxyz"
			if _, err := c.Source.Change(ctx, scope, command); err != nil {
				t.Fatal(err)
			}
			store := PostgresTaskCheckpoints{DB: c.Source.DB, GuardTx: ex.CheckTaskLeaseTx, RecordTx: func(context.Context, *sql.Tx, sharedkernel.Scope, CheckpointReceipt) error { return nil }}
			c.GuardPublishTx = func(ctx context.Context, tx *sql.Tx, target ProjectionScope) error {
				if target != scope {
					return ErrInvalidProjection
				}
				return ex.CheckTaskLeaseTx(ctx, tx, owner, run.LeaseToken, run.Revision)
			}
			models := &indexEmbeddingFixture{}
			if mode == "model-outage" {
				models.failAt = 2
			}
			lost := errors.New("task acknowledgment lost after commit")
			inject := mode != "model-outage"
			expected := int64(0)
			driver := IndexTaskDriver{Coordinator: c, LoadCheckpoint: func(ctx context.Context, current sharedkernel.Scope, target ProjectionScope) (StoredCheckpoint, error) {
				if current != owner || target != scope {
					return StoredCheckpoint{}, ErrInvalidProjection
				}
				saved, err := store.Load(ctx, current, scope.KnowledgeID, run.LeaseToken, run.Revision)
				if errors.Is(err, ErrCheckpointNotFound) {
					return StoredCheckpoint{}, nil
				}
				if err == nil {
					expected = saved.Receipt.Revision
				}
				return saved, err
			}}
			driver.Embedding = IndexEmbeddingWorker{Models: models, BatchSize: 1, MaximumBatchBytes: 1 << 20, CheckCurrent: func(ctx context.Context, current sharedkernel.Scope, target ProjectionScope, model string, revision int64) error {
				if current != owner || target != scope || model != config.EmbeddingModelVersion {
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
				if err := tx.Commit(); err != nil {
					return err
				}
				snapshot, err := c.Source.Snapshot(ctx, scope, config.MaximumDocuments)
				if err != nil {
					return err
				}
				if snapshot.Revision != revision {
					return ErrSourceConflict
				}
				var active int
				if err := c.Source.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM knowledge.active_generations WHERE tenant_id=$1`, scope.TenantID).Scan(&active); err != nil {
					return err
				}
				if inject && active == 1 {
					inject = false
					if mode == "canceled-after-publication" {
						if _, err := ex.BeginCancellation(owner.RunID, run.Revision); err != nil {
							t.Fatal(err)
						}
					}
					return lost
				}
				return nil
			}, SaveCheckpoint: func(ctx context.Context, current sharedkernel.Scope, target ProjectionScope, raw []byte) (CheckpointReceipt, error) {
				if target != scope {
					return CheckpointReceipt{}, ErrInvalidProjection
				}
				saved, err := store.Save(ctx, current, scope.KnowledgeID, run.LeaseToken, run.Revision, expected, raw)
				if err == nil {
					expected = saved.Receipt.Revision
				}
				return saved.Receipt, err
			}}
			if result, err := driver.Run(ctx, owner, scope, config, false); err == nil || result != (IndexTaskResult{}) {
				t.Fatal("first failure not exposed", result, err)
			}
			callsBefore := models.calls
			models.failAt = 0
			result, err := driver.Run(ctx, owner, scope, config, false)
			if mode == "canceled-after-publication" {
				if err == nil || models.calls != callsBefore {
					t.Fatal("canceled task resumed", err)
				}
				return
			}
			if err != nil || result.IndexRevision != 1 || result.SourceRevision != 1 || result.GenerationID == "" {
				t.Fatal("durable recovery", result, err)
			}
			if mode == "publication-ack-lost" && models.calls != callsBefore {
				t.Fatal("published recovery reembedded", models.calls, callsBefore)
			}
			if mode == "model-outage" && result.ReusedChunks != 1 {
				t.Fatal("completed first batch not reused", result)
			}
			var audits int
			if err := c.Source.DB.QueryRow(`SELECT COUNT(*) FROM knowledge_index_fixture_audit WHERE tenant_id=$1`, scope.TenantID).Scan(&audits); err != nil || audits != 1 {
				t.Fatal("duplicate publication", audits, err)
			}
			callsBefore = models.calls
			if again, err := driver.Run(ctx, owner, scope, config, false); err != nil || again.GenerationID != result.GenerationID || again.IndexRevision != 1 || models.calls != callsBefore {
				t.Fatal("completed-stage replay", again, err)
			}
			changed := config
			changed.WindowRunes++
			if _, err := driver.Run(ctx, owner, scope, changed, false); !errors.Is(err, ErrInvalidProjection) || models.calls != callsBefore {
				t.Fatal("checkpoint config changed", err)
			}
		})
	}
}
