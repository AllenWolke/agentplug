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

func TestPostgresIndexPersistentCheckpointExecutionFence(t *testing.T) {
	c, scope, admin, config := indexFixture(t)
	ctx := context.Background()
	if err := execution.MigrateSchema(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`CREATE TABLE IF NOT EXISTS knowledge_checkpoint_fixture_audit(run_id text,revision bigint,receipt jsonb,PRIMARY KEY(run_id,revision))`); err != nil {
		t.Fatal(err)
	}
	ex, err := execution.OpenSQLStore(ctx, "pgx", os.Getenv("KNOWLEDGE_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer ex.Close()
	owner := sharedkernel.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: "indexer-instance", AgentID: "indexer", PrincipalID: "source-admin", PrincipalType: "user", InstallationID: "install", AgentVersionID: "v1", SessionID: scope.TenantID, RunID: scope.TenantID, AuthorizationEpoch: 1, TraceID: "checkpoint-trace"}
	if _, err := ex.Create(platformruntime.CreateRequest{ID: owner.RunID, Scope: owner, AgentVersionID: owner.AgentVersionID, IdempotencyKey: "index", Fingerprint: "fixture"}); err != nil {
		t.Fatal(err)
	}
	claimed, err := ex.AcquireLease(owner.RunID, "checkpoint-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	run, err := ex.TransitionLeased(owner.RunID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Source.Change(ctx, scope, sourceCommand("doc", "create", 0, 0)); err != nil {
		t.Fatal(err)
	}
	plan, err := c.Prepare(ctx, scope, config, false)
	if err != nil {
		t.Fatal(err)
	}
	chunks := plan.RequiredChunks()
	first, err := plan.Checkpoint(map[string][]float32{chunks[0].ID: {1, .5}})
	if err != nil {
		t.Fatal(err)
	}
	full, err := plan.Checkpoint(indexFixtureVectors(plan))
	if err != nil {
		t.Fatal(err)
	}
	record := func(ctx context.Context, tx *sql.Tx, _ sharedkernel.Scope, r CheckpointReceipt) error {
		raw, err := json.Marshal(r)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO knowledge_checkpoint_fixture_audit VALUES($1,$2,$3::jsonb)`, r.RunID, r.Revision, string(raw))
		return err
	}
	store := PostgresTaskCheckpoints{DB: c.Source.DB, GuardTx: ex.CheckTaskLeaseTx, RecordTx: record}
	save := func(s PostgresTaskCheckpoints, expected int64, raw []byte) (StoredCheckpoint, error) {
		return s.Save(ctx, owner, scope.KnowledgeID, run.LeaseToken, run.Revision, expected, raw)
	}
	load := func(s PostgresTaskCheckpoints) (StoredCheckpoint, error) {
		return s.Load(ctx, owner, scope.KnowledgeID, run.LeaseToken, run.Revision)
	}
	created, err := save(store, 0, first)
	if err != nil || created.Receipt.Revision != 1 || created.Replayed {
		t.Fatal("initial", err)
	}
	retry, err := save(store, 0, first)
	if err != nil || !retry.Replayed || retry.Receipt != created.Receipt {
		t.Fatal("retry", err)
	}
	if _, err := save(store, 0, full); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatal("conflicting create accepted", err)
	}
	reopened, err := sql.Open("pgx", os.Getenv("KNOWLEDGE_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	other := store
	other.DB = reopened
	loaded, err := load(other)
	if err != nil || !bytes.Equal(loaded.Payload, first) {
		t.Fatal("durable reopen", err)
	}
	if restored, err := c.Restore(ctx, scope, loaded.Payload); err != nil || restored.ReusedChunks() != 1 {
		t.Fatal("restore", err)
	}
	fault := store
	fault.RecordTx = func(ctx context.Context, tx *sql.Tx, s sharedkernel.Scope, r CheckpointReceipt) error {
		if err := record(ctx, tx, s, r); err != nil {
			return err
		}
		return errors.New("audit fault")
	}
	if _, err := save(fault, 1, full); err == nil {
		t.Fatal("audit failure committed")
	}
	loaded, err = load(store)
	if err != nil || loaded.Receipt.Revision != 1 {
		t.Fatal("rollback", err)
	}
	var audits int
	if err := admin.QueryRow(`SELECT COUNT(*) FROM knowledge_checkpoint_fixture_audit WHERE run_id=$1`, owner.RunID).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("audit rollback/replay", audits, err)
	}
	advanced, err := save(store, 1, full)
	if err != nil || advanced.Receipt.Revision != 2 {
		t.Fatal("advance", err)
	}
	if _, err := save(store, 0, first); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatal("stale retry", err)
	}
	foreign := owner
	foreign.PrincipalID = "other-user"
	if _, err := store.Load(ctx, foreign, scope.KnowledgeID, run.LeaseToken, run.Revision); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("foreign read", err)
	}
	missing := store
	missing.GuardTx = nil
	if _, err := save(missing, 2, full); !errors.Is(err, ErrCheckpointUnavailable) {
		t.Fatal("missing guard", err)
	}
	denied := store
	denied.GuardTx = func(context.Context, *sql.Tx, sharedkernel.Scope, string, uint64) error {
		return errors.New("current IAM denied fixture")
	}
	if _, err := load(denied); err == nil {
		t.Fatal("authority denial ignored")
	}
	var injected map[string]any
	if err := json.Unmarshal(full, &injected); err != nil {
		t.Fatal(err)
	}
	injected["document_body"] = "private"
	invalid, _ := json.Marshal(injected)
	if _, err := save(store, 2, invalid); !errors.Is(err, ErrInvalidProjection) {
		t.Fatal("body field accepted", err)
	}
	if _, err := ex.BeginCancellation(owner.RunID, run.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := save(store, 2, full); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("cancelled write", err)
	}
	if _, err := load(store); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("cancelled restore", err)
	}
}
