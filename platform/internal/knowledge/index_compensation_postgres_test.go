package knowledge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Actual PG owner/CAS tests. This explicit fixture authority supplies execution
// stop facts; it is not an authenticated Agent/production composition test.
type indexCancelFixtureAuthority struct {
	scope   sharedkernel.Scope
	stopped bool
}

func (a *indexCancelFixtureAuthority) RegisterEffectTx(_ context.Context, _ *sql.Tx, s compensation.Step) error {
	if a.stopped || s.Scope != a.scope || s.Root != a.scope {
		return compensation.ErrConflict
	}
	return nil
}
func (a *indexCancelFixtureAuthority) BeginCancellationTx(_ context.Context, _ *sql.Tx, s sharedkernel.Scope, r uint64) error {
	if !a.stopped || s != a.scope || r != 2 {
		return compensation.ErrConflict
	}
	return nil
}
func (a *indexCancelFixtureAuthority) ConfirmStoppedTx(_ context.Context, _ *sql.Tx, s sharedkernel.Scope, p compensation.StopProof) error {
	if !a.stopped || s != a.scope || p.Validate(s) != nil {
		return compensation.ErrPending
	}
	return nil
}
func (a *indexCancelFixtureAuthority) GuardCompensationTx(_ context.Context, _ *sql.Tx, s sharedkernel.Scope) error {
	if !a.stopped || s != a.scope {
		return compensation.ErrPending
	}
	return nil
}
func (a *indexCancelFixtureAuthority) FinishCancellationTx(ctx context.Context, tx *sql.Tx, s sharedkernel.Scope, p compensation.StopProof) error {
	return a.ConfirmStoppedTx(ctx, tx, s, p)
}
func indexCompensationFixture(t *testing.T) (IndexCoordinator, ProjectionScope, *sql.DB, IndexConfig, *compensation.SQLStore, *compensation.Engine, *indexCancelFixtureAuthority) {
	t.Helper()
	dsn := os.Getenv("COMPENSATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "127.0.0.1" || !strings.HasPrefix(u.Path, "/agentplug_compensation_test_") {
		t.Fatal("test requires verifier-owned loopback PostgreSQL")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	if _, err = db.ExecContext(ctx, ProjectionSchema+SourceSchema); err != nil {
		t.Fatal(err)
	}
	if err = MigrateIndexCompensation(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err = compensation.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	facade := sqlutil.TransactionDB(tx)
	err = compensation.ApplyLocalEffectSchema(ctx, facade)
	facade.Close()
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("idx-undo-%d", time.Now().UnixNano())
	scope := sharedkernel.Scope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", AgentID: "indexer", AgentInstanceID: "instance", AgentVersionID: "v1", InstallationID: "install", PrincipalID: "owner", PrincipalType: "user", RunID: id, SessionID: "session", TraceID: strings.Repeat("a", 32), AuthorizationEpoch: 1}
	a := &indexCancelFixtureAuthority{scope: scope}
	store, err := compensation.NewSQLStore(db, a)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := compensation.NewLocalEffectLedger(ctx, db, store)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewIndexCompensation(ledger, func(context.Context, *sql.Tx, sharedkernel.Scope, ProjectionScope, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	binding, err := owner.Bind(scope)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := owner.Registration()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := compensation.NewEngine(store, "index-test", reg)
	if err != nil {
		t.Fatal(err)
	}
	p := ProjectionScope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", KnowledgeID: "docs"}
	source := PostgresSource{DB: db, RecordChange: func(context.Context, *sql.Tx, ProjectionScope, SourceReceipt) error { return nil }}
	c := IndexCoordinator{Source: source, Projection: PostgresProjection{DB: db}, RecordPublish: func(context.Context, *sql.Tx, ProjectionScope, string, int64, int64) error { return nil }}
	if _, err = source.Change(ctx, p, sourceCommand("doc", "doc", 0, 0)); err != nil {
		t.Fatal(err)
	}
	config := IndexConfig{EmbeddingModelVersion: "fixture", Dimensions: 2, WindowRunes: 8, OverlapRunes: 2, MaximumDocuments: 100, MaximumChunks: 100}
	// Seed the activity head outside the cancelled Run; it is not enrolled.
	plan, err := c.Prepare(ctx, p, config, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Build(ctx, plan, "original", indexFixtureVectors(plan)); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Publish(ctx, plan, "original"); err != nil {
		t.Fatal(err)
	}
	c.Cancellation = binding
	return c, p, db, config, store, engine, a
}
func indexCancelPublish(t *testing.T, c IndexCoordinator, p ProjectionScope, config IndexConfig, id string) *IndexPlan {
	t.Helper()
	ctx := context.Background()
	plan, err := c.Prepare(ctx, p, config, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Build(ctx, plan, id, indexFixtureVectors(plan)); err != nil {
		t.Fatal(err)
	}
	if _, err = c.PublishOrReplay(ctx, plan, id); err != nil {
		t.Fatal(err)
	}
	return plan
}
func indexCancelBegin(t *testing.T, db *sql.DB, s *compensation.SQLStore, a *indexCancelFixtureAuthority) {
	t.Helper()
	a.stopped = true
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = s.BeginTx(ctx, tx, a.scope, 2); err != nil {
		t.Fatal(err)
	}
	proof := compensation.StopProof{Version: "cancellation-tree-stop/v1", ScopeDigest: compensation.ScopeDigest(a.scope), Revision: 2, EvidenceDigest: strings.Repeat("b", 64)}
	if err = s.ConfirmStoppedTx(ctx, tx, a.scope, proof); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
func indexCancelHead(t *testing.T, db *sql.DB, p ProjectionScope, want string, revision int64) {
	t.Helper()
	var actual string
	var rev int64
	if err := db.QueryRow(`SELECT generation_id,revision FROM knowledge.active_generations WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4`, p.args()...).Scan(&actual, &rev); err != nil || actual != want || rev != revision {
		t.Fatalf("head %s/%d: %v", actual, rev, err)
	}
}
func TestIndexCompensationReversePublicationsAndReplayPostgres(t *testing.T) {
	c, p, db, config, store, engine, a := indexCompensationFixture(t)
	ctx := context.Background()
	plan := indexCancelPublish(t, c, p, config, "new-one")
	if rev, err := c.PublishOrReplay(ctx, plan, "new-one"); err != nil || rev != 2 {
		t.Fatal("exact replay", rev, err)
	}
	indexCancelPublish(t, c, p, config, "new-two")
	indexCancelBegin(t, db, store, a)
	if ok, err := engine.Tick(ctx, a.scope); err != nil || !ok {
		t.Fatal(ok, err)
	}
	indexCancelHead(t, db, p, "new-one", 4)
	if ok, err := engine.Tick(ctx, a.scope); err != nil || !ok {
		t.Fatal(ok, err)
	}
	indexCancelHead(t, db, p, "original", 5)
	if err := store.TryFinalize(ctx, a.scope); err != nil {
		t.Fatal(err)
	}
	if ok, err := engine.Tick(ctx, a.scope); err != nil || ok {
		t.Fatal("replayed inverse", ok, err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM knowledge.generations WHERE tenant_id=$1`, p.TenantID).Scan(&count); err != nil || count != 3 {
		t.Fatal("deleted immutable generation history", count, err)
	}
}
func TestIndexCompensationPreservesConcurrentAndSourceChangesPostgres(t *testing.T) {
	for _, kind := range []string{"same-head-aba", "new-source"} {
		t.Run(kind, func(t *testing.T) {
			c, p, db, config, store, engine, a := indexCompensationFixture(t)
			ctx := context.Background()
			indexCancelPublish(t, c, p, config, "new-one")
			if kind == "same-head-aba" {
				if _, err := db.Exec(`UPDATE knowledge.active_generations SET revision=revision+1 WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4`, p.args()...); err != nil {
					t.Fatal(err)
				}
			} else {
				change := sourceCommand("doc", "changed", 1, 1)
				change.Body = "new authorized source"
				if _, err := c.Source.Change(ctx, p, change); err != nil {
					t.Fatal(err)
				}
			}
			indexCancelBegin(t, db, store, a)
			if ok, err := engine.Tick(ctx, a.scope); err != nil || !ok {
				t.Fatal(ok, err)
			}
			if err := store.TryFinalize(ctx, a.scope); !errors.Is(err, compensation.ErrPending) {
				t.Fatal("conflict cancellation passed", err)
			}
			var generation string
			if err := db.QueryRow(`SELECT generation_id FROM knowledge.active_generations WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4`, p.args()...).Scan(&generation); err != nil || generation != "new-one" {
				t.Fatal("overwrote concurrent change", generation, err)
			}
		})
	}
}
func TestIndexCompensationForwardAuditFailureRollsBackPostgres(t *testing.T) {
	c, p, db, config, _, _, _ := indexCompensationFixture(t)
	ctx := context.Background()
	plan, err := c.Prepare(ctx, p, config, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Build(ctx, plan, "audit-fail", indexFixtureVectors(plan)); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("fixture audit failure")
	c.RecordPublish = func(context.Context, *sql.Tx, ProjectionScope, string, int64, int64) error { return failure }
	if _, err = c.Publish(ctx, plan, "audit-fail"); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	indexCancelHead(t, db, p, "original", 1)
	step, err := indexEffectStep(c.Cancellation.scope, plan, "audit-fail")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM platform_compensation_step WHERE step_id=$1`, step.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("orphan compensation registration", count, err)
	}
}
