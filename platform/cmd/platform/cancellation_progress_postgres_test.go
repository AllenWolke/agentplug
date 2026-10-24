package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

// Exercise the actual startup-composed progress callback, not a simplified
// execution-authority stub. PostgreSQL denies SELECT on coverage history:
// the progress fence must still check models and the admitted route tree.
func TestPostgresCancellationProgressCompositionDoesNotReadFrozenToolHistory(t *testing.T) {
	dsn := os.Getenv("COMPENSATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated owned compensation database required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(cfg.Database, "agentplug_compensation_test_") {
		t.Fatal("owned compensation database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = compensation.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	models, err := capability.NewSQLModelInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = models.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	money := usagecost.NewSQLStore(db)
	if err = money.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err = models.SetModelBudgetClosureReader(money); err != nil {
		t.Fatal(err)
	}
	routes, err := agentcoordination.NewSQLRouteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = routes.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err = routes.EnsureDelegationAuthoritySchema(ctx); err != nil {
		t.Fatal(err)
	}
	module := capability.NewModuleWithGovernance("", "", nil, "", "", nil, nil, nil, models)
	composition := &cancellationEffects{routes: routes, capabilities: module}
	ports := composition.ports(nil)
	if ports.ProgressFenceTx == nil || ports.ValidateCoverageTx == nil {
		t.Fatal("startup composition omitted a fence")
	}
	role := fmt.Sprintf("cancel_progress_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{role}.Sanitize()
	if _, err = db.ExecContext(ctx, "CREATE ROLE "+quoted+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = db.ExecContext(context.Background(), "DROP OWNED BY "+quoted)
		_, _ = db.ExecContext(context.Background(), "DROP ROLE "+quoted)
	}()
	if _, err = db.ExecContext(ctx, "GRANT USAGE ON SCHEMA public TO "+quoted); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "GRANT SELECT ON ALL TABLES IN SCHEMA public TO "+quoted); err != nil {
		t.Fatal(err)
	}
	// PostgreSQL FOR SHARE needs UPDATE privilege, even though this callback
	// only locks the route rows and does not alter them.
	if _, err = db.ExecContext(ctx, "GRANT UPDATE ON platform_agent_route,platform_agent_child_reservation TO "+quoted); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "REVOKE SELECT ON platform_compensation_step FROM "+quoted); err != nil {
		t.Fatal(err)
	}
	scope := cancellationCompositionScope()
	scope.RunID = role
	scope.SessionID = role + "-session"
	for i := 0; i < 1000; i++ {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.ExecContext(ctx, "SET LOCAL ROLE "+quoted); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		err = ports.ProgressFenceTx(ctx, tx, scope)
		tx.Rollback()
		if err != nil {
			t.Fatal("composed progress fence read denied history or omitted valid live checks", i, err)
		}
	}
	// Prove the role restriction was effective instead of merely assuming it.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SET LOCAL ROLE "+quoted); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, "SELECT 1 FROM platform_compensation_step LIMIT 1"); err == nil {
		t.Fatal("coverage history restriction did not take effect")
	}
	t.Log("1000 actual composed model/tree progress checks passed with frozen effect history unreadable")
}
