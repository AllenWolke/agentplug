package capability

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

func TestPostgresModelPerformanceKeepsHistoricalClockMismatchMissing(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_CONTEXT_CACHE_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires registered independent PostgreSQL fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, _ := NewSQLModelInvocationStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	scope := scopeFromHarness(capabilityContext())
	scope.SessionID, scope.RunID = billingIntegrationID(t), billingIntegrationID(t)
	start, _ := time.Parse(time.RFC3339Nano, "2026-10-14T03:39:44.592886612Z")
	finish, _ := time.Parse(time.RFC3339Nano, "2026-10-14T03:39:44.600352725Z")
	insert := func(key string, corrupt bool) string {
		t.Helper()
		o := audit.NewPerformanceObservation(scope, key, "model_gateway", "succeeded", start, finish)
		o.Operation, o.ModelVersionID = "generate", "approved-version"
		o.UsageStepID = *usagecost.StableModelUsageStepID(usagecost.Scope{TenantID: scope.TenantID,
			DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentID: scope.AgentID,
			AgentVersionID: scope.AgentVersionID, RunID: scope.RunID}, key)
		if key != "valid" {
			o.DurationMS = 9
		}
		if corrupt {
			o.ModelVersionID = "wrong-version"
		}
		raw, _ := json.Marshal(map[string]any{"performance_observation": o, "model_version_id": "approved-version"})
		_, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_invocation
(scope_hash,idempotency_key,fingerprint,status,response_json,cost_cents,billing_state,created_at,updated_at)
VALUES(?,?,?,'completed',?,0,'done',?,?)`), modelEvidenceScopeHash(scope), key, "fingerprint", string(raw), start, finish)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	insert("valid", false)
	original := insert("historical-mismatch", false)
	items, complete, err := store.EvaluationModelPerformance(ctx, scope)
	if err != nil || complete || len(items) != 1 || items[0].DurationMS != 7 {
		t.Fatalf("known-good evidence lost or historical timing invented: items=%v complete=%v err=%v", items, complete, err)
	}
	var retained string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT response_json FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key=?`),
		modelEvidenceScopeHash(scope), "historical-mismatch").Scan(&retained); err != nil || retained != original {
		t.Fatal("historical durable receipt was changed", err)
	}
	insert("corrupt-model-binding", true)
	if _, _, err := store.EvaluationModelPerformance(ctx, scope); err == nil {
		t.Fatal("foreign model binding hidden as clock mismatch")
	}
}
