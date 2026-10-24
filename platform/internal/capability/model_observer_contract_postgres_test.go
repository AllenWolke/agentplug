package capability

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/execution"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

func TestSQLUnsentDecisionObserverLifecycle(t *testing.T) {
	ownerDSN, runtimeDSN := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"), os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if ownerDSN == "" || runtimeDSN == "" {
		t.Skip("owned DML PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	owner, err := sqlutil.OpenPostgres(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	schemaModels, _ := NewSQLModelInvocationStore(owner)
	for _, ensure := range []func(context.Context) error{schemaModels.EnsureSchema, usagecost.NewSQLStore(owner).EnsureSchema, usagecost.NewSQLRunTreeBudgetStore(owner).EnsureSchema, audit.NewSQLStore(owner).EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sqlutil.OpenPostgres(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	models, _ := NewSQLModelInvocationStore(db)
	window := usagecost.NewSQLStore(db)
	tree := usagecost.NewSQLRunTreeBudgetStore(db)
	if err := models.SetModelBudgetClosureReader(window); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("native-observer-%d", time.Now().UnixNano())
	scope := sharedkernel.Scope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", AgentID: "qa", AgentVersionID: "v1", InstallationID: id, AgentInstanceID: id, PrincipalType: "user", PrincipalID: id, SessionID: id, RunID: id, TraceID: strings.Repeat("c", 32), AuthorizationEpoch: 1}
	if err := execution.MigrateSchema(ctx, owner); err != nil {
		t.Fatal(err)
	}
	runs, err := execution.ConnectSQLStore(ctx, "pgx", runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	createRun := func(scope sharedkernel.Scope) {
		t.Helper()
		_, err := runs.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope,
			AgentVersionID: scope.AgentVersionID, IdempotencyKey: scope.RunID, Fingerprint: strings.Repeat("d", 64),
			RequestJSON: []byte(`{"operation":"invoke"}`), AgentEndpoint: "http://agent.invalid"})
		if err != nil {
			t.Fatal(err)
		}
	}
	createRun(scope)
	authority := &admissionSQLAuthority{scope: scope, models: models, tree: tree}
	tree.SetAuthority(authority)
	tree.SetAuditRecorder(audit.NewSQLStore(db))
	budgets, err := usagecost.NewSQLRunTreeModelBudgetStore(db, tree, window, authority)
	if err != nil {
		t.Fatal(err)
	}
	hash, fp := modelEvidenceScopeHash(scope), strings.Repeat("b", 64)
	attempt, _, err := models.ReserveGoverned(ctx, hash, id, fp)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := usagecost.ModelBudgetRequest{Scope: usagecost.ModelBudgetScope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", AgentID: "qa", AgentVersionID: "v1"}, RunID: id, RequestID: id, Fingerprint: fp, PriceVersionID: "price", Window: usagecost.ModelBudgetWindow{Start: now.Add(-time.Minute), End: now.Add(time.Hour)}, BudgetLimitMicros: 1000, ReserveMicros: 80, ExpiresAt: now.Add(time.Minute)}
	reservation, err := budgets.Reserve(withModelBudgetPreparation(ctx, hash, id, fp, attempt.AttemptToken), request)
	if err != nil {
		t.Fatal(err)
	}
	gateway := &captureModelGateway{}
	module := &Module{modelStore: models, modelBudgets: budgets, modelGateway: gateway}
	observe := func(t *testing.T, stage string) {
		t.Helper()
		// Observe through this project's public platform composition port. The
		// reference project's business observer bridge is deliberately not used.
		// An expired send or even released ledgers do not prove the persisted
		// billing decision was applied. Only the original, fully closed receipt
		// permits the execution owner to acknowledge stop/completion.
		err := models.CheckModelQuiescence(ctx, hash)
		if stage == "applied" {
			if err != nil {
				t.Fatalf("original applied receipt did not close the fence: %v", err)
			}
		} else if !errors.Is(err, ErrModelInvocationReconciliationNeeded) {
			t.Fatalf("unconfirmed %s allowed completion: %v", stage, err)
		}
		t.Logf("platform quiescence observed %s without a provider send", stage)
	}
	t.Run("expired-admission-retains-budget-until-platform-recovery", func(t *testing.T) {
		var original string
		var originalUntil time.Time
		if err := db.QueryRowContext(ctx, `SELECT billing_recovery_json,preparation_deadline FROM platform_model_invocation WHERE scope_hash=$1 AND idempotency_key=$2`, hash, id).Scan(&original, &originalUntil); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE platform_model_invocation SET billing_recovery_json=jsonb_set(billing_recovery_json::jsonb,'{admission_until}',to_jsonb('2020-01-01T00:00:00Z'::text))::text,preparation_deadline='2020-01-01T00:00:00Z' WHERE scope_hash=$1 AND idempotency_key=$2`, hash, id); err != nil {
			t.Fatal(err)
		}
		defer db.ExecContext(ctx, `UPDATE platform_model_invocation SET billing_recovery_json=$1,preparation_deadline=$2 WHERE scope_hash=$3 AND idempotency_key=$4`, original, originalUntil, hash, id)
		observe(t, "owned-admission-expired")
	})
	if err := module.prepareModelSend(ctx, hash, id, fp, reservation, now.Add(time.Minute), attempt.AttemptToken); err != nil {
		t.Fatal(err)
	}
	t.Run("expired-preparation-is-owned-pending-work-not-foreign-activity", func(t *testing.T) {
		key := id + "-preparation"
		prepared, _, err := models.ReserveGoverned(ctx, hash, key, fp)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `UPDATE platform_model_invocation SET preparation_deadline=clock_timestamp()-interval '1 second' WHERE scope_hash=$1 AND idempotency_key=$2 AND invocation_token=$3`, hash, key, prepared.AttemptToken); err != nil {
			t.Fatal(err)
		}
		observe(t, "owned-preparation-expired")
		second := scope
		second.RunID = id + "-same-session"
		createRun(second)
		observe(t, "ambiguous-preparation-session")
		if err = models.FailPreparation(ctx, hash, key, fp, prepared.AttemptToken); err != nil {
			t.Fatal(err)
		}
		observe(t, "preparation-closed")
	})
	t.Run("expired-owned-send-retains-full-budget-and-allows-active-completion", func(t *testing.T) {
		var original string
		if err := db.QueryRowContext(ctx, "SELECT billing_recovery_json FROM platform_model_invocation WHERE scope_hash=$1 AND idempotency_key=$2", hash, id).Scan(&original); err != nil {
			t.Fatal(err)
		}
		// Deterministic deadline fault on an actual governed send intent. There
		// is no provider call or invented response/no-charge decision.
		if _, err := db.ExecContext(ctx, `UPDATE platform_model_invocation SET billing_recovery_json=jsonb_set(billing_recovery_json::jsonb,'{send_deadline}',to_jsonb('2020-01-01T00:00:00Z'::text))::text WHERE scope_hash=$1 AND idempotency_key=$2`, hash, id); err != nil {
			t.Fatal(err)
		}
		defer db.ExecContext(ctx, "UPDATE platform_model_invocation SET billing_recovery_json=$1 WHERE scope_hash=$2 AND idempotency_key=$3", original, hash, id)
		observe(t, "owned-expired")
	})
	record, err := models.PersistUnsent(ctx, hash, id, fp, attempt.AttemptToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("accepted-retains-nonzero-double-hold", func(t *testing.T) { observe(t, "accepted") })
	t.Run("mismatched-durable-decision-rejected", func(t *testing.T) {
		var raw string
		if err := db.QueryRowContext(ctx, "SELECT decision_json FROM platform_model_billing_decision WHERE reservation_id=$1", reservation.ReservationID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE platform_model_billing_decision SET decision_json=jsonb_set(decision_json::jsonb,'{reason}','"mismatch"'::jsonb)::text WHERE reservation_id=$1`, reservation.ReservationID); err != nil {
			t.Fatal(err)
		}
		defer db.ExecContext(ctx, "UPDATE platform_model_billing_decision SET decision_json=$1 WHERE reservation_id=$2", raw, reservation.ReservationID)
		observe(t, "corrupt-decision")
	})
	t.Run("actual-response-never-counts-as-unsent", func(t *testing.T) {
		var raw sql.NullString
		if err := db.QueryRowContext(ctx, "SELECT response_json FROM platform_model_invocation WHERE scope_hash=$1 AND idempotency_key=$2", hash, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "UPDATE platform_model_invocation SET response_json='{}' WHERE scope_hash=$1 AND idempotency_key=$2", hash, id); err != nil {
			t.Fatal(err)
		}
		var prior any
		if raw.Valid {
			prior = raw.String
		}
		defer db.ExecContext(ctx, "UPDATE platform_model_invocation SET response_json=$1 WHERE scope_hash=$2 AND idempotency_key=$3", prior, hash, id)
		observe(t, "response-present")
	})
	t.Run("expired-observation-grace-rejected", func(t *testing.T) {
		var created time.Time
		if err := db.QueryRowContext(ctx, "SELECT created_at FROM platform_model_billing_decision WHERE reservation_id=$1", reservation.ReservationID).Scan(&created); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "UPDATE platform_model_billing_decision SET created_at=clock_timestamp()-interval '31 seconds' WHERE reservation_id=$1", reservation.ReservationID); err != nil {
			t.Fatal(err)
		}
		defer db.ExecContext(ctx, "UPDATE platform_model_billing_decision SET created_at=$1 WHERE reservation_id=$2", created, reservation.ReservationID)
		observe(t, "expired")
	})
	t.Run("manual-result-still-stops", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, "UPDATE platform_model_invocation SET billing_state='manual' WHERE scope_hash=$1 AND idempotency_key=$2", hash, id); err != nil {
			t.Fatal(err)
		}
		defer db.ExecContext(ctx, "UPDATE platform_model_invocation SET billing_state='decision_pending' WHERE scope_hash=$1 AND idempotency_key=$2", hash, id)
		observe(t, "manual")
	})
	if record.Recovery == nil || record.Recovery.Decision == nil {
		t.Fatal("original unsent intent missing")
	}
	if err := budgets.ResolveUncharged(ctx, reservation, record.Recovery.Decision.ProviderRef); err != nil {
		t.Fatal(err)
	}
	t.Run("partial-finalization-still-pauses", func(t *testing.T) { observe(t, "ledgers-released") })
	reopened, _ := NewSQLModelInvocationStore(db)
	if err := reopened.SetModelBudgetClosureReader(window); err != nil {
		t.Fatal(err)
	}
	restarted := &Module{modelStore: reopened, modelBudgets: budgets, modelGateway: gateway}
	restarted.reconcileBilling(ctx)
	restarted.reconcileBilling(ctx)
	t.Run("reopen-worker-applies-original-once", func(t *testing.T) {
		observe(t, "applied")
		if err := reopened.CheckModelQuiescence(ctx, hash); err != nil {
			t.Fatal(err)
		}
		var decisions, events int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM platform_model_billing_decision WHERE reservation_id=$1", reservation.ReservationID).Scan(&decisions); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM platform_usage_event WHERE run_id=$1", id).Scan(&events); err != nil {
			t.Fatal(err)
		}
		if decisions != 1 || events != 0 || gateway.calls != 0 {
			t.Fatal("duplicate decision or invented usage/send", decisions, events, gateway.calls)
		}
	})
}
