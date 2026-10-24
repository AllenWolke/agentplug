package capability

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

func TestSQLCancellationModelRetentionDoesNotAuthorizeRecoveryOrResend(t *testing.T) {
	adminDSN, runtimeDSN := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"), os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if adminDSN == "" || runtimeDSN == "" {
		t.Skip("explicit isolated PostgreSQL identities required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := sqlutil.OpenPostgres(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema, _ := NewSQLModelInvocationStore(admin)
	for _, ensure := range []func(context.Context) error{schema.EnsureSchema, usagecost.NewSQLStore(admin).EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sqlutil.OpenPostgres(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// A caller-owned finalization transaction must not need a second connection.
	db.SetMaxOpenConns(1)
	models, _ := NewSQLModelInvocationStore(db)
	window := usagecost.NewSQLStore(db)
	if err := models.SetModelBudgetClosureReader(window); err != nil {
		t.Fatal(err)
	}
	m, op, gateway, _ := failoverInvocationFixture(t)
	m.modelStore, m.modelBudgets, m.usageRecorder = models, window, window
	op.Context.TaskID = "cancel-fixed-" + time.Now().UTC().Format("150405.000000000")
	op.Context.SessionID = op.Context.TaskID + "-session"
	owner := scopeFromHarness(op.Context)
	manual := policyasset.ModelSelectionBinding{Selection: policyasset.ModelSelection{Mode: "manual"},
		PolicySHA256: op.Policy.Hash, CommandFingerprint: strings.Repeat("d", 64)}
	if err := models.BindModelSelection(ctx, owner, manual); err != nil {
		t.Fatal(err)
	}
	gateway.firstError = &modelgateway.ProviderFailure{Category: "body_read"}
	w := invokeFailover(m, op, ctx)
	if w.Code != 502 || len(gateway.calls) != 1 {
		t.Fatal("fixed model failure switched or resent", w.Code, w.Body.String(), len(gateway.calls))
	}
	hash := modelEvidenceScopeHash(owner)
	record, err := models.GetBillingRecord(ctx, hash, "logical-call")
	if err != nil || record.Recovery == nil || !record.Recovery.HoldConfirmed || record.Recovery.FailureKind != "provider_body_read" {
		t.Fatal("actual gateway path did not persist an exact hold", err)
	}
	before, _ := json.Marshal(record)
	if err := m.CheckTaskModelQuiescence(ctx, owner); !errors.Is(err, ErrModelInvocationReconciliationNeeded) {
		t.Fatal("ordinary completion/recovery accepted the unknown", err)
	}
	if err := m.CheckTaskCancellationModelQuiescence(ctx, owner); err != nil {
		t.Fatal("cancellation failed to retain native hold", err)
	}
	after, _ := models.GetBillingRecord(ctx, hash, "logical-call")
	encoded, _ := json.Marshal(after)
	if string(encoded) != string(before) {
		t.Fatal("cancellation rewrote invocation or charge")
	}
	for _, dimension := range []string{"reserve_micros", "request_fingerprint", "price_version_id", "run_id", "agent_version_id", "status"} {
		t.Run("native-hold-"+dimension, func(t *testing.T) {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			var value any = "substituted"
			if dimension == "reserve_micros" {
				value = record.Recovery.Reservation.ReserveMicros + 1
			}
			if dimension == "status" {
				value = "released"
			}
			if _, err = tx.ExecContext(ctx, sqlutil.Bind("UPDATE platform_model_budget_reservation SET "+dimension+"=? WHERE reservation_id=?"), value, record.Recovery.Reservation.ReservationID); err != nil {
				t.Fatal(err)
			}
			if err = m.CheckTaskCancellationModelQuiescenceTx(ctx, tx, owner); !errors.Is(err, ErrModelInvocationReconciliationNeeded) {
				t.Fatal("substituted native hold accepted", err)
			}
		})
	}
	foreign := owner
	foreign.RunID += "-other"
	if err := m.CheckTaskCancellationModelQuiescence(ctx, foreign); !errors.Is(err, ErrModelInvocationReconciliationNeeded) {
		t.Fatal("different Run borrowed the hold", err)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.CheckTaskCancellationModelQuiescenceTx(ctx, tx, owner); err != nil {
		t.Fatal("single-connection finalization blocked", err)
	}
	_ = tx.Rollback()
	w = invokeFailover(m, op, ctx)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "MODEL_RECONCILIATION_REQUIRED") || len(gateway.calls) != 1 {
		t.Fatal("unknown original was resent after cancellation check", w.Code, w.Body.String(), len(gateway.calls))
	}
	independent := op
	independent.Context.TaskID += "-independent"
	independent.Context.SessionID += "-independent"
	if err = models.BindModelSelection(ctx, scopeFromHarness(independent.Context), manual); err != nil {
		t.Fatal(err)
	}
	w = invokeFailover(m, independent, ctx)
	if w.Code != 200 || len(gateway.calls) != 2 {
		t.Fatal("independent model request was blocked by original hold", w.Code, w.Body.String(), len(gateway.calls))
	}
	if err = m.CheckTaskModelQuiescence(ctx, owner); !errors.Is(err, ErrModelInvocationReconciliationNeeded) {
		t.Fatal("independent success cleared original unknown", err)
	}
}
