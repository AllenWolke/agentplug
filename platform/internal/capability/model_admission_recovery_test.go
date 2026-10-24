package capability

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

// Facts in this fixture are explicit test authority, never live IAM evidence.
type admissionSQLAuthority struct {
	scope     sharedkernel.Scope
	models    *SQLModelInvocationStore
	tree      *usagecost.SQLRunTreeBudgetStore
	omitProof bool // Reproduce the old transaction boundary only in the test.
}

func (a *admissionSQLAuthority) Facts(_ context.Context, _ *sql.Tx, scope sharedkernel.Scope, _ bool) (usagecost.RunTreeBudgetFacts, error) {
	if scope != a.scope {
		return usagecost.RunTreeBudgetFacts{}, usagecost.ErrBudgetScopeMismatch
	}
	return usagecost.RunTreeBudgetFacts{ActorScope: scope, RootScope: scope, PolicyHash: strings.Repeat("d", 64), LimitMicros: 1000, LimitTokens: 1000}, nil
}
func (a *admissionSQLAuthority) ReserveCommand(_ context.Context, _ *sql.Tx, r usagecost.ModelBudgetRequest) (sharedkernel.Scope, usagecost.RunTreeBudgetCommand, error) {
	return a.scope, usagecost.RunTreeBudgetCommand{Action: "reserve", RequestID: r.RequestID, Fingerprint: r.Fingerprint, Hold: usagecost.RunTreeBudgetHold{Micros: r.ReserveMicros, Tokens: 10}}, nil
}
func (a *admissionSQLAuthority) RecordAdmission(ctx context.Context, tx *sql.Tx, r usagecost.ModelBudgetReservation) error {
	if a.omitProof {
		return nil
	}
	return a.models.RecordBudgetAdmissionTx(ctx, tx, r)
}
func (a *admissionSQLAuthority) ExistingCommand(ctx context.Context, tx *sql.Tx, r usagecost.ModelBudgetReservation, action string, _ *usagecost.Event, _ string, ref string) (sharedkernel.Scope, usagecost.RunTreeBudgetCommand, error) {
	b, err := a.tree.ModelBindingTx(ctx, tx, r)
	if err != nil {
		return sharedkernel.Scope{}, usagecost.RunTreeBudgetCommand{}, err
	}
	c := usagecost.RunTreeBudgetCommand{Action: action, RequestID: r.RequestID, Fingerprint: r.Fingerprint, Hold: usagecost.RunTreeBudgetHold{Micros: r.ReserveMicros, Tokens: b.HoldTokens}}
	if action != "unknown" {
		e, err := a.models.BudgetEvidenceTx(ctx, tx, r)
		if err != nil {
			return sharedkernel.Scope{}, c, err
		}
		if action != "release_unbilled" || e.NoChargeRef == "" || ref != e.NoChargeRef || e.Event != nil {
			return sharedkernel.Scope{}, c, usagecost.ErrBudgetReservationConflict
		}
		c.OutcomeFingerprint = e.Fingerprint
	}
	return b.Scope, c, nil
}
func (a *admissionSQLAuthority) VerifyOutcome(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, c usagecost.RunTreeBudgetCommand) error {
	r, err := a.tree.ModelReservationTx(ctx, tx, scope, c.RequestID)
	if err != nil {
		return err
	}
	e, err := a.models.BudgetEvidenceTx(ctx, tx, r)
	if err != nil {
		return err
	}
	if c.Action != "release_unbilled" || e.NoChargeRef == "" || e.Event != nil || c.OutcomeFingerprint != e.Fingerprint {
		return usagecost.ErrBudgetReservationConflict
	}
	return nil
}

type lostAdmissionAck struct {
	*usagecost.SQLRunTreeModelBudgetStore
	cancel context.CancelFunc
}

func (s lostAdmissionAck) Reserve(ctx context.Context, r usagecost.ModelBudgetRequest) (usagecost.ModelBudgetReservation, error) {
	_, err := s.SQLRunTreeModelBudgetStore.Reserve(ctx, r)
	if err != nil {
		return usagecost.ModelBudgetReservation{}, err
	}
	s.cancel() // Commit happened. Its acknowledgement never reaches the caller.
	return usagecost.ModelBudgetReservation{}, context.Canceled
}

func TestSQLBudgetAdmissionCommitAcknowledgementRecovery(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	models, err := NewSQLModelInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	window := usagecost.NewSQLStore(db)
	tree := usagecost.NewSQLRunTreeBudgetStore(db)
	audits := audit.NewSQLStore(db)
	for _, ensure := range []func(context.Context) error{models.EnsureSchema, window.EnsureSchema, tree.EnsureSchema, audits.EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := models.SetModelBudgetClosureReader(window); err != nil {
		t.Fatal(err)
	}
	t.Run("response-contract", func(t *testing.T) {
		assertNativeModelResponseContract(t, ctx, db, models)
	})
	for _, name := range []string{"legacy-gap-reproduction", "commit-ack-lost", "missing-owner-rolls-back", "stale-nonce-rolls-back", "send-intent-retains-unknown", "unsent-window-closure", "expired-prepared-closes", "late-unsent-after-send-expiry"} {
		t.Run(name, func(t *testing.T) {
			id := fmt.Sprintf("admission-%d", time.Now().UnixNano())
			scope := sharedkernel.Scope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", AgentID: "qa", AgentVersionID: "v1", InstallationID: id, AgentInstanceID: id, PrincipalType: "user", PrincipalID: id, SessionID: id, RunID: id, TraceID: strings.Repeat("c", 32), AuthorizationEpoch: 1}
			a := &admissionSQLAuthority{scope: scope, models: models, tree: tree, omitProof: name == "legacy-gap-reproduction"}
			tree.SetAuthority(a)
			tree.SetAuditRecorder(audits)
			budgets, err := usagecost.NewSQLRunTreeModelBudgetStore(db, tree, window, a)
			if err != nil {
				t.Fatal(err)
			}
			hash, fp := modelEvidenceScopeHash(scope), strings.Repeat("b", 64)
			attempt, _, err := models.ReserveGoverned(ctx, hash, id, fp)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			r := usagecost.ModelBudgetRequest{Scope: usagecost.ModelBudgetScope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", AgentID: "qa", AgentVersionID: "v1"}, RunID: id, RequestID: id, Fingerprint: fp, PriceVersionID: "price", Window: usagecost.ModelBudgetWindow{Start: now.Add(-time.Minute), End: now.Add(time.Hour)}, BudgetLimitMicros: 1000, ReserveMicros: 80, ExpiresAt: now.Add(time.Minute)}
			caller, stop := context.WithCancel(ctx)
			defer stop()
			bound := withModelBudgetPreparation(caller, hash, id, fp, attempt.AttemptToken)
			if name == "missing-owner-rolls-back" {
				bound = caller
			}
			if name == "stale-nonce-rolls-back" {
				bound = withModelBudgetPreparation(caller, hash, id, fp, "old-nonce")
			}
			var res usagecost.ModelBudgetReservation
			direct := strings.Contains(name, "send") || name == "unsent-window-closure" || name == "expired-prepared-closes"
			if direct {
				res, err = budgets.Reserve(bound, r)
			} else {
				_, err = reserveModelBudgetAdmission(bound, lostAdmissionAck{budgets, stop}, r)
			}
			if strings.HasSuffix(name, "rolls-back") {
				if !errors.Is(err, ErrModelInvocationConflict) {
					t.Fatal("unowned reservation accepted", err)
				}
				for _, table := range []string{"platform_model_budget_reservation", "platform_run_tree_budget_request", "platform_run_tree_model_binding"} {
					var count int
					column := "request_id"
					if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE "+column+"=$1", id).Scan(&count); err != nil || count != 0 {
						t.Fatal("partial transaction persisted", table, count, err)
					}
				}
				if err := models.FailPreparation(ctx, hash, id, fp, attempt.AttemptToken); err != nil {
					t.Fatal(err)
				}
				return
			}
			if !direct && !errors.Is(err, context.Canceled) {
				t.Fatal("fault did not lose committed ack", err)
			}
			gateway := &captureModelGateway{}
			m := &Module{modelStore: models, modelBudgets: budgets, modelGateway: gateway}
			if name == "late-unsent-after-send-expiry" {
				if err != nil {
					t.Fatal(err)
				}
				if err := m.prepareModelSend(ctx, hash, id, fp, res, now.Add(time.Minute), attempt.AttemptToken); err != nil {
					t.Fatal(err)
				}
				if err := models.BeginModelDispatch(ctx, hash, id, fp, attempt.AttemptToken); err != nil {
					t.Fatal(err)
				}
				record, err := models.GetBillingRecord(ctx, hash, id)
				if err != nil {
					t.Fatal(err)
				}
				record.Recovery.SendDeadline = now.Add(-time.Second)
				raw, err := json.Marshal(record.Recovery)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.ExecContext(ctx, "UPDATE platform_model_invocation SET billing_recovery_json=$1,billing_retry_at=$2 WHERE scope_hash=$3 AND idempotency_key=$4", string(raw), record.Recovery.SendDeadline, hash, id); err != nil {
					t.Fatal(err)
				}
				m.reconcileBilling(ctx)
				assertAdmissionBudgetStates(t, ctx, db, id, "reconcile", "uncertain")
				// Simulate the owning adapter returning its positive no-send
				// proof after expiry promotion. No human settlement API is used.
				if err := m.abortUnsentModel(ctx, hash, id, fp, res, attempt.AttemptToken); err != nil {
					t.Fatal("late trusted proof did not close original holds", err)
				}
				assertAdmissionBudgetStates(t, ctx, db, id, "released", "released")
				if err := models.BeginModelDispatch(ctx, hash, id, fp, attempt.AttemptToken); !errors.Is(err, ErrModelInvocationConflict) {
					t.Fatal("late proof granted send rights", err)
				}
				return
			}
			if name == "expired-prepared-closes" {
				if err != nil {
					t.Fatal(err)
				}
				if err := m.prepareModelSend(ctx, hash, id, fp, res, now.Add(time.Minute), attempt.AttemptToken); err != nil {
					t.Fatal(err)
				}
				record, err := models.GetBillingRecord(ctx, hash, id)
				if err != nil {
					t.Fatal(err)
				}
				record.Recovery.SendDeadline = now.Add(-time.Second)
				raw, err := json.Marshal(record.Recovery)
				if err != nil {
					t.Fatal(err)
				}
				// Fault injection advances only this attempt's persisted cutoff;
				// no operator settlement, fabricated provider usage or Run edits.
				if _, err := db.ExecContext(ctx, "UPDATE platform_model_invocation SET billing_recovery_json=$1,billing_retry_at=$2 WHERE scope_hash=$3 AND idempotency_key=$4", string(raw), record.Recovery.SendDeadline, hash, id); err != nil {
					t.Fatal(err)
				}
				m.reconcileBilling(ctx)
				m.reconcileBilling(ctx)
				assertAdmissionBudgetStates(t, ctx, db, id, "released", "released")
				if gateway.calls != 0 || m.billingStats.Completed.Load() != 1 || m.billingStats.Failed.Load() != 0 {
					t.Fatal("prepared recovery did not close both holds exactly once")
				}
				if err := models.BeginModelDispatch(ctx, hash, id, fp, attempt.AttemptToken); !errors.Is(err, ErrModelInvocationConflict) {
					t.Fatal("expired owner still has send rights", err)
				}
				return
			}
			if name == "unsent-window-closure" {
				if err != nil {
					t.Fatal(err)
				}
				if err := m.prepareModelSend(ctx, hash, id, fp, res, now.Add(time.Minute), attempt.AttemptToken); err != nil {
					t.Fatal(err)
				}
				assertAdmissionBudgetStates(t, ctx, db, id, "reconcile", "uncertain")
				// This is the existing exact-proof cleanup now invoked by the
				// HTTP expired-provider-window branch, not an expired-hold refund.
				if err := m.abortUnsentModel(ctx, hash, id, fp, res, attempt.AttemptToken); err != nil {
					t.Fatal(err)
				}
				assertAdmissionBudgetStates(t, ctx, db, id, "released", "released")
				reopened, err := NewSQLModelInvocationStore(db)
				if err != nil {
					t.Fatal(err)
				}
				if err := reopened.SetModelBudgetClosureReader(window); err != nil {
					t.Fatal(err)
				}
				restarted := &Module{modelStore: reopened, modelBudgets: budgets, modelGateway: gateway}
				restarted.reconcileBilling(ctx)
				restarted.reconcileBilling(ctx)
				if err := reopened.CheckModelQuiescence(ctx, hash); err != nil {
					t.Fatal("closed unsent window blocks cancellation", err)
				}
				var decisions, usage int
				if err := db.QueryRowContext(ctx, "SELECT count(*) FROM platform_model_billing_decision WHERE scope_hash=$1 AND idempotency_key=$2", hash, id).Scan(&decisions); err != nil {
					t.Fatal(err)
				}
				if err := db.QueryRowContext(ctx, "SELECT count(*) FROM platform_usage_event WHERE run_id=$1", id).Scan(&usage); err != nil {
					t.Fatal(err)
				}
				if decisions != 1 || usage != 0 || gateway.calls != 0 {
					t.Fatal("unsent window cleanup fabricated usage or duplicate effect", decisions, usage, gateway.calls)
				}
				return
			}
			if name == "legacy-gap-reproduction" {
				m.failModelInvocation(caller, hash, id, fp, "fixture", attempt.AttemptToken)
				var state string
				if err := db.QueryRowContext(ctx, "SELECT billing_state FROM platform_model_invocation WHERE scope_hash=$1 AND idempotency_key=$2", hash, id).Scan(&state); err != nil || state != "done" {
					t.Fatal("old gap not reproduced", state, err)
				}
				assertAdmissionBudgetStates(t, ctx, db, id, "pending", "held")
				var raw string
				if err := db.QueryRowContext(ctx, "SELECT reservation_json FROM platform_run_tree_model_binding WHERE request_id=$1", id).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal([]byte(raw), &res); err != nil {
					t.Fatal(err)
				}
				wrong := res
				wrong.Scope.TenantID = "other-tenant"
				if err := models.RecoverFailedPreparationAdmission(ctx, tree, window, id, wrong); err == nil {
					t.Fatal("cross-scope repair accepted")
				}
				if err := models.RecoverFailedPreparationAdmission(ctx, tree, window, "other-key", res); err == nil {
					t.Fatal("wrong invocation accepted")
				}
				for range 2 {
					if err := models.RecoverFailedPreparationAdmission(ctx, tree, window, id, res); err != nil {
						t.Fatal("failed preparation proof rejected", err)
					}
				}
				assertAdmissionBudgetStates(t, ctx, db, id, "reconcile", "held")
				m.reconcileBilling(ctx)
				m.reconcileBilling(ctx)
				assertAdmissionBudgetStates(t, ctx, db, id, "released", "released")
				if m.billingStats.Completed.Load() != 1 || m.billingStats.Failed.Load() != 0 || gateway.calls != 0 {
					t.Fatal("legacy recovery did not close exactly once")
				}
				if err := models.RecoverFailedPreparationAdmission(ctx, tree, window, id, res); err != nil {
					t.Fatal("exact terminal repair replay failed", err)
				}
				return
			}
			if err != nil && name == "send-intent-retains-unknown" {
				t.Fatal(err)
			}
			if name == "send-intent-retains-unknown" {
				if err := m.prepareModelSend(ctx, hash, id, fp, res, now.Add(time.Minute), attempt.AttemptToken); err != nil {
					t.Fatal(err)
				}
				if err := models.BeginModelDispatch(ctx, hash, id, fp, attempt.AttemptToken); err != nil {
					t.Fatal(err)
				}
				if err := models.FailPreparation(ctx, hash, id, fp, attempt.AttemptToken); !errors.Is(err, ErrModelInvocationConflict) {
					t.Fatal("send intent unfenced", err)
				}
				if err := models.RecoverFailedPreparationAdmission(ctx, tree, window, id, res); !errors.Is(err, ErrModelInvocationConflict) {
					t.Fatal("sent/unknown call accepted as failed preparation", err)
				}
				// Expired preparation is insufficient to infer that a provider was unsent.
				m.reconcileBilling(ctx)
				assertAdmissionBudgetStates(t, ctx, db, id, "reconcile", "uncertain")
				if gateway.calls != 0 {
					t.Fatal("recovery called provider")
				}
				return
			}
			m.failModelInvocation(caller, hash, id, fp, "fixture", attempt.AttemptToken)
			assertAdmissionBudgetStates(t, ctx, db, id, "pending", "held")
			record, err := models.GetBillingRecord(ctx, hash, id)
			if err != nil || record.Recovery == nil || record.Recovery.AdmissionUntil.IsZero() {
				t.Fatal("commit lost recovery intent", err)
			}
			if _, err := models.PersistUnsent(ctx, hash, id, fp, attempt.AttemptToken); !errors.Is(err, ErrModelInvocationConflict) {
				t.Fatal("live admission released", err)
			}
			m.reconcileBilling(ctx)
			assertAdmissionBudgetStates(t, ctx, db, id, "pending", "held")
			// Advance only this isolated fixture's durable deadline, then reopen store.
			record.Recovery.AdmissionUntil = now.Add(-time.Second)
			raw, _ := json.Marshal(record.Recovery)
			if _, err := db.ExecContext(ctx, "UPDATE platform_model_invocation SET preparation_deadline=$1,billing_retry_at=$1,billing_recovery_json=$2 WHERE scope_hash=$3 AND idempotency_key=$4", record.Recovery.AdmissionUntil, string(raw), hash, id); err != nil {
				t.Fatal(err)
			}
			reopened, err := NewSQLModelInvocationStore(db)
			if err != nil {
				t.Fatal(err)
			}
			if err := reopened.SetModelBudgetClosureReader(window); err != nil {
				t.Fatal(err)
			}
			a.models = reopened
			restarted := &Module{modelStore: reopened, modelBudgets: budgets, modelGateway: gateway}
			restarted.reconcileBilling(ctx)
			restarted.reconcileBilling(ctx)
			assertAdmissionBudgetStates(t, ctx, db, id, "released", "released")
			if restarted.billingStats.Completed.Load() != 1 || restarted.billingStats.Failed.Load() != 0 || gateway.calls != 0 {
				t.Fatal("recovery must close once without provider", restarted.billingStats.Completed.Load(), restarted.billingStats.Failed.Load(), gateway.calls)
			}
			if err := models.SaveBillingRecovery(ctx, hash, id, fp, nil, 0, BillingRecovery{Reservation: record.Recovery.Reservation, PriceID: "price", AttemptToken: attempt.AttemptToken, SendDeadline: now.Add(time.Minute)}); !errors.Is(err, ErrModelInvocationConflict) {
				t.Fatal("stale producer regained send authority", err)
			}
			if err := reopened.CheckModelQuiescence(ctx, hash); err != nil {
				t.Fatal("confirmed unsent admission still blocks", err)
			}
		})
	}
}

func assertAdmissionBudgetStates(t *testing.T, ctx context.Context, db *sql.DB, id, window, tree string) {
	t.Helper()
	for _, check := range []struct{ table, want string }{{"platform_model_budget_reservation", window}, {"platform_run_tree_budget_request", tree}} {
		var state string
		if err := db.QueryRowContext(ctx, "SELECT status FROM "+check.table+" WHERE request_id=$1", id).Scan(&state); err != nil || state != check.want {
			t.Fatal(check.table, "status", state, "want", check.want, "error", err)
		}
	}
}

func assertNativeModelResponseContract(t *testing.T, ctx context.Context, db *sql.DB, models *SQLModelInvocationStore) {
	t.Helper()
	for _, sample := range []struct {
		name     string
		response map[string]any
	}{
		{"absent", nil},
		{"empty-object", map[string]any{}},
		{"known-response", map[string]any{"text": "observed"}},
	} {
		t.Run(sample.name, func(t *testing.T) {
			id := fmt.Sprintf("response-contract-%d", time.Now().UnixNano())
			hash, fp := fmt.Sprintf("%064x", time.Now().UnixNano()), strings.Repeat("b", 64)
			r, _, err := models.ReserveGoverned(ctx, hash, id, fp)
			if err != nil {
				t.Fatal(err)
			}
			recovery := BillingRecovery{AttemptToken: r.AttemptToken, SendPhase: "prepared", SendDeadline: time.Now().Add(time.Minute),
				Reservation: usagecost.ModelBudgetReservation{ReservationID: id, Scope: usagecost.ModelBudgetScope{TenantID: id}}}
			if err := models.SaveBillingRecovery(ctx, hash, id, fp, sample.response, 0, recovery); err != nil {
				t.Fatal(err)
			}
			var sqlNull bool
			if err := db.QueryRowContext(ctx, "SELECT response_json IS NULL FROM platform_model_invocation WHERE scope_hash=$1 AND idempotency_key=$2", hash, id).Scan(&sqlNull); err != nil || sqlNull != (sample.response == nil) {
				t.Fatal("nil and real response storage confused", sqlNull, err)
			}
			if err := models.BeginModelDispatch(ctx, hash, id, fp, "stale-owner"); !errors.Is(err, ErrModelInvocationConflict) {
				t.Fatal("stale owner entered send", err)
			}
			// Two contenders must grant one send right for absent responses,
			// and none if a real response (including an empty object) exists.
			results := make(chan error, 2)
			for range 2 {
				go func() { results <- models.BeginModelDispatch(ctx, hash, id, fp, r.AttemptToken) }()
			}
			won := 0
			for range 2 {
				err := <-results
				if err == nil {
					won++
				} else if !errors.Is(err, ErrModelInvocationConflict) {
					t.Fatal(err)
				}
			}
			want := 0
			if sample.response == nil {
				want = 1
			}
			if won != want {
				t.Fatal("incorrect number of provider send rights", won, want)
			}
		})
	}
}
