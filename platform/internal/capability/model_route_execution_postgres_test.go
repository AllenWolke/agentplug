package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

type lostSQLDispositionStore struct{ *SQLModelInvocationStore }

func (s lostSQLDispositionStore) AdvanceModelRouteExecution(ctx context.Context, scope, logical string,
	state ModelRouteExecution, route StoredModelRoute, fingerprint string, p policyasset.ModelRoutingPolicy) (ModelRouteExecution, error) {
	record, err := s.GetBillingRecord(context.Background(), scope, physicalRouteAttemptKey(logical, len(state.Steps)))
	if err == nil && record.Status == "reconcile" {
		return ModelRouteExecution{}, context.Canceled
	}
	return s.SQLModelInvocationStore.AdvanceModelRouteExecution(ctx, scope, logical, state, route, fingerprint, p)
}

func TestSQLModelRouteExecutionRecoveryAndAccountingIsolation(t *testing.T) {
	adminDSN, runtimeDSN := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"), os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if adminDSN == "" || runtimeDSN == "" {
		t.Skip("explicit isolated PostgreSQL identities required")
	}
	for _, dsn := range []string{adminDSN, runtimeDSN} {
		u, err := url.Parse(dsn)
		if err != nil || u.Hostname() != "127.0.0.1" || u.Path != "/knowledge_test" {
			t.Fatal("owned loopback fixture required")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := sqlutil.OpenPostgres(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	migration, err := NewSQLModelInvocationStore(admin)
	if err != nil {
		t.Fatal(err)
	}
	if err := migration.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := usagecost.NewSQLStore(admin).EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := audit.NewSQLStore(admin).EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := sqlutil.OpenPostgres(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLModelInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	budgets := usagecost.NewSQLStore(db)
	if err := store.SetModelBudgetClosureReader(budgets); err != nil {
		t.Fatal(err)
	}
	m, op, g, _ := resilientInvocationFixture(t)
	m.modelStore, m.modelBudgets, m.usageRecorder = store, budgets, budgets
	m.SetModelAttemptRecorder(audit.NewSQLStore(db))
	var parentInput modelGenerateInput
	_ = json.Unmarshal(op.Input, &parentInput)
	parentInput.DeadlineMS = time.Now().Add(25 * time.Second).UnixMilli()
	op.Input, _ = json.Marshal(parentInput)
	op.Context.TaskID = "route-execution-native-" + time.Now().UTC().Format("150405.000000000")
	scope := scopeFromHarness(op.Context)
	if err := store.BindModelSelection(ctx, scope, policyasset.ModelSelectionBinding{Selection: policyasset.ModelSelection{Mode: "automatic"}, PolicySHA256: op.Policy.Hash, CommandFingerprint: strings.Repeat("d", 64)}); err != nil {
		t.Fatal(err)
	}
	hash := modelSelectionScopeHash(scope)
	g.firstError = &modelgateway.ProviderFailure{Category: "body_read"}
	w := invokeFailover(m, op, ctx)
	if w.Code != 200 || len(g.calls) != 2 {
		t.Fatal("native fallback failed", w.Code, w.Body.String(), len(g.calls))
	}
	t.Run("native-audit-links-failure-and-actual-alternate", func(t *testing.T) {
		rows, err := db.QueryContext(ctx, sqlutil.Bind(`SELECT summary FROM platform_audit_event WHERE aggregate_id=? AND action='model.provider_attempt' ORDER BY created_at,event_id`), scope.RunID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var attempts []map[string]any
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var value map[string]any
			if json.Unmarshal([]byte(raw), &value) != nil {
				t.Fatal("invalid audit JSON")
			}
			attempts = append(attempts, value)
		}
		if rows.Err() != nil || len(attempts) != 2 {
			t.Fatal("missing native attempt audit", len(attempts), rows.Err())
		}
		if attempts[0]["model_version_id"] != g.calls[0].ModelVersionID || attempts[0]["error_kind"] != "provider_body_read" || attempts[0]["outcome"] != "failed" {
			t.Fatal("original cause or actual model missing", attempts[0])
		}
		if attempts[1]["model_version_id"] != g.calls[1].ModelVersionID || attempts[1]["outcome"] != "succeeded" {
			t.Fatal("actual handling model missing", attempts[1])
		}
		fallback, ok := attempts[1]["fallback"].(map[string]any)
		if !ok || fallback["previous_decision_sha256"] != attempts[0]["decision_sha256"] {
			t.Fatal("fallback predecessor missing")
		}
	})
	t.Run("business-completion-keeps-native-original-hold", func(t *testing.T) {
		if err := m.CheckTaskModelQuiescence(ctx, scope); err != nil {
			t.Fatal(err)
		}
		original, err := store.GetBillingRecord(ctx, hash, "logical-call")
		if err != nil || original.Recovery == nil || original.Status != "reconcile" {
			t.Fatal(original.Status, err)
		}
		if original.Recovery.Decision != nil || original.Recovery.Event != nil {
			t.Fatal("invented known billing")
		}
		var status string
		var held int64
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,reserve_micros FROM platform_model_budget_reservation WHERE reservation_id=?`), original.Recovery.Reservation.ReservationID).Scan(&status, &held); err != nil || status != "reconcile" || held != original.Recovery.Reservation.ReserveMicros {
			t.Fatal("full native hold lost", status, held, err)
		}
		zero, err := store.EvaluationNoModelRequests(ctx, scope)
		if err != nil || zero {
			t.Fatal("routed model request disappeared from evaluation", zero, err)
		}
		qualified, err := store.EvaluationUsedChatModel(ctx, scope, g.calls[1].ModelVersionID)
		if err != nil || qualified {
			t.Fatal("mixed uncertain model run became fixed-model qualification", qualified, err)
		}
	})
	t.Run("new-connection-replay-and-read-only-recovery", func(t *testing.T) {
		reopened, err := sqlutil.OpenPostgres(ctx, runtimeDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		restored, err := NewSQLModelInvocationStore(reopened)
		if err != nil {
			t.Fatal(err)
		}
		m.modelStore = restored
		w := invokeFailover(m, op, ctx)
		if w.Code != 200 || len(g.calls) != 2 || !strings.Contains(w.Body.String(), `"retained_unknown_attempts":1`) {
			t.Fatal(w.Code, w.Body.String(), len(g.calls))
		}
		w = httptest.NewRecorder()
		m.modelReceiptAuthorized(w, httptest.NewRequest("POST", "/internal/model/generate/receipt", nil).WithContext(ctx), op, false)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"completed"`) || len(g.calls) != 2 {
			t.Fatal(w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"retained_unknown_attempts":1`) {
			t.Fatal("receipt recovery dropped accounting disposition", w.Body.String())
		}
		m.modelStore = store
	})
	t.Run("hold-reader-rejects-changed-native-reservation", func(t *testing.T) {
		original, err := store.GetBillingRecord(ctx, hash, "logical-call")
		if err != nil || original.Recovery == nil {
			t.Fatal(err)
		}
		reservation := original.Recovery.Reservation
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_reservation SET status='pending' WHERE reservation_id=?`), reservation.ReservationID); err != nil {
			t.Fatal(err)
		}
		if m.CheckTaskModelQuiescence(ctx, scope) == nil {
			t.Fatal("non-retained native hold was accepted")
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_reservation SET status='reconcile' WHERE reservation_id=?`), reservation.ReservationID); err != nil {
			t.Fatal(err)
		}
		if err := m.CheckTaskModelQuiescence(ctx, scope); err != nil {
			t.Fatal("restored exact proof rejected", err)
		}
	})
	t.Run("concurrent-disposition-has-one-durable-winner", func(t *testing.T) {
		var in modelGenerateInput
		_ = json.Unmarshal(op.Input, &in)
		in.IdempotencyKey = "concurrent-call"
		attempt := op
		attempt.Input, _ = json.Marshal(in)
		// A completed native call is disposed by competing recovery owners.
		captured := &modelCallResponse{header: make(http.Header)}
		m.generateAuthorizedOnce(captured, httptest.NewRequest("POST", "/internal/model/generate", nil).WithContext(ctx), attempt)
		if captured.status != 200 {
			t.Fatal(captured.status, captured.body.String())
		}
		route, found, err := store.LookupModelRoute(ctx, hash, in.IdempotencyKey)
		if err != nil || !found {
			t.Fatal(err)
		}
		state, err := store.BeginModelRouteExecution(ctx, hash, in.IdempotencyKey, ModelRouteExecution{Version: "model-route-execution/v1", RequestFingerprint: route.RequestFingerprint, PolicySHA256: route.Decision.PolicySHA256, MaxAttempts: 3, Revision: 1, Status: "active", Deadline: time.Now().Add(30 * time.Second)})
		if err != nil {
			t.Fatal(err)
		}
		var workers sync.WaitGroup
		type result struct {
			state ModelRouteExecution
			err   error
		}
		results := make(chan result, 8)
		for i := 0; i < 8; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				value, err := store.AdvanceModelRouteExecution(ctx, hash, in.IdempotencyKey, state, route, routeNativeFingerprint(op, in, route), *op.Policy.Model.Routing)
				results <- result{value, err}
			}()
		}
		workers.Wait()
		close(results)
		winner := ""
		for item := range results {
			if item.err != nil || item.state.Status != "completed" || item.state.Revision != 2 {
				t.Fatal(item.state, item.err)
			}
			if winner == "" {
				winner = modelRouteHash(item.state)
			}
			if winner != modelRouteHash(item.state) {
				t.Fatal("CAS returned different winners")
			}
		}
		if len(g.calls) != 3 {
			t.Fatal("disposition replay called provider")
		}
	})
	t.Run("undisposed-routed-call-blocks-quiescence", func(t *testing.T) {
		if _, _, err := store.Reserve(ctx, hash, "unrelated-pending", strings.Repeat("e", 64), 0, 0); err != nil {
			t.Fatal(err)
		}
		if m.CheckTaskModelQuiescence(ctx, scope) == nil {
			t.Fatal("routed running invocation missed")
		}
		if err := store.Fail(ctx, hash, "unrelated-pending", strings.Repeat("e", 64)); err != nil {
			t.Fatal(err)
		}
		if err := m.CheckTaskModelQuiescence(ctx, scope); err != nil {
			t.Fatal("resolved independent fixture still blocks", err)
		}
	})
	t.Run("owner-loss-before-disposition-recovers-with-native-hold-and-concurrent-stop", func(t *testing.T) {
		for _, savedPolicy := range []bool{true, false} {
			attempt := op
			attempt.Context.TaskID += "-owner-loss"
			if savedPolicy {
				attempt.Context.TaskID += "-saved"
			}
			originalScope := scopeFromHarness(attempt.Context)
			scopeHash := modelSelectionScopeHash(originalScope)
			if err := store.BindModelSelection(ctx, originalScope, policyasset.ModelSelectionBinding{
				Selection: policyasset.ModelSelection{Mode: "automatic"}, PolicySHA256: op.Policy.Hash,
				CommandFingerprint: strings.Repeat("d", 64)}); err != nil {
				t.Fatal(err)
			}
			gateway := &failoverGatewayFixture{firstError: &modelgateway.ProviderFailure{Category: "body_read"}}
			m.modelGateway, m.modelStore = gateway, lostSQLDispositionStore{store}
			w := invokeFailover(m, attempt, ctx)
			if w.Code == 200 || len(gateway.calls) != 1 {
				t.Fatal("owner-loss fixture dispatched alternate", w.Code, w.Body.String())
			}
			before, err := store.GetBillingRecord(ctx, scopeHash, "logical-call")
			if err != nil || before.Status != "reconcile" || before.Recovery == nil || !before.Recovery.HoldConfirmed {
				t.Fatal("native unknown hold fixture missing", before.Status, err)
			}
			if !savedPolicy {
				state, _, err := store.LookupModelRouteExecution(ctx, scopeHash, "logical-call")
				if err != nil || state.Revision != 1 || len(state.Steps) != 0 {
					t.Fatal(state, err)
				}
				state.RecoveryPolicy = nil // Exact pre-fix persisted format, no billing mutation.
				raw, _ := json.Marshal(state)
				if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_route_execution SET state_json=? WHERE scope_hash=? AND logical_key=? AND revision=1`),
					string(raw), scopeHash, "logical-call"); err != nil {
					t.Fatal(err)
				}
			}
			resolved := op.Policy
			resolved.ModelProfileID, resolved.PromptVersionID, resolved.ToolPolicyID = "model-fixture", "prompt-fixture", "tool-fixture"
			resolved.MemoryPolicyID, resolved.KnowledgePolicyID, resolved.RuntimePolicyID = "memory-fixture", "knowledge-fixture", "runtime-fixture"
			resolved.Revision = 1
			m.policy, m.modelStore = policyasset.StaticResolver{Snapshot: resolved}, store
			var workers sync.WaitGroup
			failures := make(chan error, 8)
			for i := 0; i < 8; i++ {
				workers.Add(1)
				go func() {
					defer workers.Done()
					failures <- m.CheckTaskModelQuiescence(ctx, originalScope)
				}()
			}
			workers.Wait()
			close(failures)
			for err := range failures {
				if err != nil {
					t.Fatal("native cancelled/owner-lost run did not become quiescent", err)
				}
			}
			after, err := store.GetBillingRecord(ctx, scopeHash, "logical-call")
			if err != nil || modelRouteHash(before) != modelRouteHash(after) || len(gateway.calls) != 1 {
				t.Fatal("recovery changed bill or resent provider", err)
			}
			state, _, err := store.LookupModelRouteExecution(ctx, scopeHash, "logical-call")
			if err != nil || state.Revision != 2 || len(state.Steps) != 1 || state.Steps[0].Disposition != "retained_unknown" {
				t.Fatal("recovery created multiple dispositions", state, err)
			}
		}
	})
	t.Run("more-than-sixty-four-completed-routes-do-not-block-one-retained-outcome", func(t *testing.T) {
		attempt := op
		attempt.Context.TaskID += "-large-route-history"
		attempt.Context.ApplicationID += "-large-route-history"
		originalScope := scopeFromHarness(attempt.Context)
		scopeHash := modelSelectionScopeHash(originalScope)
		if err := store.BindModelSelection(ctx, originalScope, policyasset.ModelSelectionBinding{
			Selection: policyasset.ModelSelection{Mode: "automatic"}, PolicySHA256: op.Policy.Hash,
			CommandFingerprint: strings.Repeat("d", 64)}); err != nil {
			t.Fatal(err)
		}
		gateway := &failoverGatewayFixture{}
		m.modelGateway, m.modelStore = gateway, store
		var input modelGenerateInput
		_ = json.Unmarshal(op.Input, &input)
		for i := 0; i < 65; i++ {
			input.IdempotencyKey = fmt.Sprintf("finished-%03d", i)
			attempt.Input, _ = json.Marshal(input)
			if w := invokeFailover(m, attempt, ctx); w.Code != 200 {
				t.Fatal("completed history preparation failed", i, w.Code, w.Body.String())
			}
		}
		gateway = &failoverGatewayFixture{firstError: &modelgateway.ProviderFailure{Category: "body_read"}}
		m.modelGateway, m.modelStore = gateway, lostSQLDispositionStore{store}
		input.IdempotencyKey = "large-history-lost-disposition"
		attempt.Input, _ = json.Marshal(input)
		if w := invokeFailover(m, attempt, ctx); w.Code == 200 || len(gateway.calls) != 1 {
			t.Fatal("owner-loss fixture did not retain one physical attempt", w.Code, w.Body.String())
		}
		m.modelStore = store
		if err := m.CheckTaskModelQuiescence(ctx, originalScope); err != nil {
			t.Fatal("completed route count blocked the one retained unknown", err)
		}
		// The retained state stays active without inventing a replacement. A
		// subsequent recovery pass bulk-filters that absent next physical key.
		active, err := store.ListActiveModelRouteExecutions(ctx, scopeHash)
		if err != nil || len(active) != 0 || len(gateway.calls) != 1 {
			t.Fatal("recovery keeps revisiting an absent next attempt", len(active), err)
		}
	})
}
