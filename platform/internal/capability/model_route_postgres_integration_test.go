package capability

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Native persistence is required here: a scripted driver cannot establish
// ON CONFLICT winner semantics, durable restart, or runtime DML privileges.
func TestSQLModelRoutingPersistenceRecovery(t *testing.T) {
	adminDSN, runtimeDSN := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"), os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if adminDSN == "" || runtimeDSN == "" {
		t.Skip("explicit isolated PostgreSQL migration and runtime identities required")
	}
	for _, dsn := range []string{adminDSN, runtimeDSN} {
		u, err := url.Parse(dsn)
		if err != nil || u.Hostname() != "127.0.0.1" || u.Path != "/knowledge_test" {
			t.Fatal("owned loopback knowledge_test fixture required")
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
	openRuntime := func() (*SQLModelInvocationStore, *sql.DB) {
		t.Helper()
		db, err := sqlutil.OpenPostgres(ctx, runtimeDSN)
		if err != nil {
			t.Fatal(err)
		}
		store, err := NewSQLModelInvocationStore(db)
		if err != nil {
			db.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return store, db
	}
	store, db := openRuntime()
	scope, policy, catalog, at := routeFixture()
	scope.RunID = fmt.Sprintf("native-model-route-%d", time.Now().UnixNano())
	hash := modelSelectionScopeHash(scope)
	decision, err := SelectModelRoute(ctx, scope, policy, routeRequest("指标定义是什么"), policyasset.ToolPolicy{}, true, catalog, catalog, at)
	if err != nil {
		t.Fatal(err)
	}
	proposal := StoredModelRoute{RequestFingerprint: strings.Repeat("a", 64), Decision: decision, DecisionSHA256: modelRouteHash(decision)}
	binding := policyasset.ModelSelectionBinding{Selection: policyasset.ModelSelection{Mode: "automatic"}, PolicySHA256: strings.Repeat("c", 64), CommandFingerprint: strings.Repeat("d", 64)}
	if err := store.BindModelSelection(ctx, scope, binding); err != nil {
		t.Fatal(err)
	}
	t.Run("availability-probe-survives-restart-and-rejects-corruption", func(t *testing.T) {
		healthScope := scope
		healthScope.ApplicationID = scope.RunID
		partition := modelAvailabilityPartition(healthScope)
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if _, err := admin.ExecContext(cleanup, sqlutil.Bind(`DELETE FROM platform_model_route_availability WHERE partition_hash=?`), partition); err != nil {
				t.Error(err)
			}
		})
		p := availabilityPolicy()
		if err := recordModelAvailability(ctx, store, partition, "model", strings.Repeat("a", 64), p, at, at.Add(time.Second), false); err != nil {
			t.Fatal(err)
		}
		restarted, _ := openRuntime()
		saved, found, err := restarted.LookupModelAvailability(ctx, partition, "model")
		if err != nil || !found || saved.OpenUntil.IsZero() {
			t.Fatal("availability lost after new connection", err)
		}
		results := make(chan error, 8)
		for i := 0; i < 8; i++ {
			go func(i int) {
				results <- claimModelAvailability(ctx, restarted, partition, "model", modelRouteHash(i), p, at.Add(32*time.Second))
			}(i)
		}
		winners := 0
		for i := 0; i < 8; i++ {
			err := <-results
			if err == nil {
				winners++
			} else if !errors.Is(err, ErrModelRouteCandidateUnavailable) && !errors.Is(err, ErrModelRouteUnavailable) {
				t.Fatal(err)
			}
		}
		if winners != 1 {
			t.Fatal("native CAS allowed multiple probes", winners)
		}
		if _, err := admin.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_route_availability SET state_json=? WHERE partition_hash=? AND model_version_id=?`), `{"revision":-1}`, partition, "model"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := restarted.LookupModelAvailability(ctx, partition, "model"); !errors.Is(err, ErrModelRouteUnavailable) {
			t.Fatal("corrupt health admitted a model", err)
		}
	})

	t.Run("concurrent-winner-survives-new-connection", func(t *testing.T) {
		alternative := cloneStoredModelRoute(proposal)
		alternative.Decision.ModelVersionID, alternative.Decision.ModelKey = "large", "large"
		alternative.Decision.Price = catalog.prices["large"]
		alternative.DecisionSHA256 = modelRouteHash(alternative.Decision)
		type result struct {
			value StoredModelRoute
			err   error
		}
		results := make(chan result, 8)
		var workers sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 8; i++ {
			workers.Add(1)
			go func(i int) {
				defer workers.Done()
				<-start
				p := proposal
				if i%2 == 1 {
					p = alternative
				}
				value, err := store.PersistModelRoute(ctx, hash, "race", p)
				results <- result{value, err}
			}(i)
		}
		close(start)
		workers.Wait()
		close(results)
		winnerHash := ""
		for r := range results {
			if r.err != nil {
				t.Fatal(r.err)
			}
			if winnerHash == "" {
				winnerHash = r.value.DecisionSHA256
			}
			if r.value.DecisionSHA256 != winnerHash {
				t.Fatal("concurrent callers received different durable choices")
			}
		}
		restarted, _ := openRuntime()
		value, found, err := restarted.LookupModelRoute(ctx, hash, "race")
		if err != nil || !found || value.DecisionSHA256 != winnerHash {
			t.Fatal("new connection lost the winning model and price", err)
		}
		var count int
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_model_route_decision WHERE scope_hash=? AND idempotency_key=?`), hash, "race").Scan(&count); err != nil || count != 1 {
			t.Fatal("concurrent selection did not persist exactly one row", err)
		}
		changed := proposal
		changed.RequestFingerprint = strings.Repeat("e", 64)
		if _, err := restarted.PersistModelRoute(ctx, hash, "race", changed); !errors.Is(err, ErrModelInvocationConflict) {
			t.Fatal("changed command intent replaced the winner", err)
		}
	})

	t.Run("scope-binding-and-trace-recovery", func(t *testing.T) {
		restarted, _ := openRuntime()
		recovery := scope
		recovery.TraceID = "new-recovery-trace"
		actual, found, err := restarted.LookupModelSelection(ctx, recovery)
		if err != nil || !found || actual != binding {
			t.Fatal("trace change lost original execution binding", err)
		}
		for _, dimension := range []string{"principal", "application", "epoch", "run"} {
			alien := scope
			switch dimension {
			case "principal":
				alien.PrincipalID += "-other"
			case "application":
				alien.ApplicationID += "-other"
			case "epoch":
				alien.AuthorizationEpoch++
			case "run":
				alien.RunID += "-other"
			}
			if _, found, err := restarted.LookupModelSelection(ctx, alien); err != nil || found {
				t.Fatal("binding crossed execution scope", dimension, err)
			}
		}
		changed := binding
		changed.Selection.Mode = "manual"
		if err := restarted.BindModelSelection(ctx, scope, changed); !errors.Is(err, ErrModelInvocationConflict) {
			t.Fatal("recovery changed original automatic preference", err)
		}
	})

	t.Run("cancelled-write-and-corrupt-durable-record", func(t *testing.T) {
		stopped, stop := context.WithCancel(ctx)
		stop()
		if _, err := store.PersistModelRoute(stopped, hash, "cancelled", proposal); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled context admitted a decision", err)
		}
		if _, found, err := store.LookupModelRoute(ctx, hash, "cancelled"); err != nil || found {
			t.Fatal("cancelled selection produced a row", err)
		}
		if _, err := store.PersistModelRoute(ctx, hash, "corrupt", proposal); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_route_decision SET decision_json=? WHERE scope_hash=? AND idempotency_key=?`), `{"unexpected":"field"}`, hash, "corrupt"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.LookupModelRoute(ctx, hash, "corrupt"); !errors.Is(err, ErrModelRouteUnavailable) {
			t.Fatal("corrupt persisted selection was accepted", err)
		}
	})

	t.Run("unknown-billing-is-not-zero-or-retryable", func(t *testing.T) {
		// Use a separate Run: the intentionally corrupt record above must not
		// contaminate this independent receipt observation.
		unknownScope := scope
		unknownScope.RunID += "-unknown"
		unknownHash := modelSelectionScopeHash(unknownScope)
		if err := store.BindModelSelection(ctx, unknownScope, binding); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PersistModelRoute(ctx, unknownHash, "call", proposal); err != nil {
			t.Fatal(err)
		}
		fingerprint := strings.Repeat("f", 64)
		if _, replayed, err := store.Reserve(ctx, unknownHash, "call", fingerprint, 10, 1); err != nil || replayed {
			t.Fatal("initial native admission failed", err)
		}
		if err := store.MarkReconciliationNeeded(ctx, unknownHash, "call", fingerprint, map[string]any{}, 0); err != nil {
			t.Fatal(err)
		}
		restarted, _ := openRuntime()
		summary, err := restarted.ReadRunModelRouting(ctx, unknownScope)
		if err != nil || len(summary.Decisions) != 1 || summary.Decisions[0].InvocationStatus != "reconcile" || summary.Decisions[0].ActualCostMicros != nil {
			t.Fatal("unknown provider usage became zero-cost success", err)
		}
		if _, _, err := restarted.Reserve(ctx, unknownHash, "call", fingerprint, 10, 1); !errors.Is(err, ErrModelInvocationReconciliationNeeded) {
			t.Fatal("unknown provider response was admitted for resend", err)
		}
		var count int
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_model_invocation WHERE scope_hash=?`), unknownHash).Scan(&count); err != nil || count != 1 {
			t.Fatal("receipt read or retry created another invocation", err)
		}
	})

	t.Run("completed-receipt-requires-native-billing", func(t *testing.T) {
		knownScope := scope
		knownScope.RunID += "-settled"
		knownHash := modelSelectionScopeHash(knownScope)
		if err := store.BindModelSelection(ctx, knownScope, binding); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PersistModelRoute(ctx, knownHash, "call", proposal); err != nil {
			t.Fatal(err)
		}
		fingerprint := strings.Repeat("f", 64)
		if _, _, err := store.Reserve(ctx, knownHash, "call", fingerprint, 10, 1); err != nil {
			t.Fatal(err)
		}
		if err := store.Complete(ctx, knownHash, "call", fingerprint, map[string]any{"billing": map[string]any{"price_version_id": proposal.Decision.Price.ID, "currency": "USD", "cost_micros": 17}}, 1); err != nil {
			t.Fatal(err)
		}
		summary, err := store.ReadRunModelRouting(ctx, knownScope)
		if err != nil || len(summary.Decisions) != 1 || summary.Decisions[0].ActualCostMicros == nil || *summary.Decisions[0].ActualCostMicros != 17 {
			t.Fatal("settled actual cost did not survive native receipt read", err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET response_json=? WHERE scope_hash=? AND idempotency_key=?`), `{"billing":{"currency":"USD","cost_micros":17,"price_version_id":"wrong"}}`, knownHash, "call"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ReadRunModelRouting(ctx, knownScope); !errors.Is(err, ErrModelRouteUnavailable) {
			t.Fatal("mismatched settlement price was disclosed as valid cost", err)
		}
	})
}
