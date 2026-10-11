package usagecost

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestCanonicalBudgetScopeUsesStructuredHashAndRejectsDelimiterAmbiguity(t *testing.T) {
	first := ModelBudgetScope{TenantID: "tenant", DepartmentID: "dept", ApplicationID: "app", AgentID: "qa", AgentVersionID: "v1"}
	second := first
	second.AgentID = "validation"
	_, firstHash, err := canonicalBudgetScope(first)
	if err != nil {
		t.Fatal(err)
	}
	_, secondHash, err := canonicalBudgetScope(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash == secondHash {
		t.Fatal("different agent scopes must have distinct canonical hashes")
	}
	ambiguous := first
	ambiguous.DepartmentID = "dept:app"
	if _, _, err := canonicalBudgetScope(ambiguous); !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("delimiter-containing scope must be rejected to protect legacy usage snapshot key: %v", err)
	}
}

func TestModelBudgetRequestRejectsInvalidFingerprintWindowAndOverflowInputs(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 123456000, time.UTC)
	request := validBudgetTestRequest(now, "req", "qa", 100, 60)
	if _, _, err := validModelBudgetRequest(request, now); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	bad := request
	bad.Fingerprint = "not-a-hash"
	if _, _, err := validModelBudgetRequest(bad, now); !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("invalid fingerprint must fail: %v", err)
	}
	bad = request
	bad.ExpiresAt = request.Window.End.Add(time.Second)
	if _, _, err := validModelBudgetRequest(bad, now); !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("lease outside window must fail: %v", err)
	}
	bad = request
	bad.ReserveMicros = -1
	if _, _, err := validModelBudgetRequest(bad, now); !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("negative reserve must fail: %v", err)
	}
}

func TestSQLModelBudgetLedgerTransactionalLifecycle(t *testing.T) {
	store := openModelBudgetSQLStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	var clockMu sync.RWMutex
	clockNow := now
	store.now = func() time.Time { clockMu.RLock(); defer clockMu.RUnlock(); return clockNow }
	request := validBudgetTestRequest(now, "request-main", uniqueBudgetSuffix(t), 100, 60)
	reservation, err := store.Reserve(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := store.Reserve(ctx, request)
	if err != nil || replay.ReservationID != reservation.ReservationID {
		t.Fatalf("same request replay should return same reservation: first=%+v replay=%+v err=%v", reservation, replay, err)
	}

	wrongPrice := Event{ID: "wrong-price-" + reservation.ReservationID, Scope: budgetUsageScope(request), Provider: "p", Model: "m", CostMicros: 5}
	if _, err := store.Settle(ctx, reservation, wrongPrice, "price-v2"); !errors.Is(err, ErrBudgetPriceVersion) {
		t.Fatalf("wrong price version must be rejected: %v", err)
	}
	wrongScope := wrongPrice
	wrongScope.Scope.AgentID = "different-agent"
	if _, err := store.Settle(ctx, reservation, wrongScope, request.PriceVersionID); !errors.Is(err, ErrBudgetScopeMismatch) {
		t.Fatalf("wrong scope must be rejected: %v", err)
	}

	// A globally conflicting event ID fails within the transaction and must
	// leave the pending reservation available for an exact retry.
	collisionID := "event-collision-" + reservation.ReservationID
	otherScope := budgetUsageScope(request)
	otherScope.TenantID = "other-" + request.Scope.TenantID
	if _, err := store.Apply(ctx, Event{ID: collisionID, Scope: otherScope, Provider: "p", Model: "m", CostMicros: 9}); err != nil {
		t.Fatal(err)
	}
	conflicting := Event{ID: collisionID, Scope: budgetUsageScope(request), Provider: "p", Model: "m", CostMicros: 9}
	if _, err := store.Settle(ctx, reservation, conflicting, request.PriceVersionID); !errors.Is(err, ErrUsageConflict) {
		t.Fatalf("conflicting event must fail without consuming reservation: %v", err)
	}
	if _, err := store.Reserve(ctx, validBudgetTestRequest(now, "second-too-large", request.Scope.AgentID, 100, 50)); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("failed settlement must leave original 60-unit reservation held: %v", err)
	}

	event := Event{ID: "event-success-" + reservation.ReservationID, Scope: budgetUsageScope(request), Provider: "p", Model: "m", InputTokens: 3, OutputTokens: 4, CostMicros: 75}
	firstSnapshot, err := store.Settle(ctx, reservation, event, request.PriceVersionID)
	if err != nil || firstSnapshot.UsedMicros != 75 || firstSnapshot.InputTokens != 3 || firstSnapshot.OutputTokens != 4 {
		t.Fatalf("actual usage must settle even if it exceeds estimate: %+v err=%v", firstSnapshot, err)
	}
	replaySnapshot, err := store.Settle(ctx, reservation, event, request.PriceVersionID)
	if err != nil || replaySnapshot != firstSnapshot {
		t.Fatalf("settle replay must be exact/idempotent: first=%+v replay=%+v err=%v", firstSnapshot, replaySnapshot, err)
	}
	if err := store.Release(ctx, reservation); !errors.Is(err, ErrBudgetReservationClosed) {
		t.Fatalf("settled reservation must not be released: %v", err)
	}
	if _, err := store.Reserve(ctx, validBudgetTestRequest(now, "after-overrun", request.Scope.AgentID, 100, 30)); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("actual spend over the limit must block later reserve: %v", err)
	}
}

func TestSQLUsageStepIDsAreNullableVisibleAndDoNotBackfillLegacyRows(t *testing.T) {
	store := openModelBudgetSQLStore(t)
	ctx := context.Background()
	suffix := uniqueBudgetSuffix(t)
	scope := Scope{TenantID: "usage-step-" + suffix, DepartmentID: "department", ApplicationID: "application", AgentID: "agent", AgentVersionID: "v1", RunID: "run-" + suffix}
	stepID := StableModelUsageStepID(scope, "model-request-"+suffix)
	if stepID == nil {
		t.Fatal("expected a valid step ID for the fixture scope")
	}
	withStep := Event{ID: "usage-step-event-" + suffix, Scope: scope, Provider: "provider", Model: "model", InputTokens: 3, OutputTokens: 2, CostMicros: 5, StepID: stepID}
	legacy := Event{ID: "usage-step-legacy-" + suffix, Scope: scope, Provider: "provider", Model: "model", InputTokens: 4, OutputTokens: 1, CostMicros: 5}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), sqlutil.Bind(`DELETE FROM platform_usage_event WHERE event_id IN (?,?)`), withStep.ID, legacy.ID)
		_, _ = store.db.ExecContext(context.Background(), sqlutil.Bind(`DELETE FROM platform_usage_snapshot WHERE scope_key=?`), ScopeKey(scope))
	})
	if _, err := store.Apply(ctx, withStep); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	legacyReplay := legacy
	legacyReplay.StepID = StableModelUsageStepID(scope, "legacy-replay-"+suffix)
	legacyTx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	exists, lookupErr := existingUsageEventTx(ctx, legacyTx, legacyReplay)
	_ = legacyTx.Rollback()
	if lookupErr != nil || !exists {
		t.Fatalf("budget settlement lookup must accept a legacy NULL step ID without backfilling it: exists=%v err=%v", exists, lookupErr)
	}
	if _, err := store.Apply(ctx, legacyReplay); err != nil {
		t.Fatalf("newly derived metadata must not reject a true historical billing replay: %v", err)
	}
	var storedLegacyStep sql.NullString
	if err := store.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT step_id FROM platform_usage_event WHERE event_id=?`), legacy.ID).Scan(&storedLegacyStep); err != nil || storedLegacyStep.Valid {
		t.Fatalf("legacy history must remain unlinked instead of being backfilled: value=%+v err=%v", storedLegacyStep, err)
	}
	from, to := time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(time.Hour)
	steps, err := store.ListRunSteps(ctx, scope, from, to, 1, 10)
	if err != nil || len(steps.Items) != 2 {
		t.Fatalf("list model usage steps: items=%+v err=%v", steps.Items, err)
	}
	seenCurrent, seenLegacy := false, false
	for _, step := range steps.Items {
		switch step.EventID {
		case withStep.ID:
			seenCurrent = step.StepID != nil && *step.StepID == *stepID
		case legacy.ID:
			seenLegacy = step.StepID == nil
		}
	}
	if !seenCurrent || !seenLegacy {
		t.Fatalf("read model must expose the real link and explicit null for old rows: %+v", steps.Items)
	}
	page, err := store.ListUsageEvents(ctx, scope, from, to, 1, 10)
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("list usage event history: items=%+v err=%v", page.Items, err)
	}
	for _, item := range page.Items {
		if item.Event.ID == withStep.ID && (item.Event.StepID == nil || *item.Event.StepID != *stepID) {
			t.Fatalf("usage event response lost step ID: %+v", item.Event)
		}
		if item.Event.ID == legacy.ID && item.Event.StepID != nil {
			t.Fatalf("historical event response must keep a null step ID: %+v", item.Event)
		}
	}
}

func TestSQLModelBudgetConcurrentReservationsCannotOverrunWindow(t *testing.T) {
	store := openModelBudgetSQLStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	base := validBudgetTestRequest(now, "concurrent-base", uniqueBudgetSuffix(t), 100, 60)
	const callers = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	errorsSeen := []error{}
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			request := base
			request.RequestID = fmt.Sprintf("concurrent-%02d", i)
			reservation, err := store.Reserve(context.Background(), request)
			mu.Lock()
			defer mu.Unlock()
			if err == nil && reservation.Status == "pending" {
				accepted++
				return
			}
			if !errors.Is(err, ErrBudgetExceeded) {
				errorsSeen = append(errorsSeen, err)
			}
		}(i)
	}
	wg.Wait()
	if len(errorsSeen) > 0 {
		t.Fatalf("unexpected concurrent reserve errors: %v", errorsSeen)
	}
	if accepted != 1 {
		t.Fatalf("only one 60-micro reservation may fit in 100-micro window; accepted=%d", accepted)
	}
	edge := validBudgetTestRequest(now, "int64-max", "overflow-edge-"+uniqueBudgetSuffix(t), maxInt64, maxInt64)
	if _, err := store.Reserve(context.Background(), edge); err != nil {
		t.Fatalf("MaxInt64 reservation should be admitted without arithmetic overflow: %v", err)
	}
	edge.RequestID = "int64-max-plus-one"
	edge.Fingerprint = fingerprintFor(edge.RequestID)
	edge.ReserveMicros = 1
	if _, err := store.Reserve(context.Background(), edge); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("reservation beyond MaxInt64 window must fail closed: %v", err)
	}
}

func TestSQLModelBudgetReleaseIsIdempotentAndAgentScopesAreIsolated(t *testing.T) {
	store := openModelBudgetSQLStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	base := validBudgetTestRequest(now, "release-first", uniqueBudgetSuffix(t), 100, 80)
	first, err := store.Reserve(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := base
	secondRequest.Scope.AgentID = "other-agent-" + uniqueBudgetSuffix(t)
	secondRequest.RequestID = "release-second"
	second, err := store.Reserve(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("different Agent must have independent budget window: %v", err)
	}
	if err := store.Release(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := store.Release(context.Background(), first); err != nil {
		t.Fatalf("repeated release should be idempotent: %v", err)
	}
	if _, err := store.Reserve(context.Background(), base); !errors.Is(err, ErrBudgetReservationClosed) {
		t.Fatalf("released request cannot resurrect the reservation: %v", err)
	}
	if err := store.Release(context.Background(), second); err != nil {
		t.Fatal(err)
	}
}

func TestSQLModelBudgetExpiryReclaimsLeaseExactlyOnce(t *testing.T) {
	store := openModelBudgetSQLStore(t)
	// Keep the fixture away from an hour boundary so the one-minute lease is
	// always inside its fixed UTC accounting window.
	// 固定在整点之外，确保一分钟租约始终落在 UTC 计费窗口内。
	now := time.Date(2026, 9, 25, 12, 15, 0, 0, time.UTC)
	var clockMu sync.RWMutex
	clockNow := now
	store.now = func() time.Time { clockMu.RLock(); defer clockMu.RUnlock(); return clockNow }
	request := validBudgetTestRequest(now, "expiring-request", uniqueBudgetSuffix(t), 100, 70)
	request.ExpiresAt = now.Add(time.Minute)
	old, err := store.Reserve(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	clockMu.Lock()
	clockNow = now.Add(time.Minute + time.Second)
	clockMu.Unlock()

	if _, err := store.Settle(context.Background(), old, Event{ID: "late-" + old.ReservationID, Scope: budgetUsageScope(request), Provider: "p", Model: "m", CostMicros: 5}, request.PriceVersionID); !errors.Is(err, ErrBudgetReservationExpired) {
		t.Fatalf("expired lease must not settle: %v", err)
	}
	newRequest := request
	newRequest.RequestID = "after-expiry"
	newRequest.Fingerprint = fingerprintFor("after-expiry")
	newRequest.ReserveMicros = 70
	newRequest.ExpiresAt = request.Window.End
	current, err := store.Reserve(context.Background(), newRequest)
	if err != nil {
		t.Fatalf("expired lease should be reclaimed before the next admission: %v", err)
	}
	if err := store.Release(context.Background(), old); err != nil {
		t.Fatalf("release of already expired lease should be idempotent: %v", err)
	}
	if err := store.Release(context.Background(), old); err != nil {
		t.Fatalf("second release of expired lease should be idempotent: %v", err)
	}
	windowID, err := windowIDFromReservation(current)
	if err != nil {
		t.Fatal(err)
	}
	var reserved int64
	if err := store.db.QueryRow(sqlutil.Bind(`SELECT reserved_micros FROM platform_model_budget_window WHERE window_id=?`), windowID).Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	if reserved != current.ReserveMicros {
		t.Fatalf("expired lease was deducted more than once: reserved=%d want=%d", reserved, current.ReserveMicros)
	}
}

func TestSQLModelBudgetReconciliationHoldSurvivesLeaseExpiryAndSettles(t *testing.T) {
	store := openModelBudgetSQLStore(t)
	baseline, err := store.ReconciliationSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	request := validBudgetTestRequest(now, "known-provider-result", uniqueBudgetSuffix(t), 100, 80)
	request.ExpiresAt = now.Add(time.Minute)
	reservation, err := store.Reserve(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkReconciliationNeeded(context.Background(), reservation); err != nil {
		t.Fatalf("mark known provider result for reconciliation: %v", err)
	}
	pending, err := store.ReconciliationSnapshot(context.Background())
	if err != nil || pending.Pending != baseline.Pending+1 || pending.OldestAt.IsZero() {
		t.Fatalf("durable reconciliation hold not visible to metrics: before=%+v after=%+v err=%v", baseline, pending, err)
	}
	now = now.Add(2 * time.Minute)
	blocked := validBudgetTestRequest(now, "after-known-result", request.Scope.AgentID, 100, 30)
	blocked.Window = request.Window
	blocked.ExpiresAt = request.Window.End
	if _, err := store.Reserve(context.Background(), blocked); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("reconciliation hold must continue occupying budget past lease expiry: %v", err)
	}
	event := Event{ID: "settled-known-result", Scope: budgetUsageScope(request), Provider: "provider-a", Model: "model-a", InputTokens: 12, OutputTokens: 4, CostMicros: 60}
	if _, err := store.Settle(context.Background(), reservation, event, request.PriceVersionID); err != nil {
		t.Fatalf("known billable result must settle after its original lease expires: %v", err)
	}
	settled, err := store.ReconciliationSnapshot(context.Background())
	if err != nil || settled.Pending != baseline.Pending {
		t.Fatalf("settled reservation remained in reconciliation metrics: before=%+v after=%+v err=%v", baseline, settled, err)
	}
	if err := store.Release(context.Background(), reservation); !errors.Is(err, ErrBudgetReservationClosed) {
		t.Fatalf("settled reconciliation hold must not be released: %v", err)
	}
}

func TestSQLModelBudgetPolicyChangePreservesSpendHoldsAndReservationEvidence(t *testing.T) {
	store := openModelBudgetSQLStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	store.now = func() time.Time { return now }
	agent := uniqueBudgetSuffix(t)
	first := validBudgetTestRequest(now, "before-policy-change", agent, 100, 60)
	old, err := store.Reserve(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	second := validBudgetTestRequest(now, "after-policy-increase", agent, 200, 80)
	newer, err := store.Reserve(ctx, second)
	if err != nil {
		t.Fatalf("authorized increased policy must admit against existing holds: %v", err)
	}
	if _, err := store.Reserve(ctx, validBudgetTestRequest(now, "after-policy-decrease", agent, 100, 1)); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("lower policy must count both previous holds, not create/reset a window: %v", err)
	}
	replay, err := store.Reserve(ctx, first)
	if err != nil || replay != old {
		t.Fatalf("old immutable request must remain replayable: %v", err)
	}
	tampered := old
	tampered.BudgetLimitMicros = 200
	if err := store.Release(ctx, tampered); !errors.Is(err, ErrBudgetReservationConflict) {
		t.Fatalf("changing reservation limit must not bypass stored evidence: %v", err)
	}
	if err := store.MarkReconciliationNeeded(ctx, old); err != nil {
		t.Fatal(err)
	}
	event := Event{ID: "policy-change-" + old.ReservationID, Scope: budgetUsageScope(first), Provider: "p", Model: "m", CostMicros: 70}
	if _, err := store.Settle(ctx, old, event, first.PriceVersionID); err != nil {
		t.Fatalf("old known result must still settle after policy change: %v", err)
	}
	if err := store.Release(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(ctx, validBudgetTestRequest(now, "lower-policy-after-release", agent, 50, 1)); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("released holds must not erase the 70 actual spend: %v", err)
	}
	last, err := store.Reserve(ctx, validBudgetTestRequest(now, "lower-policy-with-headroom", agent, 100, 30))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(ctx, validBudgetTestRequest(now, "lower-policy-full", agent, 100, 1)); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("updated lower policy must enforce actual plus reserved atomically: %v", err)
	}
	if err := store.Release(ctx, last); err != nil {
		t.Fatal(err)
	}
}

func openModelBudgetSQLStore(t *testing.T) *SQLStore {
	t.Helper()
	raw := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if raw == "" {
		t.Skip("set PUBLIC_TEST_POSTGRES_MIGRATION_DSN to run transactional PostgreSQL model-budget tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, raw)
	if err != nil {
		t.Fatalf("connect model-budget PostgreSQL test database: %T", err)
	}
	store := NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		db.Close()
		t.Fatalf("ensure model-budget test schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return store
}

func validBudgetTestRequest(now time.Time, requestID, agentID string, limit, reserve int64) ModelBudgetRequest {
	start := now.Truncate(time.Hour)
	window := ModelBudgetWindow{Start: start, End: start.Add(time.Hour)}
	// The reservation lease cannot outlive its accounting window. Near an
	// hour boundary, extending it by a minute makes an otherwise valid SQL
	// test request invalid and hides the transaction assertions below.
	// 预占租约不得越过计费窗口；整点附近不能用额外一分钟掩盖事务断言。
	expires := window.End
	return ModelBudgetRequest{
		Scope: ModelBudgetScope{TenantID: "budget-test-" + agentID, DepartmentID: "department", ApplicationID: "application", AgentID: agentID, AgentVersionID: "v1"},
		RunID: "run-" + requestID, Window: window, RequestID: requestID, Fingerprint: fingerprintFor(requestID),
		PriceVersionID: "price-v1", BudgetLimitMicros: limit, ReserveMicros: reserve, ExpiresAt: expires,
	}
}

func budgetUsageScope(request ModelBudgetRequest) Scope {
	return Scope{TenantID: request.Scope.TenantID, DepartmentID: request.Scope.DepartmentID, ApplicationID: request.Scope.ApplicationID,
		AgentID: request.Scope.AgentID, AgentVersionID: request.Scope.AgentVersionID, RunID: request.RunID}
}

func fingerprintFor(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func uniqueBudgetSuffix(t *testing.T) string {
	t.Helper()
	id, err := newBudgetReservationID()
	if err != nil {
		t.Fatal(err)
	}
	return id[:12]
}
