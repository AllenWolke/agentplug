package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

type routeResponseBudgetFixture struct {
	*captureModelBudgetStore
	reads     int
	held      int64
	err       error
	afterRead func()
}

func (b *routeResponseBudgetFixture) ReadRuntimeBudget(ctx context.Context, scope sharedkernel.Scope) (usagecost.RunTreeBudgetReceipt, error) {
	b.reads++
	if _, _, err := RuntimeBudgetExecutionAuthority(ctx, scope); err != nil {
		return usagecost.RunTreeBudgetReceipt{}, err
	}
	if b.afterRead != nil {
		b.afterRead()
	}
	return usagecost.RunTreeBudgetReceipt{Version: "run-tree-budget/v1", RootRunID: scope.RunID,
		Counters: usagecost.RunTreeBudgetCounters{LimitMicros: 1000000, LimitTokens: 1000000, HeldMicros: b.held}}, b.err
}

// Exercise the completed logical-operation path, including retained unknown
// attempts. Replays must read fresh counters once, not reserve or send again.
func TestRouteCompletedResponseReadsFreshBudgetOnce(t *testing.T) {
	m, op, gateway, accounting := resilientInvocationFixture(t)
	gateway.firstError = &modelgateway.ProviderFailure{Category: "body_read"}
	if got := invokeFailover(m, op, context.Background()); got.Code != http.StatusOK {
		t.Fatal(got.Code, got.Body.String())
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	op.Context.PlatformContextToken = signedContextToken(t, private, op.Context, time.Now().Unix()-1, time.Now().Unix()+120)
	budget := &routeResponseBudgetFixture{captureModelBudgetStore: accounting, held: 29}
	m.modelBudgets = budget
	store := m.modelStore.(*memoryModelInvocationStore)
	scope := modelSelectionScopeHash(scopeFromHarness(op.Context))
	before, _, err := store.LookupModelRouteExecution(context.Background(), scope, "logical-call")
	if err != nil {
		t.Fatal(err)
	}
	for _, hold := range []int64{29, 47} {
		budget.held = hold
		reads := budget.reads
		got := invokeFailover(m, op, context.Background())
		if got.Code != http.StatusOK || budget.reads != reads+1 {
			t.Fatal("logical replay did not read its current budget exactly once", got.Code, got.Body.String(), budget.reads-reads)
		}
		var body struct {
			Data struct {
				Budget struct {
					Counters usagecost.RunTreeBudgetCounters `json:"counters"`
				} `json:"run_budget"`
			} `json:"data"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil || body.Data.Budget.Counters.HeldMicros != hold {
			t.Fatal("stale or missing retained exposure", err, got.Body.String())
		}
	}
	budget.err = errors.New("owned budget read failure")
	if got := invokeFailover(m, op, context.Background()); got.Code != 503 || !strings.Contains(got.Body.String(), "RUNTIME_BUDGET_UNAVAILABLE") || strings.Contains(got.Body.String(), `"text":"complete"`) {
		t.Fatal("read failure disclosed a completed answer", got.Code, got.Body.String())
	}
	budget.err = nil
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	budget.afterRead = cancel
	if got := invokeFailover(m, op, ctx); got.Code != http.StatusForbidden || strings.Contains(got.Body.String(), `"text":"complete"`) {
		t.Fatal("cancellation during counter read escaped final authority fence", got.Code, got.Body.String())
	}
	after, _, err := store.LookupModelRouteExecution(context.Background(), scope, "logical-call")
	if err != nil || modelRouteHash(before) != modelRouteHash(after) || len(gateway.calls) != 2 || len(accounting.settled) != 1 || len(accounting.released) != 0 {
		t.Fatal("response reads changed immutable winner, billing, or retained unknown", err)
	}
	for _, record := range store.records {
		if _, exists := record.Response["run_budget"]; exists {
			t.Fatal("volatile counters persisted in immutable model receipt")
		}
	}
}
