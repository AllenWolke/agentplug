package capability

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
)

type lostDispositionStore struct{ *memoryModelInvocationStore }

func (s lostDispositionStore) AdvanceModelRouteExecution(ctx context.Context, scope, logical string,
	state ModelRouteExecution, route StoredModelRoute, fingerprint string, p policyasset.ModelRoutingPolicy) (ModelRouteExecution, error) {
	record, err := s.GetBillingRecord(context.Background(), scope, physicalRouteAttemptKey(logical, len(state.Steps)))
	if err == nil && record.Status == "reconcile" {
		return ModelRouteExecution{}, context.Canceled // Death after durable hold, before disposition CAS.
	}
	return s.memoryModelInvocationStore.AdvanceModelRouteExecution(ctx, scope, logical, state, route, fingerprint, p)
}

func TestRouteExecutionCancelledRPCPersistsDispositionWithoutAnotherSend(t *testing.T) {
	m, op, g, b := resilientInvocationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.cancel = cancel
	g.firstError = &modelgateway.ProviderFailure{Category: "body_read"}
	w := invokeFailover(m, op, ctx)
	if w.Code == 200 || len(g.calls) != 1 || len(b.released) != 0 || len(b.settled) != 0 {
		t.Fatal("cancelled caller dispatched or changed accounting", w.Code, len(g.calls))
	}
	store := m.modelStore.(*memoryModelInvocationStore)
	state, _, err := store.LookupModelRouteExecution(context.Background(), modelSelectionScopeHash(scopeFromHarness(op.Context)), "logical-call")
	if err != nil || state.RecoveryPolicy == nil || len(state.Steps) != 1 || state.Steps[0].Disposition != "retained_unknown" {
		t.Fatal("RPC cancellation lost physical disposition", state, err)
	}
	if err := m.CheckTaskModelQuiescence(context.Background(), scopeFromHarness(op.Context)); err != nil {
		t.Fatal("retained cancelled call still blocked stop", err)
	}
}

func TestStoppedRouteDispositionRecoversPersistedOutcomeAfterOwnerLoss(t *testing.T) {
	for _, mode := range []string{"saved-policy", "old-matching-policy", "old-changed-policy", "no-consent"} {
		t.Run(mode, func(t *testing.T) {
			m, op, g, b := resilientInvocationFixture(t)
			if mode == "no-consent" {
				op.Policy.Model.Routing.Availability.UnknownOutcome = ""
			}
			store := m.modelStore.(*memoryModelInvocationStore)
			m.modelStore = lostDispositionStore{store}
			g.firstError = &modelgateway.ProviderFailure{Category: "body_read"}
			w := invokeFailover(m, op, context.Background())
			if w.Code == 200 || len(g.calls) != 1 {
				t.Fatal("owner-loss fixture sent replacement", w.Code, len(g.calls))
			}
			scope := scopeFromHarness(op.Context)
			hash := modelSelectionScopeHash(scope)
			before, _ := store.GetBillingRecord(context.Background(), hash, "logical-call")
			var current policyasset.Snapshot
			raw, _ := json.Marshal(op.Policy)
			_ = json.Unmarshal(raw, &current)
			current.ModelProfileID, current.PromptVersionID, current.ToolPolicyID = "model-fixture", "prompt-fixture", "tool-fixture"
			current.MemoryPolicyID, current.KnowledgePolicyID, current.RuntimePolicyID = "memory-fixture", "knowledge-fixture", "runtime-fixture"
			current.Revision = 1
			if mode == "saved-policy" || mode == "old-changed-policy" {
				current.Model.Routing.Availability.UnknownOutcome = ""
			}
			m.policy = policyasset.StaticResolver{Snapshot: current}
			if mode == "old-matching-policy" || mode == "old-changed-policy" {
				store.mu.Lock()
				key := hash + "\x00logical-call"
				state := store.routeExecutions[key]
				state.RecoveryPolicy = nil
				store.routeExecutions[key] = state
				store.mu.Unlock()
			}
			m.modelStore = store // Reopened execution owner, same durable records.
			err := m.CheckTaskModelQuiescence(context.Background(), scope)
			allowed := mode == "saved-policy" || mode == "old-matching-policy"
			if (err == nil) != allowed {
				t.Fatal("recovery did not honor original policy consent/hash", mode, err)
			}
			after, _ := store.GetBillingRecord(context.Background(), hash, "logical-call")
			if modelRouteHash(before) != modelRouteHash(after) || len(g.calls) != 1 || len(b.released) != 0 || len(b.settled) != 0 {
				t.Fatal("disposition recovery resent or changed original bill")
			}
			if allowed {
				state, _, _ := store.LookupModelRouteExecution(context.Background(), hash, "logical-call")
				revision := state.Revision
				if err := m.CheckTaskModelQuiescence(context.Background(), scope); err != nil {
					t.Fatal(err)
				}
				state, _, _ = store.LookupModelRouteExecution(context.Background(), hash, "logical-call")
				if state.Revision != revision {
					t.Fatal("recovery replay advanced allowance")
				}
			}
		})
	}
}
