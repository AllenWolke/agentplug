package capability

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/policyasset"
)

func TestPersistedRouteKeepsWinnerAndRejectsChangedIntent(t *testing.T) {
	scope, p, f, at := routeFixture()
	d, err := SelectModelRoute(context.Background(), scope, p, routeRequest("指标定义是什么"), policyasset.ToolPolicy{}, true, f, f, at)
	if err != nil {
		t.Fatal(err)
	}
	proposal := StoredModelRoute{RequestFingerprint: strings.Repeat("a", 64), Decision: d, DecisionSHA256: modelRouteHash(d)}
	store := newMemoryModelInvocationStore()
	key := strings.Repeat("c", 64)
	original, err := store.PersistModelRoute(context.Background(), key, "command", proposal)
	if err != nil {
		t.Fatal(err)
	}
	f.denied["small"] = errors.New("catalog changed after selection")
	changed := proposal
	changed.Decision.ModelVersionID = "large"
	changed.Decision.Price = f.prices["large"]
	changed.DecisionSHA256 = modelRouteHash(changed.Decision)
	winner, err := store.PersistModelRoute(context.Background(), key, "command", changed)
	if err != nil || winner.DecisionSHA256 != original.DecisionSHA256 {
		t.Fatal("concurrent/replayed selection replaced original decision")
	}
	changed.RequestFingerprint = strings.Repeat("d", 64)
	if _, err = store.PersistModelRoute(context.Background(), key, "command", changed); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("changed routing intent admitted")
	}
	winner.Decision.Features.Reasons[0] = "mutated"
	actual, found, err := store.LookupModelRoute(context.Background(), key, "command")
	if err != nil || !found || actual.DecisionSHA256 != original.DecisionSHA256 {
		t.Fatal("read exposed mutable stored selection")
	}
}

func TestRouteStoreRejectsCorruptionAndCancelledWrite(t *testing.T) {
	scope, p, f, at := routeFixture()
	d, err := SelectModelRoute(context.Background(), scope, p, routeRequest("定义是什么"), policyasset.ToolPolicy{}, true, f, f, at)
	if err != nil {
		t.Fatal(err)
	}
	proposal := StoredModelRoute{RequestFingerprint: strings.Repeat("a", 64), Decision: d, DecisionSHA256: modelRouteHash(d)}
	store := newMemoryModelInvocationStore()
	key := strings.Repeat("c", 64)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = store.PersistModelRoute(ctx, key, "command", proposal); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled decision persisted")
	}
	proposal.Decision.EstimatedMicros++
	if _, err = store.PersistModelRoute(context.Background(), key, "command", proposal); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("corrupt decision admitted")
	}
}
