package execution

import (
	"context"
	"errors"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func (m *Module) SetPinnedRunTargetResolver(resolve func(context.Context, sharedkernel.Scope, string) error) {
	m.pinnedRunTarget = resolve
}

// ValidatePinnedRunTarget proves attribution against the durable Run before
// the catalog/workload adapter can consider a retained published deployment.
// It does not admit a new Run, issue a lease or replace the original endpoint.
func (m *Module) ValidatePinnedRunTarget(ctx context.Context, scope sharedkernel.Scope) error {
	if m == nil || m.pinnedRunTarget == nil || scope.ValidateTrusted() != nil {
		return errors.New("pinned execution authority unavailable")
	}
	var err error
	var actual sharedkernel.Scope
	var endpoint string
	if reader, ok := m.store.(interface {
		BudgetRunContext(context.Context, string) (BudgetRunFacts, error)
	}); ok {
		var facts BudgetRunFacts
		facts, err = reader.BudgetRunContext(ctx, scope.RunID)
		actual, endpoint = facts.Scope, facts.AgentEndpoint
	} else {
		run, readErr := m.store.Get(scope.RunID)
		err, actual, endpoint = readErr, run.Scope, run.AgentEndpoint
	}
	if err != nil {
		return err
	}
	if actual != scope || endpoint == "" {
		return errors.New("pinned execution attribution denied")
	}
	return m.pinnedRunTarget(ctx, scope, endpoint)
}
