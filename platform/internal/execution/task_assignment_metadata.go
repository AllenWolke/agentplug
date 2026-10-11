package execution

import (
	"context"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// ReadTaskAssignmentScope exposes durable attribution, without run input/output.
// The composition root checks management authority and requested scope first.
func (m *Module) ReadTaskAssignmentScope(ctx context.Context, id string) (sharedkernel.Scope, error) {
	if err := ctx.Err(); err != nil {
		return sharedkernel.Scope{}, err
	}
	run, err := m.store.Get(id)
	if err != nil {
		return sharedkernel.Scope{}, err
	}
	return run.Scope, nil
}
