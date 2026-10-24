package execution

import (
	"context"
	"errors"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// ValidateEventRead checks persisted ownership and the original policy. Reading
// events never renews a worker lease, restarts a Run, or grants business use.
func (m *Module) ValidateEventRead(ctx context.Context, scope sharedkernel.Scope, policyHash string) error {
	_, err := m.EventReadOriginScope(ctx, scope, policyHash)
	return err
}

// EventReadOriginScope resolves the immutable execution identity after checking
// the reader's ownership and original policy. Read epochs never replace it.
func (m *Module) EventReadOriginScope(ctx context.Context, scope sharedkernel.Scope, policyHash string) (sharedkernel.Scope, error) {
	if err := scope.ValidateTrusted(); err != nil {
		return sharedkernel.Scope{}, err
	}
	var run platformruntime.Run
	var err error
	if repository, ok := m.store.(interface {
		GetContext(context.Context, string) (platformruntime.Run, error)
	}); ok {
		run, err = repository.GetContext(ctx, scope.RunID)
	} else {
		run, err = m.store.Get(scope.RunID)
	}
	if err != nil {
		return sharedkernel.Scope{}, errors.New("event Run unavailable")
	}
	stored, requested := run.Scope, scope
	// Current read authorization and tracing may differ from execution origin.
	stored.AuthorizationEpoch, stored.TraceID = 0, ""
	requested.AuthorizationEpoch, requested.TraceID = 0, ""
	if stored != requested {
		return sharedkernel.Scope{}, errors.New("event ownership denied")
	}
	command, err := m.store.GetDispatchCommand(run.ID)
	if err != nil || command.RunID != run.ID || command.PolicyHash != policyHash {
		return sharedkernel.Scope{}, errors.New("event policy denied")
	}
	return run.Scope, nil
}
