package execution

import (
	"context"
	"errors"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// ValidateLiveCommand is the capability authorization Port backed by Run facts.
// ValidateLiveCommand 是基于真实 Run 的能力授权端口，不信任调用方自报的任务或阶段。
func (m *Module) ValidateLiveCommand(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string) error {
	if err := scope.ValidateTrusted(); err != nil {
		return err
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
		return errors.New("trusted execution Run unavailable")
	}
	if run.Scope != scope || run.Status != platformruntime.StatusRunning || run.LeaseToken == "" || !run.LeaseUntil.After(time.Now().UTC()) {
		return errors.New("trusted execution scope or lease denied")
	}
	if err := m.store.CheckSessionLease(run, time.Now().UTC()); err != nil {
		return errors.New("trusted session lease denied")
	}
	command, err := m.store.GetDispatchCommand(run.ID)
	if err != nil || command.Revision != run.Revision || command.Operation != operation || command.BodyHash != bodyHash || command.PolicyHash != policyHash {
		return errors.New("trusted execution command denied")
	}
	return nil
}
