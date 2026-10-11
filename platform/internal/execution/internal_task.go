package execution

import (
	"context"
	"errors"
	"sync"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// InternalTaskPhaseError marks which supervisor boundary failed while keeping
// the wrapped cause available to errors.Is/errors.As callers. Its Error text
// intentionally omits the cause so logs can report the phase without leaking
// provider, SQL, or credential-bearing details.
type InternalTaskPhaseError struct {
	phase string
	cause error
}

func (e *InternalTaskPhaseError) Error() string {
	if e == nil {
		return "internal task failed"
	}
	return "internal task " + e.phase + " phase failed"
}

func (e *InternalTaskPhaseError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *InternalTaskPhaseError) InternalTaskPhase() string {
	if e == nil {
		return "unknown"
	}
	return e.phase
}

func internalTaskPhaseError(phase string, err error) error {
	if err == nil {
		return nil
	}
	return &InternalTaskPhaseError{phase: phase, cause: err}
}

// InternalTaskSupervisor reuses execution ownership, heartbeat and durable
// outcome mechanisms for platform-owned work. It accepts an already claimed
// running task; admission, claim/recovery and model-context issuance remain
// scheduler responsibilities. It never grants business or management rights.
type InternalTaskSupervisor struct {
	Repository Repository
	Authorize  func(context.Context, sharedkernel.Scope) error
	Execute    func(context.Context, platformruntime.Run) (map[string]any, error)
	LeaseTTL   time.Duration
}

func (s InternalTaskSupervisor) Run(ctx context.Context, claimed platformruntime.Run) error {
	if s.Repository == nil || s.Authorize == nil || s.Execute == nil || s.LeaseTTL < 30*time.Millisecond || s.LeaseTTL > 10*time.Minute || claimed.Scope.ValidateTrusted() != nil || claimed.ID != claimed.Scope.RunID || claimed.Status != platformruntime.StatusRunning || claimed.Revision == 0 || claimed.LeaseToken == "" {
		return platformruntime.ErrLeaseConflict
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.Authorize(ctx, claimed.Scope); err != nil {
		return internalTaskPhaseError("authorize", err)
	}
	current, err := s.Repository.Get(claimed.ID)
	if err != nil {
		return internalTaskPhaseError("load", err)
	}
	if current.Scope != claimed.Scope || current.Status != claimed.Status || current.Revision != claimed.Revision || current.LeaseToken != claimed.LeaseToken {
		return platformruntime.ErrLeaseConflict
	}
	if !current.LeaseUntil.After(time.Now().UTC()) {
		return platformruntime.ErrLeaseConflict
	}
	if err := s.Repository.CheckSessionLease(current, time.Now().UTC()); err != nil {
		return internalTaskPhaseError("session_lease", err)
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Share the same heartbeat implementation as business dispatch: current
	// authorization and bounded context-aware SQL renewal, unchanged revision.
	dispatcher := &Dispatcher{repository: s.Repository, authorize: s.Authorize}
	stop := dispatcher.startHeartbeat(workCtx, cancel, current, s.LeaseTTL)
	var stopOnce sync.Once
	stopHeartbeat := func() { stopOnce.Do(stop) }
	defer stopHeartbeat()
	output, workErr := s.Execute(workCtx, current)
	stopHeartbeat()
	if workErr != nil {
		return internalTaskPhaseError("execute", workErr)
	}
	if err := workCtx.Err(); err != nil {
		return internalTaskPhaseError("execute", err)
	}
	if err := s.Authorize(workCtx, current.Scope); err != nil {
		return internalTaskPhaseError("authorize", err)
	}
	if output == nil {
		return internalTaskPhaseError("finalize", errors.New("internal task returned no durable receipt"))
	}
	// Success/outcome/event/session release are one existing lease-fenced
	// repository transaction. Errors leave durable work for explicit recovery;
	// unknown model sends must not be relabeled as successful or blindly retried.
	_, err = s.Repository.FinalizeLeased(current.ID, platformruntime.StatusSucceeded, current.Revision, current.LeaseToken, output, map[string]any{"source": "platform_internal_task"})
	return internalTaskPhaseError("finalize", err)
}
