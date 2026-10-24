package execution

import (
	"context"
	"log"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

// Only the worker lifecycle owns this key. An execution deadline, a revoked
// grant, or Cancel(runID) cancels a child context without stopping the worker.
type dispatcherWorkerLifecycleKey struct{}

func (d *Dispatcher) workerStopping(ctx context.Context) bool {
	select {
	case <-d.stop:
		return true
	default:
	}
	owner, _ := ctx.Value(dispatcherWorkerLifecycleKey{}).(context.Context)
	return owner != nil && owner.Err() != nil
}

func (d *Dispatcher) failDispatch(ctx context.Context, runID string, running platformruntime.Run, code, message string) error {
	if d.workerStopping(ctx) {
		log.Printf("execution worker stopped run_id=%q code=WORKER_STOPPED_RECOVERY_PENDING", runID)
		return nil
	}
	return d.fail(runID, running, code, message)
}

func (d *Dispatcher) recordDispatchFailure(ctx context.Context, runID string, attempt int, code string, retryable bool, httpStatus int) error {
	if d.workerStopping(ctx) {
		return nil
	}
	return d.recordAttemptFailure(runID, attempt, code, retryable, httpStatus)
}

func (d *Dispatcher) stopDispatch(ctx context.Context, running platformruntime.Run, code string) error {
	if d.workerStopping(ctx) {
		// Retain the command and generation fence. An uncertain in-flight call
		// is recovered only after lease expiry, stop proof, billing quiescence,
		// current authorization and checkpoint verification. Never auto-replay.
		log.Printf("execution worker stopped run_id=%q code=WORKER_STOPPED_RECOVERY_PENDING", running.ID)
		return nil
	}
	return d.stopUncertainExecution(running, code)
}
