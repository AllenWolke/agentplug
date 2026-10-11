package execution

import (
	"context"
	"errors"
	"log"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

// startHeartbeat maintains ownership independently of the blocking Agent call.
// startHeartbeat 独立于阻塞调用维护租约；续租或授权失败立即取消执行。
func (d *Dispatcher) startHeartbeat(ctx context.Context, cancel context.CancelFunc, run platformruntime.Run, ttl time.Duration) func() {
	stop, done := make(chan struct{}), make(chan struct{})
	interval := ttl / 3
	if interval <= 0 {
		interval = time.Millisecond
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if d.coordinatedGuard != nil {
					guardCtx, guardCancel := context.WithTimeout(ctx, min(interval, 2*time.Second))
					err := d.coordinatedGuard(guardCtx, run.Scope)
					guardCancel()
					// A lock wait that exhausts this tick is not a permission
					// denial. The live parent can hold the ancestor row while
					// the child is still the caller's work; cancelling here
					// kills that child. The next tick repeats the same check.
					if err != nil && !heartbeatLockWait(err) {
						log.Printf("execution heartbeat denied run_id=%s stage=ancestry error_type=%s", run.ID, heartbeatErrorType(err))
						cancel()
						return
					}
					if err != nil {
						log.Printf("execution heartbeat ancestry deferred run_id=%s error_type=%s", run.ID, heartbeatErrorType(err))
					}
				}
				if d.authorize != nil {
					authCtx, authCancel := context.WithTimeout(ctx, min(interval, 2*time.Second))
					err := d.authorize(authCtx, run.Scope)
					authCancel()
					// Parented authorization repeats the ancestor read. A tick
					// that only exhausts the lock wait is not a grant change;
					// the finished comparison still cancels on a later tick.
					if err != nil && !heartbeatLockWait(err) {
						log.Printf("execution heartbeat denied run_id=%s stage=authorization error_type=%s", run.ID, heartbeatErrorType(err))
						cancel()
						return
					}
					if err != nil {
						log.Printf("execution heartbeat authorization deferred run_id=%s error_type=%s", run.ID, heartbeatErrorType(err))
					}
				}
				var err error
				if store, ok := d.repository.(interface {
					HeartbeatContext(context.Context, string, string, uint64, time.Time, time.Duration) (platformruntime.Run, error)
				}); ok {
					leaseCtx, leaseCancel := context.WithTimeout(ctx, min(interval, 2*time.Second))
					_, err = store.HeartbeatContext(leaseCtx, run.ID, run.LeaseToken, run.Revision, time.Now().UTC(), ttl)
					leaseCancel()
				} else {
					_, err = d.repository.Heartbeat(run.ID, run.LeaseToken, run.Revision, time.Now().UTC(), ttl)
				}
				if err != nil {
					log.Printf("execution heartbeat failed run_id=%s stage=lease error_type=%s", run.ID, heartbeatErrorType(err))
					cancel()
					return
				}
			}
		}
	}()
	return func() { close(stop); <-done }
}

// heartbeatLockWait is a tick that expired or was canceled while waiting for a
// row lock. context.Canceled alone is the run stopping and still cancels.
func heartbeatLockWait(err error) bool {
	if err == nil {
		return false
	}
	var sqlError interface{ SQLState() string }
	if errors.As(err, &sqlError) {
		switch sqlError.SQLState() {
		case "55P03", "57014":
			return true
		}
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// Classify failure without logging SQL, credentials, or arbitrary error text.
func heartbeatErrorType(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "context_cancelled"
	case errors.Is(err, platformruntime.ErrLeaseConflict):
		return "lease_conflict"
	case errors.Is(err, platformruntime.ErrRunNotFound):
		return "run_not_found"
	case errors.Is(err, platformruntime.ErrRevisionConflict):
		return "revision_conflict"
	}
	var sqlError interface{ SQLState() string }
	if errors.As(err, &sqlError) {
		state := sqlError.SQLState()
		if len(state) == 5 {
			valid := true
			for _, char := range state {
				if !(char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
					valid = false
				}
			}
			if valid {
				return "sqlstate_" + state
			}
		}
	}
	return "database_unclassified"
}
