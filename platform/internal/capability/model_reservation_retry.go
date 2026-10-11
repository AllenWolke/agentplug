package capability

import (
	"context"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

// The reservation transaction has rolled back before this function retries.
// Retry only PostgreSQL deadlock or serialization errors, before any provider request; never
// retry ambiguous commits/network errors, input conflicts or exhausted budgets.
func retryModelReservation(ctx context.Context, reserve func() (ModelInvocation, bool, error)) (ModelInvocation, bool, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return ModelInvocation{}, false, err
		}
		result, replay, err := reserve()
		state := sqlutil.SQLState(err)
		if attempt >= 4 || (state != "40P01" && state != "40001") {
			return result, replay, err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ModelInvocation{}, false, ctx.Err()
		case <-timer.C:
		}
	}
}
