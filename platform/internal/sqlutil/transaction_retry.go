package sqlutil

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"
)

// IsTransactionRollback accepts only PostgreSQL's explicit transaction-abort
// replies. Connection errors, unknown commit replies, unique violations and
// statement_completion_unknown (40003) are not a replay permission.
func IsTransactionRollback(err error) bool {
	state := SQLState(err)
	return state == "40001" || state == "40P01"
}

type confirmedRollback struct{ cause error }

func (e *confirmedRollback) Error() string { return "SQL operation did not commit" }
func (e *confirmedRollback) Unwrap() error { return e.cause }

// IsKnownRollback also covers an operation cancelled before its first attempt.
// Only this package creates the proof; a generic timeout is never sufficient.
func IsKnownRollback(err error) bool {
	var proof *confirmedRollback
	return errors.As(err, &proof)
}

type TransactionRetryReport struct {
	Attempts int
	Aborts   []string
}

// RetryRolledBack reruns a complete, local SQL transaction at most three times.
// once MUST own its transaction and finish rollback before returning an error;
// it must not contain remote calls or effects outside that transaction. Its
// permission checks, lease fences, audit, receipt and outbox rerun together.
// An unacknowledged commit is returned unchanged and is never retried.
func RetryRolledBack[T any](ctx context.Context, once func() (T, error)) (T, TransactionRetryReport, error) {
	var zero T
	var report TransactionRetryReport
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return zero, report, &confirmedRollback{cause: errors.Join(last, err)}
		}
		if once == nil {
			return zero, report, &confirmedRollback{cause: errors.New("SQL transaction callback required")}
		}
		report.Attempts++
		result, err := once()
		if err == nil {
			return result, report, nil
		}
		if !IsTransactionRollback(err) {
			return zero, report, err
		}
		last = err
		report.Aborts = append(report.Aborts, SQLState(err))
		if attempt == 2 {
			return zero, report, &confirmedRollback{cause: err}
		}
		// Backoff is inside the original caller deadline; never renew that
		// deadline, replay an HTTP tool request, or increase provider calls.
		timer := time.NewTimer(time.Duration(1<<attempt)*10*time.Millisecond + rand.N(5*time.Millisecond))
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, report, &confirmedRollback{cause: errors.Join(err, ctx.Err())}
		case <-timer.C:
		}
	}
	panic("unreachable bounded transaction retry")
}
