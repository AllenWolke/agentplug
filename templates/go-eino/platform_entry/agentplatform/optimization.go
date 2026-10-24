package agentplatform

import (
	"context"
	"errors"
	"math/rand/v2"
	"strings"
	"sync"
	"time"
)

// DeadlineBudget bounds local work; it does not authorize platform spending.
type DeadlineBudget struct {
	mu             sync.Mutex
	expires        time.Time
	maximum, calls int
}

func NewDeadlineBudget(duration time.Duration, maximumCalls int) (*DeadlineBudget, error) {
	if duration <= 0 || maximumCalls < 1 || maximumCalls > 1024 {
		return nil, publicError("LOCAL_BUDGET_INVALID")
	}
	return &DeadlineBudget{expires: time.Now().Add(duration), maximum: maximumCalls}, nil
}
func (b *DeadlineBudget) Remaining() (time.Duration, error) {
	if b == nil {
		return 0, publicError("LOCAL_BUDGET_INVALID")
	}
	remaining := time.Until(b.expires)
	if remaining <= 0 {
		return 0, context.DeadlineExceeded
	}
	return remaining, nil
}
func (b *DeadlineBudget) AdmitCall() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, err := b.Remaining(); err != nil {
		return err
	}
	if b.calls >= b.maximum {
		return publicError("LOCAL_CALL_BUDGET_EXHAUSTED")
	}
	b.calls++
	return nil
}

func AuthorityFailure(err error) bool {
	if errors.Is(err, context.Canceled) {
		return true
	}
	var status interface{ HTTPStatus() int }
	if errors.As(err, &status) && (status.HTTPStatus() == 401 || status.HTTPStatus() == 403) {
		return true
	}
	var app *AppError
	if !errors.As(err, &app) {
		return false
	}
	code := strings.ToUpper(app.Code)
	if code == "MODEL_BUDGET_UNAVAILABLE" || code == "MODEL_BUDGET_ADMISSION_DEFERRED" || code == "RUNTIME_BUDGET_UNAVAILABLE" {
		return false
	}
	for _, part := range []string{"DENIED", "UNAUTHORIZED", "FORBIDDEN", "SIGNATURE", "CONTEXT_INVALID", "CONTEXT_EXPIRED", "POLICY_", "AUTHORIZATION_", "WORKLOAD_", "CREDENTIAL_", "TOKEN_", "BUDGET_", "RUN_CANCEL", "EXECUTION_STOP", "RUN_LEASE", "RUN_RESUME_UNCONFIRMED", "MODEL_SELECTION_MISMATCH", "ASSET_VERSION_MISMATCH", "INSTALLATION_REVOKED", "TOOL_CONFIRMATION_"} {
		if strings.Contains(code, part) {
			return true
		}
	}
	return false
}

type RetryAfterError interface{ RetryAfter() time.Duration }

// RetryBounded requires positive safe-to-retry evidence. A transport timeout
// alone never proves that a model/tool operation was not sent.
func RetryBounded[T any](ctx context.Context, budget *DeadlineBudget, attempts int, safeToRetry func(error) bool, call func(context.Context) (T, error)) (T, error) {
	var zero T
	if budget == nil || attempts < 1 || attempts > 8 || safeToRetry == nil || call == nil {
		return zero, publicError("LOCAL_RETRY_INVALID")
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if err := budget.AdmitCall(); err != nil {
			return zero, err
		}
		remaining, err := budget.Remaining()
		if err != nil {
			return zero, err
		}
		callCtx, cancel := context.WithTimeout(ctx, remaining)
		result, err := call(callCtx)
		cancel()
		if err == nil {
			return result, nil
		}
		if AuthorityFailure(err) || attempt+1 == attempts || !safeToRetry(err) {
			return zero, err
		}
		delay := time.Duration(float64(min(50*time.Millisecond*time.Duration(1<<attempt), time.Second)) * (0.5 + rand.Float64()))
		var retryHint RetryAfterError
		if errors.As(err, &retryHint) {
			hint := retryHint.RetryAfter()
			if hint >= 0 {
				delay = max(delay, min(hint, 30*time.Second))
			}
		}
		remaining, budgetError := budget.Remaining()
		if budgetError != nil {
			return zero, budgetError
		}
		if delay >= remaining {
			return zero, err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
	return zero, publicError("LOCAL_RETRY_INVALID")
}

type BoundedResult[T any] struct {
	Value T
	Err   error
}

// BoundedMap owns a fixed worker set and joins every worker before returning.
// Ordinary per-item failures are retained; authority loss cancels all siblings.
func BoundedMap[T, R any](ctx context.Context, items []T, workers, queueSize int, call func(context.Context, T) (R, error)) ([]BoundedResult[R], error) {
	if workers < 1 || workers > 64 || queueSize < 1 || queueSize > 10000 || len(items) > 10000 || call == nil {
		return nil, publicError("BATCH_CONFIG_INVALID")
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make([]BoundedResult[R], len(items))
	jobs := make(chan int, queueSize)
	var group sync.WaitGroup
	var decisive error
	var failureLock sync.Mutex
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				if workCtx.Err() != nil {
					results[index].Err = workCtx.Err()
					continue
				}
				value, err := call(workCtx, items[index])
				results[index] = BoundedResult[R]{value, err}
				if AuthorityFailure(err) {
					failureLock.Lock()
					if decisive == nil || !AuthorityFailure(decisive) {
						decisive = err
					}
					failureLock.Unlock()
					cancel()
				}
			}
		}()
	}
	produce := true
	for index := range items {
		select {
		case jobs <- index:
		case <-workCtx.Done():
			for rest := index; rest < len(items); rest++ {
				results[rest].Err = workCtx.Err()
			}
			produce = false
		}
		if !produce {
			break
		}
	}
	close(jobs)
	group.Wait()
	if ctx.Err() != nil {
		return results, ctx.Err()
	}
	return results, decisive
}

type StageMeasurement struct {
	Version   string           `json:"version"`
	Stage     string           `json:"stage"`
	WallMS    float64          `json:"wall_ms"`
	Status    string           `json:"status"`
	ErrorType string           `json:"error_type"`
	Counts    map[string]int64 `json:"counts"`
}
type StageRecorder struct{ Sink func(StageMeasurement) }

// Stage emits only bounded labels/counters; never inputs, outputs or secrets.
func (r StageRecorder) Stage(name string, counts map[string]int64) (func(error), error) {
	if requirePublicName(name) != nil || len(name) > 64 {
		return nil, publicError("STAGE_MEASUREMENT_INVALID")
	}
	allowed := map[string]bool{}
	for _, key := range []string{"calls", "input_tokens", "output_tokens", "retry_count", "cache_hits", "cache_misses", "queue_depth", "admission_ms", "queue_wait_ms", "documents", "chunks"} {
		allowed[key] = true
	}
	copy := map[string]int64{}
	for key, value := range counts {
		if !allowed[key] || value < 0 {
			return nil, publicError("STAGE_MEASUREMENT_INVALID")
		}
		copy[key] = value
	}
	started := time.Now()
	var once sync.Once
	return func(err error) {
		once.Do(func() {
			if r.Sink == nil {
				return
			}
			status, kind := "succeeded", ""
			if err != nil {
				status, kind = "failed", "operation_error"
				if errors.Is(err, context.Canceled) {
					status, kind = "cancelled", "cancelled"
				}
			}
			defer func() { _ = recover() }()
			r.Sink(StageMeasurement{"agent-stage-measurement/v1", name, float64(time.Since(started)) / float64(time.Millisecond), status, kind, copy})
		})
	}, nil
}

func (m StageMeasurement) MarshalJSON() ([]byte, error) {
	value := map[string]any{"version": m.Version, "stage": m.Stage, "wall_ms": m.WallMS, "status": m.Status, "error_type": m.ErrorType, "cpu_attribution": "unavailable"}
	for key, count := range m.Counts {
		value[key] = count
	}
	return publicJSON(value)
}
