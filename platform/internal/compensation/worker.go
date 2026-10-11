package compensation

import (
	"context"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type WorkerStore interface {
	ListPending(context.Context, int) ([]sharedkernel.Scope, error)
	TryFinalize(context.Context, sharedkernel.Scope) error
}

// SweepStats contains fixed numeric telemetry only. Provider error strings,
// effect references, user values, credentials and control leases are excluded.
type SweepStats struct {
	Visited   int
	Handled   int
	Completed int
	Pending   int
	Failed    int
}

// Sweep visits a bounded batch once. Each Tick handles at most one inverse;
// crashes resume through the durable queue, never through an in-memory retry.
func (e *Engine) Sweep(ctx context.Context, store WorkerStore, limit int) (SweepStats, error) {
	var stats SweepStats
	if ctx == nil || store == nil || limit < 1 || limit > 16 {
		return stats, ErrInvalid
	}
	scopes, err := store.ListPending(ctx, limit)
	if err != nil {
		return stats, err
	}
	if len(scopes) > limit {
		return stats, ErrConflict
	}
	for _, scope := range scopes {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		stats.Visited++
		// Each root gets its own bounded control context. Cancellation of the
		// host stops admission; confirmed receipts remain durable for restart.
		unit, cancel := context.WithTimeout(ctx, 65*time.Second)
		handled, tickErr := e.Tick(unit, scope)
		if handled {
			stats.Handled++
		}
		if tickErr != nil {
			stats.Failed++
			cancel()
			continue
		}
		finishErr := store.TryFinalize(unit, scope)
		cancel()
		switch {
		case finishErr == nil:
			stats.Completed++
		case errors.Is(finishErr, ErrPending):
			stats.Pending++
		default:
			stats.Failed++
		}
	}
	return stats, nil
}

// Run is one fixed worker, started explicitly by the host after every adapter
// and permission/coverage port is composed. It spawns no per-Run goroutines.
// Independent hosts remain fenced by PostgreSQL leases and immutable keys.
func (e *Engine) Run(ctx context.Context, store WorkerStore, interval time.Duration, observe func(SweepStats, bool)) error {
	if ctx == nil || store == nil || interval < time.Second || interval > time.Minute {
		return ErrInvalid
	}
	for {
		stats, err := e.Sweep(ctx, store, 16)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if observe != nil {
			observe(stats, err != nil)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
