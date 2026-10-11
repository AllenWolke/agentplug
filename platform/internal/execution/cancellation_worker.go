package execution

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/lexagent/platform/internal/compensation"
)

// The composition root installs the bounded engine only after every effect
// owner, coverage port and current-permission fence has been configured.
// The execution module owns its lifecycle; the shared SQL pool outlives it.
func (m *Module) SetCancellationCompensationWorker(engine *compensation.Engine, store compensation.WorkerStore, observe func(compensation.SweepStats, bool)) error {
	if m == nil || engine == nil || store == nil || m.cancellationWorker != nil {
		return compensation.ErrInvalid
	}
	m.cancellationWorker = &cancellationWorkerLifecycle{run: func(ctx context.Context) error { return engine.Run(ctx, store, time.Second, observe) }}
	return nil
}

type cancellationWorkerLifecycle struct {
	mu      sync.Mutex
	run     func(context.Context) error
	cancel  context.CancelFunc
	done    chan struct{}
	started bool
	closed  bool
	err     error
}

func (w *cancellationWorkerLifecycle) start(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || w.run == nil {
		return compensation.ErrUnavailable
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started || w.closed {
		return compensation.ErrConflict
	}
	workerCtx, cancel := context.WithCancel(ctx)
	w.cancel, w.done, w.started = cancel, make(chan struct{}), true
	go func() {
		err := w.run(workerCtx)
		w.mu.Lock()
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			w.err = compensation.ErrUnavailable
		}
		w.mu.Unlock()
		close(w.done)
	}()
	return nil
}

func (w *cancellationWorkerLifecycle) close(ctx context.Context) error {
	if ctx == nil {
		return compensation.ErrInvalid
	}
	w.mu.Lock()
	w.closed = true
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}
