package execution

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/compensation"
)

func TestCancellationWorkerLifecycleDrainsBeforeReturnAndCannotRestart(t *testing.T) {
	entered, drained := make(chan struct{}), make(chan struct{})
	w := &cancellationWorkerLifecycle{run: func(ctx context.Context) error { close(entered); <-ctx.Done(); close(drained); return ctx.Err() }}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("worker did not start")
	}
	if err := w.start(ctx); !errors.Is(err, compensation.ErrConflict) {
		t.Fatal("second worker started")
	}
	if err := w.close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-drained:
	default:
		t.Fatal("close returned before worker drained")
	}
	if err := w.close(ctx); err != nil {
		t.Fatal("idempotent close failed", err)
	}
	if err := w.start(ctx); !errors.Is(err, compensation.ErrConflict) {
		t.Fatal("closed worker restarted")
	}
}

func TestCancellationWorkerLifecycleShutdownTimeoutRetainsDrainAndSanitizesFailure(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	w := &cancellationWorkerLifecycle{run: func(context.Context) error { close(started); <-release; return errors.New("SECRET_PRIVATE_ERROR") }}
	if err := w.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-started
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.close(expired); !errors.Is(err, context.Canceled) {
		t.Fatal("shutdown falsely claimed drain", err)
	}
	close(release)
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	err := w.close(ctx)
	if !errors.Is(err, compensation.ErrUnavailable) || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("private worker failure leaked", err)
	}
}
