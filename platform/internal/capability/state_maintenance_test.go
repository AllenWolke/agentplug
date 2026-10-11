package capability

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type checkpointMaintenanceProbe struct {
	calls   atomic.Int32
	entered chan struct{}
}

func (*checkpointMaintenanceProbe) Load(context.Context, sharedkernel.Scope, string, string, string, uint64) (Checkpoint, bool, error) {
	return Checkpoint{}, false, ErrStateUnavailable
}
func (*checkpointMaintenanceProbe) Save(context.Context, StateWrite, func(context.Context) error) (Checkpoint, error) {
	return Checkpoint{}, ErrStateUnavailable
}
func (s *checkpointMaintenanceProbe) PruneExpired(ctx context.Context, limit int) (int64, error) {
	if limit != 128 {
		panic("unexpected unbounded checkpoint batch")
	}
	if s.calls.Add(1) == 1 {
		close(s.entered)
	}
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestCheckpointMaintenanceStartsOnceAndStopsWithModule(t *testing.T) {
	probe := &checkpointMaintenanceProbe{entered: make(chan struct{})}
	m := NewModule("internal", "secret", nil, "platform", "agent")
	m.toolStore = nil
	m.SetCheckpointStore(probe)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-probe.entered:
	case <-ctx.Done():
		t.Fatal("checkpoint worker did not start")
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if probe.calls.Load() != 1 {
		t.Fatal("duplicate maintenance worker started")
	}
	select {
	case <-m.stateDone:
	default:
		t.Fatal("module returned before checkpoint worker stopped")
	}
}
