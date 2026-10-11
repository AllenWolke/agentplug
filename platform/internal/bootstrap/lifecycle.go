package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Dependency is the narrow lifecycle port used by Bootstrap. Concrete DB,
// Kafka, object storage and telemetry adapters are introduced in later cards.
// Dependency 是 Bootstrap 使用的最小生命周期 Port，具体 DB/Kafka/对象存储/遥测
// Adapter 在后续任务接入。
type Dependency interface {
	Name() string
	Check(context.Context) error
	Close(context.Context) error
}

type Bootstrap struct {
	config RuntimeConfig
	deps   []Dependency
	mu     sync.Mutex
	ready  bool
	closed bool
}

func NewBootstrap(config RuntimeConfig, deps ...Dependency) *Bootstrap {
	return &Bootstrap{config: config, deps: deps}
}

func (b *Bootstrap) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	if err := b.config.Validate(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	if b.ready {
		return nil
	}
	for _, dep := range b.deps {
		if dep == nil || dep.Name() == "" {
			return errors.New("platform dependency name is required")
		}
		if err := dep.Check(ctx); err != nil {
			return fmt.Errorf("dependency %s is not ready: %w", dep.Name(), err)
		}
	}
	b.ready = true
	return nil
}

func (b *Bootstrap) Ready() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ready && !b.closed
}

func (b *Bootstrap) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ErrClosed
	}
	b.closed = true
	b.ready = false
	b.mu.Unlock()
	var firstErr error
	for i := len(b.deps) - 1; i >= 0; i-- {
		if err := b.deps[i].Close(ctx); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close dependency %s: %w", b.deps[i].Name(), err)
		}
	}
	return firstErr
}
