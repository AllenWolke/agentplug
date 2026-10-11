package knowledge

import (
	"context"
	"errors"
)

func (m *ControlModule) SetWorker(worker func(context.Context) error) error {
	m.workerMu.Lock()
	defer m.workerMu.Unlock()
	if m.workerStarted {
		return errors.New("knowledge worker already started")
	}
	m.worker = worker
	return nil
}

func (m *ControlModule) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("knowledge worker context required")
	}
	m.workerMu.Lock()
	defer m.workerMu.Unlock()
	if m.workerStarted {
		return nil
	}
	m.workerStarted = true
	if m.worker == nil {
		return nil
	}
	lifetime, cancel := context.WithCancel(ctx)
	m.workerCancel = cancel
	m.workerDone = make(chan struct{})
	worker, done := m.worker, m.workerDone
	go func() {
		err := worker(lifetime)
		m.workerMu.Lock()
		if lifetime.Err() == nil {
			if err == nil {
				err = errors.New("knowledge worker stopped unexpectedly")
			}
			m.workerError = err
		}
		m.workerMu.Unlock()
		close(done)
	}()
	return nil
}

func (m *ControlModule) Close(ctx context.Context) error {
	m.workerMu.Lock()
	cancel, done := m.workerCancel, m.workerDone
	m.workerMu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
