package conversation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// The worker is internal, with no public claim/erase route or caller-supplied scope.
func (m *Module) SetErasureWorkerEnabled(enabled bool) { m.erasureEnabled = enabled }

func (m *Module) startErasureWorker(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !m.erasureEnabled {
		return ctx.Err()
	}
	store, ok := m.store.(*SQLStore)
	if !ok || store.erasureAuthorize == nil || store.erasureQuiescent == nil || store.erasureRecorder == nil || store.deletionGuard == nil || store.deletionReplay == nil {
		return errors.New("conversation erasure ports required")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	owner := "conversation-erasure-" + hex.EncodeToString(random[:])
	workerCtx, cancel := context.WithCancel(ctx)
	m.erasureCancel, m.erasureDone = cancel, make(chan struct{})
	go func() {
		defer close(m.erasureDone)
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-timer.C:
			}
			stepCtx, stop := context.WithTimeout(workerCtx, 30*time.Second)
			claim, err := store.ClaimErasure(stepCtx, owner, time.Minute)
			if err == nil {
				_, err = store.CompleteErasure(stepCtx, claim)
				if err != nil && workerCtx.Err() == nil {
					retryCtx, retryStop := context.WithTimeout(workerCtx, 5*time.Second)
					_ = store.RetryErasure(retryCtx, claim, err)
					retryStop()
				}
			}
			stop()
			if workerCtx.Err() != nil {
				return
			}
			if err == nil {
				timer.Reset(time.Second)
			} else {
				timer.Reset(30 * time.Second)
			}
		}
	}()
	return nil
}

func (m *Module) stopErasureWorker(ctx context.Context) error {
	if m.erasureCancel == nil {
		return nil
	}
	m.erasureCancel()
	select {
	case <-m.erasureDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
