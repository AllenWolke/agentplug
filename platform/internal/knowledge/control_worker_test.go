package knowledge

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestKnowledgeWorkerLifecycleDrainsAndMarksUnexpectedExit(t *testing.T) {
	for _, mode := range []string{"shutdown", "parent-canceled", "failure", "unexpected-success"} {
		t.Run(mode, func(t *testing.T) {
			module := NewControlModule("internal", &indexControlFixture{})
			started, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
			failure := errors.New("fixture worker failure")
			if err := module.SetWorker(func(ctx context.Context) error {
				close(started)
				defer close(exited)
				if mode == "shutdown" || mode == "parent-canceled" {
					<-ctx.Done()
					return ctx.Err()
				}
				<-release
				if mode == "failure" {
					return failure
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := module.Start(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("not started")
			}
			if err := module.Start(ctx); err != nil {
				t.Fatal("duplicate start", err)
			}
			if err := module.SetWorker(nil); err == nil {
				t.Fatal("live worker replaced")
			}
			if mode == "parent-canceled" {
				cancel()
			}
			if mode == "failure" || mode == "unexpected-success" {
				close(release)
				select {
				case <-module.workerDone:
				case <-time.After(time.Second):
					t.Fatal("worker did not exit")
				}
				if err := module.ReadyContext(context.Background()); err == nil {
					t.Fatal("exited worker remained ready")
				}
			}
			closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := module.Close(closeCtx); err != nil {
				t.Fatal(err)
			}
			select {
			case <-exited:
			default:
				t.Fatal("close returned before worker exit")
			}
			if err := module.Close(closeCtx); err != nil {
				t.Fatal("duplicate close", err)
			}
		})
	}
}
