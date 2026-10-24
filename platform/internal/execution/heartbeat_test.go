package execution

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type heartbeatFaultRepository struct {
	Repository
	fail atomic.Bool
}

func (s *heartbeatFaultRepository) Heartbeat(id, token string, revision uint64, now time.Time, ttl time.Duration) (platformruntime.Run, error) {
	if s.fail.Load() {
		return platformruntime.Run{}, errors.New("database unavailable")
	}
	return s.Repository.Heartbeat(id, token, revision, now, ttl)
}

func TestHeartbeatLockTimeoutDoesNotCancelAndDenialStillDoes(t *testing.T) {
	base := platformruntime.NewStore()
	scope := testScope("heartbeat-ancestry-timeout")
	created, err := base.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "heartbeat-ancestry", Fingerprint: "fp"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := base.AcquireLease(created.Run.ID, "owner", time.Now(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	run, err := base.TransitionLeased(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(base, "secret", 1)
	var deny atomic.Bool
	d.coordinatedGuard = func(context.Context, sharedkernel.Scope) error {
		if deny.Load() {
			return errors.New("ancestry denied")
		}
		return context.DeadlineExceeded
	}
	d.authorize = func(context.Context, sharedkernel.Scope) error {
		if deny.Load() {
			return errors.New("authorization denied")
		}
		return context.DeadlineExceeded
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := d.startHeartbeat(ctx, cancel, run, time.Second)
	defer stop()
	deadline := time.Now().Add(3 * time.Second)
	for {
		current, err := base.Get(run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.LeaseUntil.After(run.LeaseUntil) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("deferred ancestry timeout blocked lease renewal")
		}
		time.Sleep(time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("ancestry lock timeout cancelled the run")
	}
	deny.Store(true)
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("ancestry denial did not cancel the run")
	}
}

func TestHeartbeatStatementCancelDoesNotCancelAndDenialStillDoes(t *testing.T) {
	base := platformruntime.NewStore()
	scope := testScope("heartbeat-statement-cancel")
	created, err := base.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "heartbeat-statement-cancel", Fingerprint: "fp"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := base.AcquireLease(created.Run.ID, "owner", time.Now(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	run, err := base.TransitionLeased(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(base, "secret", 1)
	var deny atomic.Bool
	wait := func(context.Context, sharedkernel.Scope) error {
		if deny.Load() {
			return errors.New("permission denied")
		}
		return heartbeatSQLFailure{state: "57014"}
	}
	d.coordinatedGuard = wait
	d.authorize = wait
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := d.startHeartbeat(ctx, cancel, run, time.Second)
	defer stop()
	deadline := time.Now().Add(3 * time.Second)
	for {
		current, err := base.Get(run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.LeaseUntil.After(run.LeaseUntil) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("deferred statement cancel blocked lease renewal")
		}
		time.Sleep(time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("statement cancel cancelled the run")
	}
	deny.Store(true)
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("permission denial did not cancel the run")
	}
}

func TestHeartbeatCallerCancelStillCancels(t *testing.T) {
	base := platformruntime.NewStore()
	scope := testScope("heartbeat-caller-cancel")
	created, err := base.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "heartbeat-caller-cancel", Fingerprint: "fp"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := base.AcquireLease(created.Run.ID, "owner", time.Now(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	run, err := base.TransitionLeased(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(base, "secret", 1)
	d.coordinatedGuard = func(context.Context, sharedkernel.Scope) error { return context.Canceled }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := d.startHeartbeat(ctx, cancel, run, time.Second)
	defer stop()
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("caller cancellation was deferred")
	}
}

// Renewal loss and revocation cancel the blocking call before further work.
// 续租失败和撤权会取消阻塞调用，而不是继续使用旧租约。
func TestHeartbeatRenewsLeaseAndCancelsOnDatabaseFailureOrRevocation(t *testing.T) {
	for _, failure := range []string{"database", "revocation"} {
		t.Run(failure, func(t *testing.T) {
			base := platformruntime.NewStore()
			scope := testScope("heartbeat-" + failure)
			created, err := base.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "heartbeat-idem", Fingerprint: "fp"})
			if err != nil {
				t.Fatal(err)
			}
			claimed, err := base.AcquireLease(created.Run.ID, "owner", time.Now(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			run, err := base.TransitionLeased(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
			if err != nil {
				t.Fatal(err)
			}
			repository := &heartbeatFaultRepository{Repository: base}
			d := NewDispatcher(repository, "secret", 1)
			var revoked atomic.Bool
			d.authorize = func(context.Context, sharedkernel.Scope) error {
				if revoked.Load() {
					return errors.New("revoked")
				}
				return nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stop := d.startHeartbeat(ctx, cancel, run, time.Second)
			defer stop()
			deadline := time.Now().Add(3 * time.Second)
			for {
				current, err := base.Get(run.ID)
				if err != nil {
					t.Fatal(err)
				}
				if current.LeaseUntil.After(run.LeaseUntil) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("heartbeat did not renew lease")
				}
				time.Sleep(time.Millisecond)
			}
			if failure == "database" {
				repository.fail.Store(true)
			} else {
				revoked.Store(true)
			}
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
				t.Fatal("execution was not cancelled")
			}
		})
	}
}
