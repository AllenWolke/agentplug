package execution

import (
	"fmt"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestCancellationRetryBackoffAndGenerationIsolation(t *testing.T) {
	d := &Dispatcher{}
	run := platformruntime.Run{ID: "waiting-for-ledger", Revision: 4, LeaseToken: "lease", Status: platformruntime.StatusCancelling}
	now := time.Unix(1000, 0)
	for _, delay := range []time.Duration{1, 2, 4, 8, 16, 30, 30} {
		if !d.cancellationDue(run, now) {
			t.Fatal("due cancellation was skipped")
		}
		d.deferCancellation(run, now)
		wait := delay * time.Second
		if d.cancellationDue(run, now.Add(wait-time.Nanosecond)) || !d.cancellationDue(run, now.Add(wait)) {
			t.Fatal("retry did not respect its bounded delay", delay)
		}
		now = now.Add(wait)
	}
	for _, change := range []string{"revision", "lease", "status"} {
		t.Run(change, func(t *testing.T) {
			changed := run
			switch change {
			case "revision":
				changed.Revision++
			case "lease":
				changed.LeaseToken = "another-generation"
			case "status":
				changed.Status = platformruntime.StatusRecovering
			}
			if !d.cancellationDue(changed, now.Add(-time.Second)) {
				t.Fatal("a different generation inherited old retry delay")
			}
			d.deferCancellation(changed, now)
			if d.cancellationRetries[run.ID].next != now.Add(time.Second) {
				t.Fatal("new generation did not reset backoff")
			}
		})
	}
	if !(&Dispatcher{}).cancellationDue(run, now) {
		t.Fatal("restart must reread durable proof immediately")
	}
}

func TestCancellationRetryBoundNeverStarvesNewRun(t *testing.T) {
	d := &Dispatcher{}
	now := time.Unix(1000, 0)
	for i := 0; i < 4096; i++ {
		d.deferCancellation(platformruntime.Run{ID: fmt.Sprint(i), Revision: 1, Status: platformruntime.StatusCancelling}, now)
	}
	fresh := platformruntime.Run{ID: "fresh", Revision: 1, Status: platformruntime.StatusCancelling}
	d.deferCancellation(fresh, now)
	if len(d.cancellationRetries) != 4096 || !d.cancellationDue(fresh, now) {
		t.Fatal("full hint cache blocked a new cancellation or grew without bound")
	}
	d.deferCancellation(fresh, now.Add(6*time.Minute))
	if len(d.cancellationRetries) != 1 || d.cancellationDue(fresh, now.Add(6*time.Minute)) {
		t.Fatal("expired scheduling hints were not reclaimed")
	}
}
