package execution

import (
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

// Scheduling only, never a stop/settlement proof. The durable Run and receipt
// are revalidated on every due attempt. Restart discards this bounded hint and
// immediately rereads durable state; no stop command is assumed successful.
type cancellationRetry struct {
	revision uint64
	lease    string
	status   platformruntime.Status
	failures uint8
	next     time.Time
	touched  time.Time
}

func (d *Dispatcher) cancellationDue(run platformruntime.Run, now time.Time) bool {
	r, found := d.cancellationRetries[run.ID]
	return !found || r.revision != run.Revision || r.lease != stopHash([]byte(run.LeaseToken)) || r.status != run.Status || !now.Before(r.next)
}

func (d *Dispatcher) deferCancellation(run platformruntime.Run, now time.Time) {
	if d.cancellationRetries == nil {
		d.cancellationRetries = make(map[string]cancellationRetry)
	}
	const capacity = 4096
	r, found := d.cancellationRetries[run.ID]
	if !found && len(d.cancellationRetries) >= capacity {
		for id, old := range d.cancellationRetries {
			if now.Sub(old.touched) > 5*time.Minute {
				delete(d.cancellationRetries, id)
			}
		}
		if len(d.cancellationRetries) >= capacity {
			return // Capacity never prevents attempting an uncached Run.
		}
	}
	lease := stopHash([]byte(run.LeaseToken))
	if r.revision != run.Revision || r.lease != lease || r.status != run.Status {
		r = cancellationRetry{revision: run.Revision, lease: lease, status: run.Status}
	}
	if r.failures < 6 {
		r.failures++
	}
	delay := time.Second * time.Duration(1<<(r.failures-1))
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	r.next, r.touched = now.Add(delay), now
	d.cancellationRetries[run.ID] = r
}
