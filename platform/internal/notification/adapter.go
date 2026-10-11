package notification

import (
	"context"
	"errors"
	"time"
)

var ErrAdapterUnavailable = errors.New("notification channel adapter unavailable")

// ChannelAdapter is the only seam for WeCom/email/SMS/etc. Providers remain
// outside the platform domain and receive no database credentials.
// ChannelAdapter 是企微/邮件/短信等通道的唯一接缝，Provider 不进入平台领域。
type ChannelAdapter interface {
	Send(context.Context, Event) error
}

type Dispatcher struct {
	Store   EventStore
	Adapter ChannelAdapter
}

func (d Dispatcher) Dispatch(ctx context.Context, eventID, owner string) error {
	if d.Store == nil || d.Adapter == nil {
		return ErrAdapterUnavailable
	}
	event, err := d.Store.ClaimID(eventID, owner, timeNow(), time.Second*30)
	if err != nil {
		return err
	}
	if err = d.Adapter.Send(ctx, event); err != nil {
		// Keep the provider failure visible to HTTP callers and supervisors. The
		// durable state transition still happens before returning, so a caller
		// may safely retry without losing the failure or falsely observing a
		// successful delivery.
		markErr := d.Store.MarkFailed(event.ID, owner, timeNow(), 5)
		if markErr != nil {
			return errors.Join(err, markErr)
		}
		return err
	}
	return d.Store.MarkPublished(event.ID, owner)
}

// timeNow is a test seam; future Kafka workers use the same bounded clock.
// timeNow 是测试接缝，未来 Kafka Worker 复用同一时间边界。
var timeNow = func() time.Time { return time.Now().UTC() }
