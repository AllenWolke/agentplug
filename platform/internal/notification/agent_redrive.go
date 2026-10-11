package notification

import (
	"context"
	"database/sql"
	"errors"

	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Redrive restores transport admission for one exact committed notification,
// never the forward Agent tool. A controlled inbox makes an UNKNOWN send safe
// through message-ID deduplication and a durable withdrawal tombstone.
func (p *CompensationPort) PrepareAgentRedriveTx(ctx context.Context, tx *sql.Tx, event Event, guard func(context.Context, *sql.Tx, compensation.Step) error) error {
	if p == nil || tx == nil || guard == nil {
		return ErrDeadLetterUnavailable
	}
	binding, err := AgentReversalBinding(event)
	if err != nil {
		return ErrDeadLetterConflict
	}
	step, err := p.coordinator.ReadEffectReferenceTx(ctx, tx, NotificationCompensationProvider, event.ID)
	if err != nil || p.check(step) != nil || !matchesNotificationStep(step, event) {
		return ErrDeadLetterUnavailable
	}
	// The composition locks IAM/Run ancestors before any owner/outbox lock.
	if err = guard(ctx, tx, step); err != nil {
		return ErrDeadLetterUnavailable
	}
	if err = inboxLock(ctx, tx, event.ID); err != nil {
		return err
	}
	var digest, state string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT binding_digest,state FROM platform_notification_inbox WHERE event_id=? FOR UPDATE`), event.ID).Scan(&digest, &state)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && (digest != reversalDigest(binding) || state != "delivered") {
		return ErrDeadLetterConflict
	}
	stored, err := getEventTx(ctx, tx, event.ID, true)
	if err != nil || !sameEventValue(stored, event) || (stored.Status != Published && stored.Status != Dead) {
		return ErrDeadLetterConflict
	}
	var delivery string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_notification_delivery WHERE event_id=? FOR UPDATE`), event.ID).Scan(&delivery)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		if delivery != string(Dead) && delivery != string(Failed) && delivery != "unknown" {
			return ErrDeadLetterConflict
		}
		if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_notification_delivery SET status='failed',attempts=0,claim_owner='',claim_until=NULL,last_error='' WHERE event_id=?`), event.ID); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_notification_outbox SET status='pending',attempts=0,next_attempt_at=clock_timestamp(),claim_owner='',claim_until=NULL WHERE event_id=? AND status IN ('published','dead')`), event.ID)
	return err
}
