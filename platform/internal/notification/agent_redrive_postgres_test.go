package notification

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Named metadata authority fixture only. Real IAM/run cancellation races are
// separately exercised against the installed main composition.
type redriveMetadataFixture struct{}

func (redriveMetadataFixture) RegisterEffectTx(context.Context, *sql.Tx, compensation.Step) error {
	return nil
}
func (redriveMetadataFixture) BeginCancellationTx(context.Context, *sql.Tx, sharedkernel.Scope, uint64) error {
	return compensation.ErrUnavailable
}
func (redriveMetadataFixture) ConfirmStoppedTx(context.Context, *sql.Tx, sharedkernel.Scope, compensation.StopProof) error {
	return compensation.ErrUnavailable
}
func (redriveMetadataFixture) GuardCompensationTx(context.Context, *sql.Tx, sharedkernel.Scope) error {
	return compensation.ErrUnavailable
}
func (redriveMetadataFixture) FinishCancellationTx(context.Context, *sql.Tx, sharedkernel.Scope, compensation.StopProof) error {
	return compensation.ErrUnavailable
}

func TestAgentNotificationRedriveOwnerTombstoneAndNoForwardReplayPostgres(t *testing.T) {
	for _, mode := range []string{"unknown_delivery", "withdrawn", "no_preregistration", "denied", "changed_message"} {
		t.Run(mode, func(t *testing.T) {
			ctx, channel, event, scope := ownedInboxFixture(t)
			if err := compensation.Migrate(ctx, channel.db); err != nil {
				t.Fatal(err)
			}
			coordinator, err := compensation.NewSQLStore(channel.db, redriveMetadataFixture{})
			if err != nil {
				t.Fatal(err)
			}
			store := NewSQLStore(channel.db)
			if err = store.EnsureSchema(ctx); err != nil {
				t.Fatal(err)
			}
			scope.AgentID = "agent-redrive"
			scope.AgentInstanceID = "instance-redrive"
			scope.AgentVersionID = "version-reversal"
			scope.InstallationID = "install-reversal"
			scope.RunID = event.ID
			scope.SessionID = "session-reversal"
			scope.TraceID = "trace-redrive"
			scope.AuthorizationEpoch = 1
			event.Payload["agent_id"] = scope.AgentID
			event.Payload["agent_instance_id"] = scope.AgentInstanceID
			event.Payload["run_id"] = scope.RunID
			event.Payload["trace_id"] = scope.TraceID
			step := compensation.Step{Root: scope, Scope: scope, Kind: "notification", Tool: "notify.self", Provider: NotificationCompensationProvider, ProviderVersion: InboxChannelVersion + ".withdraw", CallID: "call-reversal", Fingerprint: event.Payload["tool_fingerprint"].(string), Ref: event.ID}
			step.ID = compensation.StepID(scope, step.Kind, step.CallID)
			if step.Validate() != nil {
				t.Fatal("invalid fixture scope")
			}
			if mode != "no_preregistration" {
				tx, err := channel.db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				err = coordinator.RegisterTx(ctx, tx, step)
				if err != nil {
					tx.Rollback()
					t.Fatal(err)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = store.Enqueue(event); err != nil {
				t.Fatal(err)
			}
			if _, err = channel.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_notification_outbox SET status='published' WHERE event_id=?`), event.ID); err != nil {
				t.Fatal(err)
			}
			if _, err = channel.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_notification_delivery(event_id,status,attempts) VALUES(?,'unknown',3)`), event.ID); err != nil {
				t.Fatal(err)
			}
			if err = channel.Send(ctx, event); err != nil {
				t.Fatal(err)
			}
			if mode == "withdrawn" {
				binding, _ := AgentReversalBinding(event)
				if _, err = channel.Revoke(ctx, ReversalRequest{Version: "notification-reversal/v1", Binding: binding, Key: step.CompensationKey(), Action: "withdraw"}); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "changed_message" {
				event.Payload["text"] = "different message"
			}
			p := &CompensationPort{store: store, coordinator: coordinator, channel: channel, action: "withdraw", version: InboxChannelVersion + ".withdraw"}
			tx, err := channel.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = p.PrepareAgentRedriveTx(ctx, tx, event, func(_ context.Context, _ *sql.Tx, s compensation.Step) error {
				if mode == "denied" || s.Digest() != step.Digest() {
					return errors.New("denied")
				}
				return nil
			})
			if mode == "unknown_delivery" {
				if err != nil {
					tx.Rollback()
					t.Fatal(err)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
				if err = channel.Send(ctx, event); err != nil {
					t.Fatal(err)
				}
				matches := 0
				for _, m := range inboxRead(t, ctx, channel, scope) {
					if m.EventID == event.ID {
						matches++
					}
				}
				if matches != 1 {
					t.Fatal("notification duplicated", matches)
				}
			} else {
				tx.Rollback()
				if err == nil {
					t.Fatal("unverified redrive admitted")
				}
			}
			var status string
			if err = channel.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_notification_outbox WHERE event_id=?`), event.ID).Scan(&status); err != nil {
				t.Fatal(err)
			}
			expected := "published"
			if mode == "unknown_delivery" {
				expected = "pending"
			}
			if status != expected {
				t.Fatal("redrive changed wrong state", status)
			}
		})
	}
}
