package notification

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func ownedInboxFixture(t *testing.T) (context.Context, *SQLInboxChannel, Event, sharedkernel.Scope) {
	t.Helper()
	dsn := os.Getenv("COMPENSATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated owned PostgreSQL fixture required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(cfg.Database, "agentplug_compensation_test_") {
		t.Fatal("dedicated fixture database required; credentials suppressed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("fixture database unavailable")
	}
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	facade := sqlutil.TransactionDB(tx)
	err = ApplyReversalSchema(ctx, facade)
	facade.Close()
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Named fixture authority: verifies the transaction is open, but is not
	// evidence of the deployed compensation lease/IAM composition.
	channel, err := NewSQLInboxChannel(ctx, db, func(ctx context.Context, tx *sql.Tx, r ReversalRequest) error {
		var one int
		return tx.QueryRowContext(ctx, `SELECT 1`).Scan(&one)
	})
	if err != nil {
		t.Fatal(err)
	}
	event := reversalFixtureEvent()
	event.ID = fmt.Sprintf("inbox-%d", time.Now().UnixNano())
	scope := sharedkernel.Scope{TenantID: event.TenantID, DepartmentID: event.DepartmentID, ApplicationID: event.ApplicationID, PrincipalType: "user", PrincipalID: event.Payload["recipient_id"].(string)}
	return ctx, channel, event, scope
}
func inboxRead(t *testing.T, ctx context.Context, channel *SQLInboxChannel, scope sharedkernel.Scope) []InboxMessage {
	t.Helper()
	messages, err := channel.ReadRecipientInbox(ctx, scope, 100, func(context.Context, *sql.Tx, sharedkernel.Scope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return messages
}
func TestInboxWithdrawalAndLateForwardTombstonePostgres(t *testing.T) {
	ctx, channel, event, scope := ownedInboxFixture(t)
	if err := channel.Send(ctx, event); err != nil {
		t.Fatal(err)
	}
	if len(inboxRead(t, ctx, channel, scope)) < 1 {
		t.Fatal("message never visible")
	}
	binding, _ := AgentReversalBinding(event)
	r := ReversalRequest{Version: "notification-reversal/v1", Binding: binding, Key: reversalDigest(event.ID + "-undo"), Action: "withdraw"}
	p, err := channel.Revoke(ctx, r)
	if err != nil || p.Validate(r) != nil || p.Disposition != "withdrawn" {
		t.Fatalf("withdrawal missing: %v", err)
	}
	p2, err := channel.Revoke(ctx, r)
	if err != nil || p2 != p {
		t.Fatal("idempotency changed receipt")
	}
	if err = channel.Send(ctx, event); err != nil {
		t.Fatal(err)
	}
	for _, m := range inboxRead(t, ctx, channel, scope) {
		if m.EventID == event.ID {
			t.Fatal("withdrawn message resurrected")
		}
	}
	p2, found, err := channel.LookupReversal(ctx, r)
	if err != nil || !found || p2 != p {
		t.Fatal("authoritative receipt lost")
	}
	r.Binding.RecipientDigest = reversalDigest("other-recipient")
	if _, _, err = channel.LookupReversal(ctx, r); !errors.Is(err, ErrConflict) {
		t.Fatal("recipient boundary lost")
	}
}
func TestInboxConfirmedCorrectionAndNeverDeliveredFencePostgres(t *testing.T) {
	ctx, channel, event, scope := ownedInboxFixture(t)
	if err := channel.Send(ctx, event); err != nil {
		t.Fatal(err)
	}
	binding, _ := AgentReversalBinding(event)
	r := ReversalRequest{Version: "notification-reversal/v1", Binding: binding, Key: reversalDigest(event.ID + "-correct"), Action: "correct"}
	p, err := channel.Revoke(ctx, r)
	if err != nil || p.Validate(r) != nil || p.Disposition != "corrected" {
		t.Fatal("correction unconfirmed")
	}
	seen := false
	for _, m := range inboxRead(t, ctx, channel, scope) {
		if m.EventID == event.ID {
			seen = m.Correction != "" && m.State == "corrected"
		}
	}
	if !seen {
		t.Fatal("recipient cannot see confirmed correction")
	}
	other := scope
	other.PrincipalID = "someone-else"
	for _, m := range inboxRead(t, ctx, channel, other) {
		if m.EventID == event.ID {
			t.Fatal("message crossed recipient")
		}
	}
	event.ID += "-never-sent"
	binding, _ = AgentReversalBinding(event)
	r.Binding = binding
	r.Key = reversalDigest(event.ID + "-inverse")
	p, err = channel.Revoke(ctx, r)
	if err != nil || p.Validate(r) != nil || p.Disposition != "no_effect" {
		t.Fatal("never-delivered receipt unconfirmed")
	}
	if err = channel.Send(ctx, event); err != nil {
		t.Fatal(err)
	}
	for _, m := range inboxRead(t, ctx, channel, scope) {
		if m.EventID == event.ID {
			t.Fatal("delayed delivery bypassed tombstone")
		}
	}
}
func TestDeadLetterDoesNotClaimDelivery(t *testing.T) {
	store := NewStore()
	event := reversalFixtureEvent()
	now := time.Now()
	claim, err := store.ClaimDelivery(event, "worker", now, time.Second)
	if err != nil || !claim.Acquired {
		t.Fatal(err)
	}
	if err = store.MarkDeliveryFailed(event.ID, "worker", now, 1, errors.New("provider failed")); err != nil {
		t.Fatal(err)
	}
	claim, err = store.ClaimDelivery(event, "worker", now.Add(time.Minute), time.Second)
	if !errors.Is(err, ErrEventDeliveryDeadLetter) || claim.Delivered || claim.Acquired {
		t.Fatal("dead-letter reported as delivered")
	}
}
