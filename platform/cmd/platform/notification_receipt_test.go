package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type notificationLosingGuard struct{ calls int }

func (g *notificationLosingGuard) GuardToolCommit(context.Context, *sql.Tx, capability.ToolReceiptQuery) error {
	g.calls++
	if g.calls == 2 {
		return capability.ErrToolInvocationConflict
	}
	return nil
}

func TestSQLNotificationGuardLossRollsBackOutbox(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	store := notification.NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("notification-guard-%d", time.Now().UnixNano())
	scope := sharedkernel.Scope{TenantID: id, DepartmentID: "department", ApplicationID: "application", AgentID: "validation", AgentInstanceID: "instance", AgentVersionID: "v1", InstallationID: "installation", PrincipalType: "user", PrincipalID: "actor", SessionID: "session", RunID: id, TraceID: "trace"}
	guard := &notificationLosingGuard{}
	adapter := platformNotificationToolAdapter{outbox: store, db: db, guard: guard}
	command := capability.NotificationToolCommand{Scope: scope, CallID: id, Fingerprint: "fingerprint", EventID: id, RecipientID: "recipient", Title: "title", Text: "body"}
	if _, err := adapter.Enqueue(ctx, command); !errors.Is(err, capability.ErrToolInvocationConflict) || guard.calls != 2 {
		t.Fatal("outbox commit guard was not rechecked")
	}
	if _, found, err := store.FindCommittedEvent(ctx, id); err != nil || found {
		t.Fatal("lost lease left a committed outbox event")
	}
}

func TestSQLNotificationCommitReceiptSurvivesReopenAndRejectsTampering(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store := notification.NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("notification-receipt-%d", time.Now().UnixNano())
	scope := sharedkernel.Scope{TenantID: id, DepartmentID: "department", ApplicationID: "application", AgentID: "validation", AgentInstanceID: "instance", AgentVersionID: "v1", InstallationID: "installation", PrincipalType: "user", PrincipalID: "actor", SessionID: "session", RunID: id, TraceID: "trace"}
	fp, err := capability.ToolCommandFingerprint("send_notification", map[string]any{"receiver_id": "recipient", "title": "title", "text": "body"})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(capability.ToolReceiptScopeHash(scope) + "\x00" + id))
	command := capability.NotificationToolCommand{Scope: scope, CallID: id, Fingerprint: fp, EventID: fmt.Sprintf("agent-tool-%x", digest), RecipientID: "recipient", Title: "title", Text: "body"}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if _, err := db.ExecContext(cleanup, sqlutil.Bind(`DELETE FROM platform_notification_outbox WHERE event_id=?`), command.EventID); err != nil {
			t.Error("notification fixture cleanup failed")
		}
	}()
	adapter := platformNotificationToolAdapter{outbox: store}
	if _, err := adapter.Enqueue(ctx, command); err != nil {
		t.Fatal(err)
	}
	// Publishing later must not change the original accepted/not-delivered receipt.
	// 后续消息发布状态不得改写最初的受理回执，受理不等于已送达。
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_notification_outbox SET status='published' WHERE event_id=?`), command.EventID); err != nil {
		t.Fatal(err)
	}
	reopenedDB, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedDB.Close()
	reopened := platformNotificationToolAdapter{outbox: notification.NewSQLStore(reopenedDB)}
	q := capability.ToolReceiptQuery{Scope: scope, CallID: id, Name: "send_notification", Fingerprint: fp}
	result, found, err := reopened.LookupToolReceipt(ctx, q)
	if err != nil || !found || result["delivery_status"] != "pending" || result["delivered"] != false || result["message_id"] != command.EventID {
		t.Fatal("original acceptance receipt not restored")
	}
	var count int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_notification_outbox WHERE event_id=?`), command.EventID).Scan(&count); err != nil || count != 1 {
		t.Fatal("receipt lookup duplicated notification")
	}
	q.Fingerprint = "changed"
	if _, _, err := reopened.LookupToolReceipt(ctx, q); !errors.Is(err, capability.ErrToolInvocationConflict) {
		t.Fatal("changed fingerprint accepted")
	}
	q.Fingerprint = fp
	q.Scope.PrincipalID = "another-user"
	if _, found, err := reopened.LookupToolReceipt(ctx, q); err != nil || found {
		t.Fatal("another user recovered notification")
	}
	q.Scope = scope
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_notification_outbox SET payload_json='{}' WHERE event_id=?`), command.EventID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopened.LookupToolReceipt(ctx, q); !errors.Is(err, capability.ErrToolInvocationConflict) {
		t.Fatal("incomplete persisted scope accepted")
	}
}
