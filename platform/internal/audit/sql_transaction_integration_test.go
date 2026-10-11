package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sqlutil"
	"net/url"
)

// Only the dedicated disposable fixture database may be used by this test.
// 本测试只允许专用可丢弃夹具数据库，不能使用业务库。
func TestSQLAuditNotificationPortAtomicity(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	config, err := url.Parse(dsn)
	if err != nil || config.Hostname() != "127.0.0.1" || config.Path != "/knowledge_test" {
		t.Fatal("dedicated fixture database required")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	outbox := notification.NewSQLStore(db)
	store := NewSQLStoreWithOutbox(db, outbox)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := outbox.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	event := Event{ID: fmt.Sprintf("audit-port-%d", time.Now().UnixNano()), TenantID: "fixture", DepartmentID: "compliance", ApplicationID: "business-app", ActorID: "operator", AggregateType: "run", AggregateID: "fixture-run", Action: "complete", Outcome: "success", CreatedAt: time.Now().UTC()}
	for i := 0; i < 2; i++ {
		if err := store.Record(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	count := func(table, id string) int {
		t.Helper()
		if table != "platform_audit_event" && table != "platform_notification_outbox" {
			t.Fatal("invalid fixture table")
		}
		var n int
		if err := db.QueryRowContext(ctx, sqlutil.Bind("SELECT COUNT(*) FROM "+table+" WHERE event_id=?"), id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count("platform_audit_event", event.ID) != 1 || count("platform_notification_outbox", "audit-"+event.ID) != 1 {
		t.Fatal("atomic exact replay lost")
	}
	conflict := event
	conflict.ID += "-conflict"
	_, err = outbox.Enqueue(notification.Event{ID: "audit-" + conflict.ID, TenantID: conflict.TenantID, DepartmentID: conflict.DepartmentID, ApplicationID: conflict.ApplicationID, Topic: "platform.audit", EventType: "audit.complete", PartitionKey: conflict.AggregateID, Payload: map[string]any{"outcome": "different"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(ctx, conflict); !errors.Is(err, notification.ErrConflict) {
		t.Fatalf("expected immutable outbox conflict, got %v", err)
	}
	if count("platform_audit_event", conflict.ID) != 0 {
		t.Fatal("audit write committed despite outbox conflict")
	}
	failed := event
	failed.ID += "-failed"
	if err := NewSQLStoreWithOutbox(db, &recordingOutbox{err: notification.ErrClaimLost}).Record(ctx, failed); !errors.Is(err, notification.ErrClaimLost) {
		t.Fatalf("failure not propagated: %v", err)
	}
	if count("platform_audit_event", failed.ID) != 0 {
		t.Fatal("audit write committed despite port failure")
	}
}
