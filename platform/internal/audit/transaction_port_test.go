package audit

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/notification"
)

// A deterministic SQL seam checks transaction wiring, not MySQL durability.
// 此夹具验证事务接线，不冒充真实 MySQL 持久化验收。
type auditDriver struct{}
type auditConn struct{}
type auditTx struct{}
type emptyRows struct{}

func (auditDriver) Open(string) (driver.Conn, error)  { return auditConn{}, nil }
func (auditConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unexpected prepare") }
func (auditConn) Close() error                        { return nil }
func (auditConn) Begin() (driver.Tx, error)           { return auditTx{}, nil }
func (auditTx) Commit() error                         { return nil }
func (auditTx) Rollback() error                       { return nil }
func (emptyRows) Columns() []string                   { return []string{"digest"} }
func (emptyRows) Close() error                        { return nil }
func (emptyRows) Next([]driver.Value) error           { return io.EOF }
func (auditConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(query, "FROM platform_audit_event") {
		return nil, errors.New("foreign table read")
	}
	return emptyRows{}, nil
}
func (auditConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if !strings.HasPrefix(query, "INSERT INTO platform_audit_event") {
		return nil, errors.New("foreign table write")
	}
	return driver.RowsAffected(1), nil
}

type recordingOutbox struct {
	tx    *sql.Tx
	event notification.Event
	err   error
}

func (p *recordingOutbox) EnqueueTx(_ context.Context, tx *sql.Tx, event notification.Event) (notification.Event, error) {
	p.tx, p.event = tx, event
	return event, p.err
}

func init() { sql.Register("audit-port-fixture", auditDriver{}) }

func TestAuditTransactionUsesNotificationPort(t *testing.T) {
	db, err := sql.Open("audit-port-fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	event := Event{ID: "e1", TenantID: "t", DepartmentID: "d", ApplicationID: "a", ActorID: "u", AggregateType: "run", AggregateID: "r", Action: "complete", Outcome: "success", CreatedAt: time.Now().UTC()}
	for _, portErr := range []error{nil, notification.ErrConflict} {
		port := &recordingOutbox{err: portErr}
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		err = NewSQLStoreWithOutbox(db, port).RecordTx(tx, event)
		if !errors.Is(err, portErr) {
			t.Fatalf("error = %v, want %v", err, portErr)
		}
		if port.tx != tx || port.event.ID != "audit-e1" || port.event.TenantID != event.TenantID || port.event.Payload["outcome"] != event.Outcome {
			t.Fatal("transaction or immutable event projection lost")
		}
		if err := port.event.Validate(); err != nil {
			t.Fatal(err)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuditMissingRequiredPortFailsBeforeSQL(t *testing.T) {
	// A non-nil but unusable transaction would panic if any SQL were attempted.
	// 不可用事务用于证明缺失 Port 在任何 SQL 前被拒绝。
	if err := NewSQLStoreWithOutbox(nil, nil).RecordTx(&sql.Tx{}, Event{}); err == nil {
		t.Fatal("missing port accepted")
	}
}
