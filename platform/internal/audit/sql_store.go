package audit

// SQL persistence for redacted audit events. Critical callers can use
// RecordTx so the audit row and a notification Outbox row commit atomically.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sqlutil"
)

var (
	ErrNotFound = errors.New("audit event not found")
	ErrConflict = errors.New("audit event conflict")
)

type Page struct {
	MetadataOnly bool    `json:"metadata_only,omitempty"`
	Items        []Event `json:"items"`
	Total        int64   `json:"total"`
	Page         int     `json:"page"`
	PageSize     int     `json:"page_size"`
}

type Store interface {
	EnsureSchema(context.Context) error
	Record(context.Context, Event) error
	List(context.Context, string, string, string, int, int) (Page, error)
}

// FilteredReader is the indexed/query-aware extension used by audit consoles.
// It keeps trace/task matching in SQL instead of loading a page and filtering it
// in memory, while the tenant/department/application predicates remain mandatory.
// FilteredReader 是审计控制台使用的查询扩展；task/trace 在 SQL 中过滤，且组织作用域条件始终必填。
type FilteredReader interface {
	ListFiltered(context.Context, string, string, string, string, string, int, int) (Page, error)
}

// TxRecorder is consumed by business modules that already own a SQL
// transaction. It keeps audit persistence behind a replaceable port while
// preserving the outbox atomicity contract.
type TxRecorder interface {
	RecordTx(*sql.Tx, Event) error
}

type SQLStore struct {
	db         *sql.DB
	withOutbox bool
	outbox     notification.TxEnqueuer
}

func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

func NewSQLStoreWithOutbox(db *sql.DB, outbox notification.TxEnqueuer) *SQLStore {
	return &SQLStore{db: db, withOutbox: true, outbox: outbox}
}

func (s *SQLStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("audit database is required")
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE IF NOT EXISTS platform_audit_event (
		event_id VARCHAR(128) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL,
		department_id VARCHAR(128) NOT NULL, application_id VARCHAR(128) NOT NULL,
		actor_type VARCHAR(32) NOT NULL, actor_id VARCHAR(128) NOT NULL,
		trace_id VARCHAR(255) NOT NULL, aggregate_type VARCHAR(128) NOT NULL,
		aggregate_id VARCHAR(128) NOT NULL, action VARCHAR(128) NOT NULL,
		outcome VARCHAR(32) NOT NULL, summary TEXT NOT NULL, digest VARCHAR(64) NOT NULL,
		created_at TIMESTAMPTZ(6) NOT NULL,
		CONSTRAINT uq_platform_audit_digest UNIQUE (event_id,digest)
	);
CREATE INDEX IF NOT EXISTS idx_platform_audit_scope ON platform_audit_event (tenant_id,department_id,application_id,created_at);`))
	if err != nil {
		return fmt.Errorf("audit schema: %w", err)
	}
	return nil
}

func (s *SQLStore) Record(ctx context.Context, event Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit transaction: %w", err)
	}
	defer tx.Rollback()
	if err := s.RecordTx(tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit transaction: %w", err)
	}
	return nil
}

func (s *SQLStore) RecordTx(tx *sql.Tx, event Event) error {
	// Fail before any write if required atomic notification wiring is missing.
	// 必需的事务通知 Port 缺失时，在任何写入之前拒绝。
	if s == nil || (s.withOutbox && s.outbox == nil) {
		return errors.New("audit notification transaction port is required")
	}
	if tx == nil {
		return errors.New("audit transaction is required")
	}
	if err := event.Validate(); err != nil {
		return err
	}
	digest, err := event.Digest()
	if err != nil {
		return err
	}
	var existingDigest string
	err = tx.QueryRow(sqlutil.Bind(`SELECT digest FROM platform_audit_event WHERE event_id=? FOR UPDATE`), event.ID).Scan(&existingDigest)
	if err == nil {
		if existingDigest != digest {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("lookup audit event: %w", err)
	}
	now := event.CreatedAt.UTC()
	inserted, err := tx.Exec(sqlutil.Bind(`INSERT INTO platform_audit_event(event_id,tenant_id,department_id,application_id,actor_type,actor_id,trace_id,aggregate_type,aggregate_id,action,outcome,summary,digest,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (event_id) DO NOTHING`), event.ID, event.TenantID, event.DepartmentID, event.ApplicationID, event.ActorType, event.ActorID, event.TraceID, event.AggregateType, event.AggregateID, event.Action, event.Outcome, event.Summary, digest, now)
	if err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	count, err := inserted.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		// PostgreSQL has no gap lock for a missing row. ON CONFLICT preserves
		// the transaction, then the next READ COMMITTED statement sees the winner.
		if err := tx.QueryRow(sqlutil.Bind(`SELECT digest FROM platform_audit_event WHERE event_id=? FOR UPDATE`), event.ID).Scan(&existingDigest); err != nil {
			return err
		}
		if existingDigest != digest {
			return ErrConflict
		}
		return nil
	}
	if s.withOutbox {
		_, err = s.outbox.EnqueueTx(context.Background(), tx, notification.Event{
			ID: "audit-" + event.ID, TenantID: event.TenantID,
			DepartmentID: event.DepartmentID, ApplicationID: event.ApplicationID,
			Topic: "platform.audit", EventType: "audit." + event.Action,
			PartitionKey: event.AggregateID, NextAttemptAt: now,
			Payload: map[string]any{"event_id": event.ID, "digest": digest, "action": event.Action, "aggregate_type": event.AggregateType, "aggregate_id": event.AggregateID, "outcome": event.Outcome},
		})
		if err != nil {
			return fmt.Errorf("record audit outbox: %w", err)
		}
	}
	return nil
}

func (s *SQLStore) List(ctx context.Context, tenantID, departmentID, applicationID string, page, pageSize int) (Page, error) {
	return s.list(ctx, tenantID, departmentID, applicationID, "", "", page, pageSize)
}

func (s *SQLStore) ListFiltered(ctx context.Context, tenantID, departmentID, applicationID, taskID, traceID string, page, pageSize int) (Page, error) {
	if strings.TrimSpace(taskID) == "" && strings.TrimSpace(traceID) == "" {
		return Page{}, ErrInvalidEvent
	}
	return s.list(ctx, tenantID, departmentID, applicationID, strings.TrimSpace(taskID), strings.TrimSpace(traceID), page, pageSize)
}

func (s *SQLStore) list(ctx context.Context, tenantID, departmentID, applicationID, taskID, traceID string, page, pageSize int) (Page, error) {
	if tenantID == "" || departmentID == "" || applicationID == "" {
		return Page{}, ErrInvalidEvent
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	where := `tenant_id=? AND department_id=? AND application_id=?`
	args := []any{tenantID, departmentID, applicationID}
	if taskID != "" && traceID != "" {
		where += ` AND (aggregate_id=? OR trace_id=?)`
		args = append(args, taskID, traceID)
	} else if taskID != "" {
		where += ` AND aggregate_id=?`
		args = append(args, taskID)
	} else if traceID != "" {
		where += ` AND trace_id=?`
		args = append(args, traceID)
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event WHERE `+where), args...).Scan(&total); err != nil {
		return Page{}, fmt.Errorf("count audit events: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT event_id,tenant_id,department_id,application_id,actor_type,actor_id,trace_id,aggregate_type,aggregate_id,action,outcome,summary,created_at FROM platform_audit_event WHERE `+where+` ORDER BY created_at DESC,event_id DESC LIMIT ? OFFSET ?`), append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return Page{}, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	items := make([]Event, 0)
	for rows.Next() {
		var item Event
		if err := rows.Scan(&item.ID, &item.TenantID, &item.DepartmentID, &item.ApplicationID, &item.ActorType, &item.ActorID, &item.TraceID, &item.AggregateType, &item.AggregateID, &item.Action, &item.Outcome, &item.Summary, &item.CreatedAt); err != nil {
			return Page{}, fmt.Errorf("scan audit event: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("iterate audit events: %w", err)
	}
	return Page{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

var _ Store = (*SQLStore)(nil)
var _ FilteredReader = (*SQLStore)(nil)
var _ TxRecorder = (*SQLStore)(nil)
