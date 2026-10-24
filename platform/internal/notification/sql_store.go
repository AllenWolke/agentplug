package notification

// SQL-backed outbox persistence for the modular-monolith process.
// 模块化单体进程使用的 SQL Outbox 持久化。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"time"
)

type SQLStore struct {
	db *sql.DB
}

func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

func (s *SQLStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("notification database is required")
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE IF NOT EXISTS platform_notification_outbox (
		event_id VARCHAR(128) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL,
		department_id VARCHAR(128) NOT NULL, application_id VARCHAR(128) NOT NULL,
		topic VARCHAR(255) NOT NULL, event_type VARCHAR(128) NOT NULL,
		partition_key VARCHAR(255) NOT NULL, payload_json TEXT NOT NULL,
		status VARCHAR(32) NOT NULL, attempts INT NOT NULL DEFAULT 0,
		next_attempt_at TIMESTAMPTZ(6) NOT NULL, claim_owner VARCHAR(128) NOT NULL DEFAULT '',
		claim_until TIMESTAMPTZ(6) NULL);
CREATE INDEX IF NOT EXISTS idx_platform_notification_ready ON platform_notification_outbox (status,next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_notification_active_ready ON platform_notification_outbox (next_attempt_at,event_id)
 WHERE status IN ('pending','failed','publishing');`))
	if err != nil {
		return fmt.Errorf("notification schema: %w", err)
	}
	_, err = s.db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE IF NOT EXISTS platform_notification_delivery (
		event_id VARCHAR(128) PRIMARY KEY, status VARCHAR(32) NOT NULL,
		attempts INT NOT NULL DEFAULT 0, claim_owner VARCHAR(128) NOT NULL DEFAULT '',
		claim_until TIMESTAMPTZ(6) NULL, last_error VARCHAR(1024) NOT NULL DEFAULT '',
		delivered_at TIMESTAMPTZ(6) NULL);
CREATE INDEX IF NOT EXISTS idx_platform_notification_delivery_claim ON platform_notification_delivery (status,claim_until);`))
	if err != nil {
		return fmt.Errorf("notification delivery schema: %w", err)
	}
	return nil
}

func (s *SQLStore) Enqueue(event Event) (Event, error) {
	if s == nil || s.db == nil {
		return Event{}, errors.New("notification database is required")
	}
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	if event.Status == "" {
		event.Status = Pending
	}
	if event.NextAttemptAt.IsZero() {
		event.NextAttemptAt = time.Now().UTC()
	}
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		return Event{}, err
	}
	// Treat an existing event id as an immutable idempotency key.  A retry of
	// the same event returns the stored record, while reusing the id for a
	// different payload is rejected instead of being silently accepted.
	// 将 event id 视为不可变幂等键：相同事件重试返回已存记录，复用 id
	// 但内容不同则拒绝，避免数据库的重复键语义静默吞掉冲突。
	if existing, lookupErr := s.get(event.ID); lookupErr == nil {
		if sameEvent(existing, event, payload) {
			return existing, nil
		}
		return Event{}, ErrConflict
	} else if !errors.Is(lookupErr, sql.ErrNoRows) {
		return Event{}, fmt.Errorf("lookup notification event: %w", lookupErr)
	}
	_, err = s.db.Exec(sqlutil.Bind(`INSERT INTO platform_notification_outbox(event_id,tenant_id,department_id,application_id,topic,event_type,partition_key,payload_json,status,attempts,next_attempt_at,claim_owner,claim_until) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`), event.ID, event.TenantID, event.DepartmentID, event.ApplicationID, event.Topic, event.EventType, event.PartitionKey, payload, event.Status, event.Attempts, event.NextAttemptAt, event.ClaimOwner, nullTime(event.ClaimUntil))
	if err != nil {
		// Another writer may have won the race between the lookup and insert.
		// Re-read and apply the same immutable comparison so concurrent retries
		// have deterministic idempotency semantics.
		if existing, lookupErr := s.get(event.ID); lookupErr == nil {
			if sameEvent(existing, event, payload) {
				return existing, nil
			}
			return Event{}, ErrConflict
		}
		return Event{}, fmt.Errorf("enqueue notification: %w", err)
	}
	return event, nil
}

// EnqueueTx writes an event into a caller-owned transaction. Critical domain
// changes can therefore commit atomically with their outbox event.
// EnqueueTx 将事件写入调用方持有的事务，使关键领域状态与 Outbox 事件原子提交。
func (s *SQLStore) EnqueueTx(ctx context.Context, tx *sql.Tx, event Event) (Event, error) {
	if s == nil || s.db == nil {
		return Event{}, errors.New("notification database is required")
	}
	if tx == nil {
		return Event{}, errors.New("notification transaction is required")
	}
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	if event.Status == "" {
		event.Status = Pending
	}
	if event.NextAttemptAt.IsZero() {
		event.NextAttemptAt = time.Now().UTC()
	}
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		return Event{}, err
	}
	if existing, lookupErr := getEventTx(ctx, tx, event.ID, false); lookupErr == nil {
		if sameEvent(existing, event, payload) {
			return existing, nil
		}
		return Event{}, ErrConflict
	} else if !errors.Is(lookupErr, sql.ErrNoRows) {
		return Event{}, fmt.Errorf("lookup notification event in transaction: %w", lookupErr)
	}
	inserted, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_notification_outbox(event_id,tenant_id,department_id,application_id,topic,event_type,partition_key,payload_json,status,attempts,next_attempt_at,claim_owner,claim_until) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (event_id) DO NOTHING`), event.ID, event.TenantID, event.DepartmentID, event.ApplicationID, event.Topic, event.EventType, event.PartitionKey, payload, event.Status, event.Attempts, event.NextAttemptAt, event.ClaimOwner, nullTime(event.ClaimUntil))
	if err != nil {
		return Event{}, fmt.Errorf("enqueue notification in transaction: %w", err)
	}
	count, err := inserted.RowsAffected()
	if err != nil {
		return Event{}, err
	}
	if count == 0 {
		existing, err := getEventTx(ctx, tx, event.ID, true)
		if err != nil {
			return Event{}, err
		}
		if !sameEvent(existing, event, payload) {
			return Event{}, ErrConflict
		}
		return existing, nil
	}
	return event, nil
}

func sameEvent(existing, incoming Event, incomingPayload []byte) bool {
	if existing.TenantID != incoming.TenantID ||
		existing.DepartmentID != incoming.DepartmentID ||
		existing.ApplicationID != incoming.ApplicationID ||
		existing.Topic != incoming.Topic ||
		existing.EventType != incoming.EventType ||
		existing.PartitionKey != incoming.PartitionKey {
		return false
	}
	storedPayload, err := json.Marshal(existing.Payload)
	return err == nil && string(storedPayload) == string(incomingPayload)
}

func (s *SQLStore) Claim(owner string, limit int, now time.Time, lease time.Duration) ([]Event, error) {
	if owner == "" || limit <= 0 || lease <= 0 {
		return nil, ErrInvalidEvent
	}
	// Fixed protocol states make the active partial index usable even with a
	// generic prepared plan; eligibility and the subsequent per-event CAS stay
	// identical to ClaimID. Published history is never part of this read.
	rows, err := s.db.Query(sqlutil.Bind(`SELECT event_id,tenant_id,department_id,application_id,topic,event_type,partition_key,payload_json,status,attempts,next_attempt_at,claim_owner,claim_until FROM platform_notification_outbox WHERE next_attempt_at<=? AND status IN ('pending','failed','publishing') AND (status IN ('pending','failed') OR (status='publishing' AND claim_until<=?)) ORDER BY next_attempt_at,event_id LIMIT ?`), now, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	selected := make([]Event, 0, limit)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		selected = append(selected, event)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	// Release the SELECT connection before per-event CAS writes. With a one-
	// connection pool, invoking ClaimID while rows remain open deadlocks.
	if err = rows.Close(); err != nil {
		return nil, err
	}
	result := make([]Event, 0, len(selected))
	for _, event := range selected {
		claimed, err := s.ClaimID(event.ID, owner, now, lease)
		if err != nil {
			continue
		}
		result = append(result, claimed)
	}
	return result, nil
}

func (s *SQLStore) ClaimID(id, owner string, now time.Time, lease time.Duration) (Event, error) {
	if id == "" || owner == "" || lease <= 0 {
		return Event{}, ErrInvalidEvent
	}
	until := now.Add(lease)
	result, err := s.db.Exec(sqlutil.Bind(`UPDATE platform_notification_outbox SET status=?,claim_owner=?,claim_until=? WHERE event_id=? AND next_attempt_at<=? AND (status=? OR status=? OR (status=? AND claim_until<=?))`), Publishing, owner, until, id, now, Pending, Failed, Publishing, now)
	if err != nil {
		return Event{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return Event{}, ErrClaimLost
	}
	return s.get(id)
}

func (s *SQLStore) MarkPublished(id, owner string) error {
	result, err := s.db.Exec(sqlutil.Bind(`UPDATE platform_notification_outbox SET status=?,claim_owner='',claim_until=NULL WHERE event_id=? AND status=? AND claim_owner=?`), Published, id, Publishing, owner)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrClaimLost
	}
	return nil
}

func (s *SQLStore) MarkFailed(id, owner string, now time.Time, maxAttempts int) error {
	if maxAttempts < 1 {
		return ErrInvalidEvent
	}
	event, err := s.get(id)
	if err != nil {
		return err
	}
	if event.Status != Publishing || event.ClaimOwner != owner {
		return ErrClaimLost
	}
	next := Pending
	if event.Attempts+1 >= maxAttempts {
		next = Dead
	} else {
		next = Failed
	}
	result, err := s.db.Exec(sqlutil.Bind(`UPDATE platform_notification_outbox SET status=?,attempts=attempts+1,next_attempt_at=?,claim_owner='',claim_until=NULL WHERE event_id=? AND status=? AND claim_owner=?`), next, now.Add(time.Duration(event.Attempts+1)*time.Second), id, Publishing, owner)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrClaimLost
	}
	return nil
}

func (s *SQLStore) ClaimDelivery(event Event, owner string, now time.Time, lease time.Duration) (DeliveryClaim, error) {
	if s == nil || s.db == nil || event.ID == "" || owner == "" || lease <= 0 {
		return DeliveryClaim{}, ErrInvalidEvent
	}
	tx, err := s.db.Begin()
	if err != nil {
		return DeliveryClaim{}, err
	}
	defer tx.Rollback()
	var status string
	var attempts int
	var claimOwner string
	var claimUntil sql.NullTime
	rowErr := tx.QueryRow(sqlutil.Bind(`SELECT status,attempts,claim_owner,claim_until FROM platform_notification_delivery WHERE event_id=? FOR UPDATE`), event.ID).Scan(&status, &attempts, &claimOwner, &claimUntil)
	if errors.Is(rowErr, sql.ErrNoRows) {
		inserted, err := tx.Exec(sqlutil.Bind(`INSERT INTO platform_notification_delivery(event_id,status,attempts,claim_owner,claim_until,last_error) VALUES(?,?,?,?,?,?) ON CONFLICT (event_id) DO NOTHING`), event.ID, Publishing, 1, owner, now.Add(lease), "")
		if err != nil {
			return DeliveryClaim{}, err
		}
		count, err := inserted.RowsAffected()
		if err != nil {
			return DeliveryClaim{}, err
		}
		if count == 0 {
			return DeliveryClaim{}, ErrDeliveryInProgress
		}
		if err = tx.Commit(); err != nil {
			return DeliveryClaim{}, err
		}
		return DeliveryClaim{Acquired: true, Attempt: 1}, nil
	}
	if rowErr != nil {
		return DeliveryClaim{}, rowErr
	}
	if status == string(Dead) {
		return DeliveryClaim{Attempt: attempts}, ErrEventDeliveryDeadLetter
	}
	if status == string(Published) {
		if err = tx.Commit(); err != nil {
			return DeliveryClaim{}, err
		}
		return DeliveryClaim{Delivered: true, Attempt: attempts}, nil
	}
	if status == string(Publishing) && claimUntil.Valid && claimUntil.Time.After(now) {
		return DeliveryClaim{}, ErrDeliveryInProgress
	}
	attempts++
	if _, err = tx.Exec(sqlutil.Bind(`UPDATE platform_notification_delivery SET status=?,attempts=?,claim_owner=?,claim_until=?,last_error='' WHERE event_id=?`), Publishing, attempts, owner, now.Add(lease), event.ID); err != nil {
		return DeliveryClaim{}, err
	}
	if err = tx.Commit(); err != nil {
		return DeliveryClaim{}, err
	}
	return DeliveryClaim{Acquired: true, Attempt: attempts}, nil
}

func (s *SQLStore) MarkDeliverySucceeded(id, owner string) error {
	result, err := s.db.Exec(sqlutil.Bind(`UPDATE platform_notification_delivery SET status=?,claim_owner='',claim_until=NULL,delivered_at=? WHERE event_id=? AND status=? AND claim_owner=?`), Published, time.Now().UTC(), id, Publishing, owner)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrClaimLost
	}
	return nil
}

func (s *SQLStore) MarkDeliveryFailed(id, owner string, now time.Time, maxAttempts int, deliveryErr error) error {
	if maxAttempts < 1 {
		return ErrInvalidEvent
	}
	var attempts int
	if err := s.db.QueryRow(sqlutil.Bind(`SELECT attempts FROM platform_notification_delivery WHERE event_id=? AND status=? AND claim_owner=?`), id, Publishing, owner).Scan(&attempts); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrClaimLost
		}
		return err
	}
	status := Failed
	if attempts >= maxAttempts {
		status = Dead
	}
	result, err := s.db.Exec(sqlutil.Bind(`UPDATE platform_notification_delivery SET status=?,claim_owner='',claim_until=NULL,last_error=? WHERE event_id=? AND status=? AND claim_owner=?`), status, truncateKafkaError(deliveryErr), id, Publishing, owner)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrClaimLost
	}
	return nil
}

func (s *SQLStore) get(id string) (Event, error) {
	row := s.db.QueryRow(sqlutil.Bind(`SELECT event_id,tenant_id,department_id,application_id,topic,event_type,partition_key,payload_json,status,attempts,next_attempt_at,claim_owner,claim_until FROM platform_notification_outbox WHERE event_id=?`), id)
	return scanEvent(row)
}

func getEventTx(ctx context.Context, tx *sql.Tx, id string, lock bool) (Event, error) {
	query := `SELECT event_id,tenant_id,department_id,application_id,topic,event_type,partition_key,payload_json,status,attempts,next_attempt_at,claim_owner,claim_until FROM platform_notification_outbox WHERE event_id=?`
	if lock {
		query += ` FOR UPDATE`
	}
	row := tx.QueryRowContext(ctx, sqlutil.Bind(query), id)
	return scanEvent(row)
}

type rowScanner interface{ Scan(...any) error }

func scanEvent(row rowScanner) (Event, error) {
	var event Event
	var payload string
	var claimUntil sql.NullTime
	if err := row.Scan(&event.ID, &event.TenantID, &event.DepartmentID, &event.ApplicationID, &event.Topic, &event.EventType, &event.PartitionKey, &payload, &event.Status, &event.Attempts, &event.NextAttemptAt, &event.ClaimOwner, &claimUntil); err != nil {
		return Event{}, err
	}
	if err := json.Unmarshal([]byte(payload), &event.Payload); err != nil {
		return Event{}, fmt.Errorf("decode notification payload: %w", err)
	}
	if claimUntil.Valid {
		event.ClaimUntil = claimUntil.Time
	}
	return event, nil
}

func nullTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

var _ EventStore = (*SQLStore)(nil)
var _ DeliveryStore = (*SQLStore)(nil)
