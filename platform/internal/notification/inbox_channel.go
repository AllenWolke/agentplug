package notification

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/internal/sharedkernel"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

const InboxChannelVersion = "sql-inbox.v1"
const ReversalSchemaVersion uint64 = 2026100903
const inboxDDL = `
CREATE TABLE IF NOT EXISTS platform_notification_control_version(version BIGINT PRIMARY KEY,checksum VARCHAR(64) NOT NULL,applied_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS platform_notification_inbox (
 event_id VARCHAR(128) PRIMARY KEY,
 binding_json JSONB NOT NULL,
 binding_digest VARCHAR(64) NOT NULL,
 state VARCHAR(32) NOT NULL CHECK(state IN ('delivered','withdrawn','corrected','tombstoned')),
 original_payload JSONB NULL,
 correction_text TEXT NOT NULL DEFAULT '',
 reversal_key VARCHAR(64) NOT NULL DEFAULT '',
 reversal_receipt JSONB NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
CREATE INDEX IF NOT EXISTS idx_notification_inbox_recipient ON platform_notification_inbox((binding_json->>'recipient_digest'),created_at,event_id);
`

func ApplyReversalSchema(ctx context.Context, db *sql.DB) error {
	if ctx == nil || db == nil {
		return ErrInvalidEvent
	}
	if _, err := db.ExecContext(ctx, `SELECT pg_advisory_xact_lock(2026100903,16)`); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, inboxDDL); err != nil {
		return err
	}
	h := sha256.Sum256([]byte(inboxDDL))
	sum := hex.EncodeToString(h[:])
	var saved string
	err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT checksum FROM platform_notification_control_version WHERE version=?`), ReversalSchemaVersion).Scan(&saved)
	if err == nil && saved != sum {
		return ErrConflict
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		_, err = db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_notification_control_version VALUES(?,?,clock_timestamp())`), ReversalSchemaVersion, sum)
	}
	if err != nil {
		return err
	}
	for table, privileges := range map[string]string{"platform_notification_control_version": "INSERT,UPDATE,DELETE", "platform_notification_inbox": "DELETE"} {
		rows, err := db.QueryContext(ctx, sqlutil.Bind(`SELECT DISTINCT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid=to_regclass(?) AND a.grantee<>c.relowner AND a.privilege_type=ANY(string_to_array(?,','))`), "public."+table, privileges)
		if err != nil {
			return err
		}
		var roles []string
		for rows.Next() {
			var role string
			if err = rows.Scan(&role); err != nil {
				rows.Close()
				return err
			}
			roles = append(roles, role)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, role := range roles {
			name := pgx.Identifier{role}.Sanitize()
			if role == "PUBLIC" {
				name = "PUBLIC"
			}
			if _, err = db.ExecContext(ctx, "REVOKE "+privileges+" ON "+pgx.Identifier{"public", table}.Sanitize()+" FROM "+name); err != nil {
				return err
			}
		}
	}
	return nil
}

type InboxRevocationGuard func(context.Context, *sql.Tx, ReversalRequest) error

// SQLInboxChannel is an actual controlled channel: Send makes a private inbox
// record visible, withdrawal removes it from the visible feed, and correction
// attaches a fixed cancellation notice to the original recipient's message.
// It retains the original private evidence rather than deleting audit history.
type SQLInboxChannel struct {
	db    *sql.DB
	guard InboxRevocationGuard
}

func NewSQLInboxChannel(ctx context.Context, db *sql.DB, guard InboxRevocationGuard) (*SQLInboxChannel, error) {
	if ctx == nil || db == nil || guard == nil {
		return nil, ErrAdapterUnavailable
	}
	var saved string
	h := sha256.Sum256([]byte(inboxDDL))
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT checksum FROM platform_notification_control_version WHERE version=?`), ReversalSchemaVersion).Scan(&saved); err != nil {
		return nil, ErrAdapterUnavailable
	}
	if saved != hex.EncodeToString(h[:]) {
		return nil, ErrConflict
	}
	return &SQLInboxChannel{db: db, guard: guard}, nil
}

func inboxLock(ctx context.Context, tx *sql.Tx, id string) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,30916))`, id)
	return err
}

func (s *SQLInboxChannel) Send(ctx context.Context, event Event) error {
	if s == nil || ctx == nil || event.ValidateForDelivery() != nil {
		return ErrInvalidEvent
	}
	binding, err := AgentReversalBinding(event)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = inboxLock(ctx, tx, event.ID); err != nil {
		return err
	}
	var savedDigest, state string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT binding_digest,state FROM platform_notification_inbox WHERE event_id=? FOR UPDATE`), event.ID).Scan(&savedDigest, &state)
	if err == nil {
		if savedDigest != reversalDigest(binding) {
			return ErrConflict
		}
		// A delayed/replayed forward delivery cannot resurrect a withdrawn or
		// never-delivered tombstone, nor remove a confirmed correction.
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	rawBinding, _ := json.Marshal(binding)
	payload, err := json.Marshal(event.Payload)
	if err != nil || len(payload) > 256<<10 {
		return ErrInvalidEvent
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_notification_inbox(event_id,binding_json,binding_digest,state,original_payload) VALUES(?,?::jsonb,?,'delivered',?::jsonb)`), event.ID, string(rawBinding), reversalDigest(binding), string(payload))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLInboxChannel) LookupReversal(ctx context.Context, request ReversalRequest) (ReversalReceipt, bool, error) {
	if s == nil || ctx == nil || request.Validate() != nil {
		return ReversalReceipt{}, false, ErrInvalidEvent
	}
	var savedDigest string
	var raw []byte
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT binding_digest,reversal_receipt FROM platform_notification_inbox WHERE event_id=?`), request.Binding.EventID).Scan(&savedDigest, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ReversalReceipt{}, false, nil
	}
	if err != nil {
		return ReversalReceipt{}, false, err
	}
	if savedDigest != reversalDigest(request.Binding) {
		return ReversalReceipt{}, false, ErrConflict
	}
	if len(raw) == 0 {
		return ReversalReceipt{}, false, nil
	}
	var receipt ReversalReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.Validate(request) != nil {
		return ReversalReceipt{}, false, ErrReversalUnconfirmed
	}
	return receipt, true, nil
}

func (s *SQLInboxChannel) Revoke(ctx context.Context, request ReversalRequest) (ReversalReceipt, error) {
	if s == nil || ctx == nil || request.Validate() != nil {
		return ReversalReceipt{}, ErrInvalidEvent
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ReversalReceipt{}, err
	}
	defer tx.Rollback()
	// The composition supplies the current exact compensation lease fence in
	// this same transaction. No browser can select a message/recipient to undo.
	if err = s.guard(ctx, tx, request); err != nil {
		return ReversalReceipt{}, err
	}
	if err = inboxLock(ctx, tx, request.Binding.EventID); err != nil {
		return ReversalReceipt{}, err
	}
	var savedDigest, state string
	var raw []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT binding_digest,state,reversal_receipt FROM platform_notification_inbox WHERE event_id=? FOR UPDATE`), request.Binding.EventID).Scan(&savedDigest, &state, &raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ReversalReceipt{}, err
	}
	if err == nil && savedDigest != reversalDigest(request.Binding) {
		return ReversalReceipt{}, ErrConflict
	}
	if len(raw) > 0 {
		var existing ReversalReceipt
		if json.Unmarshal(raw, &existing) != nil || existing.Validate(request) != nil {
			return ReversalReceipt{}, ErrConflict
		}
		return existing, tx.Commit()
	}
	disposition, newState, correction := "no_effect", "tombstoned", ""
	if state != "" {
		if state != "delivered" {
			return ReversalReceipt{}, ErrConflict
		}
		if request.Action == "withdraw" {
			disposition, newState = "withdrawn", "withdrawn"
		} else {
			disposition, newState, correction = "corrected", "corrected", "此通知由已取消的执行产生，请以当前业务记录为准。"
		}
	}
	receipt := ReversalReceipt{Version: "notification-reversal-receipt/v1", Binding: request.Binding, Key: request.Key, Action: request.Action, Disposition: disposition, ForwardClosed: true, EvidenceDigest: reversalDigest([]any{InboxChannelVersion, request, newState})}
	rawReceipt, _ := json.Marshal(receipt)
	rawBinding, _ := json.Marshal(request.Binding)
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_notification_inbox(event_id,binding_json,binding_digest,state,correction_text,reversal_key,reversal_receipt) VALUES(?,?::jsonb,?,?,?,?,?::jsonb)
ON CONFLICT(event_id) DO UPDATE SET state=EXCLUDED.state,correction_text=EXCLUDED.correction_text,reversal_key=EXCLUDED.reversal_key,reversal_receipt=EXCLUDED.reversal_receipt,updated_at=clock_timestamp()`), request.Binding.EventID, string(rawBinding), reversalDigest(request.Binding), newState, correction, request.Key, string(rawReceipt))
	if err != nil {
		return ReversalReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return ReversalReceipt{}, err
	}
	return receipt, nil
}

var _ RevocableChannel = (*SQLInboxChannel)(nil)

type InboxMessage struct {
	EventID    string    `json:"event_id"`
	Title      string    `json:"title"`
	Text       string    `json:"text"`
	Correction string    `json:"correction,omitempty"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
}

// Reader authority comes from the authenticated gateway/IAM composition, not
// a caller-selected recipient. Withdrawn and tombstoned messages are absent
// from the visible feed; corrected messages retain the same original ID.
func (s *SQLInboxChannel) ReadRecipientInbox(ctx context.Context, scope sharedkernel.Scope, limit int, authorize func(context.Context, *sql.Tx, sharedkernel.Scope) error) ([]InboxMessage, error) {
	if s == nil || ctx == nil || scope.Validate() != nil || scope.PrincipalType != "user" || authorize == nil || limit < 1 || limit > 100 {
		return nil, ErrInvalidEvent
	}
	// The feed is logically read-only, but current IAM continuity takes row
	// locks. PostgreSQL rejects those in a READ ONLY transaction.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = authorize(ctx, tx, scope); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT event_id,original_payload,correction_text,state,created_at FROM platform_notification_inbox
WHERE binding_json->>'tenant_id'=? AND binding_json->>'department_id'=? AND binding_json->>'application_id'=? AND binding_json->>'recipient_digest'=? AND state IN ('delivered','corrected') ORDER BY created_at DESC,event_id DESC LIMIT ?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, reversalDigest([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalID}), limit)
	if err != nil {
		return nil, err
	}
	result := []InboxMessage{}
	for rows.Next() {
		var message InboxMessage
		var raw []byte
		var payload map[string]any
		if err = rows.Scan(&message.EventID, &raw, &message.Correction, &message.State, &message.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		if json.Unmarshal(raw, &payload) != nil {
			rows.Close()
			return nil, ErrConflict
		}
		message.Title, _ = payload["title"].(string)
		message.Text, _ = payload["text"].(string)
		result = append(result, message)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return result, tx.Commit()
}
