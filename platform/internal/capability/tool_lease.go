package capability

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
	"time"
)

// Lease generations fence old HTTP workers without relying on process locks.
// 租约代际隔离旧HTTP执行者，不依赖单进程锁实现并发安全。
// Fence is ordered only within ScopeHash+CallID. Owner/Token identify this
// attempt; neither belongs in the stable remote ToolOperationIdentity.
type ToolExecutionLease struct {
	ScopeHash   string
	CallID      string
	Fingerprint string
	Owner       string
	Token       string
	Fence       uint64
	Until       time.Time
}

type toolLeaseContextKey struct{}

type toolReceiptContextKey struct{}

func receiptQueryFromContext(ctx context.Context, scope, id, fp string) (*ToolReceiptQuery, error) {
	q, ok := ctx.Value(toolReceiptContextKey{}).(ToolReceiptQuery)
	if !ok {
		return nil, nil
	} // Direct low-level fixtures do not submit business commands.
	if q.CallID != id || q.Fingerprint != fp || q.Name == "" || ToolReceiptScopeHash(q.Scope) != scope {
		return nil, ErrToolInvocationConflict
	}
	if q.RemoteContract != nil {
		if q.RemoteContract.Validate() != nil {
			return nil, ErrToolInvocationConflict
		}
		contract := *q.RemoteContract
		q.RemoteContract = &contract
	}
	return &q, nil
}

type ToolExecutionLeaseStore interface {
	AcquireTool(context.Context, string, string, string, string, time.Duration) (ToolInvocation, bool, error)
	BeginTool(context.Context, ToolExecutionLease) error
	FinishTool(context.Context, ToolExecutionLease, map[string]any) error
	RejectTool(context.Context, ToolExecutionLease) error
	UnknownTool(context.Context, ToolExecutionLease) error
}

func newToolLease(scope, id, fp, owner string, ttl time.Duration) (ToolExecutionLease, error) {
	if scope == "" || id == "" || len(id) > 255 || fp == "" || strings.TrimSpace(owner) == "" || len(owner) > 64 || ttl < time.Second || ttl > 10*time.Minute {
		return ToolExecutionLease{}, errors.New("invalid tool lease")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ToolExecutionLease{}, err
	}
	return ToolExecutionLease{ScopeHash: scope, CallID: id, Fingerprint: fp, Owner: owner, Token: hex.EncodeToString(nonce[:]), Fence: 1, Until: time.Now().UTC().Add(ttl)}, nil
}

func (s *memoryToolInvocationStore) AcquireTool(ctx context.Context, scope, id, fp, owner string, ttl time.Duration) (ToolInvocation, bool, error) {
	q, err := receiptQueryFromContext(ctx, scope, id, fp)
	if err != nil {
		return ToolInvocation{}, false, err
	}
	lease, err := newToolLease(scope, id, fp, owner, ttl)
	if err != nil {
		return ToolInvocation{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scope + "\x00" + id
	if old, ok := s.records[key]; ok {
		if old.Fingerprint != fp {
			return ToolInvocation{}, false, ErrToolInvocationConflict
		}
		if old.Status == "completed" {
			return cloneToolInvocation(old), true, nil
		}
		if old.Status == "unknown" {
			return ToolInvocation{}, false, ErrToolResultUnknown
		}
		if old.Status == "running" && old.Lease.Token != "" && !old.Lease.Until.After(time.Now()) {
			if old.Phase != "preparing" {
				old.Status = "unknown"
				s.records[key] = old
				return ToolInvocation{}, false, ErrToolResultUnknown
			}
		} else if old.Status != "failed" {
			return ToolInvocation{}, false, ErrToolInvocationPending
		}
		lease.Fence = old.Lease.Fence + 1
	}
	r := ToolInvocation{ScopeHash: scope, CallID: id, Fingerprint: fp, Status: "running", Phase: "preparing", Lease: lease, ReceiptQuery: q}
	s.records[key] = r
	return cloneToolInvocation(r), false, nil
}

func validToolOwner(r ToolInvocation, l ToolExecutionLease, allowExpired bool) bool {
	return r.ScopeHash == l.ScopeHash && r.CallID == l.CallID && r.Fingerprint == l.Fingerprint && r.Lease.Owner == l.Owner && r.Lease.Token == l.Token && l.Token != "" && r.Lease.Fence == l.Fence && (allowExpired || r.Lease.Until.After(time.Now()))
}

func (s *memoryToolInvocationStore) transitionTool(l ToolExecutionLease, phase, status string, result map[string]any, expired bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := l.ScopeHash + "\x00" + l.CallID
	r, ok := s.records[key]
	if !ok || r.Status != "running" || !validToolOwner(r, l, expired) || phase != "" && r.Phase != phase {
		return ErrToolInvocationConflict
	}
	if status == "executing" {
		r.Phase = "executing"
	} else {
		r.Status = status
		r.Result = cloneToolResult(result)
	}
	s.records[key] = r
	return nil
}
func (s *memoryToolInvocationStore) BeginTool(_ context.Context, l ToolExecutionLease) error {
	return s.transitionTool(l, "preparing", "executing", nil, false)
}
func (s *memoryToolInvocationStore) FinishTool(_ context.Context, l ToolExecutionLease, r map[string]any) error {
	if r == nil {
		return errors.New("empty tool result")
	}
	return s.transitionTool(l, "executing", "completed", r, false)
}
func (s *memoryToolInvocationStore) RejectTool(_ context.Context, l ToolExecutionLease) error {
	return s.transitionTool(l, "", "failed", nil, false)
}
func (s *memoryToolInvocationStore) UnknownTool(_ context.Context, l ToolExecutionLease) error {
	return s.transitionTool(l, "", "unknown", nil, true)
}

func (s *SQLToolInvocationStore) AcquireTool(ctx context.Context, scope, id, fp, owner string, ttl time.Duration) (ToolInvocation, bool, error) {
	q, queryErr := receiptQueryFromContext(ctx, scope, id, fp)
	if queryErr != nil {
		return ToolInvocation{}, false, queryErr
	}
	queryJSON, queryErr := json.Marshal(q)
	if queryErr != nil {
		return ToolInvocation{}, false, queryErr
	}
	l, err := newToolLease(scope, id, fp, owner, ttl)
	if err != nil {
		return ToolInvocation{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ToolInvocation{}, false, err
	}
	defer tx.Rollback()
	// Serialize legacy and leased first requests for the same scoped call.
	if err := lockLedgerScope(ctx, tx, "tool-invocation", scope+"\x00"+id); err != nil {
		return ToolInvocation{}, false, err
	}
	// The unique key and following row lock resolve a committed winner.
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_tool_invocation(scope_hash,call_id,fingerprint,status,phase,lease_owner,lease_token,lease_fence,lease_until,recovery_query,created_at,updated_at) VALUES(?,?,?,'running','preparing',?,?,1,(clock_timestamp() + ?::bigint * INTERVAL '1 microsecond'),?,clock_timestamp(),clock_timestamp()) ON CONFLICT (scope_hash,call_id) DO NOTHING`), scope, id, fp, owner, l.Token, ttl.Microseconds(), nullableJSON(queryJSON))
	if err != nil {
		return ToolInvocation{}, false, err
	}
	r := ToolInvocation{ScopeHash: scope, CallID: id}
	var raw sql.NullString
	var until sql.NullTime
	var expired bool
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT fingerprint,status,result_json,phase,lease_owner,lease_token,lease_fence,lease_until,COALESCE(lease_until<=clock_timestamp(),FALSE) FROM platform_tool_invocation WHERE scope_hash=? AND call_id=? FOR UPDATE`), scope, id).Scan(&r.Fingerprint, &r.Status, &raw, &r.Phase, &r.Lease.Owner, &r.Lease.Token, &r.Lease.Fence, &until, &expired)
	if err != nil {
		return ToolInvocation{}, false, err
	}
	if r.Fingerprint != fp {
		return ToolInvocation{}, false, ErrToolInvocationConflict
	}
	r.Lease.ScopeHash, r.Lease.CallID, r.Lease.Fingerprint = scope, id, fp
	if until.Valid {
		r.Lease.Until = until.Time
	}
	if r.Status == "completed" {
		if !raw.Valid || decodeToolStoredResult([]byte(raw.String), &r.Result) != nil {
			return ToolInvocation{}, false, errors.New("corrupt tool receipt")
		}
		return r, true, tx.Commit()
	}
	if r.Status == "unknown" {
		return ToolInvocation{}, false, ErrToolResultUnknown
	}
	if r.Lease.Token == l.Token {
		return r, false, tx.Commit()
	}
	if r.Status == "running" && r.Lease.Token != "" && expired {
		if r.Phase != "preparing" {
			if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET status='unknown',updated_at=clock_timestamp() WHERE scope_hash=? AND call_id=?`), scope, id); err != nil {
				return ToolInvocation{}, false, err
			}
			if err := tx.Commit(); err != nil {
				return ToolInvocation{}, false, err
			}
			return ToolInvocation{}, false, ErrToolResultUnknown
		}
	} else if r.Status != "failed" {
		return ToolInvocation{}, false, ErrToolInvocationPending
	}
	if r.Lease.Fence == ^uint64(0) {
		return ToolInvocation{}, false, ErrToolInvocationConflict
	}
	l.Fence = r.Lease.Fence + 1
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET status='running',phase='preparing',result_json=NULL,lease_owner=?,lease_token=?,lease_fence=?,lease_until=(clock_timestamp() + ?::bigint * INTERVAL '1 microsecond'),recovery_query=?,retry_after=NULL,updated_at=clock_timestamp() WHERE scope_hash=? AND call_id=? AND fingerprint=?`), owner, l.Token, l.Fence, ttl.Microseconds(), nullableJSON(queryJSON), scope, id, fp)
	if err != nil {
		return ToolInvocation{}, false, err
	}
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT lease_until FROM platform_tool_invocation WHERE scope_hash=? AND call_id=?`), scope, id).Scan(&l.Until); err != nil {
		return ToolInvocation{}, false, err
	}
	r.Status, r.Phase, r.Lease = "running", "preparing", l
	return r, false, tx.Commit()
}

func (s *SQLToolInvocationStore) transitionTool(ctx context.Context, l ToolExecutionLease, phase, status string, result map[string]any, expired bool) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	query := `UPDATE platform_tool_invocation SET status=?,result_json=?,updated_at=clock_timestamp() WHERE scope_hash=? AND call_id=? AND fingerprint=? AND lease_owner=? AND lease_token=? AND lease_fence=? AND status='running'`
	args := []any{status, nullableJSON(raw), l.ScopeHash, l.CallID, l.Fingerprint, l.Owner, l.Token, l.Fence}
	if status == "executing" {
		query = `UPDATE platform_tool_invocation SET phase='executing',updated_at=clock_timestamp() WHERE scope_hash=? AND call_id=? AND fingerprint=? AND lease_owner=? AND lease_token=? AND lease_fence=? AND status='running'`
		args = args[2:]
	}
	if !expired {
		query += ` AND lease_until>clock_timestamp()`
	}
	if phase != "" {
		query += ` AND phase=?`
		args = append(args, phase)
	}
	if l.Token == "" {
		return ErrToolInvocationConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if status == "executing" && s.admitExecution != nil {
		q, err := receiptQueryFromContext(ctx, l.ScopeHash, l.CallID, l.Fingerprint)
		if err != nil || q == nil {
			return ErrToolInvocationConflict
		}
		if err := s.admitExecution(ctx, tx, q.Scope); err != nil {
			return err
		}
	}
	updated, err := tx.ExecContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return err
	}
	count, err := updated.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrToolInvocationConflict
	}
	if status == "executing" {
		if err := s.registerCancellationToolTx(ctx, tx, l); err != nil {
			return err
		}
	}
	if err := s.recordRuntimeAuditTx(ctx, tx, l, status, result); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *SQLToolInvocationStore) BeginTool(ctx context.Context, l ToolExecutionLease) error {
	return s.transitionTool(ctx, l, "preparing", "executing", nil, false)
}
func (s *SQLToolInvocationStore) FinishTool(ctx context.Context, l ToolExecutionLease, r map[string]any) error {
	if r == nil {
		return errors.New("empty tool result")
	}
	return s.transitionTool(ctx, l, "executing", "completed", r, false)
}
func (s *SQLToolInvocationStore) RejectTool(ctx context.Context, l ToolExecutionLease) error {
	return s.transitionTool(ctx, l, "", "failed", nil, false)
}
func (s *SQLToolInvocationStore) UnknownTool(ctx context.Context, l ToolExecutionLease) error {
	return s.transitionTool(ctx, l, "", "unknown", nil, true)
}
