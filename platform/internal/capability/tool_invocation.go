package capability

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"sync"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// ToolInvocation is the durable idempotency record for one side-effecting
// capability call.  ToolInvocation 是一次可能产生业务副作用的工具调用的
// 持久化幂等记录；Agent 重试或平台恢复只能回放已完成结果。
type ToolInvocation struct {
	ScopeHash    string
	CallID       string
	Fingerprint  string
	Status       string
	Result       map[string]any
	Lease        ToolExecutionLease
	Phase        string
	ReceiptQuery *ToolReceiptQuery
	RetryAt      time.Time
}

var (
	ErrToolInvocationConflict = errors.New("tool invocation idempotency conflict")
	ErrToolInvocationPending  = errors.New("tool invocation is still running")
	ErrToolResultUnknown      = errors.New("tool result requires reconciliation")
	// Ports may wrap this only when they can prove no side effect was submitted.
	// 仅当 Port 能证明尚未提交任何副作用时，才允许包装此错误。
	ErrToolNotSubmitted = errors.New("tool side effect was not submitted")
)

type toolInvocationUnknownStore interface {
	MarkUnknown(context.Context, string, string, string) error
}

// ToolInvocationStore is intentionally a narrow Port.  A future distributed
// platform can replace the SQL implementation with a remote ledger without
// changing Agent Tool contracts.
// ToolInvocationStore 是窄 Port；后续分布式平台可替换为远程账本，Agent
// 工具协议无需变化。
type ToolInvocationStore interface {
	EnsureSchema(context.Context) error
	Reserve(context.Context, string, string, string) (ToolInvocation, bool, error)
	Complete(context.Context, string, string, string, map[string]any) error
}

// toolInvocationFailureStore is optional for backward-compatible adapters;
// production stores implement it so a rejected business command cannot leave
// a permanently running ledger row that blocks retries.
// toolInvocationFailureStore 是可选扩展；生产账本实现它，确保被拒绝的业务
// 命令不会留下永久 running 记录而阻塞后续重试。
type toolInvocationFailureStore interface {
	Fail(context.Context, string, string, string, string) error
}

type memoryToolInvocationStore struct {
	mu      sync.Mutex
	records map[string]ToolInvocation
}

func newMemoryToolInvocationStore() *memoryToolInvocationStore {
	return &memoryToolInvocationStore{records: make(map[string]ToolInvocation)}
}

func (s *memoryToolInvocationStore) EnsureSchema(context.Context) error { return nil }

func (s *memoryToolInvocationStore) Reserve(_ context.Context, scopeHash, callID, fingerprint string) (ToolInvocation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopeHash + "\x00" + callID
	if existing, ok := s.records[key]; ok {
		if existing.Fingerprint != fingerprint {
			return ToolInvocation{}, false, ErrToolInvocationConflict
		}
		if existing.Lease.Token != "" && existing.Status != "completed" {
			if existing.Status == "unknown" {
				return ToolInvocation{}, false, ErrToolResultUnknown
			}
			return ToolInvocation{}, false, ErrToolInvocationPending
		}
		if existing.Status == "failed" {
			// A retry with the same immutable fingerprint may reclaim a failed
			// attempt. Side-effect Ports must use the same call ID as their own
			// idempotency key so an ambiguous prior commit is safe to replay.
			// 同一指纹的重试可重新认领失败记录；副作用 Port 必须复用相同调用 ID
			// 作为自身幂等键，确保前次提交结果不确定时安全重放。
			existing.Status = "running"
			existing.Result = nil
			s.records[key] = existing
			return ToolInvocation{}, false, nil
		}
		if existing.Status == "unknown" {
			return ToolInvocation{}, false, ErrToolResultUnknown
		}
		if existing.Status != "completed" {
			return ToolInvocation{}, false, ErrToolInvocationPending
		}
		return cloneToolInvocation(existing), true, nil
	}
	s.records[key] = ToolInvocation{ScopeHash: scopeHash, CallID: callID, Fingerprint: fingerprint, Status: "running"}
	return ToolInvocation{}, false, nil
}

func (s *memoryToolInvocationStore) Complete(_ context.Context, scopeHash, callID, fingerprint string, result map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopeHash + "\x00" + callID
	existing, ok := s.records[key]
	if !ok || existing.Fingerprint != fingerprint || existing.Status != "running" || existing.Lease.Token != "" {
		return ErrToolInvocationConflict
	}
	existing.Status = "completed"
	existing.Result = cloneToolResult(result)
	s.records[key] = existing
	return nil
}

func (s *memoryToolInvocationStore) Fail(_ context.Context, scopeHash, callID, fingerprint, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopeHash + "\x00" + callID
	existing, ok := s.records[key]
	if !ok || existing.Fingerprint != fingerprint || existing.Status != "running" || existing.Lease.Token != "" {
		return ErrToolInvocationConflict
	}
	existing.Status = "failed"
	existing.Result = map[string]any{"error": reason}
	s.records[key] = existing
	return nil
}

func cloneToolInvocation(value ToolInvocation) ToolInvocation {
	value.Result = cloneToolResult(value.Result)
	if value.ReceiptQuery != nil {
		q := *value.ReceiptQuery
		if q.RemoteContract != nil {
			contract := *q.RemoteContract
			q.RemoteContract = &contract
		}
		value.ReceiptQuery = &q
	}
	return value
}

// SQLToolInvocationStore provides restart-safe side-effect idempotency. The
// primary key is scope + call ID, so tenants, users and Agent instances cannot
// replay one another's Tool result.
// SQLToolInvocationStore 提供可跨重启的副作用幂等；主键包含作用域和调用
// ID，租户、用户及 Agent 实例之间不能互相回放结果。
type SQLToolInvocationStore struct {
	recoveryHolds           sharedkernel.RecoveryHolds
	recoveryHoldsConfigured bool
	db                      *sql.DB
	audit                   audit.TxRecorder
	admitExecution          func(context.Context, *sql.Tx, sharedkernel.Scope) error
	cancellationRegistrar   CancellationToolRegistrar
}

// Configured before workers start; receipt and audit share the owning transaction.
func (s *SQLToolInvocationStore) SetAuditRecorder(recorder audit.TxRecorder) {
	s.audit = recorder
}

// Installed before Start. Admission locks current IAM, Run ancestors and the
// root budget before the tool row, in the same transaction as BeginTool.
func (s *SQLToolInvocationStore) SetExecutionAdmission(admit func(context.Context, *sql.Tx, sharedkernel.Scope) error) {
	s.admitExecution = admit
}

func (s *SQLToolInvocationStore) RequiresExecutionAdmission() bool { return s.admitExecution != nil }

func NewSQLToolInvocationStore(db *sql.DB) (*SQLToolInvocationStore, error) {
	if db == nil {
		return nil, errors.New("tool invocation database is required")
	}
	return &SQLToolInvocationStore{db: db}, nil
}

func (s *SQLToolInvocationStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`
CREATE TABLE IF NOT EXISTS platform_tool_invocation (
  scope_hash VARCHAR(64) NOT NULL,
  call_id VARCHAR(255) NOT NULL,
  fingerprint VARCHAR(64) NOT NULL,
  status VARCHAR(16) NOT NULL,
  result_json TEXT NULL,
  lease_owner VARCHAR(64) NOT NULL DEFAULT '',
  lease_token VARCHAR(32) NOT NULL DEFAULT '',
  lease_fence NUMERIC(20,0) CHECK (lease_fence>=0 AND lease_fence<=18446744073709551615) NOT NULL DEFAULT 0,
  lease_until TIMESTAMPTZ(6) NULL,
  phase VARCHAR(16) NOT NULL DEFAULT '',
  recovery_query TEXT NULL,
  retry_after TIMESTAMPTZ(6) NULL,
  created_at TIMESTAMPTZ(6) NOT NULL,
  updated_at TIMESTAMPTZ(6) NOT NULL,
  PRIMARY KEY (scope_hash, call_id));
CREATE INDEX IF NOT EXISTS idx_platform_tool_invocation_scope ON platform_tool_invocation (scope_hash, status);`))
	if err != nil {
		return fmt.Errorf("migrate tool invocation: %w", err)
	}
	return nil
}

func (s *SQLToolInvocationStore) Reserve(ctx context.Context, scopeHash, callID, fingerprint string) (ToolInvocation, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ToolInvocation{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockLedgerScope(ctx, tx, "tool-invocation", scopeHash+"\x00"+callID); err != nil {
		return ToolInvocation{}, false, err
	}
	var existing ToolInvocation
	var resultJSON sql.NullString
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT fingerprint,status,result_json,lease_token FROM platform_tool_invocation WHERE scope_hash=? AND call_id=? FOR UPDATE`), scopeHash, callID).Scan(&existing.Fingerprint, &existing.Status, &resultJSON, &existing.Lease.Token)
	if err == nil {
		existing.ScopeHash, existing.CallID = scopeHash, callID
		if existing.Lease.Token != "" && existing.Status != "completed" {
			if existing.Fingerprint != fingerprint {
				return ToolInvocation{}, false, ErrToolInvocationConflict
			}
			if existing.Status == "unknown" {
				return ToolInvocation{}, false, ErrToolResultUnknown
			}
			return ToolInvocation{}, false, ErrToolInvocationPending
		}
		if existing.Fingerprint != fingerprint {
			return ToolInvocation{}, false, ErrToolInvocationConflict
		}
		if existing.Status == "failed" {
			// SELECT ... FOR UPDATE serializes competing retries. The existing
			// scoped CallID/fingerprint remains immutable while only the failed
			// attempt state is reclaimed.
			// SELECT ... FOR UPDATE 串行化并发重试；Scope/CallID/指纹不变，
			// 仅重新认领已失败的尝试。
			if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET status='running',result_json=NULL,updated_at=clock_timestamp() WHERE scope_hash=? AND call_id=? AND fingerprint=? AND status='failed'`), scopeHash, callID, fingerprint); err != nil {
				return ToolInvocation{}, false, err
			}
			if err = tx.Commit(); err != nil {
				return ToolInvocation{}, false, err
			}
			return ToolInvocation{}, false, nil
		}
		if existing.Status == "unknown" {
			return ToolInvocation{}, false, ErrToolResultUnknown
		}
		if existing.Status != "completed" {
			return ToolInvocation{}, false, ErrToolInvocationPending
		}
		if resultJSON.Valid && resultJSON.String != "" && decodeToolStoredResult([]byte(resultJSON.String), &existing.Result) != nil {
			return ToolInvocation{}, false, errors.New("corrupt tool invocation result")
		}
		if err = tx.Commit(); err != nil {
			return ToolInvocation{}, false, err
		}
		return existing, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ToolInvocation{}, false, err
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_tool_invocation(scope_hash,call_id,fingerprint,status,created_at,updated_at) VALUES(?,?,?,'running',clock_timestamp(),clock_timestamp())`), scopeHash, callID, fingerprint); err != nil {
		return ToolInvocation{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return ToolInvocation{}, false, err
	}
	return ToolInvocation{}, false, nil
}

func (s *SQLToolInvocationStore) Complete(ctx context.Context, scopeHash, callID, fingerprint string, result map[string]any) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	updated, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET status='completed',result_json=?,updated_at=clock_timestamp() WHERE scope_hash=? AND call_id=? AND fingerprint=? AND status='running' AND lease_token=''`), string(raw), scopeHash, callID, fingerprint)
	if err != nil {
		return err
	}
	if affected, err := updated.RowsAffected(); err != nil {
		return err
	} else if affected != 1 {
		return ErrToolInvocationConflict
	}
	return nil
}

func (s *SQLToolInvocationStore) Fail(ctx context.Context, scopeHash, callID, fingerprint, reason string) error {
	raw, err := json.Marshal(map[string]any{"error": reason})
	if err != nil {
		return err
	}
	updated, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET status='failed',result_json=?,updated_at=clock_timestamp() WHERE scope_hash=? AND call_id=? AND fingerprint=? AND status='running' AND lease_token=''`), string(raw), scopeHash, callID, fingerprint)
	if err != nil {
		return err
	}
	if affected, err := updated.RowsAffected(); err != nil {
		return err
	} else if affected != 1 {
		return ErrToolInvocationConflict
	}
	return nil
}

var _ ToolInvocationStore = (*SQLToolInvocationStore)(nil)

// Unknown is not retryable: a downstream commit may already have happened.
// 结果未知不可重试：下游可能已提交，必须先查询持久化提交回执。
func (s *memoryToolInvocationStore) MarkUnknown(_ context.Context, scope, id, fp string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scope + "\x00" + id
	r, ok := s.records[key]
	if !ok || r.Fingerprint != fp || r.Status != "running" && r.Status != "unknown" {
		return ErrToolInvocationConflict
	}
	r.Status, r.Result = "unknown", nil
	s.records[key] = r
	return nil
}

func (s *SQLToolInvocationStore) MarkUnknown(ctx context.Context, scope, id, fp string) error {
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET status='unknown',result_json=NULL,updated_at=clock_timestamp() WHERE scope_hash=? AND call_id=? AND fingerprint=? AND status IN ('running','unknown')`), scope, id, fp)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrToolInvocationConflict
	}
	return nil
}
