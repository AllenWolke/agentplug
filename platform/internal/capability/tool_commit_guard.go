package capability

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
)

// ToolCommitGuard participates in the caller's local transaction, while only
// the capability owner reads its ledger. Remote services must implement an
// equivalent durable fencing protocol rather than sharing this SQL adapter.
// 工具账本所有者在业务事务内锁定执行代际；远程服务须替换为持久化fencing协议。
type ToolCommitGuard interface {
	GuardToolCommit(context.Context, *sql.Tx, ToolReceiptQuery) error
}

func (s *SQLToolInvocationStore) GuardToolCommit(ctx context.Context, tx *sql.Tx, q ToolReceiptQuery) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := q.Scope.Validate(); err != nil {
		return ErrToolInvocationConflict
	}
	l, ok := ctx.Value(toolLeaseContextKey{}).(ToolExecutionLease)
	if !ok || tx == nil || l.ScopeHash != ToolReceiptScopeHash(q.Scope) || l.CallID != q.CallID || l.Fingerprint != q.Fingerprint || l.Token == "" {
		return ErrToolInvocationConflict
	}
	// Match BeginTool's lock order: admission owns the IAM/Run/ancestry fence,
	// then the tool row. A late business transaction must not commit after the
	// Run was stopped merely because its tool lease is still alive.
	if s.admitExecution != nil {
		if err := s.admitExecution(ctx, tx, q.Scope); err != nil {
			return err
		}
	}
	// The row lock survives until the business transaction commits/rolls back.
	// 行锁保持到业务事务结束，其他代际不能在核验与提交之间接管。
	var alive int
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT CASE WHEN lease_until>clock_timestamp() THEN 1 ELSE 0 END FROM platform_tool_invocation WHERE scope_hash=? AND call_id=? AND fingerprint=? AND lease_owner=? AND lease_token=? AND lease_fence=? AND status='running' AND phase='executing' FOR UPDATE`), l.ScopeHash, l.CallID, l.Fingerprint, l.Owner, l.Token, l.Fence).Scan(&alive)
	if errors.Is(err, sql.ErrNoRows) || err == nil && alive != 1 {
		return ErrToolInvocationConflict
	}
	return err
}
