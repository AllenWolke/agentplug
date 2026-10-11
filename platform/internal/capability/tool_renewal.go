package capability

import (
	"context"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"log"
	"sync/atomic"
	"time"
)

// Renewal is conditional on the same live owner/generation, never resurrection.
// 续租只允许同一存活owner/代际，不能复活过期或撤销的执行。
type ToolLeaseRenewalStore interface {
	RenewTool(context.Context, ToolExecutionLease, time.Duration) (ToolExecutionLease, error)
}

func (s *memoryToolInvocationStore) RenewTool(ctx context.Context, l ToolExecutionLease, ttl time.Duration) (ToolExecutionLease, error) {
	if err := ctx.Err(); err != nil {
		return ToolExecutionLease{}, err
	}
	if ttl < time.Second || ttl > 10*time.Minute {
		return ToolExecutionLease{}, errors.New("invalid tool renewal duration")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := l.ScopeHash + "\x00" + l.CallID
	r, ok := s.records[key]
	if !ok || r.Status != "running" || r.Phase != "executing" || !validToolOwner(r, l, false) {
		return ToolExecutionLease{}, ErrToolInvocationConflict
	}
	until := time.Now().UTC().Add(ttl)
	if until.After(r.Lease.Until) {
		r.Lease.Until = until
	}
	s.records[key] = r
	return r.Lease, nil
}

func (s *SQLToolInvocationStore) RenewTool(ctx context.Context, l ToolExecutionLease, ttl time.Duration) (ToolExecutionLease, error) {
	if ttl < time.Second || ttl > 10*time.Minute || l.Token == "" {
		return ToolExecutionLease{}, errors.New("invalid tool renewal")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ToolExecutionLease{}, err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET lease_until=GREATEST(lease_until,(clock_timestamp() + ?::bigint * INTERVAL '1 microsecond')),updated_at=clock_timestamp() WHERE scope_hash=? AND call_id=? AND fingerprint=? AND lease_owner=? AND lease_token=? AND lease_fence=? AND status='running' AND phase='executing' AND lease_until>clock_timestamp()`), ttl.Microseconds(), l.ScopeHash, l.CallID, l.Fingerprint, l.Owner, l.Token, l.Fence)
	if err != nil {
		return ToolExecutionLease{}, err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return ToolExecutionLease{}, err
	}
	if n != 1 {
		return ToolExecutionLease{}, ErrToolInvocationConflict
	}
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT lease_until FROM platform_tool_invocation WHERE scope_hash=? AND call_id=?`), l.ScopeHash, l.CallID).Scan(&l.Until); err != nil {
		return ToolExecutionLease{}, err
	}
	return l, tx.Commit()
}

type toolLeaseWatch struct {
	stop   context.CancelFunc
	done   chan struct{}
	failed atomic.Bool
}

// A watch owns one goroutine; stopping joins it before terminal ledger writes.
// 每次工具调用仅一条监督协程，终结写账本前先停止并等待，防止并行续租竞态。
func (m *Module) watchToolLease(ctx context.Context, cancelExecution context.CancelFunc, l ToolExecutionLease, ttl time.Duration, op envelope, store ToolLeaseRenewalStore) *toolLeaseWatch {
	watchCtx, stop := context.WithCancel(ctx)
	w := &toolLeaseWatch{stop: stop, done: make(chan struct{})}
	go func() {
		defer close(w.done)
		interval := ttl / 3
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticker.C:
			}
			budget := interval
			if budget > 2*time.Second {
				budget = 2 * time.Second
			}
			probeCtx, end := context.WithTimeout(watchCtx, budget)
			var err error
			if m.liveAuthority != nil {
				err = m.validateLiveAuthority(probeCtx, op)
			}
			if err == nil {
				_, err = store.RenewTool(probeCtx, l, ttl)
			}
			end()
			if err != nil {
				// Supervisor shutdown itself is not a lease failure.
				// 主动结束监督不算租约失败；真实续租/授权失败取消下游。
				if watchCtx.Err() != nil && ctx.Err() == nil {
					return
				}
				w.failed.Store(true)
				cancelExecution()
				log.Print("tool execution stopped code=TOOL_LEASE_OR_AUTHORITY_LOST")
				return
			}
		}
	}()
	return w
}

func (w *toolLeaseWatch) finish() bool { w.stop(); <-w.done; return !w.failed.Load() }
