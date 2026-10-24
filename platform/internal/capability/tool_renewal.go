package capability

import (
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"log"
	"net"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
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
	stop context.CancelFunc
	done chan struct{}
	// Only the watcher writes these; readers join done before accessing them.
	failure error
	stage   string
}

func transientToolLeaseCheck(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if budgetAdmissionDeferred(err) || errors.Is(err, driver.ErrBadConn) || errors.Is(err, io.EOF) {
		return true
	}
	var network net.Error
	if errors.As(err, &network) {
		return true
	}
	switch sqlutil.SQLState(err) {
	case "40001", "40P01", "08000", "08001", "08003", "08006", "57P01":
		return true
	}
	return false
}

// Retry only the conditional renewal/read, never the tool command. An
// unacknowledged renewal cannot increase our last confirmed lease deadline.
func (m *Module) renewToolLeaseWithinFence(ctx context.Context, l ToolExecutionLease, ttl time.Duration, op envelope, store ToolLeaseRenewalStore) (ToolExecutionLease, string, error) {
	stage := "lease_renewal"
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return l, stage, err
		}
		if !l.Until.After(time.Now()) {
			return l, "lease_expired", ErrToolInvocationConflict
		}
		budget := min(ttl/3, 2*time.Second, time.Until(l.Until))
		if budget <= 0 {
			return l, "lease_expired", ErrToolInvocationConflict
		}
		probeCtx, end := context.WithTimeout(ctx, budget)
		var err error
		stage = "current_authority"
		if m.liveAuthority != nil {
			err = m.validateLiveAuthority(probeCtx, op)
		}
		var renewed ToolExecutionLease
		if err == nil {
			stage = "lease_renewal"
			renewed, err = store.RenewTool(probeCtx, l, ttl)
		}
		end()
		if err == nil {
			if renewed.ScopeHash != l.ScopeHash || renewed.CallID != l.CallID || renewed.Fingerprint != l.Fingerprint || renewed.Owner != l.Owner || renewed.Token != l.Token || renewed.Fence != l.Fence || renewed.Until.Before(l.Until) || !renewed.Until.After(time.Now()) {
				return l, "lease_receipt", ErrToolInvocationConflict
			}
			return renewed, stage, nil
		}
		if !transientToolLeaseCheck(err) || attempt == 2 {
			return l, stage, err
		}
		// The retry and its delay both remain inside the original execution
		// context and the last acknowledged lease. Unknown commits add no time.
		delay := time.Duration(attempt+1) * 50 * time.Millisecond
		if time.Until(l.Until) <= delay {
			return l, stage, err
		}
		log.Printf("tool renewal deferred run_id=%q call_id=%s stage=%s attempt=%d reason=%s", op.Context.TaskID, l.CallID, stage, attempt+1, budgetAdmissionErrorType(err))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return l, stage, ctx.Err()
		case <-timer.C:
		}
	}
	return l, stage, ErrToolInvocationConflict
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
			renewed, stage, err := m.renewToolLeaseWithinFence(watchCtx, l, ttl, op, store)
			if err != nil {
				// Supervisor shutdown itself is not a lease failure.
				// 主动结束监督不算租约失败；真实续租/授权失败取消下游。
				if watchCtx.Err() != nil && ctx.Err() == nil {
					return
				}
				w.failure, w.stage = err, stage
				cancelExecution()
				log.Printf("tool execution stopped run_id=%q call_id=%s stage=%s reason=%s", op.Context.TaskID, l.CallID, stage, budgetAdmissionErrorType(err))
				return
			}
			l = renewed
		}
	}()
	return w
}

func (w *toolLeaseWatch) finish() bool { w.stop(); <-w.done; return w.failure == nil }

func (w *toolLeaseWatch) failureStatus() (int, string) {
	w.finish()
	if w.stage == "current_authority" {
		if transientToolLeaseCheck(w.failure) {
			return 503, "CAPABILITY_UNAVAILABLE"
		}
		return 403, "CAPABILITY_DENIED"
	}
	// A tool-local lease failure does not prove that the whole Run was revoked.
	// Keep its receipt unresolved; another independent item can still proceed.
	if errors.Is(w.failure, ErrToolInvocationConflict) {
		return 409, "TOOL_RESULT_UNKNOWN"
	}
	return 503, "TOOL_RECEIPT_UNAVAILABLE"
}
