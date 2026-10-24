package capability

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"sort"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
)

// Only persisted receipt queries cross this Port; no command payload is replayed.
// 仅持久化回执查询经过此Port，补偿线程绝不重放业务命令Payload。
type ToolRecoveryStore interface {
	ListToolRecovery(context.Context, int) ([]ToolInvocation, error)
	RecoverToolPreparation(context.Context, ToolExecutionLease) error
	ExpireSubmittedTool(context.Context, ToolExecutionLease) error
	DeferToolRecovery(context.Context, ToolExecutionLease) error
}

const (
	toolRecoveryPollFloor   = 2 * time.Second
	toolRecoveryPollCeiling = 30 * time.Second
	toolRecoveryLogInterval = 30 * time.Second
)

// nextToolRecoveryInterval backs off only when the durable due-work query is
// empty (or unavailable). A non-empty page returns promptly to the base poll
// interval so newly due unknown receipts are not delayed by an idle period.
func nextToolRecoveryInterval(current time.Duration, dueRecords int) time.Duration {
	if dueRecords > 0 {
		return toolRecoveryPollFloor
	}
	if current < toolRecoveryPollFloor {
		return toolRecoveryPollFloor
	}
	if current >= toolRecoveryPollCeiling/2 {
		return toolRecoveryPollCeiling
	}
	return current * 2
}

func (m *Module) allowToolRecoveryLog(now time.Time) bool {
	m.toolRecoveryLogMu.Lock()
	defer m.toolRecoveryLogMu.Unlock()
	if !m.toolRecoveryLogAt.IsZero() && now.Sub(m.toolRecoveryLogAt) < toolRecoveryLogInterval {
		return false
	}
	m.toolRecoveryLogAt = now
	return true
}

// reconcileTools returns -1 for a failed scan and otherwise the number of due
// durable records observed. Recovery still queries only the original receipt;
// it never replays a tool command or treats a missing receipt as success.
func (m *Module) reconcileTools(ctx context.Context) int {
	s, ok := m.toolStore.(ToolRecoveryStore)
	if !ok {
		return 0
	}
	ctx, span := telemetry.Start(ctx, "platform.worker.tool_recovery", trace.SpanKindInternal)
	defer span.End()
	m.toolStats.Runs.Add(1)
	readCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	records, err := s.ListToolRecovery(readCtx, 16)
	stop()
	if err != nil {
		m.toolStats.Failed.Add(1)
		telemetry.Failed(span, "TOOL_RECOVERY_READ_FAILED")
		if m.allowToolRecoveryLog(time.Now()) {
			log.Print("tool recovery failed code=TOOL_RECOVERY_READ_FAILED")
		}
		return -1
	}
	if len(records) == 0 {
		return 0
	}
	pending, backoffFailed := 0, 0
	for _, r := range records {
		if ctx.Err() != nil {
			return len(records)
		}
		writeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if r.Status == "running" && r.Phase == "preparing" {
			err = s.RecoverToolPreparation(writeCtx, r.Lease)
		} else {
			if r.Status == "running" {
				err = s.ExpireSubmittedTool(writeCtx, r.Lease)
			} else {
				err = nil
			}
			if err == nil {
				if r.ReceiptQuery == nil || r.ReceiptQuery.CallID != r.CallID || r.ReceiptQuery.Fingerprint != r.Fingerprint || ToolReceiptScopeHash(r.ReceiptQuery.Scope) != r.ScopeHash {
					err = errors.New("invalid persisted tool receipt query")
				} else {
					var found bool
					_, found, err = m.restoreBusinessTool(writeCtx, *r.ReceiptQuery)
					if err == nil && !found {
						err = ErrToolResultUnknown
					}
				}
			}
		}
		cancel()
		if err != nil {
			pending++
			m.toolStats.Failed.Add(1)
			deferCtx, end := context.WithTimeout(ctx, 2*time.Second)
			if err := s.DeferToolRecovery(deferCtx, r.Lease); err != nil {
				backoffFailed++
			}
			end()
		} else {
			m.toolStats.Completed.Add(1)
		}
	}
	if pending > 0 {
		telemetry.Failed(span, "TOOL_RECOVERY_PENDING")
		if m.allowToolRecoveryLog(time.Now()) {
			log.Printf("tool recovery pending code=TOOL_RECOVERY_PENDING count=%d backoff_failed=%d", pending, backoffFailed)
		}
	}
	return len(records)
}

func (m *Module) toolRecoveryLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	interval := time.Second
	for {
		due := m.reconcileTools(ctx)
		interval = nextToolRecoveryInterval(interval, due)
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-timer.C:
		}
	}
}

func (s *memoryToolInvocationStore) ListToolRecovery(ctx context.Context, limit int) ([]ToolInvocation, error) {
	if limit < 1 || limit > 64 {
		return nil, errors.New("invalid tool recovery page")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ToolInvocation
	for _, r := range s.records {
		if r.Lease.Token != "" && !r.RetryAt.After(time.Now()) && (r.Status == "unknown" || r.Status == "running" && !r.Lease.Until.After(time.Now())) {
			out = append(out, cloneToolInvocation(r))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].RetryAt.Equal(out[j].RetryAt) {
			return out[i].RetryAt.Before(out[j].RetryAt)
		}
		return out[i].ScopeHash+"\x00"+out[i].CallID < out[j].ScopeHash+"\x00"+out[j].CallID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (s *memoryToolInvocationStore) recoverExpired(l ToolExecutionLease, phase, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := l.ScopeHash + "\x00" + l.CallID
	r, ok := s.records[key]
	if !ok || r.Status != "running" || r.Phase != phase || !validToolOwner(r, l, true) || r.Lease.Until.After(time.Now()) {
		return ErrToolInvocationConflict
	}
	r.Status = status
	s.records[key] = r
	return nil
}
func (s *memoryToolInvocationStore) RecoverToolPreparation(_ context.Context, l ToolExecutionLease) error {
	return s.recoverExpired(l, "preparing", "failed")
}
func (s *memoryToolInvocationStore) ExpireSubmittedTool(_ context.Context, l ToolExecutionLease) error {
	return s.recoverExpired(l, "executing", "unknown")
}
func (s *memoryToolInvocationStore) DeferToolRecovery(_ context.Context, l ToolExecutionLease) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := l.ScopeHash + "\x00" + l.CallID
	r, ok := s.records[key]
	if !ok || !validToolOwner(r, l, true) || r.Status != "running" && r.Status != "unknown" {
		return ErrToolInvocationConflict
	}
	r.RetryAt = time.Now().Add(5 * time.Second)
	s.records[key] = r
	return nil
}

func (s *SQLToolInvocationStore) ListToolRecovery(ctx context.Context, limit int) ([]ToolInvocation, error) {
	if limit < 1 || limit > 64 {
		return nil, errors.New("invalid tool recovery page")
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT scope_hash,call_id,fingerprint,status,phase,lease_owner,lease_token,lease_fence,lease_until,recovery_query FROM platform_tool_invocation WHERE lease_token<>'' AND scope_hash NOT IN (SELECT jsonb_array_elements_text(?::jsonb)) AND (retry_after IS NULL OR retry_after<=clock_timestamp()) AND (status='unknown' OR status='running' AND lease_until<=clock_timestamp()) ORDER BY updated_at,scope_hash,call_id LIMIT ?`), s.recoveryHolds.RunIDsJSON(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ToolInvocation
	for rows.Next() {
		var r ToolInvocation
		var until sql.NullTime
		var raw sql.NullString
		if err := rows.Scan(&r.ScopeHash, &r.CallID, &r.Fingerprint, &r.Status, &r.Phase, &r.Lease.Owner, &r.Lease.Token, &r.Lease.Fence, &until, &raw); err != nil {
			return nil, err
		}
		r.Lease.ScopeHash, r.Lease.CallID, r.Lease.Fingerprint = r.ScopeHash, r.CallID, r.Fingerprint
		if until.Valid {
			r.Lease.Until = until.Time
		}
		// One malformed query remains visible for safe backoff, not whole-page failure.
		// 单条损坏查询保留为安全退避项，不让整个页面读取失败。
		if raw.Valid && len(raw.String) <= 65536 {
			if json.Unmarshal([]byte(raw.String), &r.ReceiptQuery) != nil {
				r.ReceiptQuery = nil
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *SQLToolInvocationStore) recoverExpired(ctx context.Context, l ToolExecutionLease, phase, status string) error {
	if s.recoveryHolds.Contains(l.ScopeHash) {
		return sharedkernel.ErrAutomaticRecoveryHeld
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET status=?,updated_at=clock_timestamp() WHERE scope_hash=? AND call_id=? AND fingerprint=? AND lease_owner=? AND lease_token=? AND lease_fence=? AND phase=? AND status='running' AND lease_until<=clock_timestamp()`), status, l.ScopeHash, l.CallID, l.Fingerprint, l.Owner, l.Token, l.Fence, phase)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrToolInvocationConflict
	}
	action := "execution_expired"
	if phase == "preparing" {
		action = "preparation_expired"
	}
	if err := s.recordRuntimeAuditTx(ctx, tx, l, action, nil); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *SQLToolInvocationStore) RecoverToolPreparation(ctx context.Context, l ToolExecutionLease) error {
	return s.recoverExpired(ctx, l, "preparing", "failed")
}
func (s *SQLToolInvocationStore) ExpireSubmittedTool(ctx context.Context, l ToolExecutionLease) error {
	return s.recoverExpired(ctx, l, "executing", "unknown")
}

// Unknown receipts are retried forever, but long-unresolved ones are polled
// proportionally less often (age/10, clamped 5s..5m) so idle recovery cannot
// saturate the shared pool. Backoff only schedules work; it never resolves.
// 未知回执永久重试，按存在时长的十分之一退避（5秒至5分钟），避免空闲期占满共享连接池；退避只安排重试，不代表结果已确定。
func (s *SQLToolInvocationStore) DeferToolRecovery(ctx context.Context, l ToolExecutionLease) error {
	if s.recoveryHolds.Contains(l.ScopeHash) {
		return sharedkernel.ErrAutomaticRecoveryHeld
	}
	r, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET retry_after=(clock_timestamp() + LEAST(GREATEST((clock_timestamp()-created_at)/10, INTERVAL '5 seconds'), INTERVAL '5 minutes')),updated_at=clock_timestamp() WHERE scope_hash=? AND call_id=? AND fingerprint=? AND lease_owner=? AND lease_token=? AND lease_fence=? AND status IN ('running','unknown')`), l.ScopeHash, l.CallID, l.Fingerprint, l.Owner, l.Token, l.Fence)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrToolInvocationConflict
	}
	return nil
}
