package runtime

import "time"

func (s *Store) PendingCancellations(limit int) ([]Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []Run{}
	if limit < 1 {
		return result, nil
	}
	if limit > 256 {
		limit = 256
	}
	for _, run := range s.runs {
		if run.Status == StatusCancelling || run.Status == StatusRecovering {
			result = append(result, run)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

// BeginRecovery retains the old token until its signed stop is acknowledged.
// 过期租约不能证明远程已停止，保留旧令牌供签名停止命令使用。
func (s *Store) BeginRecovery(id string, expected uint64, now time.Time) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return Run{}, ErrRunNotFound
	}
	if run.Status != StatusRunning || run.Revision != expected || run.LeaseToken == "" || run.LeaseUntil.After(now) {
		return Run{}, ErrLeaseConflict
	}
	run.Status = StatusRecovering
	run.Revision++
	run.UpdatedAt = now
	s.runs[id] = run
	s.appendEventLocked(id, "recovery_stop_requested", map[string]any{"revision": run.Revision, "code": "EXECUTION_LEASE_EXPIRED"})
	return run, nil
}

// CompleteRecovery requeues the original command, never a fabricated cancellation.
// 停止确认后恢复原命令及审核输入，不伪造取消终态，不释放 FIFO 归属。
func (s *Store) CompleteRecovery(id string, expected uint64) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return Run{}, ErrRunNotFound
	}
	if run.Status != StatusRecovering || run.Revision != expected {
		return Run{}, ErrRevisionConflict
	}
	run.Status = StatusRunning
	run.LeaseToken = ""
	run.LeaseUntil = time.Time{}
	run.Revision++
	run.UpdatedAt = time.Now().UTC()
	s.runs[id] = run
	s.sessions[SessionExecutionKey(run.Scope)] = sessionLease{RunID: id}
	s.appendEventLocked(id, "recovery_stop_confirmed", map[string]any{"revision": run.Revision})
	return run, nil
}

// BeginCancellation fences new business work without releasing the session.
// 先阻止新业务副作用，停止确认前不释放同一会话的锁。
func (s *Store) BeginCancellation(id string, expected uint64) (Run, error) {
	return s.BeginCancellationWithReason(id, expected, "USER_CANCEL_REQUESTED")
}

// BeginCancellationWithReason records why stop is required in the intent txn.
// 停止原因与意图同锁保存，不能因为后续日志/事件故障丢失原始错误分类。
func (s *Store) BeginCancellationWithReason(id string, expected uint64, reason string) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return Run{}, ErrRunNotFound
	}
	if run.Status == StatusCancelling || run.Status == StatusCancelled {
		return run, nil
	}
	if expected != 0 && run.Revision != expected {
		return Run{}, ErrRevisionConflict
	}
	if run.Status != StatusAccepted && run.Status != StatusRunning && run.Status != StatusWaiting {
		return Run{}, ErrInvalidTransition
	}
	run.Status = StatusCancelling
	run.Revision++
	run.UpdatedAt = time.Now().UTC()
	s.runs[id] = run
	s.appendEventLocked(id, "cancel_requested", map[string]any{"revision": run.Revision, "code": reason})
	return run, nil
}
