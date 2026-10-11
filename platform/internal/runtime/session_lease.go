package runtime

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// SessionExecutionKey includes the checkpoint namespace but excludes Run/epoch/trace.
// 同会话跨 Run 连续执行；版本属于 Checkpoint 命名空间，授权版本变化不新建会话。
func SessionExecutionKey(scope sharedkernel.Scope) string {
	raw, _ := json.Marshal([10]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID,
		scope.InstallationID, scope.AgentInstanceID, scope.AgentID, scope.PrincipalType,
		scope.PrincipalID, scope.SessionID, scope.AgentVersionID})
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

type sessionLease struct {
	RunID string
	Token string
	Until time.Time
}

func sessionPending(status Status) bool {
	return status == StatusAccepted || status == StatusRunning || status == StatusWaiting || status == StatusCancelling || status == StatusRecovering
}

// claimSessionLocked preserves FIFO and reserves interrupted sessions until resolved.
// 中断等待期间保留会话归属；租约过期只能由原 Run 恢复，后续 Run 不得覆盖图状态。
func (s *Store) claimSessionLocked(run Run, token string, now, until time.Time) error {
	key := SessionExecutionKey(run.Scope)
	for _, other := range s.runs {
		if other.ID != run.ID && sessionPending(other.Status) && SessionExecutionKey(other.Scope) == key &&
			(other.CreatedAt.Before(run.CreatedAt) || other.CreatedAt.Equal(run.CreatedAt) && other.ID < run.ID) {
			return ErrLeaseConflict
		}
	}
	if lease, exists := s.sessions[key]; exists && lease.RunID != run.ID {
		if owner, exists := s.runs[lease.RunID]; exists && sessionPending(owner.Status) {
			return ErrLeaseConflict
		}
	}
	s.sessions[key] = sessionLease{RunID: run.ID, Token: token, Until: until}
	return nil
}

func (s *Store) releaseSessionLocked(run Run) {
	key := SessionExecutionKey(run.Scope)
	if current, exists := s.sessions[key]; exists && current.RunID == run.ID {
		if run.Status == StatusWaiting {
			s.sessions[key] = sessionLease{RunID: run.ID}
		} else if !sessionPending(run.Status) {
			delete(s.sessions, key)
		}
	}
}

func (s *Store) CheckSessionLease(run Run, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkSessionLeaseLocked(run, now)
}

func (s *Store) checkSessionLeaseLocked(run Run, now time.Time) error {
	lease, ok := s.sessions[SessionExecutionKey(run.Scope)]
	if !ok || lease.RunID != run.ID || lease.Token != run.LeaseToken || !lease.Until.After(now) {
		return ErrLeaseConflict
	}
	return nil
}
