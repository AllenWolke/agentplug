package capability

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

// releaseUnsentAdmission is called ONLY by known pre-provider admission failures.
// Shared tree accounting requires a durable no-send proof, not a bare Release.
// true means this path owns the recovery record (including retained failure);
// callers must not overwrite it with a preparation-failed transition.
func (m *Module) releaseUnsentAdmission(ctx context.Context, scope, key, fingerprint string, reservation usagecost.ModelBudgetReservation, traceID, attemptToken string) bool {
	binding, required := m.modelBudgets.(usagecost.ModelBudgetExecutionBindingStore)
	if !required || !binding.RequiresExecutionBinding() {
		m.releaseModelBudget(ctx, reservation, traceID)
		return false
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := m.prepareModelSend(writeCtx, scope, key, fingerprint, reservation, time.Now().UTC().Add(2*time.Minute), attemptToken); err != nil {
		log.Printf("unsent admission accounting retained trace=%q error_type=%T", traceID, err)
		return true
	}
	if err := m.abortUnsentModel(writeCtx, scope, key, fingerprint, reservation, attemptToken); err != nil {
		log.Printf("unsent admission proof awaits accounting trace=%q error_type=%T", traceID, err)
	}
	return true
}

// PrepareSend writes the recovery envelope before the budget hold and HTTP send.
// 发出 HTTP 前保存恢复意图再锁定预算；两阶段失败均禁止调用模型。
func (m *Module) prepareModelSend(ctx context.Context, scope, key, fingerprint string, reservation usagecost.ModelBudgetReservation, deadline time.Time, tokens ...string) error {
	if !deadline.After(time.Now()) || deadline.After(time.Now().Add(5*time.Minute)) {
		return errors.New("invalid model send deadline")
	}
	store, ok := m.modelStore.(ModelBillingRecoveryStore)
	_, lifecycle := m.modelStore.(ModelSendLifecycleStore)
	_, dispatch := m.modelStore.(ModelDispatchStore)
	hold, retained := m.modelBudgets.(usagecost.ModelBudgetReconciliationStore)
	if !ok || !lifecycle || !dispatch || !retained {
		return errors.New("model send persistence unavailable")
	}
	intent := BillingRecovery{Reservation: reservation, PriceID: reservation.PriceVersionID, SendDeadline: deadline, SendPhase: "prepared"}
	if len(tokens) == 1 {
		intent.AttemptToken = tokens[0]
	} else if len(tokens) > 1 {
		return ErrModelInvocationConflict
	}
	if err := store.SaveBillingRecovery(ctx, scope, key, fingerprint, nil, 0, intent); err != nil {
		return err
	}
	return hold.MarkReconciliationNeeded(ctx, reservation)
}

// Call only for a classified adapter error produced before any generation send.
// 仅用于已分类的发送前适配器错误；超时、断连、未知响应绝不能进入此分支。
func (m *Module) abortUnsentModel(ctx context.Context, scope, key, fingerprint string, reservation usagecost.ModelBudgetReservation, attemptToken string) error {
	release, ok := m.modelBudgets.(usagecost.ModelBudgetManualReleaseStore)
	store, durable := m.modelStore.(ModelSendLifecycleStore)
	if !ok || !durable {
		return errors.New("unsent accounting unavailable")
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	// Persist the no-send proof before releasing; retry only its exact receipt.
	// 先持久化未发送证据，释放失败或终结失败均只补偿同一回执。
	record, err := store.PersistUnsent(writeCtx, scope, key, fingerprint, attemptToken)
	if err != nil {
		return err
	}
	if record.Recovery == nil || record.Recovery.Reservation.ReservationID != reservation.ReservationID || record.Recovery.Decision == nil {
		return ErrModelInvocationConflict
	}
	if err := release.ResolveUncharged(writeCtx, reservation, record.Recovery.Decision.ProviderRef); err != nil {
		return err
	}
	return store.FinishUnsent(writeCtx, record)
}

func (s *SQLModelInvocationStore) PromoteExpiredSend(ctx context.Context, r ModelInvocation) error {
	if r.Recovery == nil || r.Recovery.SendDeadline.IsZero() || r.Recovery.SendDeadline.After(time.Now()) {
		return ErrModelInvocationConflict
	}
	original, err := json.Marshal(r.Recovery)
	if err != nil {
		return err
	}
	intent := *r.Recovery
	intent.SendDeadline = time.Time{}
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	updated, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET billing_state='manual',billing_recovery_json=?,billing_retry_at=NULL,updated_at=clock_timestamp() WHERE scope_hash=? AND idempotency_key=? AND fingerprint=? AND status='reconcile' AND billing_state='inflight' AND billing_recovery_json::jsonb=?::jsonb AND billing_retry_at<=clock_timestamp()`), string(raw), r.ScopeHash, r.Key, r.Fingerprint, string(original))
	if err != nil {
		return err
	}
	n, err := updated.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrModelInvocationConflict
	}
	return nil
}

func (s *memoryModelInvocationStore) PromoteExpiredSend(_ context.Context, r ModelInvocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[r.ScopeHash+"\x00"+r.Key]
	if !ok || current.Fingerprint != r.Fingerprint || current.Status != "reconcile" || current.Recovery == nil || current.Recovery.SendDeadline.IsZero() || current.Recovery.SendDeadline.After(time.Now()) {
		return ErrModelInvocationConflict
	}
	actual, err := json.Marshal(current.Recovery)
	expected, expectedErr := json.Marshal(r.Recovery)
	if err != nil || expectedErr != nil || string(actual) != string(expected) {
		return ErrModelInvocationConflict
	}
	current = cloneInvocation(current)
	current.Recovery.SendDeadline = time.Time{}
	current.RetryAt = time.Time{}
	s.records[r.ScopeHash+"\x00"+r.Key] = current
	return nil
}
