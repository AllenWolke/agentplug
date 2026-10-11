package capability

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"sync/atomic"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/telemetry"
	"github.com/lexagent/platform/internal/usagecost"
	"go.opentelemetry.io/otel/trace"
)

// BillingRecovery stores the exact settlement envelope, not a provider retry.
// 保存确切结算意图，而非重新调用厂商的请求；Event 为空表示结果未知。
type BillingRecovery struct {
	Reservation  usagecost.ModelBudgetReservation `json:"reservation"`
	Event        *usagecost.Event                 `json:"event,omitempty"`
	PriceID      string                           `json:"price_id"`
	Decision     *BillingDecision                 `json:"decision,omitempty"`
	SendDeadline time.Time                        `json:"send_deadline,omitempty"`
	AttemptToken string                           `json:"attempt_token,omitempty"`
	Unsent       bool                             `json:"unsent,omitempty"`
}

type ModelBillingRecoveryStore interface {
	SaveBillingRecovery(context.Context, string, string, string, map[string]any, int64, BillingRecovery) error
	ListBillingRecovery(context.Context, int) ([]ModelInvocation, error)
	DeferBillingRecovery(context.Context, string, string, string) error
}

// Persist before sending, then reconcile expired attempts without a provider retry.
// 发请求前持久化，过期尝试只转人工核对，绝不重发厂商请求。
type ModelSendLifecycleStore interface {
	PromoteExpiredSend(context.Context, ModelInvocation) error
	PersistUnsent(context.Context, string, string, string, string) (ModelInvocation, error)
	FinishUnsent(context.Context, ModelInvocation) error
}

type BillingWorkerStats struct{ Runs, Completed, Failed atomic.Uint64 }

func (m *Module) reconcileBilling(ctx context.Context) {
	store, ok := m.modelStore.(ModelBillingRecoveryStore)
	if !ok || m.modelBudgets == nil {
		return
	}
	ctx, span := telemetry.Start(ctx, "platform.worker.model_billing", trace.SpanKindInternal)
	defer span.End()
	m.billingStats.Runs.Add(1)
	if preparations, ok := m.modelStore.(ModelPreparationStore); ok {
		prepareCtx, stop := context.WithTimeout(ctx, 2*time.Second)
		_, prepareErr := preparations.RecoverExpiredPreparations(prepareCtx)
		stop()
		if prepareErr != nil {
			m.billingStats.Failed.Add(1)
			telemetry.Failed(span, "MODEL_PREPARATION_RECOVERY_FAILED")
			log.Print("model preparation recovery failed code=MODEL_PREPARATION_RECOVERY_FAILED")
		}
	}
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	records, err := store.ListBillingRecovery(readCtx, 16)
	cancel()
	if err != nil {
		m.billingStats.Failed.Add(1)
		telemetry.Failed(span, "BILLING_RECOVERY_READ_FAILED")
		log.Print("model billing reconciliation failed code=BILLING_RECOVERY_READ_FAILED")
		return
	}
	for _, record := range records {
		if ctx.Err() != nil {
			return
		}
		writeCtx, stop := context.WithTimeout(ctx, 2*time.Second)
		if record.RecoveryCorrupt {
			// Isolate one bad row; backoff below rotates it out of the next page.
			// 单条损坏记录只进入退避，不结算、不释放预算，也不阻断其他记录。
			err = errors.New("corrupt saved billing recovery")
		} else if record.Recovery != nil && !record.Recovery.SendDeadline.IsZero() {
			hold, supported := m.modelBudgets.(usagecost.ModelBudgetReconciliationStore)
			lifecycle, durable := m.modelStore.(ModelSendLifecycleStore)
			if !supported || !durable || record.Recovery.SendDeadline.After(time.Now()) {
				err = errors.New("model send lifecycle unavailable")
			} else {
				err = hold.MarkReconciliationNeeded(writeCtx, record.Recovery.Reservation)
				if err == nil {
					err = lifecycle.PromoteExpiredSend(writeCtx, record)
				}
			}
		} else if record.Recovery != nil && record.Recovery.Decision != nil {
			decisionStore, ok := m.modelStore.(ModelBillingDecisionStore)
			if !ok && !record.Recovery.Unsent {
				err = errors.New("billing decision store unavailable")
			} else if record.Recovery.Decision.Outcome == "no_charge" {
				release, ok := m.modelBudgets.(usagecost.ModelBudgetManualReleaseStore)
				if !ok {
					err = errors.New("manual release store unavailable")
				} else {
					err = release.ResolveUncharged(writeCtx, record.Recovery.Reservation, record.Recovery.Decision.ProviderRef)
				}
			} else if record.Recovery.Decision.Outcome == "charged" && record.Recovery.Event != nil {
				_, err = m.modelBudgets.Settle(writeCtx, record.Recovery.Reservation, *record.Recovery.Event, record.Recovery.PriceID)
			} else {
				err = errors.New("invalid billing decision")
			}
			if err == nil {
				if record.Recovery.Unsent {
					lifecycle, ok := m.modelStore.(ModelSendLifecycleStore)
					if !ok {
						err = errors.New("unsent completion store unavailable")
					} else {
						err = lifecycle.FinishUnsent(writeCtx, record)
					}
				} else {
					err = decisionStore.FinishBillingDecision(writeCtx, record)
				}
			}
		} else if record.Recovery == nil || record.Recovery.Event == nil || record.Response == nil || record.Recovery.PriceID != record.Recovery.Reservation.PriceVersionID {
			err = errors.New("invalid saved billing recovery")
		} else {
			hold, ok := m.modelBudgets.(usagecost.ModelBudgetReconciliationStore)
			if !ok {
				err = errors.New("billing hold store unavailable")
			} else {
				err = hold.MarkReconciliationNeeded(writeCtx, record.Recovery.Reservation)
			}
			// A settled reservation is intentionally idempotent at Settle.
			// 已结算的预占通过 Settle 精确回放，不再次计费。
			if err == nil || errors.Is(err, usagecost.ErrBudgetReservationClosed) {
				_, err = m.modelBudgets.Settle(writeCtx, record.Recovery.Reservation, *record.Recovery.Event, record.Recovery.PriceID)
			}
			if err == nil {
				err = m.modelStore.Complete(writeCtx, record.ScopeHash, record.Key, record.Fingerprint, record.Response, record.CostCents)
			}
		}
		stop()
		if err != nil {
			m.billingStats.Failed.Add(1)
			telemetry.Failed(span, "BILLING_RECOVERY_WRITE_FAILED")
			log.Print("model billing reconciliation failed code=BILLING_RECOVERY_WRITE_FAILED")
			deferCtx, done := context.WithTimeout(ctx, 2*time.Second)
			if deferErr := store.DeferBillingRecovery(deferCtx, record.ScopeHash, record.Key, record.Fingerprint); deferErr != nil {
				log.Print("model billing reconciliation failed code=BILLING_RECOVERY_BACKOFF_FAILED")
			}
			done()
		} else {
			m.billingStats.Completed.Add(1)
		}
	}
}

func (m *Module) billingLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		m.reconcileBilling(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *memoryModelInvocationStore) SaveBillingRecovery(ctx context.Context, scope, key, fingerprint string, response map[string]any, cost int64, recovery BillingRecovery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[scope+"\x00"+key]
	if !ok || record.Fingerprint != fingerprint || record.Status != "running" && record.Status != "reconcile" {
		return ErrModelInvocationConflict
	}
	if record.AttemptToken != recovery.AttemptToken || record.Status == "running" && record.AttemptToken != "" && !record.PreparationUntil.After(time.Now()) {
		return ErrModelInvocationConflict
	}
	// Snapshot caller-owned objects before publishing recovery to another worker.
	// 复制调用者对象，防止对账线程与请求线程共享可变状态。
	raw, err := json.Marshal(recovery)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &record.Recovery); err != nil {
		return err
	}
	record.Status, record.Response, record.CostCents = "reconcile", cloneMap(response), cost
	record.RetryAt = recovery.SendDeadline
	s.records[scope+"\x00"+key] = record
	return nil
}

func (s *memoryModelInvocationStore) ListBillingRecovery(_ context.Context, limit int) ([]ModelInvocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ModelInvocation
	for _, record := range s.records {
		if record.Status == "reconcile" && record.Recovery != nil && (record.Recovery.Event != nil || record.Recovery.Decision != nil || !record.Recovery.SendDeadline.IsZero()) && !record.RetryAt.After(time.Now()) {
			out = append(out, cloneInvocation(record))
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (s *memoryModelInvocationStore) DeferBillingRecovery(_ context.Context, scope, key, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[scope+"\x00"+key]
	if !ok || record.Fingerprint != fingerprint {
		return ErrModelInvocationConflict
	}
	record.RetryAt = time.Now().Add(5 * time.Second)
	s.records[scope+"\x00"+key] = record
	return nil
}

func (s *SQLModelInvocationStore) SaveBillingRecovery(ctx context.Context, scope, key, fingerprint string, response map[string]any, cost int64, recovery BillingRecovery) error {
	raw, err := json.Marshal(response)
	if err != nil {
		return err
	}
	intent, err := json.Marshal(recovery)
	if err != nil {
		return err
	}
	state := "manual"
	if response != nil && recovery.Event != nil {
		state = "pending"
	}
	var retryAt any
	if !recovery.SendDeadline.IsZero() {
		state, retryAt = "inflight", recovery.SendDeadline.UTC()
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET status='reconcile',response_json=?,cost_cents=?,billing_recovery_json=?,billing_state=?,billing_retry_at=?,updated_at=clock_timestamp() WHERE scope_hash=? AND idempotency_key=? AND fingerprint=? AND invocation_token=? AND status IN ('running','reconcile') AND (billing_state IN ('','manual','pending','inflight') OR billing_state='preparing' AND preparation_deadline>clock_timestamp())`), nullableJSON(raw), cost, string(intent), state, retryAt, scope, key, fingerprint, recovery.AttemptToken)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrModelInvocationConflict
	}
	return nil
}

func (s *SQLModelInvocationStore) ListBillingRecovery(ctx context.Context, limit int) ([]ModelInvocation, error) {
	if limit < 1 || limit > 64 {
		return nil, errors.New("invalid billing recovery page size")
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT scope_hash,idempotency_key,fingerprint,response_json,cost_cents,billing_recovery_json FROM platform_model_invocation WHERE status='reconcile' AND billing_state IN ('pending','decision_pending','inflight') AND (billing_retry_at IS NULL OR billing_retry_at<=clock_timestamp()) ORDER BY updated_at LIMIT ?`), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ModelInvocation
	for rows.Next() {
		var record ModelInvocation
		var response, intent sql.NullString
		if err := rows.Scan(&record.ScopeHash, &record.Key, &record.Fingerprint, &response, &record.CostCents, &intent); err != nil {
			return nil, err
		}
		if response.Valid && json.Unmarshal([]byte(response.String), &record.Response) != nil || !intent.Valid || json.Unmarshal([]byte(intent.String), &record.Recovery) != nil {
			record.Response, record.Recovery = nil, nil
			record.RecoveryCorrupt = true
		}
		record.Status = "reconcile"
		out = append(out, record)
	}
	return out, rows.Err()
}

func (s *SQLModelInvocationStore) DeferBillingRecovery(ctx context.Context, scope, key, fingerprint string) error {
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET billing_retry_at=(clock_timestamp() + INTERVAL '5 seconds'),updated_at=clock_timestamp() WHERE scope_hash=? AND idempotency_key=? AND fingerprint=? AND status='reconcile'`), scope, key, fingerprint)
	return err
}
