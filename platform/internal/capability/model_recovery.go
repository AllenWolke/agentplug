package capability

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"strings"
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
	// Empty is a legacy attempt: recovery must conservatively treat it as sent.
	SendPhase    string `json:"send_phase,omitempty"`
	AttemptToken string `json:"attempt_token,omitempty"`
	Unsent       bool   `json:"unsent,omitempty"`
	// Nonzero only while an atomic budget admission has not entered send.
	AdmissionUntil time.Time `json:"admission_until,omitempty"`
	FailureKind    string    `json:"failure_kind,omitempty"`
	HoldConfirmed  bool      `json:"hold_confirmed,omitempty"`
}

// A zero time.Time does not obey omitempty in encoding/json. Keep old v1
// recovery envelopes byte-compatible for exact replay during rolling upgrades.
func (r BillingRecovery) MarshalJSON() ([]byte, error) {
	type legacy BillingRecovery
	var until *time.Time
	if !r.AdmissionUntil.IsZero() {
		until = &r.AdmissionUntil
	}
	return json.Marshal(struct {
		legacy
		AdmissionUntil *time.Time `json:"admission_until,omitempty"`
	}{legacy(r), until})
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

// Optional durable dispatch fence. A prepared attempt cannot call a provider
// until this CAS wins; recovery closes only prepared attempts whose CAS cannot
// subsequently win. A lost dispatch acknowledgment never authorizes a send.
type ModelDispatchStore interface {
	BeginModelDispatch(context.Context, string, string, string, string) error
	PersistExpiredPrepared(context.Context, ModelInvocation) (ModelInvocation, error)
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
		// Keep the recovery write bounded at 5s: the run-row lease admission no
		// longer holds this row, but a long write would still extend the
		// root/window contention. A failed write is deferred, never a missing amount.
		writeCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		err = nil
		// A cancellation may request reconciliation before an attempt is due.
		// An active deadline is a wait condition, not a failed recovery. Known
		// decisions/results take priority over any older deadline metadata.
		if record.Recovery != nil && record.Recovery.Decision == nil && record.Recovery.Event == nil &&
			(record.Recovery.SendDeadline.After(time.Now()) || record.Recovery.AdmissionUntil.After(time.Now())) {
			stop()
			continue
		}
		if record.RecoveryCorrupt {
			// Isolate one bad row; backoff below rotates it out of the next page.
			// 单条损坏记录只进入退避，不结算、不释放预算，也不阻断其他记录。
			err = errors.New("corrupt saved billing recovery")
		} else if record.Recovery != nil && record.Recovery.Decision == nil && record.Recovery.Event == nil && !record.Recovery.AdmissionUntil.IsZero() {
			hold, supported := m.modelBudgets.(usagecost.ModelBudgetReconciliationStore)
			if !supported || record.Recovery.AdmissionUntil.After(time.Now()) {
				err = ErrModelInvocationConflict
			} else {
				err = hold.MarkReconciliationNeeded(writeCtx, record.Recovery.Reservation)
				if err == nil {
					err = m.abortUnsentModel(writeCtx, record.ScopeHash, record.Key, record.Fingerprint, record.Recovery.Reservation, record.Recovery.AttemptToken)
				}
			}
		} else if record.Recovery != nil && record.Recovery.Decision == nil && record.Recovery.Event == nil && !record.Recovery.SendDeadline.IsZero() {
			hold, supported := m.modelBudgets.(usagecost.ModelBudgetReconciliationStore)
			lifecycle, durable := m.modelStore.(ModelSendLifecycleStore)
			if !supported || !durable || record.Recovery.SendDeadline.After(time.Now()) {
				err = errors.New("model send lifecycle unavailable")
			} else {
				err = hold.MarkReconciliationNeeded(writeCtx, record.Recovery.Reservation)
				if err == nil {
					if record.Recovery.SendPhase == "prepared" {
						if dispatch, ok := m.modelStore.(ModelDispatchStore); ok {
							var unsent ModelInvocation
							unsent, err = dispatch.PersistExpiredPrepared(writeCtx, record)
							if err == nil {
								release, supported := m.modelBudgets.(usagecost.ModelBudgetManualReleaseStore)
								if !supported {
									err = errors.New("unsent accounting unavailable")
								} else {
									err = release.ResolveUncharged(writeCtx, unsent.Recovery.Reservation, unsent.Recovery.Decision.ProviderRef)
									if err == nil {
										err = lifecycle.FinishUnsent(writeCtx, unsent)
									}
								}
							}
						} else {
							err = errors.New("model dispatch fence unavailable")
						}
					} else {
						err = lifecycle.PromoteExpiredSend(writeCtx, record)
					}
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
					// An owner-return proof can precede the first hold transition.
					// Replay the original transition before releasing its reservation.
					if strings.HasPrefix(record.Recovery.Decision.ID, "returned-") {
						if hold, ok := m.modelBudgets.(usagecost.ModelBudgetReconciliationStore); ok {
							err = hold.MarkReconciliationNeeded(writeCtx, record.Recovery.Reservation)
							if errors.Is(err, usagecost.ErrBudgetReservationClosed) {
								err = nil
							}
						} else {
							err = errors.New("original return hold recovery unavailable")
						}
					}
					if err == nil {
						err = release.ResolveUncharged(writeCtx, record.Recovery.Reservation, record.Recovery.Decision.ProviderRef)
					}
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
			log.Printf("model billing reconciliation failed code=BILLING_RECOVERY_WRITE_FAILED detail=%v", err)
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
	if !recovery.AdmissionUntil.IsZero() || record.Recovery != nil && !record.Recovery.AdmissionUntil.IsZero() && (!record.PreparationUntil.After(time.Now()) || !budgetRecoveryMatches(record.Recovery.Reservation, recovery.Reservation)) {
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
		if record.Status == "reconcile" && record.Recovery != nil && (record.Recovery.Event != nil || record.Recovery.Decision != nil || !record.Recovery.SendDeadline.IsZero() || !record.Recovery.AdmissionUntil.IsZero()) && !record.RetryAt.After(time.Now()) {
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
	if !recovery.AdmissionUntil.IsZero() {
		return ErrModelInvocationConflict
	}
	// A nil response is absence, not a JSON response containing null. Keep
	// the same SQL representation as MarkReconciliationNeeded so the atomic
	// dispatch fence can distinguish it from a real (even empty) response.
	var raw []byte
	var err error
	if response != nil {
		raw, err = json.Marshal(response)
		if err != nil {
			return err
		}
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
	reservationJSON, err := json.Marshal(recovery.Reservation)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET status='reconcile',response_json=?,cost_cents=?,billing_recovery_json=?,billing_state=?,billing_retry_at=?,updated_at=clock_timestamp() WHERE scope_hash=? AND idempotency_key=? AND fingerprint=? AND invocation_token=? AND status IN ('running','reconcile') AND (billing_state IN ('','manual','pending','inflight') OR billing_state='preparing' AND preparation_deadline>clock_timestamp() OR billing_state='admitted' AND preparation_deadline>clock_timestamp() AND billing_recovery_json::jsonb->'reservation'=?::jsonb)`), nullableJSON(raw), cost, string(intent), state, retryAt, scope, key, fingerprint, recovery.AttemptToken, string(reservationJSON))
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
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT scope_hash,idempotency_key,fingerprint,response_json,cost_cents,billing_recovery_json FROM platform_model_invocation WHERE status='reconcile' AND billing_state IN ('pending','decision_pending','inflight','admitted') AND (billing_retry_at IS NULL OR billing_retry_at<=clock_timestamp()) ORDER BY updated_at LIMIT ?`), limit)
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

// ExpediteBillingRecovery makes a run's in-doubt model calls immediately due for
// the existing reconciliation worker, so a finalizing run does not have to wait
// for a settlement backoff. Active sends and admissions retain their absolute
// deadline; making them due early cannot establish whether they were sent.
func (s *SQLModelInvocationStore) ExpediteBillingRecovery(ctx context.Context, scopeHash string) error {
	if s == nil || s.db == nil || len(scopeHash) != 64 {
		return nil
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation
SET billing_retry_at=clock_timestamp(),updated_at=clock_timestamp()
WHERE scope_hash=? AND status='reconcile'
  AND billing_state IN ('pending','decision_pending')
  AND (billing_retry_at IS NULL OR billing_retry_at>clock_timestamp())`), scopeHash)
	return err
}
