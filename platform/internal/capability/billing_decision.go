package capability

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

type BillingDecision struct {
	ID            string `json:"id"`
	ActorID       string `json:"actor_id"`
	ActorTenant   string `json:"actor_tenant"`
	Outcome       string `json:"outcome"`
	Reason        string `json:"reason"`
	ProviderRef   string `json:"provider_ref"`
	ReservationID string `json:"reservation_id"`
	Provider      string `json:"provider,omitempty"`
	Model         string `json:"model,omitempty"`
	InputTokens   int64  `json:"input_tokens,omitempty"`
	OutputTokens  int64  `json:"output_tokens,omitempty"`
	CostMicros    int64  `json:"cost_micros,omitempty"`
}

type ModelBillingDecisionStore interface {
	GetBillingRecord(context.Context, string, string) (ModelInvocation, error)
	AcceptBillingDecision(context.Context, string, string, string, BillingDecision) error
	FinishBillingDecision(context.Context, ModelInvocation) error
}

func validBillingDecision(d BillingDecision) bool {
	return d.ID != "" && len(d.ID) <= 64 && d.ReservationID != "" && len(d.ReservationID) <= 128 && d.ActorID != "" && len(d.ActorID) <= 128 && d.ActorTenant != "" && len(d.ActorTenant) <= 128 &&
		strings.TrimSpace(d.Reason) != "" && len(d.Reason) <= 1024 && strings.TrimSpace(d.ProviderRef) != "" && len(d.ProviderRef) <= 256 &&
		(d.Outcome == "no_charge" && d.CostMicros == 0 && d.InputTokens == 0 && d.OutputTokens == 0 ||
			d.Outcome == "charged" && strings.TrimSpace(d.Provider) != "" && len(d.Provider) <= 128 && strings.TrimSpace(d.Model) != "" && len(d.Model) <= 128 && d.CostMicros >= 0 && d.InputTokens >= 0 && d.OutputTokens >= 0)
}

func decisionIntent(record ModelInvocation, d BillingDecision) (BillingRecovery, error) {
	if !validBillingDecision(d) || record.Recovery == nil || d.ReservationID != record.Recovery.Reservation.ReservationID || record.Recovery.Decision != nil || record.Recovery.Event != nil || record.Response != nil || record.Status != "reconcile" {
		return BillingRecovery{}, ErrModelInvocationConflict
	}
	intent := *record.Recovery
	intent.SendDeadline = time.Time{}
	intent.Decision = &d
	if d.Outcome == "charged" {
		r := intent.Reservation
		digest := sha256.Sum256([]byte(r.ReservationID + "\x00" + d.ID))
		scope := usagecost.Scope{TenantID: r.Scope.TenantID, DepartmentID: r.Scope.DepartmentID, ApplicationID: r.Scope.ApplicationID, AgentID: r.Scope.AgentID, AgentVersionID: r.Scope.AgentVersionID, RunID: r.RunID}
		intent.Event = &usagecost.Event{ID: "manual-" + hex.EncodeToString(digest[:]), StepID: usagecost.StableModelUsageStepID(scope, r.RequestID), Scope: scope, Provider: d.Provider, Model: d.Model, InputTokens: d.InputTokens, OutputTokens: d.OutputTokens, CostMicros: d.CostMicros}
	}
	return intent, nil
}

func (s *SQLModelInvocationStore) GetBillingRecord(ctx context.Context, scope, key string) (ModelInvocation, error) {
	var r ModelInvocation
	var response, intent sql.NullString
	r.ScopeHash, r.Key = scope, key
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT fingerprint,status,response_json,cost_cents,billing_recovery_json FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key=?`), scope, key).Scan(&r.Fingerprint, &r.Status, &response, &r.CostCents, &intent)
	if err != nil {
		return r, err
	}
	if response.Valid && json.Unmarshal([]byte(response.String), &r.Response) != nil || intent.Valid && json.Unmarshal([]byte(intent.String), &r.Recovery) != nil {
		return r, errors.New("corrupt billing record")
	}
	return r, nil
}

func (s *SQLModelInvocationStore) AcceptBillingDecision(ctx context.Context, scope, key, fingerprint string, d BillingDecision) error {
	return s.acceptBillingDecision(ctx, scope, key, fingerprint, d, "manual", "")
}

type preparedBillingProof struct {
	Recovery      BillingRecovery
	OwnerReturned bool // Private handler proof, never accepted from an HTTP body.
}

func (s *SQLModelInvocationStore) acceptBillingDecision(ctx context.Context, scope, key, fingerprint string, d BillingDecision, expectedState, attemptToken string, prepared ...preparedBillingProof) error {
	if !validBillingDecision(d) {
		return ErrModelInvocationConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var r ModelInvocation
	var response, intent sql.NullString
	var billingState string
	r.ScopeHash, r.Key = scope, key
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT fingerprint,status,response_json,billing_recovery_json,billing_state FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key=? FOR UPDATE`), scope, key).Scan(&r.Fingerprint, &r.Status, &response, &intent, &billingState); err != nil {
		return err
	}
	if r.Fingerprint != fingerprint || !intent.Valid || json.Unmarshal([]byte(intent.String), &r.Recovery) != nil || response.Valid && json.Unmarshal([]byte(response.String), &r.Response) != nil || r.Recovery == nil {
		return ErrModelInvocationConflict
	}
	systemUnsent := attemptToken != ""
	if (expectedState == "inflight" || expectedState == "admitted" || systemUnsent) && (attemptToken == "" || r.Recovery.AttemptToken != attemptToken) {
		return ErrModelInvocationConflict
	}
	ownerReturned := len(prepared) == 1 && prepared[0].OwnerReturned
	if expectedState == "admitted" && (r.Recovery.AdmissionUntil.IsZero() || !ownerReturned && r.Recovery.AdmissionUntil.After(time.Now()) || !r.Recovery.SendDeadline.IsZero()) {
		return ErrModelInvocationConflict
	}
	if expectedState == "manual" && systemUnsent {
		expected, err := unsentDecision(r, attemptToken)
		if err != nil || modelRouteHash(expected) != modelRouteHash(d) {
			return ErrModelInvocationConflict
		}
	}
	rawDecision, err := json.Marshal(d)
	if err != nil {
		return err
	}
	// Exact retries read the durable audit, never accept a second decision.
	// 精确重试读取持久化审计，不接受第二个不同决策。
	var existing string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT decision_json FROM platform_model_billing_decision WHERE scope_hash=? AND idempotency_key=? AND reservation_id=?`), scope, key, r.Recovery.Reservation.ReservationID).Scan(&existing)
	if err == nil {
		if existing != string(rawDecision) {
			return ErrModelInvocationConflict
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err // Preserve database failures; 数据库失败不能伪装成决策冲突。
	}
	if billingState != expectedState {
		return ErrModelInvocationConflict
	}
	if len(prepared) > 0 {
		if len(prepared) != 1 {
			return ErrModelInvocationConflict
		}
		if ownerReturned {
			expectedDecision, proofErr := returnedBeforeDispatchDecision(r, attemptToken)
			if proofErr != nil || modelRouteHash(expectedDecision) != modelRouteHash(d) {
				return ErrModelInvocationConflict
			}
		} else if r.Recovery.SendPhase != "prepared" || r.Recovery.SendDeadline.IsZero() || r.Recovery.SendDeadline.After(time.Now()) {
			return ErrModelInvocationConflict
		}
		expected, err := json.Marshal(prepared[0].Recovery)
		actual, actualErr := json.Marshal(r.Recovery)
		if err != nil || actualErr != nil || string(expected) != string(actual) {
			return ErrModelInvocationConflict
		}
	}
	recovery, err := decisionIntent(r, d)
	if err != nil {
		return err
	}
	if expectedState == "inflight" || expectedState == "admitted" || systemUnsent {
		recovery.Unsent = true
		recovery.AdmissionUntil = time.Time{}
	}
	raw, err := json.Marshal(recovery)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_billing_decision(scope_hash,idempotency_key,reservation_id,decision_id,decision_json,status,created_at) VALUES(?,?,?,?,?,'accepted',clock_timestamp())`), scope, key, recovery.Reservation.ReservationID, d.ID, string(rawDecision)); err != nil {
		return err
	}
	updated, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET billing_recovery_json=?,billing_state='decision_pending',billing_retry_at=NULL,updated_at=clock_timestamp() WHERE scope_hash=? AND idempotency_key=? AND fingerprint=? AND billing_state=? AND status='reconcile'`), string(raw), scope, key, fingerprint, expectedState)
	if err != nil {
		return err
	}
	if n, err := updated.RowsAffected(); err != nil || n != 1 {
		return ErrModelInvocationConflict
	}
	return tx.Commit()
}

func (s *SQLModelInvocationStore) FinishBillingDecision(ctx context.Context, r ModelInvocation) error {
	if r.Recovery == nil || r.Recovery.Decision == nil {
		return ErrModelInvocationConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentIntent sql.NullString
	var state, storedFingerprint string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT billing_recovery_json,billing_state,fingerprint FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key=? FOR UPDATE`), r.ScopeHash, r.Key).Scan(&currentIntent, &state, &storedFingerprint); err != nil {
		return err
	}
	expectedIntent, err := json.Marshal(r.Recovery)
	if err != nil || !currentIntent.Valid || currentIntent.String != string(expectedIntent) || storedFingerprint != r.Fingerprint {
		return ErrModelInvocationConflict
	}
	status, cents := "reconcile", int64(0)
	if r.Recovery.Decision.Outcome == "no_charge" {
		status = "failed" // Safe retry only after explicit provider proof; 明确未计费才允许重试。
	} else {
		cents = ceilModelCostCents(r.Recovery.Decision.CostMicros)
	}
	raw, err := json.Marshal(r.Recovery.Decision)
	if err != nil {
		return err
	}
	var accepted string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT decision_json FROM platform_model_billing_decision WHERE scope_hash=? AND idempotency_key=? AND reservation_id=? FOR UPDATE`), r.ScopeHash, r.Key, r.Recovery.Reservation.ReservationID).Scan(&accepted); err != nil {
		return err
	}
	if accepted != string(raw) {
		return ErrModelInvocationConflict
	}
	if state == "resolved" {
		return tx.Commit()
	}
	if state != "decision_pending" {
		return ErrModelInvocationConflict
	}
	updated, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET status=?,cost_cents=?,billing_state='resolved',updated_at=clock_timestamp() WHERE scope_hash=? AND idempotency_key=? AND fingerprint=? AND billing_state='decision_pending'`), status, cents, r.ScopeHash, r.Key, r.Fingerprint)
	if err != nil {
		return err
	}
	if n, err := updated.RowsAffected(); err != nil || n != 1 {
		return ErrModelInvocationConflict
	}
	updated, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_billing_decision SET status='applied',applied_at=clock_timestamp() WHERE scope_hash=? AND idempotency_key=? AND reservation_id=? AND decision_id=? AND status='accepted'`), r.ScopeHash, r.Key, r.Recovery.Reservation.ReservationID, r.Recovery.Decision.ID)
	if err != nil {
		return err
	}
	if n, err := updated.RowsAffected(); err != nil || n != 1 {
		return ErrModelInvocationConflict
	}
	return tx.Commit()
}
