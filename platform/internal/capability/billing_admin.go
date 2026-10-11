package capability

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/sqlutil"
)

type BillingRecordView struct {
	ScopeHash     string           `json:"scope_hash"`
	Key           string           `json:"idempotency_key"`
	Fingerprint   string           `json:"fingerprint"`
	State         string           `json:"state"`
	TenantID      string           `json:"tenant_id"`
	ApplicationID string           `json:"application_id"`
	AgentID       string           `json:"agent_id"`
	ReservationID string           `json:"reservation_id"`
	ReserveMicros int64            `json:"reserve_micros"`
	Decision      *BillingDecision `json:"decision,omitempty"`
}

type modelBillingAdminStore interface {
	ModelBillingDecisionStore
	ListBillingManual(context.Context) ([]BillingRecordView, error)
}

func (m *Module) SetModelBillingAuthorizer(control modelgovernance.Authorizer) {
	m.billingControl = control
}

func (m *Module) authorizeBilling(w http.ResponseWriter, r *http.Request) (modelgovernance.Actor, bool) {
	actor := modelgovernance.Actor{TenantID: strings.TrimSpace(r.Header.Get("X-Tenant-ID")), DepartmentID: strings.TrimSpace(r.Header.Get("X-Department-ID")), ApplicationID: strings.TrimSpace(r.Header.Get("X-Application-ID")), PrincipalType: strings.TrimSpace(r.Header.Get("X-Principal-Type")), PrincipalID: strings.TrimSpace(r.Header.Get("X-Principal-ID")), Browser: true}
	if m.internalToken == "" || !hmac.Equal([]byte(m.internalToken), []byte(r.Header.Get("X-Internal-Token"))) || r.Header.Get("X-Browser-Module") != "1" {
		m.error(w, http.StatusUnauthorized, "UNAUTHENTICATED", "trusted browser session is required", "")
		return actor, false
	}
	if actor.PrincipalType != "user" || actor.PrincipalID == "" || actor.TenantID == "" || m.billingControl == nil {
		m.error(w, http.StatusForbidden, "FORBIDDEN", "model billing administrator is required", "")
		return actor, false
	}
	if err := m.billingControl.AuthorizeModelGovernance(r.Context(), actor, modelgovernance.ActionApprove, modelgovernance.Scope{}); err != nil {
		status, code := http.StatusServiceUnavailable, "IDENTITY_UNAVAILABLE"
		if errors.Is(err, modelgovernance.ErrForbidden) {
			status, code = http.StatusForbidden, "FORBIDDEN"
		}
		m.error(w, status, code, "model billing authorization denied", "")
		return actor, false
	}
	return actor, true
}

func (m *Module) billingAdmin(w http.ResponseWriter, r *http.Request) {
	actor, ok := m.authorizeBilling(w, r)
	if !ok {
		return
	}
	store, ok := m.modelStore.(modelBillingAdminStore)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "BILLING_ADMIN_UNAVAILABLE", "durable billing store is required", "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if r.Method == http.MethodGet {
		items, err := store.ListBillingManual(ctx)
		if err != nil {
			m.error(w, http.StatusServiceUnavailable, "BILLING_READ_FAILED", "billing records unavailable", "")
			return
		}
		m.ok(w, map[string]any{"items": items}, "")
		return
	}
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET or POST required", "")
		return
	}
	var input struct {
		ScopeHash   string          `json:"scope_hash"`
		Key         string          `json:"idempotency_key"`
		Fingerprint string          `json:"fingerprint"`
		Decision    BillingDecision `json:"decision"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || len(input.ScopeHash) != 64 || input.Key == "" || len(input.Key) > 255 || len(input.Fingerprint) != 64 || input.Decision.ActorID != "" || input.Decision.ActorTenant != "" {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid billing decision", "")
		return
	}
	// Actor is exclusively projected from the authenticated gateway session.
	// 决策主体只能从受信网关会话投影，禁止请求正文伪造审批人。
	input.Decision.ActorID, input.Decision.ActorTenant = actor.PrincipalID, actor.TenantID
	if !validBillingDecision(input.Decision) {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "provider receipt and valid outcome required", "")
		return
	}
	if err := store.AcceptBillingDecision(ctx, input.ScopeHash, input.Key, input.Fingerprint, input.Decision); err != nil {
		status, code := http.StatusServiceUnavailable, "BILLING_DECISION_SAVE_FAILED"
		if errors.Is(err, ErrModelInvocationConflict) {
			status, code = http.StatusConflict, "BILLING_DECISION_CONFLICT"
		} else if errors.Is(err, sql.ErrNoRows) {
			status, code = http.StatusNotFound, "NOT_FOUND"
		}
		m.error(w, status, code, "billing decision was not accepted", "")
		return
	}
	m.ok(w, map[string]any{"status": "accepted", "decision_id": input.Decision.ID}, "")
}

func (s *SQLModelInvocationStore) ListBillingManual(ctx context.Context) ([]BillingRecordView, error) {
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT scope_hash,idempotency_key,fingerprint,billing_state,billing_recovery_json FROM platform_model_invocation WHERE billing_state IN ('manual','decision_pending','resolved') ORDER BY updated_at DESC LIMIT 100`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BillingRecordView{}
	for rows.Next() {
		var item BillingRecordView
		var raw string
		if err := rows.Scan(&item.ScopeHash, &item.Key, &item.Fingerprint, &item.State, &raw); err != nil {
			return nil, err
		}
		var intent BillingRecovery
		if err := json.Unmarshal([]byte(raw), &intent); err != nil {
			return nil, errors.New("corrupt billing record")
		}
		item.TenantID, item.ApplicationID, item.AgentID = intent.Reservation.Scope.TenantID, intent.Reservation.Scope.ApplicationID, intent.Reservation.Scope.AgentID
		item.ReservationID, item.ReserveMicros, item.Decision = intent.Reservation.ReservationID, intent.Reservation.ReserveMicros, intent.Decision
		out = append(out, item)
	}
	return out, rows.Err()
}
