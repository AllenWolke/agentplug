package usagecost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"io"
	"math"
	"strings"
	"time"
)

var (
	ErrBudgetReservationConflict = errors.New("model budget reservation conflicts with an existing request")
	ErrBudgetReservationExpired  = errors.New("model budget reservation has expired")
	ErrBudgetReservationClosed   = errors.New("model budget reservation is closed")
	ErrBudgetReservationNotFound = errors.New("model budget reservation not found")
	ErrBudgetScopeMismatch       = errors.New("model budget scope does not match reservation")
	ErrBudgetPriceVersion        = errors.New("model price version does not match reservation")
)

// ModelBudgetScope identifies the budget owner. Its fixed JSON field order is
// also the canonical input to the budget-window hash; it is not built by
// delimiter concatenation.
// ModelBudgetScope 标识预算主体；固定字段顺序的 JSON 用于生成窗口哈希，不拼接分隔符。
type ModelBudgetScope struct {
	TenantID       string `json:"tenant_id"`
	DepartmentID   string `json:"department_id"`
	ApplicationID  string `json:"application_id"`
	AgentID        string `json:"agent_id"`
	AgentVersionID string `json:"agent_version_id"`
}

type ModelBudgetWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ModelBudgetRequest is an immutable admission request. ExpiresAt is a lease
// boundary: after it, Reserve reclaims the held amount under the window lock
// and Settle rejects the expired reservation.
// ExpiresAt 是租约边界：过期后 Reserve 在窗口锁内回收预占，Settle 拒绝已过期租约。
type ModelBudgetRequest struct {
	Scope             ModelBudgetScope  `json:"scope"`
	RunID             string            `json:"run_id"`
	Window            ModelBudgetWindow `json:"window"`
	RequestID         string            `json:"request_id"`
	Fingerprint       string            `json:"fingerprint"`
	PriceVersionID    string            `json:"price_version_id"`
	BudgetLimitMicros int64             `json:"budget_limit_micros"`
	ReserveMicros     int64             `json:"reserve_micros"`
	ExpiresAt         time.Time         `json:"expires_at"`
}

type ModelBudgetReservation struct {
	ReservationID     string            `json:"reservation_id"`
	Scope             ModelBudgetScope  `json:"scope"`
	RunID             string            `json:"run_id"`
	Window            ModelBudgetWindow `json:"window"`
	RequestID         string            `json:"request_id"`
	Fingerprint       string            `json:"fingerprint"`
	PriceVersionID    string            `json:"price_version_id"`
	BudgetLimitMicros int64             `json:"budget_limit_micros"`
	ReserveMicros     int64             `json:"reserve_micros"`
	ExpiresAt         time.Time         `json:"expires_at"`
	Status            string            `json:"status"`
	EventID           string            `json:"event_id,omitempty"`
	SettledMicros     int64             `json:"settled_micros,omitempty"`
}

// ModelBudgetStore is the storage port used by model invocation admission.
// SQLStore implements it with per-window transactional locking. A remote
// Usage service can implement the same port if the platform is later split.
// ModelBudgetStore 是模型调用准入的存储端口；SQLStore 以窗口事务锁实现，多实例时可由远程 Usage 服务实现。
type ModelBudgetStore interface {
	Reserve(context.Context, ModelBudgetRequest) (ModelBudgetReservation, error)
	Settle(context.Context, ModelBudgetReservation, Event, string) (Snapshot, error)
	Release(context.Context, ModelBudgetReservation) error
}

// ModelBudgetReconciliationStore keeps a potentially billable reservation
// from expiring while its provider result awaits usage settlement.
type ModelBudgetReconciliationStore interface {
	MarkReconciliationNeeded(context.Context, ModelBudgetReservation) error
}

type modelBudgetCanonicalScope struct {
	TenantID       string `json:"tenant_id"`
	DepartmentID   string `json:"department_id"`
	ApplicationID  string `json:"application_id"`
	AgentID        string `json:"agent_id"`
	AgentVersionID string `json:"agent_version_id"`
}

type modelBudgetWindowKey struct {
	ScopeHash string    `json:"scope_hash"`
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
}

func canonicalBudgetScope(scope ModelBudgetScope) (string, string, error) {
	values := []string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID}
	legacyKeyLength := len(values) - 1
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value || len(value) > 128 || strings.ContainsAny(value, ":\x00") {
			return "", "", ErrInvalidUsage
		}
		legacyKeyLength += len(value)
	}
	if legacyKeyLength > 512 {
		return "", "", ErrInvalidUsage
	}
	encoded, err := json.Marshal(modelBudgetCanonicalScope{
		TenantID: scope.TenantID, DepartmentID: scope.DepartmentID,
		ApplicationID: scope.ApplicationID, AgentID: scope.AgentID,
		AgentVersionID: scope.AgentVersionID,
	})
	if err != nil {
		return "", "", fmt.Errorf("encode model budget scope: %w", err)
	}
	hash := sha256.Sum256(encoded)
	return string(encoded), hex.EncodeToString(hash[:]), nil
}

func modelBudgetWindowID(scopeHash string, window ModelBudgetWindow) (string, error) {
	key, err := json.Marshal(modelBudgetWindowKey{ScopeHash: scopeHash, Start: window.Start.UTC(), End: window.End.UTC()})
	if err != nil {
		return "", fmt.Errorf("encode model budget window: %w", err)
	}
	hash := sha256.Sum256(key)
	return hex.EncodeToString(hash[:]), nil
}

func normalizeBudgetWindow(window ModelBudgetWindow) ModelBudgetWindow {
	window.Start = window.Start.UTC().Truncate(time.Microsecond).Round(0)
	window.End = window.End.UTC().Truncate(time.Microsecond).Round(0)
	return window
}

func validModelBudgetRequest(request ModelBudgetRequest, now time.Time) (string, string, error) {
	scopeJSON, scopeHash, err := canonicalBudgetScope(request.Scope)
	if err != nil {
		return "", "", err
	}
	request.Window = normalizeBudgetWindow(request.Window)
	request.ExpiresAt = request.ExpiresAt.UTC().Truncate(time.Microsecond).Round(0)
	if request.Window.Start.IsZero() || request.Window.End.IsZero() || !request.Window.Start.Before(request.Window.End) ||
		request.BudgetLimitMicros < 0 || request.ReserveMicros < 0 || request.ExpiresAt.IsZero() ||
		!request.ExpiresAt.After(now) || request.ExpiresAt.After(request.Window.End) ||
		!validModelBudgetID(request.RunID) || !validModelBudgetID(request.RequestID) || !validModelBudgetID(request.PriceVersionID) ||
		!isSHA256Hex(request.Fingerprint) {
		return "", "", ErrInvalidUsage
	}
	windowID, err := modelBudgetWindowID(scopeHash, request.Window)
	return scopeJSON, windowID, err
}

func validModelBudgetID(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && len(value) <= 128 && !strings.ContainsAny(value, ":\x00")
}

func isSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func (s *SQLStore) modelBudgetNow() time.Time {
	if s != nil && s.now != nil {
		return s.now().UTC().Round(0)
	}
	return time.Now().UTC()
}

// Reserve locks the budget window row before reading/creating the request
// reservation. This serializes concurrent admission decisions for a single
// tenant/application/agent/version/window across platform instances.
func (s *SQLStore) Reserve(ctx context.Context, request ModelBudgetRequest) (ModelBudgetReservation, error) {
	if s == nil || s.db == nil {
		return ModelBudgetReservation{}, errors.New("usage database is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ModelBudgetReservation{}, fmt.Errorf("begin model budget reserve: %w", err)
	}
	defer tx.Rollback()
	reservation, err := s.ReserveTx(ctx, tx, request)
	if err != nil {
		return ModelBudgetReservation{}, err
	}
	if err := tx.Commit(); err != nil {
		return ModelBudgetReservation{}, fmt.Errorf("commit model budget reservation: %w", err)
	}
	return reservation, nil
}

// ReserveTx preserves the existing price-window admission rules while letting
// the composition layer reserve a verified root Run-tree budget in the SAME
// transaction. The caller owns commit and must roll back on any error. All
// participating calls must follow one common lock order (root, then window).
func (s *SQLStore) ReserveTx(ctx context.Context, tx *sql.Tx, request ModelBudgetRequest) (ModelBudgetReservation, error) {
	if s == nil || s.db == nil || tx == nil {
		return ModelBudgetReservation{}, errors.New("usage database is required")
	}
	now := s.modelBudgetNow()
	request.Window = normalizeBudgetWindow(request.Window)
	request.ExpiresAt = request.ExpiresAt.UTC().Truncate(time.Microsecond).Round(0)
	scopeJSON, windowID, err := validModelBudgetRequest(request, now)
	if err != nil {
		return ModelBudgetReservation{}, err
	}
	_, scopeHash, err := canonicalBudgetScope(request.Scope)
	if err != nil {
		return ModelBudgetReservation{}, err
	}
	if err := ensureBudgetWindowTx(ctx, tx, windowID, scopeHash, scopeJSON, request.Window, request.BudgetLimitMicros, now); err != nil {
		return ModelBudgetReservation{}, err
	}
	window, err := lockBudgetWindowTx(ctx, tx, windowID)
	if err != nil {
		return ModelBudgetReservation{}, err
	}
	if window.ScopeJSON != scopeJSON || window.ScopeHash != scopeHash || !sameBudgetWindow(window.Window, request.Window) {
		return ModelBudgetReservation{}, ErrBudgetReservationConflict
	}
	if err := reclaimExpiredReservationsTx(ctx, tx, &window, now); err != nil {
		return ModelBudgetReservation{}, err
	}
	existing, err := readBudgetReservationByRequestTx(ctx, tx, windowID, request.RequestID)
	if err == nil {
		if existing.windowID != windowID || !matchesBudgetRequest(existing.reservation, request) {
			return ModelBudgetReservation{}, ErrBudgetReservationConflict
		}
		if existing.reservation.Status == "expired" {
			return ModelBudgetReservation{}, ErrBudgetReservationExpired
		}
		if existing.reservation.Status == "released" {
			return ModelBudgetReservation{}, ErrBudgetReservationClosed
		}
		return existing.reservation, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ModelBudgetReservation{}, fmt.Errorf("lookup model budget request: %w", err)
	}
	// The trusted caller supplies the authenticated, frozen policy limit. A
	// newly published policy may change it inside this accounting window;
	// actual spend and all earlier holds still count against that request's
	// limit. Existing reservations retain their immutable admission evidence.
	limit := request.BudgetLimitMicros
	if window.ActualMicros > limit || window.ReservedMicros > limit-window.ActualMicros ||
		request.ReserveMicros > limit-window.ActualMicros-window.ReservedMicros {
		return ModelBudgetReservation{}, ErrBudgetExceeded
	}
	if request.ReserveMicros > math.MaxInt64-window.ReservedMicros {
		return ModelBudgetReservation{}, ErrInvalidUsage
	}
	reservationID, err := newBudgetReservationID()
	if err != nil {
		return ModelBudgetReservation{}, err
	}
	reservation := ModelBudgetReservation{
		ReservationID: reservationID, Scope: request.Scope, RunID: request.RunID,
		Window: request.Window, RequestID: request.RequestID, Fingerprint: strings.ToLower(request.Fingerprint),
		PriceVersionID: request.PriceVersionID, BudgetLimitMicros: request.BudgetLimitMicros,
		ReserveMicros: request.ReserveMicros, ExpiresAt: request.ExpiresAt, Status: "pending",
	}
	created := now
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_budget_reservation
		(reservation_id,window_id,tenant_id,department_id,application_id,agent_id,agent_version_id,run_id,
		request_id,request_fingerprint,price_version_id,budget_limit_micros,reserve_micros,settled_micros,
		status,event_id,terminal_reason,expires_at,created_at,updated_at,settled_at,released_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0,'pending','', '',?,?,?,NULL,NULL)`), reservation.ReservationID, windowID, request.Scope.TenantID, request.Scope.DepartmentID, request.Scope.ApplicationID,
		request.Scope.AgentID, request.Scope.AgentVersionID, request.RunID, request.RequestID, reservation.Fingerprint,
		request.PriceVersionID, request.BudgetLimitMicros, request.ReserveMicros, request.ExpiresAt, created, created)
	if err != nil {
		return ModelBudgetReservation{}, fmt.Errorf("create model budget reservation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_window SET budget_limit_micros=?,reserved_micros=?,revision=revision+1,updated_at=? WHERE window_id=?`), limit, window.ReservedMicros+request.ReserveMicros, now, windowID); err != nil {
		return ModelBudgetReservation{}, fmt.Errorf("reserve model budget amount: %w", err)
	}
	return reservation, nil
}

// Settle atomically persists the usage event and its aggregate snapshot while
// moving the reservation from in-flight reserved to actual spend. If the
// transaction fails, the pending reservation remains unchanged for retry.
// 已发生费用即使超过 estimate 也必须落账；超预算窗口会阻止后续 Reserve。
func (s *SQLStore) Settle(ctx context.Context, reservation ModelBudgetReservation, event Event, priceVersionID string) (Snapshot, error) {
	if s == nil || s.db == nil {
		return Snapshot{}, errors.New("usage database is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("begin model budget settlement: %w", err)
	}
	defer tx.Rollback()
	snapshot, err := s.SettleTx(ctx, tx, reservation, event, priceVersionID)
	// Preserve the standalone API's existing expiry transition. A composed
	// transaction must instead roll back on this error to avoid partial ledgers.
	if err != nil && !errors.Is(err, ErrBudgetReservationExpired) {
		return Snapshot{}, err
	}
	if commitErr := tx.Commit(); commitErr != nil {
		return Snapshot{}, fmt.Errorf("commit model budget settlement: %w", commitErr)
	}
	return snapshot, err
}

// SettleTx writes usage, window settlement and reservation in the caller's
// transaction. The caller must roll back on ANY error (including expiry).
func (s *SQLStore) SettleTx(ctx context.Context, tx *sql.Tx, reservation ModelBudgetReservation, event Event, priceVersionID string) (Snapshot, error) {
	if s == nil || s.db == nil || tx == nil {
		return Snapshot{}, errors.New("usage database is required")
	}
	if err := event.Validate(); err != nil {
		return Snapshot{}, err
	}
	if len(event.ID) > 128 || len(event.Provider) > 128 || len(event.Model) > 255 {
		return Snapshot{}, ErrInvalidUsage
	}
	if err := validateReservationEnvelope(reservation); err != nil {
		return Snapshot{}, err
	}
	if priceVersionID == "" || priceVersionID != reservation.PriceVersionID {
		return Snapshot{}, ErrBudgetPriceVersion
	}
	if !budgetScopeMatchesEvent(reservation, event.Scope) {
		return Snapshot{}, ErrBudgetScopeMismatch
	}
	scopeJSON, scopeHash, err := canonicalBudgetScope(reservation.Scope)
	if err != nil {
		return Snapshot{}, err
	}
	windowID, err := modelBudgetWindowID(scopeHash, normalizeBudgetWindow(reservation.Window))
	if err != nil {
		return Snapshot{}, err
	}
	window, err := lockBudgetWindowTx(ctx, tx, windowID)
	if err != nil {
		return Snapshot{}, err
	}
	if window.ScopeHash != scopeHash || window.ScopeJSON != scopeJSON || !sameBudgetWindow(window.Window, normalizeBudgetWindow(reservation.Window)) {
		return Snapshot{}, ErrBudgetScopeMismatch
	}
	stored, err := readBudgetReservationByIDTx(ctx, tx, reservation.ReservationID)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrBudgetReservationNotFound
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("lock model budget reservation: %w", err)
	}
	if stored.windowID != windowID || !sameReservationEnvelope(stored.reservation, reservation) {
		return Snapshot{}, ErrBudgetReservationConflict
	}
	if stored.reservation.PriceVersionID != priceVersionID {
		return Snapshot{}, ErrBudgetPriceVersion
	}
	if stored.reservation.Status == "settled" {
		if stored.reservation.EventID != event.ID || stored.reservation.SettledMicros != event.CostMicros {
			return Snapshot{}, ErrBudgetReservationConflict
		}
		if err := validateExistingEventTx(ctx, tx, event, priceVersionID, reservation.ReservationID); err != nil {
			return Snapshot{}, err
		}
		snapshot, err := readUsageSnapshotTx(ctx, tx, ScopeKey(event.Scope), false)
		if err != nil {
			return Snapshot{}, err
		}
		return snapshot, nil
	}
	now := s.modelBudgetNow()
	if stored.reservation.Status == "pending" && !stored.reservation.ExpiresAt.After(now) {
		if err := expireReservationTx(ctx, tx, &window, stored.reservation.ReservationID, stored.reservation.ReserveMicros, now); err != nil {
			return Snapshot{}, err
		}
		return Snapshot{}, ErrBudgetReservationExpired
	}
	if stored.reservation.Status != "pending" && stored.reservation.Status != "reconcile" {
		return Snapshot{}, ErrBudgetReservationClosed
	}
	key := ScopeKey(event.Scope)
	snapshot, err := readUsageSnapshotTx(ctx, tx, key, true)
	if err != nil {
		return Snapshot{}, err
	}
	if event.CostMicros > maxInt64-window.ActualMicros || window.ReservedMicros < stored.reservation.ReserveMicros {
		return Snapshot{}, ErrInvalidUsage
	}
	exists, err := existingUsageEventTx(ctx, tx, event)
	if err != nil {
		return Snapshot{}, err
	}
	if !exists {
		if event.CostMicros > maxInt64-snapshot.UsedMicros || event.InputTokens > maxInt64-snapshot.InputTokens || event.OutputTokens > maxInt64-snapshot.OutputTokens {
			return Snapshot{}, ErrInvalidUsage
		}
		created := s.modelBudgetNow()
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_usage_event(event_id,tenant_id,department_id,application_id,agent_id,agent_version_id,run_id,provider,model,input_tokens,output_tokens,cost_micros,step_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), event.ID, event.Scope.TenantID, event.Scope.DepartmentID, event.Scope.ApplicationID, event.Scope.AgentID,
			event.Scope.AgentVersionID, event.Scope.RunID, event.Provider, event.Model, event.InputTokens, event.OutputTokens, event.CostMicros, event.StepID, created); err != nil {
			return Snapshot{}, fmt.Errorf("record model usage event: %w", err)
		}
		snapshot.ScopeKey, snapshot.LastEventID = key, event.ID
		snapshot.UsedMicros += event.CostMicros
		snapshot.InputTokens += event.InputTokens
		snapshot.OutputTokens += event.OutputTokens
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_usage_snapshot(scope_key,last_event_id,used_micros,input_tokens,output_tokens,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT (scope_key) DO UPDATE SET last_event_id=EXCLUDED.last_event_id,used_micros=EXCLUDED.used_micros,input_tokens=EXCLUDED.input_tokens,output_tokens=EXCLUDED.output_tokens,updated_at=EXCLUDED.updated_at`), snapshot.ScopeKey, snapshot.LastEventID, snapshot.UsedMicros, snapshot.InputTokens, snapshot.OutputTokens, created); err != nil {
			return Snapshot{}, fmt.Errorf("update model usage snapshot: %w", err)
		}
	}
	settledAt := s.modelBudgetNow()
	newActual := window.ActualMicros + event.CostMicros
	newReserved := window.ReservedMicros - stored.reservation.ReserveMicros
	windowUpdate, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_window SET actual_micros=?,reserved_micros=?,revision=revision+1,updated_at=? WHERE window_id=?`), newActual, newReserved, settledAt, windowID)
	if err != nil {
		return Snapshot{}, fmt.Errorf("settle model budget window: %w", err)
	}
	if err := requireModelBudgetRow(windowUpdate); err != nil {
		return Snapshot{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_budget_settlement(reservation_id,event_id,price_version_id,settled_micros,settled_at) VALUES(?,?,?,?,?)`), reservation.ReservationID, event.ID, priceVersionID, event.CostMicros, settledAt); err != nil {
		return Snapshot{}, fmt.Errorf("record model budget settlement: %w", err)
	}
	reservationUpdate, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_reservation SET status='settled',event_id=?,settled_micros=?,terminal_reason='settled',updated_at=?,settled_at=? WHERE reservation_id=? AND status IN ('pending','reconcile')`), event.ID, event.CostMicros, settledAt, settledAt, reservation.ReservationID)
	if err != nil {
		return Snapshot{}, fmt.Errorf("mark model budget reservation settled: %w", err)
	}
	if err := requireModelBudgetRow(reservationUpdate); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

// MarkReconciliationNeeded turns an in-flight lease into a retained hold.
// Unlike an ordinary pending lease it cannot expire or be released, because
// the provider outcome may already be billable.
func (s *SQLStore) MarkReconciliationNeeded(ctx context.Context, reservation ModelBudgetReservation) error {
	if s == nil || s.db == nil {
		return errors.New("usage database is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin model budget reconciliation hold: %w", err)
	}
	defer tx.Rollback()
	if err := s.MarkReconciliationNeededTx(ctx, tx, reservation); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit model budget reconciliation hold: %w", err)
	}
	return nil
}

// MarkReconciliationNeededTx participates in the caller's transaction; it does not commit.
// The caller must roll back on any error and use the common root/window order.
func (s *SQLStore) MarkReconciliationNeededTx(ctx context.Context, tx *sql.Tx, reservation ModelBudgetReservation) error {
	if s == nil || s.db == nil || tx == nil {
		return errors.New("usage database is required")
	}
	if err := validateReservationEnvelope(reservation); err != nil {
		return err
	}
	scopeJSON, scopeHash, err := canonicalBudgetScope(reservation.Scope)
	if err != nil {
		return err
	}
	window := normalizeBudgetWindow(reservation.Window)
	windowID, err := modelBudgetWindowID(scopeHash, window)
	if err != nil {
		return err
	}
	lockedWindow, err := lockBudgetWindowTx(ctx, tx, windowID)
	if err != nil {
		return err
	}
	if lockedWindow.ScopeJSON != scopeJSON || lockedWindow.ScopeHash != scopeHash || !sameBudgetWindow(lockedWindow.Window, window) {
		return ErrBudgetScopeMismatch
	}
	stored, err := readBudgetReservationByIDTx(ctx, tx, reservation.ReservationID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBudgetReservationNotFound
	}
	if err != nil {
		return fmt.Errorf("lock model budget reservation: %w", err)
	}
	if stored.windowID != windowID || !sameReservationEnvelope(stored.reservation, reservation) {
		return ErrBudgetReservationConflict
	}
	switch stored.reservation.Status {
	case "reconcile":
		return nil
	case "pending":
	default:
		return ErrBudgetReservationClosed
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_reservation SET status='reconcile',terminal_reason='billing_reconciliation',updated_at=? WHERE reservation_id=? AND status='pending'`), s.modelBudgetNow(), reservation.ReservationID)
	if err != nil {
		return fmt.Errorf("mark model budget reservation for reconciliation: %w", err)
	}
	if err := requireModelBudgetRow(result); err != nil {
		return err
	}
	return nil
}

// Release is idempotent for already released or expired leases. Settled
// reservations cannot be released because that would erase actual spend.
func (s *SQLStore) Release(ctx context.Context, reservation ModelBudgetReservation) error {
	if s == nil || s.db == nil {
		return errors.New("usage database is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin model budget release: %w", err)
	}
	defer tx.Rollback()
	if err := s.ReleaseTx(ctx, tx, reservation); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit model budget release: %w", err)
	}
	return nil
}

// ReleaseTx participates in the caller's transaction; it does not commit.
// The caller must roll back on any error and use the common root/window order.
func (s *SQLStore) ReleaseTx(ctx context.Context, tx *sql.Tx, reservation ModelBudgetReservation) error {
	if s == nil || s.db == nil || tx == nil {
		return errors.New("usage database is required")
	}
	if err := validateReservationEnvelope(reservation); err != nil {
		return err
	}
	scopeJSON, scopeHash, err := canonicalBudgetScope(reservation.Scope)
	if err != nil {
		return err
	}
	window := normalizeBudgetWindow(reservation.Window)
	windowID, err := modelBudgetWindowID(scopeHash, window)
	if err != nil {
		return err
	}
	lockedWindow, err := lockBudgetWindowTx(ctx, tx, windowID)
	if err != nil {
		return err
	}
	if lockedWindow.ScopeJSON != scopeJSON || lockedWindow.ScopeHash != scopeHash || !sameBudgetWindow(lockedWindow.Window, window) {
		return ErrBudgetScopeMismatch
	}
	stored, err := readBudgetReservationByIDTx(ctx, tx, reservation.ReservationID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBudgetReservationNotFound
	}
	if err != nil {
		return fmt.Errorf("lock model budget reservation: %w", err)
	}
	if stored.windowID != windowID || !sameReservationEnvelope(stored.reservation, reservation) {
		return ErrBudgetReservationConflict
	}
	switch stored.reservation.Status {
	case "released", "expired":
		return nil
	case "settled":
		return ErrBudgetReservationClosed
	case "pending":
	default:
		return ErrBudgetReservationClosed
	}
	now := s.modelBudgetNow()
	if !stored.reservation.ExpiresAt.After(now) {
		if err := expireReservationTx(ctx, tx, &lockedWindow, reservation.ReservationID, stored.reservation.ReserveMicros, now); err != nil {
			return err
		}
	} else {
		if lockedWindow.ReservedMicros < stored.reservation.ReserveMicros {
			return ErrInvalidUsage
		}
		windowUpdate, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_window SET reserved_micros=?,revision=revision+1,updated_at=? WHERE window_id=?`), lockedWindow.ReservedMicros-stored.reservation.ReserveMicros, now, windowID)
		if err != nil {
			return fmt.Errorf("release model budget amount: %w", err)
		}
		if err := requireModelBudgetRow(windowUpdate); err != nil {
			return err
		}
		reservationUpdate, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_reservation SET status='released',terminal_reason='client_release',updated_at=?,released_at=? WHERE reservation_id=? AND status='pending'`), now, now, reservation.ReservationID)
		if err != nil {
			return fmt.Errorf("mark model budget reservation released: %w", err)
		}
		if err := requireModelBudgetRow(reservationUpdate); err != nil {
			return err
		}
	}
	return nil
}

type modelBudgetWindowRow struct {
	WindowID       string
	ScopeJSON      string
	ScopeHash      string
	Window         ModelBudgetWindow
	LimitMicros    int64
	ActualMicros   int64
	ReservedMicros int64
}

type modelBudgetStoredReservation struct {
	reservation ModelBudgetReservation
	windowID    string
}

func ensureBudgetWindowTx(ctx context.Context, tx *sql.Tx, id, scopeHash, scopeJSON string, window ModelBudgetWindow, limit int64, now time.Time) error {
	_, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_budget_window(window_id,scope_hash,scope_json,window_start,window_end,budget_limit_micros,actual_micros,reserved_micros,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,0,0,1,?,?) ON CONFLICT (scope_hash,window_start,window_end) DO UPDATE SET window_id=EXCLUDED.window_id`), id, scopeHash, scopeJSON, window.Start, window.End, limit, now, now)
	if err != nil {
		return fmt.Errorf("ensure model budget window: %w", err)
	}
	return nil
}

func lockBudgetWindowTx(ctx context.Context, tx *sql.Tx, id string) (modelBudgetWindowRow, error) {
	var row modelBudgetWindowRow
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT window_id,scope_hash,scope_json,window_start,window_end,budget_limit_micros,actual_micros,reserved_micros FROM platform_model_budget_window WHERE window_id=? FOR UPDATE`), id).
		Scan(&row.WindowID, &row.ScopeHash, &row.ScopeJSON, &row.Window.Start, &row.Window.End, &row.LimitMicros, &row.ActualMicros, &row.ReservedMicros)
	if errors.Is(err, sql.ErrNoRows) {
		return modelBudgetWindowRow{}, ErrBudgetReservationNotFound
	}
	if err != nil {
		return modelBudgetWindowRow{}, fmt.Errorf("lock model budget window: %w", err)
	}
	row.Window.Start = row.Window.Start.UTC()
	row.Window.End = row.Window.End.UTC()
	if row.LimitMicros < 0 || row.ActualMicros < 0 || row.ReservedMicros < 0 {
		return modelBudgetWindowRow{}, ErrInvalidUsage
	}
	return row, nil
}

func readBudgetReservationByRequestTx(ctx context.Context, tx *sql.Tx, windowID, requestID string) (modelBudgetStoredReservation, error) {
	return scanModelBudgetReservation(tx.QueryRowContext(ctx, sqlutil.Bind(reservationSelect+` WHERE r.window_id=? AND r.request_id=? FOR UPDATE`), windowID, requestID))
}

func readBudgetReservationByIDTx(ctx context.Context, tx *sql.Tx, id string) (modelBudgetStoredReservation, error) {
	return scanModelBudgetReservation(tx.QueryRowContext(ctx, sqlutil.Bind(reservationSelect+` WHERE r.reservation_id=? FOR UPDATE`), id))
}

const reservationSelect = `SELECT r.reservation_id,r.window_id,r.tenant_id,r.department_id,r.application_id,r.agent_id,r.agent_version_id,r.run_id,r.request_id,r.request_fingerprint,r.price_version_id,r.budget_limit_micros,r.reserve_micros,r.settled_micros,r.status,r.event_id,r.expires_at,w.window_start,w.window_end FROM platform_model_budget_reservation r JOIN platform_model_budget_window w ON w.window_id=r.window_id`

func scanModelBudgetReservation(scanner interface{ Scan(...any) error }) (modelBudgetStoredReservation, error) {
	var result modelBudgetStoredReservation
	var settledMicros int64
	err := scanner.Scan(&result.reservation.ReservationID, &result.windowID, &result.reservation.Scope.TenantID, &result.reservation.Scope.DepartmentID, &result.reservation.Scope.ApplicationID, &result.reservation.Scope.AgentID, &result.reservation.Scope.AgentVersionID, &result.reservation.RunID, &result.reservation.RequestID, &result.reservation.Fingerprint, &result.reservation.PriceVersionID, &result.reservation.BudgetLimitMicros, &result.reservation.ReserveMicros, &settledMicros, &result.reservation.Status, &result.reservation.EventID, &result.reservation.ExpiresAt, &result.reservation.Window.Start, &result.reservation.Window.End)
	if err != nil {
		return modelBudgetStoredReservation{}, err
	}
	result.reservation.SettledMicros = settledMicros
	result.reservation.ExpiresAt = result.reservation.ExpiresAt.UTC()
	result.reservation.Window = normalizeBudgetWindow(result.reservation.Window)
	return result, nil
}

func matchesBudgetRequest(existing ModelBudgetReservation, request ModelBudgetRequest) bool {
	return existing.Scope == request.Scope && existing.RunID == request.RunID && sameBudgetWindow(existing.Window, request.Window) &&
		existing.RequestID == request.RequestID && existing.Fingerprint == strings.ToLower(request.Fingerprint) &&
		existing.PriceVersionID == request.PriceVersionID && existing.BudgetLimitMicros == request.BudgetLimitMicros &&
		existing.ReserveMicros == request.ReserveMicros && existing.ExpiresAt.Equal(request.ExpiresAt)
}

func validateReservationEnvelope(reservation ModelBudgetReservation) error {
	if !validModelBudgetID(reservation.ReservationID) || !validModelBudgetID(reservation.RunID) || !validModelBudgetID(reservation.RequestID) ||
		!validModelBudgetID(reservation.PriceVersionID) || !isSHA256Hex(reservation.Fingerprint) || reservation.BudgetLimitMicros < 0 ||
		reservation.ReserveMicros < 0 || reservation.ExpiresAt.IsZero() || !reservation.Window.Start.Before(reservation.Window.End) {
		return ErrInvalidUsage
	}
	_, _, err := canonicalBudgetScope(reservation.Scope)
	return err
}

func sameReservationEnvelope(a, b ModelBudgetReservation) bool {
	return a.ReservationID == b.ReservationID && a.Scope == b.Scope && a.RunID == b.RunID &&
		sameBudgetWindow(normalizeBudgetWindow(a.Window), normalizeBudgetWindow(b.Window)) && a.RequestID == b.RequestID &&
		a.Fingerprint == strings.ToLower(b.Fingerprint) && a.PriceVersionID == b.PriceVersionID &&
		a.BudgetLimitMicros == b.BudgetLimitMicros && a.ReserveMicros == b.ReserveMicros && a.ExpiresAt.Equal(b.ExpiresAt)
}

func budgetScopeMatchesEvent(reservation ModelBudgetReservation, scope Scope) bool {
	return reservation.Scope.TenantID == scope.TenantID && reservation.Scope.DepartmentID == scope.DepartmentID &&
		reservation.Scope.ApplicationID == scope.ApplicationID && reservation.Scope.AgentID == scope.AgentID &&
		reservation.Scope.AgentVersionID == scope.AgentVersionID && reservation.RunID == scope.RunID
}

func sameBudgetWindow(a, b ModelBudgetWindow) bool {
	a, b = normalizeBudgetWindow(a), normalizeBudgetWindow(b)
	return a.Start.Equal(b.Start) && a.End.Equal(b.End)
}

func newBudgetReservationID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", fmt.Errorf("generate model budget reservation id: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func reclaimExpiredReservationsTx(ctx context.Context, tx *sql.Tx, window *modelBudgetWindowRow, now time.Time) error {
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT reservation_id,reserve_micros FROM platform_model_budget_reservation WHERE window_id=? AND status='pending' AND expires_at<=? FOR UPDATE`), window.WindowID, now)
	if err != nil {
		return fmt.Errorf("list expired model budget reservations: %w", err)
	}
	type expired struct {
		id     string
		amount int64
	}
	var expiredRows []expired
	var total int64
	for rows.Next() {
		var item expired
		if err := rows.Scan(&item.id, &item.amount); err != nil {
			rows.Close()
			return fmt.Errorf("scan expired model budget reservation: %w", err)
		}
		if item.amount < 0 || item.amount > maxInt64-total {
			rows.Close()
			return ErrInvalidUsage
		}
		total += item.amount
		expiredRows = append(expiredRows, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate expired model budget reservations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if total == 0 {
		return nil
	}
	if total > window.ReservedMicros {
		return ErrInvalidUsage
	}
	for _, item := range expiredRows {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_reservation SET status='expired',terminal_reason='lease_expired',updated_at=?,released_at=? WHERE reservation_id=? AND status='pending'`), now, now, item.id); err != nil {
			return fmt.Errorf("expire model budget reservation: %w", err)
		}
	}
	window.ReservedMicros -= total
	windowUpdate, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_window SET reserved_micros=?,revision=revision+1,updated_at=? WHERE window_id=?`), window.ReservedMicros, now, window.WindowID)
	if err != nil {
		return fmt.Errorf("reclaim expired model budget amount: %w", err)
	}
	if err := requireModelBudgetRow(windowUpdate); err != nil {
		return err
	}
	return nil
}

func expireReservationTx(ctx context.Context, tx *sql.Tx, window *modelBudgetWindowRow, reservationID string, amount int64, now time.Time) error {
	if amount < 0 || amount > window.ReservedMicros {
		return ErrInvalidUsage
	}
	window.ReservedMicros -= amount
	windowUpdate, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_window SET reserved_micros=?,revision=revision+1,updated_at=? WHERE window_id=?`), window.ReservedMicros, now, window.WindowID)
	if err != nil {
		return fmt.Errorf("reclaim expired reservation amount: %w", err)
	}
	if err := requireModelBudgetRow(windowUpdate); err != nil {
		return err
	}
	reservationUpdate, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_reservation SET status='expired',terminal_reason='lease_expired',updated_at=?,released_at=? WHERE reservation_id=? AND status='pending'`), now, now, reservationID)
	if err != nil {
		return fmt.Errorf("mark reservation expired: %w", err)
	}
	if err := requireModelBudgetRow(reservationUpdate); err != nil {
		return err
	}
	return nil
}

func requireModelBudgetRow(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read model budget affected rows: %w", err)
	}
	if rows != 1 {
		return ErrBudgetReservationConflict
	}
	return nil
}

func readUsageSnapshotTx(ctx context.Context, tx *sql.Tx, scopeKey string, initialize bool) (Snapshot, error) {
	if initialize {
		// Materialize an empty row before taking the lock so concurrent
		// settlements from different budget periods serialize on the same
		// aggregate snapshot. Do not initialize on idempotent replay: a missing
		// snapshot after a committed settlement indicates corruption.
		// 插入零值锚点后再锁行，避免不同周期的并发结算丢失累计值。
		now := time.Now().UTC()
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_usage_snapshot(scope_key,last_event_id,used_micros,input_tokens,output_tokens,updated_at) VALUES(?,'',0,0,0,?) ON CONFLICT (scope_key) DO UPDATE SET scope_key=EXCLUDED.scope_key`), scopeKey, now); err != nil {
			return Snapshot{}, fmt.Errorf("ensure usage snapshot row: %w", err)
		}
	}
	var snapshot Snapshot
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT scope_key,last_event_id,used_micros,input_tokens,output_tokens FROM platform_usage_snapshot WHERE scope_key=? FOR UPDATE`), scopeKey).Scan(&snapshot.ScopeKey, &snapshot.LastEventID, &snapshot.UsedMicros, &snapshot.InputTokens, &snapshot.OutputTokens)
	if errors.Is(err, sql.ErrNoRows) {
		if !initialize {
			return Snapshot{}, ErrInvalidUsage
		}
		return Snapshot{ScopeKey: scopeKey}, nil
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("lock usage snapshot: %w", err)
	}
	if snapshot.UsedMicros < 0 || snapshot.InputTokens < 0 || snapshot.OutputTokens < 0 {
		return Snapshot{}, ErrInvalidUsage
	}
	return snapshot, nil
}

func existingUsageEventTx(ctx context.Context, tx *sql.Tx, event Event) (bool, error) {
	var existing Event
	var stepID sql.NullString
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT tenant_id,department_id,application_id,agent_id,agent_version_id,run_id,provider,model,input_tokens,output_tokens,cost_micros,step_id FROM platform_usage_event WHERE event_id=? FOR UPDATE`), event.ID).Scan(
		&existing.Scope.TenantID, &existing.Scope.DepartmentID, &existing.Scope.ApplicationID, &existing.Scope.AgentID, &existing.Scope.AgentVersionID,
		&existing.Scope.RunID, &existing.Provider, &existing.Model, &existing.InputTokens, &existing.OutputTokens, &existing.CostMicros, &stepID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lookup existing model usage event: %w", err)
	}
	if stepID.Valid {
		existing.StepID = &stepID.String
	}
	if existing.Scope != event.Scope || existing.Provider != event.Provider || existing.Model != event.Model || existing.InputTokens != event.InputTokens || existing.OutputTokens != event.OutputTokens || existing.CostMicros != event.CostMicros || !compatibleStepID(existing.StepID, event.StepID) {
		return false, ErrUsageConflict
	}
	return true, nil
}

func validateExistingEventTx(ctx context.Context, tx *sql.Tx, event Event, priceVersionID, reservationID string) error {
	if _, err := existingUsageEventTx(ctx, tx, event); err != nil {
		return err
	}
	var storedPriceVersion string
	var storedEventID string
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT event_id,price_version_id FROM platform_model_budget_settlement WHERE reservation_id=? FOR UPDATE`), reservationID).Scan(&storedEventID, &storedPriceVersion)
	if err != nil {
		return fmt.Errorf("lookup existing model settlement: %w", err)
	}
	if storedEventID != event.ID || storedPriceVersion != priceVersionID {
		return ErrBudgetReservationConflict
	}
	return nil
}

func windowIDFromReservation(reservation ModelBudgetReservation) (string, error) {
	_, hash, err := canonicalBudgetScope(reservation.Scope)
	if err != nil {
		return "", err
	}
	return modelBudgetWindowID(hash, normalizeBudgetWindow(reservation.Window))
}

var _ ModelBudgetStore = (*SQLStore)(nil)
var _ ModelBudgetReconciliationStore = (*SQLStore)(nil)
