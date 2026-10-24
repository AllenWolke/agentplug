package usagecost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type RunTreeModelBinding struct {
	Scope      sharedkernel.Scope
	Request    ModelBudgetRequest
	HoldTokens int64
}

// UniqueFailedPreparationAdmissionTx supplies accounting metadata to the model
// module's legacy pre-send recovery. It grants no send or release authority.
// The caller separately proves the preparation's durable terminal transition.
func (s *SQLRunTreeBudgetStore) UniqueFailedPreparationAdmissionTx(ctx context.Context, tx *sql.Tx, r ModelBudgetReservation, started, failed time.Time) (bool, error) {
	if started.IsZero() || failed.Before(started) {
		return false, ErrInvalidUsage
	}
	if _, err := s.ModelBindingTx(ctx, tx, r); err != nil {
		return false, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT count(*) FROM platform_model_budget_reservation WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND run_id=? AND request_fingerprint=?`), r.Scope.TenantID, r.Scope.DepartmentID, r.Scope.ApplicationID, r.Scope.AgentID, r.Scope.AgentVersionID, r.RunID, r.Fingerprint).Scan(&count); err != nil {
		return false, err
	}
	if count != 1 {
		return false, nil
	}
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT count(*) FROM platform_model_budget_reservation WHERE reservation_id=? AND request_id=? AND status='pending' AND COALESCE(event_id,'')='' AND created_at>=? AND created_at<=?`), r.ReservationID, r.RequestID, started, failed).Scan(&count)
	return count == 1, err
}

func modelBindingKey(scope ModelBudgetScope, runID, requestID string) string {
	raw, _ := json.Marshal([]any{scope, runID, requestID})
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

// SaveModelBindingTx follows verified tree admission in the SAME transaction.
// It retains original identity/parameters, never credentials or prompt text.
func (s *SQLRunTreeBudgetStore) SaveModelBindingTx(ctx context.Context, tx *sql.Tx, rootKey string, scope sharedkernel.Scope, request ModelBudgetRequest, tokens int64) error {
	// Match the existing price-window SQL envelope's UTC microsecond precision.
	request.Window = normalizeBudgetWindow(request.Window)
	request.ExpiresAt = request.ExpiresAt.UTC().Truncate(time.Microsecond).Round(0)
	if s == nil || tx == nil || !treeHash(rootKey) || !treeModelScopeMatches(scope, request.Scope, request.RunID) || tokens < 0 {
		return ErrBudgetScopeMismatch
	}
	encodedScope, err := json.Marshal(scope)
	if err != nil || len(encodedScope) > 16384 {
		return ErrInvalidUsage
	}
	encodedRequest, err := json.Marshal(request)
	if err != nil || len(encodedRequest) > 16384 {
		return ErrInvalidUsage
	}
	actorKey := treeScopeKey(scope)
	var fingerprint, status string
	var heldMicros, heldTokens int64
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT fingerprint,status,hold_micros,hold_tokens FROM platform_run_tree_budget_request WHERE root_key=? AND actor_key=? AND request_id=? FOR SHARE`), rootKey, actorKey, request.RequestID).Scan(&fingerprint, &status, &heldMicros, &heldTokens)
	if err != nil {
		return err
	}
	if fingerprint != request.Fingerprint || status != "held" || heldMicros != request.ReserveMicros || heldTokens != tokens {
		return ErrBudgetReservationConflict
	}
	key := modelBindingKey(request.Scope, request.RunID, request.RequestID)
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_run_tree_model_binding(binding_key,root_key,actor_key,request_id,scope_json,request_json,hold_tokens) VALUES(?,?,?,?,?,?,?) ON CONFLICT(binding_key) DO NOTHING`), key, rootKey, actorKey, request.RequestID, string(encodedScope), string(encodedRequest), tokens)
	if err != nil {
		return err
	}
	stored, storedRoot, err := s.readModelBindingTx(ctx, tx, key)
	if err != nil {
		return err
	}
	// Dynamic Trace/epoch never change the original owner or admission envelope.
	if storedRoot != rootKey || treeScopeKey(stored.Scope) != actorKey || stored.HoldTokens != tokens || stored.Request != request {
		return ErrBudgetReservationConflict
	}
	return nil
}

// ModelBindingTx reads original metadata for trusted accounting composition.
// It grants neither result access nor permission for another provider send.
// These reads must not lock request/binding rows before ApplyTx locks the root.
// Admission publishes this immutable envelope atomically; accounting changes
// only request status/counters, which ApplyTx rechecks under root -> request
// UPDATE locks. Taking SHARE here lets foreground and recovery transactions
// both hold the request while one holds the root and waits to upgrade it.
func (s *SQLRunTreeBudgetStore) ModelBindingTx(ctx context.Context, tx *sql.Tx, reservation ModelBudgetReservation) (RunTreeModelBinding, error) {
	if s == nil || tx == nil || validateReservationEnvelope(reservation) != nil {
		return RunTreeModelBinding{}, ErrInvalidUsage
	}
	stored, _, err := s.readModelBindingTx(ctx, tx, modelBindingKey(reservation.Scope, reservation.RunID, reservation.RequestID))
	if err != nil {
		return RunTreeModelBinding{}, err
	}
	if !matchesBudgetRequest(reservation, stored.Request) || !sameBudgetWindow(reservation.Window, stored.Request.Window) {
		return RunTreeModelBinding{}, ErrBudgetReservationConflict
	}
	var storedID sql.NullString
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT reservation_id FROM platform_run_tree_model_binding WHERE binding_key=?`), modelBindingKey(reservation.Scope, reservation.RunID, reservation.RequestID)).Scan(&storedID); err != nil {
		return RunTreeModelBinding{}, err
	}
	if !storedID.Valid || storedID.String != reservation.ReservationID {
		return RunTreeModelBinding{}, ErrBudgetReservationConflict
	}
	return stored, nil
}

func (s *SQLRunTreeBudgetStore) readModelBindingTx(ctx context.Context, tx *sql.Tx, key string) (RunTreeModelBinding, string, error) {
	var result RunTreeModelBinding
	var rootKey, actorKey, requestID, scopeJSON, requestJSON string
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT root_key,actor_key,request_id,scope_json,request_json,hold_tokens FROM platform_run_tree_model_binding WHERE binding_key=?`), key).Scan(&rootKey, &actorKey, &requestID, &scopeJSON, &requestJSON, &result.HoldTokens)
	if err != nil {
		return result, "", err
	}
	decode := func(raw string, value any) bool {
		if len(raw) > 16384 {
			return false
		}
		d := json.NewDecoder(bytes.NewBufferString(raw))
		d.DisallowUnknownFields()
		return d.Decode(value) == nil && d.Decode(new(any)) == io.EOF
	}
	if !decode(scopeJSON, &result.Scope) || !decode(requestJSON, &result.Request) || result.HoldTokens < 0 || !treeHash(rootKey) || !treeModelScopeMatches(result.Scope, result.Request.Scope, result.Request.RunID) || treeScopeKey(result.Scope) != actorKey || result.Request.RequestID != requestID || modelBindingKey(result.Request.Scope, result.Request.RunID, requestID) != key {
		return RunTreeModelBinding{}, "", ErrBudgetReservationConflict
	}
	var fingerprint, runID string
	var micros, tokens int64
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT fingerprint,run_id,hold_micros,hold_tokens FROM platform_run_tree_budget_request WHERE root_key=? AND actor_key=? AND request_id=?`), rootKey, actorKey, requestID).Scan(&fingerprint, &runID, &micros, &tokens)
	if err != nil {
		return result, "", err
	}
	if fingerprint != result.Request.Fingerprint || runID != result.Scope.RunID || micros != result.Request.ReserveMicros || tokens != result.HoldTokens {
		return RunTreeModelBinding{}, "", ErrBudgetReservationConflict
	}
	return result, rootKey, nil
}

// SaveModelReservationTx fixes the exact price-window reservation alongside its
// original actor binding. It runs after price admission and before joint commit.
func (s *SQLRunTreeBudgetStore) SaveModelReservationTx(ctx context.Context, tx *sql.Tx, reservation ModelBudgetReservation) error {
	if s == nil || tx == nil || validateReservationEnvelope(reservation) != nil {
		return ErrInvalidUsage
	}
	key := modelBindingKey(reservation.Scope, reservation.RunID, reservation.RequestID)
	binding, _, err := s.readModelBindingTx(ctx, tx, key)
	if err != nil {
		return err
	}
	if !matchesBudgetRequest(reservation, binding.Request) || !sameBudgetWindow(reservation.Window, binding.Request.Window) {
		return ErrBudgetReservationConflict
	}
	raw, err := json.Marshal(reservation)
	if err != nil || len(raw) > 16384 {
		return ErrInvalidUsage
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_run_tree_model_binding SET reservation_id=?,reservation_json=? WHERE binding_key=? AND (reservation_id IS NULL OR reservation_id=?)`), reservation.ReservationID, string(raw), key, reservation.ReservationID)
	if err != nil {
		return err
	}
	return requireModelBudgetRow(result)
}

// ModelReservationTx resolves the immutable original price reservation without
// accepting a reservation ID from an untrusted Agent or exposing credentials.
func (s *SQLRunTreeBudgetStore) ModelReservationTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, requestID string) (ModelBudgetReservation, error) {
	if s == nil || tx == nil || scope.ValidateTrusted() != nil {
		return ModelBudgetReservation{}, ErrBudgetScopeMismatch
	}
	budgetScope := ModelBudgetScope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID}
	var id, raw sql.NullString
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT reservation_id,reservation_json FROM platform_run_tree_model_binding WHERE binding_key=?`), modelBindingKey(budgetScope, scope.RunID, requestID)).Scan(&id, &raw); err != nil {
		return ModelBudgetReservation{}, err
	}
	var reservation ModelBudgetReservation
	if !id.Valid || !raw.Valid || len(raw.String) > 16384 {
		return reservation, ErrBudgetReservationConflict
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw.String))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&reservation) != nil || decoder.Decode(new(any)) != io.EOF || reservation.ReservationID != id.String || reservation.RequestID != requestID {
		return ModelBudgetReservation{}, ErrBudgetReservationConflict
	}
	binding, err := s.ModelBindingTx(ctx, tx, reservation)
	if err != nil {
		return ModelBudgetReservation{}, err
	}
	if treeScopeKey(binding.Scope) != treeScopeKey(scope) {
		return ModelBudgetReservation{}, ErrBudgetScopeMismatch
	}
	return reservation, nil
}
