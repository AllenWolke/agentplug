package identity

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

var ErrAuthorizationReceiptNotFound = errors.New("authorization receipt not found")

// Optional read port: legacy repositories retain their existing write contract.
type AuthorizationReceiptReader interface {
	QueryAuthorizationReceipt(context.Context, sharedkernel.Scope, string, string) (AuthorizationChangeReceipt, error)
}

func validAuthorizationReceiptQuery(key, plan string) bool {
	if len(plan) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(plan)
	return key != "" && len(key) <= 128 && strings.TrimSpace(key) == key && len(decoded) == 32 && err == nil && strings.ToLower(plan) == plan
}

func (s *SQLStore) QueryAuthorizationReceipt(ctx context.Context, actor sharedkernel.Scope, key, plan string) (AuthorizationChangeReceipt, error) {
	empty := AuthorizationChangeReceipt{}
	if s == nil || s.db == nil {
		return empty, ErrPermissionRecorderUnavailable
	}
	if actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) || !validAuthorizationReceiptQuery(key, plan) {
		return empty, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := s.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return empty, err
	}
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return empty, err
	}
	if owner.Mode != "v2" || !owner.Principal.IsActive {
		return empty, ErrPermissionDenied
	}
	identity := permissionHash([]byte(actor.PrincipalID + "\x00" + key))
	var saved []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT receipt FROM platform_identity_authorization_change WHERE idempotency_hash=?`), identity).Scan(&saved)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, ErrAuthorizationReceiptNotFound
	}
	if err != nil {
		return empty, err
	}
	var receipt AuthorizationChangeReceipt
	if len(saved) > 4<<20 || json.Unmarshal(saved, &receipt) != nil || receipt.ID != "change-"+identity || receipt.ActorID != actor.PrincipalID || receipt.Change.IdempotencyKey != key || receipt.SubjectID != receipt.Change.SubjectID || receipt.Revision != receipt.Change.ExpectedRevision+1 {
		return empty, ErrIdentityConflict
	}
	// Check current management authority even when the exact plan is not found.
	// Holding shared continuity prevents a concurrent revocation from committing
	// between this check and the body-free lookup's completion.
	if err := authorizeReceiptRead(ctx, tx, owner, receipt, s.clock().UTC()); err != nil {
		return empty, err
	}
	if receipt.PlanDigest != plan {
		return empty, ErrAuthorizationReceiptNotFound
	}
	if err := authorizeReceiptRead(ctx, tx, owner, receipt, s.clock().UTC()); err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return receipt, nil
}

func (m *Module) permissionReceipt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, repo, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 2 || len(query["idempotency_key"]) != 1 || len(query["plan_digest"]) != 1 || !validAuthorizationReceiptQuery(query.Get("idempotency_key"), query.Get("plan_digest")) {
		m.error(w, http.StatusBadRequest, "INVALID_RECEIPT_QUERY")
		return
	}
	reader, ok := repo.(AuthorizationReceiptReader)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "AUTHORIZATION_RECEIPT_READ_UNAVAILABLE")
		return
	}
	receipt, err := reader.QueryAuthorizationReceipt(r.Context(), actor.Scope, query.Get("idempotency_key"), query.Get("plan_digest"))
	if err != nil {
		m.permissionError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	m.json(w, http.StatusOK, receipt)
}
