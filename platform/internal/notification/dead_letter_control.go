package notification

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Only monotonic IAM invalidations have a safe built-in redrive. UNKNOWN
// business effects require their owner's receipt, not a ledger reset.
func (s *SQLStore) PrepareControlEventRedriveTx(ctx context.Context, tx *sql.Tx, event Event, readRevision func(context.Context, *sql.Tx, string, string, string) (uint64, error)) error {
	if s == nil || tx == nil || readRevision == nil {
		return ErrDeadLetterUnavailable
	}
	kind, id, version, e := authorizationRevision(event)
	if e != nil {
		return ErrDeadLetterUnavailable
	}
	current, e := readRevision(ctx, tx, event.TenantID, kind, id)
	if e != nil {
		return e
	}
	if current == 0 || version > current {
		return ErrAuthorizationRevision
	}
	stored, e := getEventTx(ctx, tx, event.ID, true)
	if e != nil {
		return e
	}
	if !sameEventValue(stored, event) {
		return ErrDeadLetterConflict
	}
	if stored.Status != Published && stored.Status != Dead {
		return ErrDeadLetterConflict
	}
	var delivery string
	e = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_notification_delivery WHERE event_id=? FOR UPDATE`), event.ID).Scan(&delivery)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if e == nil && delivery != string(Dead) && delivery != string(Failed) {
		return ErrDeadLetterConflict
	}
	if e == nil {
		if _, e = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_notification_delivery SET status='failed',attempts=0,claim_owner='',claim_until=NULL,last_error='' WHERE event_id=?`), event.ID); e != nil {
			return e
		}
	}
	// Original ID/payload remain immutable; dead-letter and action history
	// retain prior attempts. Outbox dispatch submits the new transport attempt.
	_, e = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_notification_outbox SET status='pending',attempts=0,next_attempt_at=clock_timestamp(),claim_owner='',claim_until=NULL WHERE event_id=? AND status IN ('published','dead')`), event.ID)
	return e
}

func (m *Module) SetDeadLetterOperations(store *SQLDeadLetterStore, resolve func(*http.Request) (sharedkernel.Scope, error)) error {
	if m == nil || store == nil || resolve == nil {
		return ErrDeadLetterUnavailable
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.started || m.closed || m.deadLetters != nil {
		return ErrDeadLetterUnavailable
	}
	m.deadLetters, m.deadLetterActor = store, resolve
	return nil
}
func (m *Module) deadLetterList(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(r) {
		m.writeError(w, 401, "UNAUTHENTICATED")
		return
	}
	if m.deadLetters == nil || m.deadLetterActor == nil {
		m.writeError(w, 503, "DEAD_LETTER_CONTROL_UNAVAILABLE")
		return
	}
	if r.Method != http.MethodGet {
		m.writeError(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	scope, e := m.deadLetterActor(r)
	if e != nil {
		m.writeError(w, 403, "DEAD_LETTER_FORBIDDEN")
		return
	}
	limit := 25
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, e = strconv.Atoi(raw)
		if e != nil {
			m.writeError(w, 400, "INVALID_QUERY")
			return
		}
	}
	if limit < 1 || limit > 100 || (r.URL.Query().Get("after") != "" && !deadLetterDigest(r.URL.Query().Get("after"))) {
		m.writeError(w, 400, "INVALID_QUERY")
		return
	}
	include := r.URL.Query().Get("unscoped")
	if include != "" && include != "true" && include != "false" {
		m.writeError(w, 400, "INVALID_QUERY")
		return
	}
	items, e := m.deadLetters.List(r.Context(), scope, DeadLetterQuery{AfterID: r.URL.Query().Get("after"), Limit: limit, IncludeUnscoped: include == "true"})
	if e != nil {
		m.deadLetterError(w, e)
		return
	}
	next := ""
	if len(items) == limit {
		next = items[len(items)-1].ID
	}
	m.writeJSON(w, 200, map[string]any{"version": DeadLetterVersion, "items": items, "next": next})
}
func (m *Module) deadLetterAction(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(r) {
		m.writeError(w, 401, "UNAUTHENTICATED")
		return
	}
	if m.deadLetters == nil || m.deadLetterActor == nil {
		m.writeError(w, 503, "DEAD_LETTER_CONTROL_UNAVAILABLE")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/dead-letters/"), "/"), "/")
	if len(parts) != 2 || parts[1] != "actions" || r.Method != http.MethodPost {
		m.writeError(w, 404, "RESOURCE_NOT_FOUND")
		return
	}
	scope, e := m.deadLetterActor(r)
	if e != nil {
		m.writeError(w, 403, "DEAD_LETTER_FORBIDDEN")
		return
	}
	var c DeadLetterCommand
	if e = decode(r, &c); e != nil || c.ID != "" && c.ID != parts[0] {
		m.writeError(w, 400, "INVALID_REQUEST")
		return
	}
	c.ID = parts[0]
	meta, e := m.deadLetters.Act(r.Context(), scope, c)
	if e != nil {
		m.deadLetterError(w, e)
		return
	}
	m.writeJSON(w, 200, meta)
}
func (m *Module) deadLetterError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, ErrDeadLetterForbidden):
		m.writeError(w, 403, "DEAD_LETTER_CONTROL_DENIED")
	case errors.Is(e, ErrDeadLetterConflict):
		m.writeError(w, 409, "DEAD_LETTER_CONFLICT")
	case errors.Is(e, ErrDeadLetterUnavailable):
		m.writeError(w, 422, "DEAD_LETTER_OWNER_PROOF_REQUIRED")
	case errors.Is(e, ErrAuthorizationRevision):
		m.writeError(w, 409, "AUTHORIZATION_EVENT_VERSION_UNCONFIRMED")
	default:
		m.writeError(w, 503, "DEAD_LETTER_CONTROL_UNAVAILABLE")
	}
}
