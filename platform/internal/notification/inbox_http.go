package notification

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func (m *Module) SetRecipientInbox(inbox *SQLInboxChannel, resolve func(*http.Request) (sharedkernel.Scope, error), authorize func(context.Context, *sql.Tx, sharedkernel.Scope) error) error {
	if m == nil || inbox == nil || resolve == nil || authorize == nil {
		return ErrAdapterUnavailable
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.started || m.closed || m.inbox != nil {
		return ErrConflict
	}
	m.inbox, m.inboxActor, m.inboxAuthorize = inbox, resolve, authorize
	return nil
}
func (m *Module) recipientInbox(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(r) {
		m.writeError(w, 401, "UNAUTHENTICATED")
		return
	}
	if r.Method != http.MethodGet {
		m.writeError(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if m.inbox == nil || m.inboxActor == nil || m.inboxAuthorize == nil {
		m.writeError(w, 503, "INBOX_UNAVAILABLE")
		return
	}
	// Recipient/workspace is determined exclusively by authenticated context.
	for key := range r.URL.Query() {
		if key != "limit" {
			m.writeError(w, 400, "INVALID_QUERY")
			return
		}
	}
	limit := 25
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			m.writeError(w, 400, "INVALID_QUERY")
			return
		}
		limit = n
	}
	scope, err := m.inboxActor(r)
	if err != nil {
		m.writeError(w, 403, "INBOX_FORBIDDEN")
		return
	}
	items, err := m.inbox.ReadRecipientInbox(r.Context(), scope, limit, m.inboxAuthorize)
	if err != nil {
		m.writeError(w, 403, "INBOX_READ_UNCONFIRMED")
		return
	}
	m.writeJSON(w, 200, map[string]any{"version": InboxChannelVersion, "items": items})
}
