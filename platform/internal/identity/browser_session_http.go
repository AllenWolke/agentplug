package identity

import (
	"context"
	"errors"
	"net/http"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type BrowserSessionRepository interface {
	ValidateBrowserSession(context.Context, sharedkernel.Scope, string, uint64) error
}

func (m *Module) browserSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !m.requireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost || r.Header.Get("X-Browser-Module") != "" {
		m.error(w, http.StatusForbidden, "AUTHENTICATION_GATEWAY_ONLY")
		return
	}
	store, ok := m.store.(BrowserSessionRepository)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "AUTHENTICATION_SESSION_UNAVAILABLE")
		return
	}
	var input struct {
		Scope     sharedkernel.Scope `json:"scope"`
		SessionID string             `json:"session_id"`
		Revision  uint64             `json:"auth_revision"`
	}
	if decode(r, &input) != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	err := store.ValidateBrowserSession(r.Context(), input.Scope, input.SessionID, input.Revision)
	if errors.Is(err, ErrRefreshSessionRejected) {
		m.error(w, http.StatusUnauthorized, "AUTHENTICATION_SESSION_REJECTED")
		return
	}
	if err != nil {
		m.error(w, http.StatusServiceUnavailable, "AUTHENTICATION_SESSION_UNAVAILABLE")
		return
	}
	m.json(w, http.StatusOK, map[string]bool{"valid": true})
}
