package execution

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var (
	ErrRunPermissionDenied   = errors.New("run permission denied")
	ErrBrowserSessionInvalid = errors.New("browser authentication session invalid")
)

type BrowserRunActor struct {
	Scope                  sharedkernel.Scope
	AuthenticationSession  string
	AuthenticationRevision uint64
}

type BrowserRunAuthorizer func(context.Context, sharedkernel.Scope, BrowserRunActor, string) error

func (m *Module) SetBrowserRunAuthorizer(authorize BrowserRunAuthorizer) {
	m.browserRunAuthorizer = authorize
}

func (m *Module) checkBrowserRunAccess(r *http.Request, owner sharedkernel.Scope, action string) error {
	actor := BrowserRunActor{Scope: sharedkernel.Scope{TenantID: r.Header.Get("X-Tenant-ID"), DepartmentID: r.Header.Get("X-Department-ID"), ApplicationID: r.Header.Get("X-Application-ID"), PrincipalType: r.Header.Get("X-Principal-Type"), PrincipalID: r.Header.Get("X-Principal-ID")}, AuthenticationSession: r.Header.Get("X-Authentication-Session")}
	if actor.Scope.Validate() != nil || actor.Scope.PrincipalType != "user" || actor.Scope.TenantID != owner.TenantID || actor.Scope.DepartmentID != owner.DepartmentID || actor.Scope.ApplicationID != owner.ApplicationID {
		return ErrRunPermissionDenied
	}
	if raw := r.Header.Get("X-Authentication-Revision"); raw != "" {
		revision, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || strconv.FormatUint(revision, 10) != raw {
			return ErrBrowserSessionInvalid
		}
		actor.AuthenticationRevision = revision
	}
	if m.browserRunAuthorizer == nil {
		return errors.New("browser run authority unavailable")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	return m.browserRunAuthorizer(ctx, owner, actor, action)
}

func (m *Module) writeBrowserRunPermissionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrBrowserSessionInvalid):
		w.Header().Set("X-Authentication-Error", "access_token_invalid")
		m.writeError(w, http.StatusUnauthorized, "SESSION_INVALID")
	case errors.Is(err, ErrRunPermissionDenied):
		m.writeError(w, http.StatusForbidden, "PERMISSION_DENIED")
	default:
		m.writeError(w, http.StatusServiceUnavailable, "AUTHORIZATION_UNAVAILABLE")
	}
}
