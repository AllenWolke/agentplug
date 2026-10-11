package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type eventContextSigner interface {
	SignEvent(context.Context, sharedkernel.Scope, contract.EventRequest) (string, error)
}

func (m *Module) SetEventReadAuthority(authorize func(context.Context, sharedkernel.Scope, string) error) {
	m.eventReadAuthority = authorize
}

// eventCapability grants only metadata events for the original caller's Run.
// The durable platform history API remains the route for other authorized
// reviewers; this endpoint cannot mint a token impersonating a Run owner.
func (m *Module) eventCapability(w http.ResponseWriter, r *http.Request, runID string) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		m.writeError(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if r.Header.Get("X-Browser-Module") != "1" {
		m.writeError(w, 403, "BROWSER_AUTHENTICATION_REQUIRED")
		return
	}
	var input struct {
		AfterSeq uint64 `json:"after_seq"`
	}
	body, readErr := io.ReadAll(io.LimitReader(r.Body, 4097))
	if readErr != nil || len(body) > 4096 {
		m.writeError(w, 413, "REQUEST_TOO_LARGE")
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		m.writeError(w, 400, "INVALID_REQUEST")
		return
	}
	_, request, err := m.authorizedEventRequest(r, runID, input.AfterSeq)
	if err != nil {
		m.writeEventAccessError(w, err)
		return
	}
	m.writeJSON(w, 200, map[string]any{"request": request, "transport": "agent-execution/v2", "metadata_only": true})
}

type eventAccessError struct {
	status int
	code   string
}

func (e eventAccessError) Error() string { return e.code }
func (m *Module) writeEventAccessError(w http.ResponseWriter, err error) {
	if access, ok := err.(eventAccessError); ok {
		m.writeError(w, access.status, access.code)
		return
	}
	m.writeBrowserRunPermissionError(w, err)
}

// authorizedEventRequest is shared by the explicit token API and the private
// Agent metadata proxy. The browser supplies only a cursor, never an endpoint.
func (m *Module) authorizedEventRequest(r *http.Request, runID string, afterSeq uint64) (platformruntime.Run, contract.EventRequest, error) {
	if afterSeq > contract.MaxAgentEventSequence {
		return platformruntime.Run{}, contract.EventRequest{}, eventAccessError{400, "INVALID_REQUEST"}
	}
	if r.Header.Get("X-Browser-Module") != "1" {
		return platformruntime.Run{}, contract.EventRequest{}, eventAccessError{403, "BROWSER_AUTHENTICATION_REQUIRED"}
	}
	var run platformruntime.Run
	var request contract.EventRequest
	signer, ok := m.machineSigner.(eventContextSigner)
	if !ok || m.eventReadAuthority == nil || m.authorizationEpoch == nil {
		return run, request, eventAccessError{503, "EVENT_AUTHORIZATION_UNAVAILABLE"}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	var err error
	if store, ok := m.store.(interface {
		GetContext(context.Context, string) (platformruntime.Run, error)
	}); ok {
		run, err = store.GetContext(ctx, runID)
	} else {
		run, err = m.store.Get(runID)
	}
	if err != nil || run.Scope.PrincipalType != "user" || r.Header.Get("X-Principal-Type") != "user" || r.Header.Get("X-Principal-ID") != run.Scope.PrincipalID {
		return run, request, eventAccessError{404, "RESOURCE_NOT_FOUND"}
	}
	if err := m.checkBrowserRunAccess(r, run.Scope, "history.read"); err != nil {
		return run, request, err
	}
	command, err := m.store.GetDispatchCommand(runID)
	if err != nil || command.RunID != runID {
		return run, request, eventAccessError{409, "EVENT_RUN_UNCONFIRMED"}
	}
	scope := run.Scope
	epoch, err := m.authorizationEpoch(ctx, scope, "history.read")
	if err != nil || epoch == 0 {
		return run, request, eventAccessError{403, "PERMISSION_DENIED"}
	}
	scope.AuthorizationEpoch = epoch
	if m.eventReadAuthority(ctx, scope, command.PolicyHash) != nil {
		return run, request, eventAccessError{403, "PERMISSION_DENIED"}
	}
	var original contract.ExecuteRequest
	if json.Unmarshal(run.RequestJSON, &original) != nil {
		return run, request, eventAccessError{409, "EVENT_RUN_UNCONFIRMED"}
	}
	request = contract.EventRequest{ProtocolVersion: contract.ProtocolVersion, AfterSeq: afterSeq,
		PolicySnapshotHash: command.PolicyHash, Scope: contract.ScopeKey{
			TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
			InstallationID: scope.InstallationID, AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID,
			AgentVersionID: scope.AgentVersionID, PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID,
			SessionID: scope.SessionID, RunID: scope.RunID, ParentRunID: scope.ParentRunID,
			TraceID: scope.TraceID, AuthorizationEpoch: epoch, DelegationDepth: original.Scope.DelegationDepth,
		}}
	token, err := signer.SignEvent(ctx, scope, request)
	if err != nil || token == "" {
		return run, request, eventAccessError{503, "EVENT_AUTHORIZATION_UNAVAILABLE"}
	}
	// Re-authenticate the browser session and current caller/machine boundaries
	// before returning an event-only token; never change the original Run scope.
	if err := m.checkBrowserRunAccess(r, run.Scope, "history.read"); err != nil {
		return run, request, err
	}
	if ctx.Err() != nil || m.eventReadAuthority(ctx, scope, command.PolicyHash) != nil {
		return run, request, eventAccessError{403, "PERMISSION_DENIED"}
	}
	request.ContextToken = token
	return run, request, nil
}
