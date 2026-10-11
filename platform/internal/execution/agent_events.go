package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/contract"
)

type agentEventGateway interface {
	Events(context.Context, agentgateway.Target, contract.EventRequest) (agentgateway.EventStream, error)
}

// agentEvents is a bounded, owner-only metadata snapshot. It does not append
// Agent sequence numbers to the platform's independent durable event stream.
func (m *Module) agentEvents(w http.ResponseWriter, r *http.Request, runID string) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		m.writeError(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var cursor uint64
	if raw := r.URL.Query().Get("after_seq"); raw != "" {
		var err error
		cursor, err = strconv.ParseUint(raw, 10, 64)
		if err != nil || cursor > contract.MaxAgentEventSequence {
			m.writeError(w, 400, "INVALID_REQUEST")
			return
		}
	}
	if m.dispatcher == nil || m.machineTarget == nil {
		m.writeError(w, 503, "AGENT_EVENT_GATEWAY_UNAVAILABLE")
		return
	}
	gateway, ok := m.dispatcher.gateway.(agentEventGateway)
	if !ok {
		m.writeError(w, 503, "AGENT_EVENT_GATEWAY_UNAVAILABLE")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	run, request, err := m.authorizedEventRequest(r, runID, cursor)
	if err != nil {
		m.writeEventAccessError(w, err)
		return
	}
	var original contract.ExecuteRequest
	if json.Unmarshal(run.RequestJSON, &original) != nil {
		m.writeError(w, 409, "EVENT_RUN_UNCONFIRMED")
		return
	}
	target, err := targetFromRun(run, original)
	if err != nil {
		m.writeError(w, 409, "EVENT_RUN_UNCONFIRMED")
		return
	}
	resolveTarget := func() (uint64, bool) {
		lookupCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		current, err := m.machineTarget.ResolveMachineTarget(lookupCtx, run.Scope)
		return current.Revision, err == nil && lookupCtx.Err() == nil && current.Revision > 0 &&
			current.InstallationID == target.InstallationID && current.AgentID == target.AgentID &&
			current.VersionID == target.AgentVersionID && current.Endpoint == target.Endpoint
	}
	revision, ready := resolveTarget()
	if !ready {
		m.writeError(w, 409, "EVENT_TARGET_UNCONFIRMED")
		return
	}
	target.Revision = revision
	stream, err := gateway.Events(ctx, target, request)
	if err != nil || stream.Close == nil || stream.Events == nil || stream.Errors == nil {
		if stream.Close != nil {
			_ = stream.Close()
		}
		m.writeError(w, 502, "AGENT_EVENT_READ_UNCONFIRMED")
		return
	}
	defer stream.Close()
	eventScope := run.Scope
	eventScope.AuthorizationEpoch = request.Scope.AuthorizationEpoch
	controller := http.NewResponseController(w)
	started := false
	fail := func(code string) {
		if !started {
			m.writeError(w, 502, code)
			return
		}
		_ = controller.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = fmt.Fprintf(w, "event: stream_error\ndata: {\"code\":%q}\n\n", code)
		_ = controller.Flush()
	}
	check := func() bool {
		if ctx.Err() != nil || m.checkBrowserRunAccess(r, run.Scope, "history.read") != nil {
			return false
		}
		if current, ready := resolveTarget(); !ready || current != revision {
			return false
		}
		checkCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		return m.eventReadAuthority(checkCtx, eventScope, request.PolicySnapshotHash) == nil && checkCtx.Err() == nil
	}
	// Continue checking even when an Agent is silent; disconnect/revocation must
	// close the upstream transport without leaking a late buffered observation.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	events, failures := stream.Events, stream.Errors
	count := 0
	for events != nil || failures != nil {
		select {
		case <-ctx.Done():
			fail("AGENT_EVENT_READ_UNCONFIRMED")
			return
		case <-ticker.C:
			if !check() {
				fail("EVENT_READ_UNCONFIRMED")
				return
			}
		case err, open := <-failures:
			if !open {
				failures = nil
				continue
			}
			if err != nil {
				fail("AGENT_EVENT_READ_UNCONFIRMED")
				return
			}
		case event, open := <-events:
			if !open {
				events = nil
				continue
			}
			if event.RunID != runID || event.Seq <= cursor || event.Seq > contract.MaxAgentEventSequence || !safeAgentEventIdentifier(event.EventType) || !check() {
				fail("EVENT_READ_UNCONFIRMED")
				return
			}
			// Treat remote payload as untrusted even when an SDK already sanitizes it.
			metadata := make(map[string]any)
			for _, key := range []string{"operation", "reason", "harness_key", "tool_name", "call_id", "code"} {
				if value, ok := event.Payload[key].(string); ok && safeAgentEventIdentifier(value) {
					metadata[key] = value
				}
			}
			event.Payload = metadata
			raw, marshalErr := json.Marshal(event)
			if marshalErr != nil || len(raw) > 4096 {
				fail("AGENT_EVENT_READ_UNCONFIRMED")
				return
			}
			if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			started = true
			if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.Seq, event.EventType, raw); err != nil {
				return
			}
			if controller.Flush() != nil {
				return
			}
			cursor = event.Seq
			count++
			if count == 256 {
				return
			}
		}
	}
	if !started {
		if !check() {
			m.writeError(w, 403, "EVENT_READ_UNCONFIRMED")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
	}
}

func safeAgentEventIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}
