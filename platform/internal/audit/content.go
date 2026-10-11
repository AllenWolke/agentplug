package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrContentForbidden = errors.New("audit content access forbidden")

// Only metadata is supplied to the authority; Summary is loaded afterwards.
type ContentAuthorizer func(context.Context, sharedkernel.Scope, Event, string) error
type ContentReader interface {
	GetEventMetadata(context.Context, MetadataScope, string) (Event, error)
	GetEventContent(context.Context, Event) (Event, error)
}

func (m *Module) SetContentAuthorizer(authorize ContentAuthorizer) { m.authorizeContent = authorize }

func (m *Module) contentActor(w http.ResponseWriter, r *http.Request) (sharedkernel.Scope, bool) {
	if !m.authorized(r) {
		m.error(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return sharedkernel.Scope{}, false
	}
	actor := sharedkernel.Scope{PrincipalType: r.Header.Get("X-Principal-Type"), PrincipalID: r.Header.Get("X-Principal-ID"), TenantID: r.Header.Get("X-Tenant-ID"), DepartmentID: r.Header.Get("X-Department-ID"), ApplicationID: r.Header.Get("X-Application-ID"), TraceID: r.Header.Get("X-Trace-ID")}
	if r.Header.Get("X-Browser-Module") != "1" || actor.PrincipalType != "user" || actor.Validate() != nil || m.authorizeContent == nil {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return sharedkernel.Scope{}, false
	}
	return actor, true
}

func validEventID(id string) bool {
	return id != "" && len(id) <= 128 && strings.TrimSpace(id) == id && !strings.ContainsAny(id, "/*\x00\r\n")
}

func (m *Module) contentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrContentForbidden), errors.Is(err, ErrMetadataForbidden):
		m.error(w, http.StatusForbidden, "FORBIDDEN")
	case errors.Is(err, ErrNotFound):
		m.error(w, http.StatusNotFound, "NOT_FOUND")
	default:
		m.error(w, http.StatusServiceUnavailable, "AUDIT_AUTHORITY_UNAVAILABLE")
	}
}

// All selected rows must be authorized before any sensitive column is read.
func (m *Module) readContent(ctx context.Context, actor sharedkernel.Scope, ids []string, action string) ([]Event, error) {
	reader, ok := m.store.(ContentReader)
	if !ok {
		return nil, errors.New("audit content reader unavailable")
	}
	scope := MetadataScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	metadata := make([]Event, 0, len(ids))
	for _, id := range ids {
		event, err := reader.GetEventMetadata(ctx, scope, id)
		if err != nil {
			return nil, err
		}
		if event.ID != id || !scope.contains(event) || event.Summary != "" {
			return nil, ErrContentForbidden
		}
		if err := m.authorizeContent(ctx, actor, event, action); err != nil {
			return nil, err
		}
		metadata = append(metadata, event)
	}
	result := make([]Event, 0, len(metadata))
	for _, header := range metadata {
		event, err := reader.GetEventContent(ctx, header)
		if err != nil {
			return nil, err
		}
		copy := event
		copy.Summary = ""
		if copy != header {
			return nil, ErrContentForbidden
		}
		result = append(result, event)
	}
	// Never return a partial export if any grant expired or was revoked.
	for _, header := range metadata {
		if err := m.authorizeContent(ctx, actor, header, action); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (m *Module) recordContentAccess(ctx context.Context, actor sharedkernel.Scope, ids []string, action string) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	// Record identifiers only, never the exported summary or business payload.
	encoded, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return m.store.Record(ctx, Event{ID: "audit-access-" + hex.EncodeToString(nonce[:]), TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, ActorType: actor.PrincipalType, ActorID: actor.PrincipalID, TraceID: actor.TraceID, AggregateType: "audit_access", AggregateID: ids[0], Action: action, Outcome: "authorized", Summary: string(encoded), CreatedAt: time.Now().UTC()})
}

func (m *Module) content(w http.ResponseWriter, r *http.Request) {
	actor, ok := m.contentActor(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		m.error(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/events/"), "/")
	if len(parts) == 2 && parts[1] == "permissions" && validEventID(parts[0]) {
		m.contentPermissions(w, r, actor, parts[0])
		return
	}
	if len(parts) != 2 || parts[1] != "content" || !validEventID(parts[0]) {
		m.error(w, 400, "INVALID_REQUEST")
		return
	}
	m.deliverContent(w, r, actor, []string{parts[0]}, "audit.content.read", false)
}

func (m *Module) contentPermissions(w http.ResponseWriter, r *http.Request, actor sharedkernel.Scope, id string) {
	scope := MetadataScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	if m.authorizeMetadata == nil {
		m.error(w, 403, "FORBIDDEN")
		return
	}
	if err := m.authorizeMetadata(r.Context(), actor, scope); err != nil {
		m.contentError(w, err)
		return
	}
	reader, ok := m.store.(ContentReader)
	if !ok {
		m.error(w, 503, "AUDIT_QUERY_UNAVAILABLE")
		return
	}
	event, err := reader.GetEventMetadata(r.Context(), scope, id)
	if err != nil {
		m.contentError(w, err)
		return
	}
	if event.ID != id || !scope.contains(event) || event.Summary != "" {
		m.error(w, 403, "FORBIDDEN")
		return
	}
	permissions := map[string]bool{}
	for _, action := range []string{"audit.content.read", "audit.export"} {
		err := m.authorizeContent(r.Context(), actor, event, action)
		if err != nil && !errors.Is(err, ErrContentForbidden) {
			m.contentError(w, err)
			return
		}
		permissions[action] = err == nil
	}
	w.Header().Set("Cache-Control", "no-store")
	m.json(w, 200, map[string]any{"event_id": id, "actions": permissions})
}

func (m *Module) export(w http.ResponseWriter, r *http.Request) {
	actor, ok := m.contentActor(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		m.error(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var input struct {
		EventIDs []string `json:"event_ids"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&input) != nil || decoder.Decode(&extra) != io.EOF || len(input.EventIDs) == 0 || len(input.EventIDs) > 100 {
		m.error(w, 400, "INVALID_REQUEST")
		return
	}
	seen := map[string]bool{}
	for _, id := range input.EventIDs {
		if !validEventID(id) || seen[id] {
			m.error(w, 400, "INVALID_REQUEST")
			return
		}
		seen[id] = true
	}
	m.deliverContent(w, r, actor, input.EventIDs, "audit.export", true)
}

func (m *Module) deliverContent(w http.ResponseWriter, r *http.Request, actor sharedkernel.Scope, ids []string, action string, export bool) {
	events, err := m.readContent(r.Context(), actor, ids, action)
	if err != nil {
		m.contentError(w, err)
		return
	}
	if err := m.recordContentAccess(r.Context(), actor, ids, action); err != nil {
		m.error(w, 503, "AUDIT_RECORD_FAILED")
		return
	}
	// Recording may block on an Outbox transaction; check current authority again.
	for _, event := range events {
		event.Summary = ""
		if err := m.authorizeContent(r.Context(), actor, event, action); err != nil {
			m.contentError(w, err)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	if export {
		w.Header().Set("Content-Disposition", `attachment; filename="audit-events.json"`)
		m.json(w, 200, map[string]any{"items": events, "total": len(events)})
	} else {
		m.json(w, 200, events[0])
	}
}
