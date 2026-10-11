package audit

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func (m *Module) runtimeSteps(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, target, ok := m.runtimeStepsActor(w, r)
	if !ok {
		return
	}
	if err := m.authorizeRuntimeSteps(r.Context(), actor, target); err != nil {
		m.runtimeStepsAuthorizationError(w, err)
		return
	}
	query, err := parseRuntimeStepsHTTPQuery(r.URL.Query(), target)
	if err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	reader, ok := m.store.(RuntimeStepsReader)
	if !ok {
		m.error(w, http.StatusNotImplemented, "RUNTIME_AUDIT_QUERY_UNAVAILABLE")
		return
	}
	page, err := reader.ListRuntimeSteps(r.Context(), query)
	if err != nil {
		if errors.Is(err, ErrInvalidRuntimeSteps) {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		m.error(w, http.StatusInternalServerError, "AUDIT_QUERY_FAILED")
		return
	}
	// Re-resolve active principal, workspace and current IAM immediately before
	// disclosure. A permission revoked while the SQL read was in flight wins.
	if err := m.authorizeRuntimeSteps(r.Context(), actor, target); err != nil {
		m.runtimeStepsAuthorizationError(w, err)
		return
	}
	m.json(w, http.StatusOK, page)
}

func (m *Module) runtimeStepsActor(w http.ResponseWriter, r *http.Request) (sharedkernel.Scope, MetadataScope, bool) {
	if !m.authorized(r) {
		m.error(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return sharedkernel.Scope{}, MetadataScope{}, false
	}
	actor := sharedkernel.Scope{
		PrincipalType: r.Header.Get("X-Principal-Type"), PrincipalID: r.Header.Get("X-Principal-ID"),
		TenantID: r.Header.Get("X-Tenant-ID"), DepartmentID: r.Header.Get("X-Department-ID"),
		ApplicationID: r.Header.Get("X-Application-ID"), TraceID: r.Header.Get("X-Trace-ID"),
	}
	if r.Header.Get("X-Browser-Module") != "1" || actor.PrincipalType != "user" || actor.Validate() != nil {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return sharedkernel.Scope{}, MetadataScope{}, false
	}
	target := MetadataScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	if target.Validate() != nil {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return sharedkernel.Scope{}, MetadataScope{}, false
	}
	return actor, target, true
}

func (m *Module) authorizeRuntimeSteps(ctx context.Context, actor sharedkernel.Scope, target MetadataScope) error {
	if m.authorizeMetadata != nil {
		return m.authorizeMetadata(ctx, actor, target)
	}
	// Preserve the existing legacy current-workspace audit check only when the
	// platform has not wired its versioned metadata authorizer.
	if m.canReadBrowser == nil {
		return ErrMetadataForbidden
	}
	allowed, err := m.canReadBrowser(ctx, actor.TenantID, actor.DepartmentID, actor.ApplicationID, actor.PrincipalID)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrMetadataForbidden
	}
	return nil
}

func (m *Module) runtimeStepsAuthorizationError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrMetadataForbidden) {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	m.error(w, http.StatusServiceUnavailable, "IDENTITY_UNAVAILABLE")
}

func parseRuntimeStepsHTTPQuery(values url.Values, scope MetadataScope) (RuntimeStepsQuery, error) {
	allowed := map[string]bool{"run_id": true, "step_id": true, "page_size": true, "cursor": true}
	for key, items := range values {
		if !allowed[key] || len(items) != 1 {
			return RuntimeStepsQuery{}, ErrInvalidRuntimeSteps
		}
	}
	query := RuntimeStepsQuery{Scope: scope, RunID: strings.TrimSpace(values.Get("run_id")), StepID: strings.TrimSpace(values.Get("step_id")), PageSize: 20, Cursor: values.Get("cursor")}
	if query.RunID != values.Get("run_id") || (values.Has("step_id") && query.StepID != values.Get("step_id")) {
		return RuntimeStepsQuery{}, ErrInvalidRuntimeSteps
	}
	if raw := values.Get("page_size"); raw != "" {
		pageSize, err := strconv.Atoi(raw)
		if err != nil || pageSize < 1 || pageSize > runtimeStepPageMax {
			return RuntimeStepsQuery{}, ErrInvalidRuntimeSteps
		}
		query.PageSize = pageSize
	}
	if err := validateRuntimeStepsQuery(query); err != nil {
		return RuntimeStepsQuery{}, err
	}
	return query, nil
}
