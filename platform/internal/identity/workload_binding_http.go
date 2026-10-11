package identity

import (
	"context"
	"encoding/json"
	"github.com/lexagent/platform/internal/sharedkernel"
	"io"
	"net/http"
)

func (m *Module) workloadBindingChange(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		actor, _, ok := m.permissionActor(w, r)
		if !ok {
			return
		}
		store, ok := m.store.(interface {
			ListWorkloadBindings(context.Context, sharedkernel.Scope, ManagementScope) ([]WorkloadBinding, error)
		})
		if !ok {
			m.error(w, http.StatusServiceUnavailable, "WORKLOAD_SERVICE_UNAVAILABLE")
			return
		}
		scope := ManagementScope{Type: "application", TenantID: actor.Scope.TenantID, DepartmentID: actor.Scope.DepartmentID, ApplicationID: actor.Scope.ApplicationID}
		fields := map[string]*string{"tenant_id": &scope.TenantID, "department_id": &scope.DepartmentID, "application_id": &scope.ApplicationID}
		for key, values := range r.URL.Query() {
			field, exists := fields[key]
			if !exists || len(values) != 1 || values[0] == "" {
				m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
				return
			}
			*field = values[0]
		}
		items, err := store.ListWorkloadBindings(r.Context(), actor.Scope, scope)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, map[string]any{"items": items})
		return
	}
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, _, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	store, ok := m.store.(interface {
		ChangeWorkloadBinding(context.Context, sharedkernel.Scope, WorkloadBindingCommand) (WorkloadBindingReceipt, error)
	})
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "WORKLOAD_SERVICE_UNAVAILABLE")
		return
	}
	var command WorkloadBindingCommand
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&command) != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	receipt, err := store.ChangeWorkloadBinding(r.Context(), actor.Scope, command)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, receipt)
}
