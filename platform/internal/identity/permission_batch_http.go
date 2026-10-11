package identity

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type PermissionBatchRepository interface {
	PreviewPermissionBatch(context.Context, sharedkernel.Scope, PermissionBatchCommand) (PermissionBatchPlan, error)
	CreatePermissionBatch(context.Context, sharedkernel.Scope, PermissionBatchCommand) (PermissionBatch, error)
	GetPermissionBatch(context.Context, sharedkernel.Scope, string) (PermissionBatch, error)
	ContinuePermissionBatch(context.Context, sharedkernel.Scope, string) (PermissionBatch, error)
	CancelPermissionBatch(context.Context, sharedkernel.Scope, string) (PermissionBatch, error)
}

func (m *Module) permissionBatch(w http.ResponseWriter, r *http.Request) {
	read := strings.HasPrefix(r.URL.Path, "/permission-batches/") && !strings.HasSuffix(r.URL.Path, ":continue") && !strings.HasSuffix(r.URL.Path, ":cancel")
	if read && r.Method != http.MethodGet || !read && r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, _, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	repo, ok := m.store.(PermissionBatchRepository)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/permission-batches/") {
		key := strings.TrimPrefix(r.URL.Path, "/permission-batches/")
		continuation, cancellation := strings.HasSuffix(key, ":continue"), strings.HasSuffix(key, ":cancel")
		if continuation {
			key = strings.TrimSuffix(key, ":continue")
		} else if cancellation {
			key = strings.TrimSuffix(key, ":cancel")
		}
		if !validPermissionBatchKey(key) || strings.Contains(key, ":") || len(r.URL.Query()) != 0 {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		var batch PermissionBatch
		var err error
		if continuation || cancellation {
			var empty struct{}
			if decode(r, &empty) != nil {
				m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
				return
			}
			if continuation {
				batch, err = repo.ContinuePermissionBatch(r.Context(), actor.Scope, key)
			} else {
				batch, err = repo.CancelPermissionBatch(r.Context(), actor.Scope, key)
			}
		} else {
			batch, err = repo.GetPermissionBatch(r.Context(), actor.Scope, key)
		}
		if errors.Is(err, sql.ErrNoRows) {
			m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		} else if err != nil {
			m.permissionError(w, err)
		} else {
			m.json(w, http.StatusOK, batch)
		}
		return
	}
	var command PermissionBatchCommand
	if decode(r, &command) != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if r.URL.Path == "/permission-batches:preview" {
		plan, err := repo.PreviewPermissionBatch(r.Context(), actor.Scope, command)
		if err != nil {
			m.permissionError(w, err)
		} else {
			m.json(w, http.StatusOK, plan)
		}
		return
	}
	if r.URL.Path != "/permission-batches" {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	batch, err := repo.CreatePermissionBatch(r.Context(), actor.Scope, command)
	if err != nil {
		m.permissionError(w, err)
	} else {
		m.json(w, http.StatusCreated, batch)
	}
}
