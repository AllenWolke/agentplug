package knowledge

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrManagementDenied = errors.New("knowledge management denied")

type ControlService interface {
	Change(context.Context, sharedkernel.Scope, ProjectionScope, SourceChange) (SourceReceipt, error)
	Snapshot(context.Context, sharedkernel.Scope, ProjectionScope, int) (SourceSnapshot, error)
	Ready(context.Context) error
}

type ControlModule struct {
	token         string
	service       ControlService
	indexService  IndexControlService
	workerMu      sync.Mutex
	worker        func(context.Context) error
	workerStarted bool
	workerCancel  context.CancelFunc
	workerDone    chan struct{}
	workerError   error
}

func NewControlModule(token string, service ControlService) *ControlModule {
	return &ControlModule{token: token, service: service}
}
func (*ControlModule) Name() string { return "knowledge" }
func (m *ControlModule) ReadyContext(ctx context.Context) error {
	if m == nil || m.service == nil {
		return ErrCheckpointUnavailable
	}
	m.workerMu.Lock()
	err := m.workerError
	m.workerMu.Unlock()
	if err != nil {
		return err
	}
	return m.service.Ready(ctx)
}

func (m *ControlModule) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sources/{knowledge}", m.snapshot)
	mux.HandleFunc("PUT /sources/{knowledge}/documents/{document}", m.change)
	mux.HandleFunc("POST /indexes/{knowledge}/tasks", m.submitIndex)
	mux.HandleFunc("GET /indexes/{knowledge}/tasks:receipt", m.queryIndexReceipt)
	mux.HandleFunc("GET /indexes/{knowledge}/tasks/{run}", m.queryIndex)
	mux.HandleFunc("POST /indexes/{knowledge}/tasks/{run}/cancel", m.cancelIndex)
	return mux
}

func knowledgeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func knowledgeError(w http.ResponseWriter, status int, code string) {
	knowledgeJSON(w, status, map[string]string{"error": code})
}

func (m *ControlModule) actor(w http.ResponseWriter, r *http.Request) (sharedkernel.Scope, ProjectionScope, bool) {
	var actor sharedkernel.Scope
	var scope ProjectionScope
	if m == nil || m.service == nil || m.token == "" {
		knowledgeError(w, 503, "KNOWLEDGE_UNAVAILABLE")
		return actor, scope, false
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Internal-Token")), []byte(m.token)) != 1 {
		knowledgeError(w, 401, "GATEWAY_AUTHENTICATION_REQUIRED")
		return actor, scope, false
	}
	actor = sharedkernel.Scope{TenantID: r.Header.Get("X-Tenant-ID"), DepartmentID: r.Header.Get("X-Department-ID"), ApplicationID: r.Header.Get("X-Application-ID"), PrincipalID: r.Header.Get("X-Principal-ID"), PrincipalType: r.Header.Get("X-Principal-Type"), TraceID: r.Header.Get("X-Trace-ID")}
	if r.Header.Get("X-Browser-Module") != "1" || actor.PrincipalType != "user" || actor.Validate() != nil || strings.TrimSpace(actor.TraceID) == "" {
		knowledgeError(w, 401, "TRUSTED_USER_CONTEXT_REQUIRED")
		return actor, scope, false
	}
	scope = ProjectionScope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, KnowledgeID: r.PathValue("knowledge")}
	if !scope.valid() {
		knowledgeError(w, 400, "INVALID_KNOWLEDGE_SCOPE")
		return actor, scope, false
	}
	return actor, scope, true
}

func (m *ControlModule) failure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrManagementDenied):
		knowledgeError(w, 403, "KNOWLEDGE_MANAGEMENT_DENIED")
	case errors.Is(err, ErrSourceConflict):
		knowledgeError(w, 409, "SOURCE_REVISION_CONFLICT")
	case errors.Is(err, ErrIndexTaskConflict):
		knowledgeError(w, 409, "INDEX_TASK_CONFLICT")
	case errors.Is(err, ErrIndexTaskNotFound):
		knowledgeError(w, 404, "INDEX_TASK_NOT_FOUND")
	case errors.Is(err, ErrInvalidProjection), errors.Is(err, ErrCorpusLimit):
		knowledgeError(w, 400, "INVALID_SOURCE_REQUEST")
	default:
		knowledgeError(w, 503, "KNOWLEDGE_OPERATION_UNAVAILABLE")
	}
}

func (m *ControlModule) snapshot(w http.ResponseWriter, r *http.Request) {
	actor, scope, ok := m.actor(w, r)
	if !ok {
		return
	}
	maximum := 200
	if value := r.URL.Query().Get("limit"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 1000 {
			knowledgeError(w, 400, "INVALID_SOURCE_LIMIT")
			return
		}
		maximum = n
	}
	snapshot, err := m.service.Snapshot(r.Context(), actor, scope, maximum)
	if err != nil {
		m.failure(w, err)
		return
	}
	knowledgeJSON(w, 200, map[string]any{"schema_version": "knowledge-source-snapshot/v1", "revision": snapshot.Revision, "documents": snapshot.Documents})
}

func (m *ControlModule) change(w http.ResponseWriter, r *http.Request) {
	actor, scope, ok := m.actor(w, r)
	if !ok {
		return
	}
	var request struct {
		ExpectedSourceRevision  int64             `json:"expected_source_revision"`
		ExpectedDocumentVersion int64             `json:"expected_document_version"`
		IdempotencyKey          string            `json:"idempotency_key"`
		Body                    string            `json:"body"`
		Metadata                map[string]string `json:"metadata,omitempty"`
		ACL                     DocumentACL       `json:"acl"`
		Deleted                 bool              `json:"deleted"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		knowledgeError(w, 400, "INVALID_SOURCE_REQUEST")
		return
	}
	result, err := m.service.Change(r.Context(), actor, scope, SourceChange{DocumentID: r.PathValue("document"), ActorPrincipalID: actor.PrincipalID, ExpectedSourceRevision: request.ExpectedSourceRevision, ExpectedDocumentVersion: request.ExpectedDocumentVersion, IdempotencyKey: request.IdempotencyKey, Body: request.Body, Metadata: request.Metadata, ACL: request.ACL, Deleted: request.Deleted})
	if err != nil {
		m.failure(w, err)
		return
	}
	knowledgeJSON(w, 200, result)
}
