package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrIndexTaskConflict = errors.New("index task idempotency conflict")
var ErrIndexTaskNotFound = errors.New("index task not found")

// These public receipts deliberately exclude execution envelopes, source bodies
// and credentials. The execution module remains the owner of durable outcomes.
type IndexTaskDetail struct {
	SchemaVersion string                `json:"schema_version"`
	RunID         string                `json:"run_id"`
	KnowledgeID   string                `json:"knowledge_id"`
	Mode          string                `json:"mode"`
	Status        string                `json:"status"`
	Revision      uint64                `json:"revision"`
	Result        *IndexTaskPublication `json:"result,omitempty"`
}

type IndexTaskPublication struct {
	SchemaVersion      string `json:"schema_version"`
	KnowledgeID        string `json:"knowledge_id"`
	GenerationID       string `json:"generation_id"`
	SourceRevision     int64  `json:"source_revision"`
	IndexRevision      int64  `json:"index_revision"`
	EmbeddedChunks     int    `json:"embedded_chunks"`
	ReusedChunks       int    `json:"reused_chunks"`
	CheckpointRevision int64  `json:"checkpoint_revision"`
}

type IndexQueryService interface {
	QueryIndex(context.Context, sharedkernel.Scope, ProjectionScope, string) (IndexTaskDetail, error)
}

type IndexCancelRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
}

type IndexCancellationService interface {
	CancelIndex(context.Context, sharedkernel.Scope, ProjectionScope, string, IndexCancelRequest) (IndexTaskDetail, error)
}

func (m *ControlModule) cancelIndex(w http.ResponseWriter, r *http.Request) {
	actor, scope, ok := m.actor(w, r)
	if !ok {
		return
	}
	service, ok := m.indexService.(IndexCancellationService)
	if !ok {
		knowledgeError(w, 503, "INDEX_CONTROL_UNAVAILABLE")
		return
	}
	id := r.PathValue("run")
	var request IndexCancelRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if id == "" || len(id) > 128 || strings.TrimSpace(id) != id || decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.ExpectedRevision == 0 {
		knowledgeError(w, 400, "INVALID_INDEX_CANCEL_REQUEST")
		return
	}
	detail, err := service.CancelIndex(r.Context(), actor, scope, id, request)
	if err != nil {
		m.failure(w, err)
		return
	}
	knowledgeJSON(w, http.StatusAccepted, detail)
}

func (m *ControlModule) queryIndex(w http.ResponseWriter, r *http.Request) {
	actor, scope, ok := m.actor(w, r)
	if !ok {
		return
	}
	service, ok := m.indexService.(IndexQueryService)
	if !ok {
		knowledgeError(w, 503, "INDEX_CONTROL_UNAVAILABLE")
		return
	}
	runID := r.PathValue("run")
	if runID == "" || len(runID) > 128 || strings.TrimSpace(runID) != runID {
		knowledgeError(w, 400, "INVALID_INDEX_TASK_ID")
		return
	}
	detail, err := service.QueryIndex(r.Context(), actor, scope, runID)
	if err != nil {
		m.failure(w, err)
		return
	}
	knowledgeJSON(w, http.StatusOK, detail)
}

type IndexSettings struct {
	Dimensions        int    `json:"dimensions"`
	WindowRunes       int    `json:"window_runes"`
	OverlapRunes      int    `json:"overlap_runes"`
	MaximumDocuments  int    `json:"maximum_documents"`
	MaximumChunks     int    `json:"maximum_chunks"`
	ChunkingUnit      string `json:"chunking_unit,omitempty"`
	TokenizerID       string `json:"tokenizer_id,omitempty"`
	TokenizerRevision string `json:"tokenizer_revision,omitempty"`
	TokenLimit        int    `json:"token_limit,omitempty"`
}

type IndexTaskRequest struct {
	InstallationID string        `json:"installation_id"`
	IdempotencyKey string        `json:"idempotency_key"`
	Mode           string        `json:"mode"`
	Config         IndexSettings `json:"config"`
}

func (r IndexTaskRequest) IndexConfig(modelVersion string) (IndexConfig, error) {
	c := IndexConfig{EmbeddingModelVersion: modelVersion, Dimensions: r.Config.Dimensions, WindowRunes: r.Config.WindowRunes, OverlapRunes: r.Config.OverlapRunes, MaximumDocuments: r.Config.MaximumDocuments, MaximumChunks: r.Config.MaximumChunks, ChunkingUnit: r.Config.ChunkingUnit, TokenizerID: r.Config.TokenizerID, TokenizerRevision: r.Config.TokenizerRevision, TokenLimit: r.Config.TokenLimit}
	if !c.valid() || r.InstallationID == "" || len(r.InstallationID) > 128 || strings.TrimSpace(r.InstallationID) != r.InstallationID || len(r.IdempotencyKey) < 8 || len(r.IdempotencyKey) > 128 || strings.TrimSpace(r.IdempotencyKey) != r.IdempotencyKey || (r.Mode != "full" && r.Mode != "incremental") {
		return IndexConfig{}, ErrInvalidProjection
	}
	return c, nil
}

type IndexTaskReceipt struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	Status        string `json:"status"`
	Replayed      bool   `json:"replayed"`
}

type IndexControlService interface {
	SubmitIndex(context.Context, sharedkernel.Scope, ProjectionScope, IndexTaskRequest) (IndexTaskReceipt, error)
}

func (m *ControlModule) SetIndexService(service IndexControlService) { m.indexService = service }

func (m *ControlModule) submitIndex(w http.ResponseWriter, r *http.Request) {
	actor, scope, ok := m.actor(w, r)
	if !ok {
		return
	}
	if m.indexService == nil {
		knowledgeError(w, 503, "INDEX_CONTROL_UNAVAILABLE")
		return
	}
	var request IndexTaskRequest
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		knowledgeError(w, 400, "INVALID_INDEX_REQUEST")
		return
	}
	if _, err := request.IndexConfig("published-target-required"); err != nil {
		knowledgeError(w, 400, "INVALID_INDEX_REQUEST")
		return
	}
	receipt, err := m.indexService.SubmitIndex(r.Context(), actor, scope, request)
	if err != nil {
		m.failure(w, err)
		return
	}
	knowledgeJSON(w, http.StatusAccepted, receipt)
}
