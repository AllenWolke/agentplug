package knowledge

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type IndexRecoveryReceipt struct {
	SchemaVersion         string           `json:"schema_version"`
	Scope                 ProjectionScope  `json:"scope"`
	RunID                 string           `json:"run_id"`
	Status                string           `json:"status"`
	Revision              uint64           `json:"revision"`
	AgentVersionID        string           `json:"agent_version_id"`
	Request               IndexTaskRequest `json:"request"`
	EmbeddingModelVersion string           `json:"embedding_model_version_id"`
}

type IndexReceiptReader interface {
	QueryIndexReceipt(context.Context, sharedkernel.Scope, ProjectionScope, string, string) (IndexRecoveryReceipt, error)
}

func (m *ControlModule) queryIndexReceipt(w http.ResponseWriter, r *http.Request) {
	actor, scope, ok := m.actor(w, r)
	if !ok {
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	installation, key := query.Get("installation_id"), query.Get("idempotency_key")
	if err != nil || len(query) != 2 || len(query["installation_id"]) != 1 || len(query["idempotency_key"]) != 1 || installation == "" || len(installation) > 128 || strings.TrimSpace(installation) != installation || len(key) < 8 || len(key) > 128 || strings.TrimSpace(key) != key {
		knowledgeError(w, http.StatusBadRequest, "INVALID_INDEX_RECEIPT_QUERY")
		return
	}
	service, ok := m.indexService.(IndexReceiptReader)
	if !ok {
		knowledgeError(w, http.StatusServiceUnavailable, "INDEX_RECEIPT_READ_UNAVAILABLE")
		return
	}
	receipt, err := service.QueryIndexReceipt(r.Context(), actor, scope, installation, key)
	if err != nil {
		m.failure(w, err)
		return
	}
	knowledgeJSON(w, http.StatusOK, receipt)
}
