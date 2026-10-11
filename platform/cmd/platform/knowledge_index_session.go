package main

import (
	"context"
	"net/http"
	"time"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/knowledge"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

// executeSignedIndexTask opens a current task-bound capability session rather
// than retaining callbacks from an earlier knowledge query. Admission must
// already have authorized indexing and claimed this specific execution lease.
func (p knowledgePersistence) executeSignedIndexTask(ctx context.Context, run platformruntime.Run, scope knowledge.ProjectionScope, config knowledge.IndexConfig, incremental bool, module *capability.Module, request *http.Request, ttl time.Duration) error {
	if module == nil {
		return knowledge.ErrInvalidProjection
	}
	session, err := module.OpenTaskEmbeddingSession(ctx, request, run.Scope)
	if err != nil {
		return err
	}
	defer session.Close()
	models := knowledgeIndexEmbeddings{scope: session.Scope, request: capability.KnowledgeSearchRequest{Policy: session.Policy, ModelCall: session.Call, ModelCheck: session.Check}}
	return p.executeIndexTask(ctx, run, scope, config, incremental, models, ttl)
}
