package knowledge

import (
	"context"
	"errors"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrKnowledgeAuthorityUnavailable = errors.New("current knowledge authority unavailable")
var ErrKnowledgeAuthorityChanged = errors.New("knowledge authority changed during retrieval")

// RetrievalAuthority is implemented by platform composition using current
// Identity and authoritative source metadata. It cannot be supplied by an
// Agent. The verified caller AND workload must be eligible at both calls.
type RetrievalAuthority interface {
	ResolveCurrentDocuments(context.Context, sharedkernel.Scope, string) ([]DocumentFact, error)
}

type GovernedProjectionRetriever struct {
	Projection    PostgresProjection
	Authority     RetrievalAuthority
	MaximumCorpus int
	Cache         *StageCache
	CacheBoundary CacheBoundary
}

// Retrieve takes a verified execution Scope and a governed model embedding.
// It rechecks authority after SQL to close deletion/revision/revocation races.
// The caller still owns capability validation, billing and execution cancellation.
func (r GovernedProjectionRetriever) Retrieve(ctx context.Context, scope sharedkernel.Scope, knowledgeID, modelVersion, query string, embedding []float32, topK int) (ProjectionResult, error) {
	if r.Authority == nil {
		return ProjectionResult{}, ErrKnowledgeAuthorityUnavailable
	}
	if err := scope.ValidateTrusted(); err != nil {
		return ProjectionResult{}, err
	}
	before, err := r.Authority.ResolveCurrentDocuments(ctx, scope, knowledgeID)
	if err != nil {
		return ProjectionResult{}, err
	}
	projectionScope := ProjectionScope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, KnowledgeID: knowledgeID}
	result, err := r.retrieveProjection(ctx, scope, projectionScope, before, modelVersion, query, embedding, topK)
	if err != nil {
		return ProjectionResult{}, err
	}
	after, err := r.Authority.ResolveCurrentDocuments(ctx, scope, knowledgeID)
	if err != nil {
		return ProjectionResult{}, err
	}
	current := make(map[string]DocumentFact, len(after))
	for _, fact := range after {
		if fact.ID == "" || fact.Version == "" || fact.ACLRevision == "" || current[fact.ID].ID != "" {
			return ProjectionResult{}, ErrInvalidProjection
		}
		current[fact.ID] = fact
	}
	prior := make(map[string]DocumentFact, len(before))
	for _, fact := range before {
		prior[fact.ID] = fact
	}
	if len(current) != len(prior) {
		return ProjectionResult{}, ErrKnowledgeAuthorityChanged
	}
	for id, fact := range prior {
		if current[id] != fact {
			return ProjectionResult{}, ErrKnowledgeAuthorityChanged
		}
	}
	filtered := make([]HybridChunk, 0, len(result.Chunks))
	for _, chunk := range result.Chunks {
		fact, allowed := current[chunk.DocumentID]
		if allowed && fact == prior[chunk.DocumentID] && chunk.DocumentVersion == fact.Version {
			filtered = append(filtered, chunk)
		}
	}
	result.Chunks = filtered
	if err := ctx.Err(); err != nil {
		return ProjectionResult{}, err
	}
	return result, nil
}
