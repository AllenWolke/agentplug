package knowledge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestPostgresRetrievalCacheFreshBodiesAndVersionFences(t *testing.T) {
	for _, mode := range []string{"hit", "generation-change", "revoke", "revoke-after-cache", "body-corrupt", "scope-change"} {
		t.Run(mode, func(t *testing.T) {
			p, ps := projectionFixture(t)
			ctx := context.Background()
			generation := Generation{ID: "cache-g1", EmbeddingModelVersion: "embedding-v1", Dimensions: 2}
			chunks := []ProjectedChunk{{Chunk: Chunk{ID: "chunk-1", DocumentID: "visible", DocumentVersion: "v1", Text: "canonical recovery procedure"}, ACLRevision: "acl1", Embedding: []float32{1, 0}}}
			if err := p.BuildGeneration(ctx, ps, generation, chunks); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Publish(ctx, ps, generation.ID, 0); err != nil {
				t.Fatal(err)
			}
			scope := sharedkernel.Scope{TenantID: ps.TenantID, DepartmentID: ps.DepartmentID, ApplicationID: ps.ApplicationID, AgentInstanceID: "instance", AgentID: "agent", PrincipalID: "user", PrincipalType: "user", InstallationID: "installation", AgentVersionID: "v1", SessionID: "session", RunID: "run", TraceID: "trace", AuthorizationEpoch: 1}
			authority := &pipelineAuthorityFixture{facts: []DocumentFact{{ID: "visible", Version: "v1", ACLRevision: "acl1"}}}
			cache := NewStageCache(16, 1<<20, time.Minute)
			r := GovernedProjectionRetriever{Projection: p, Authority: authority, MaximumCorpus: 10, Cache: cache, CacheBoundary: CacheBoundary{Scope: scope, PolicyFingerprint: "policy-v1", CorpusFingerprint: "corpus-v1", PipelineVersion: "pipeline-v1"}}
			search := func() (ProjectionResult, error) {
				return r.Retrieve(ctx, scope, ps.KnowledgeID, generation.EmbeddingModelVersion, "recovery", []float32{1, 0}, 1)
			}
			warm, err := search()
			if err != nil || warm.CacheHit || len(warm.Chunks) != 1 {
				t.Fatal("cold retrieval failed", err)
			}
			cache.mu.Lock()
			for _, element := range cache.entries {
				if strings.Contains(string(element.Value.(cacheEntry).value), "canonical recovery procedure") {
					t.Error("retrieval cache retained document body")
				}
			}
			cache.mu.Unlock()
			switch mode {
			case "generation-change":
				generation.ID = "cache-g2"
				if err := p.BuildGeneration(ctx, ps, generation, chunks); err != nil {
					t.Fatal(err)
				}
				if _, err := p.Publish(ctx, ps, generation.ID, 1); err != nil {
					t.Fatal(err)
				}
			case "revoke":
				authority.facts = nil
			case "revoke-after-cache":
				authority.revokeAt = authority.calls + 2
			case "body-corrupt":
				if _, err := p.DB.ExecContext(ctx, `UPDATE knowledge.chunks SET body='tampered body' WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND generation_id=$5`, append(ps.args(), generation.ID)...); err != nil {
					t.Fatal(err)
				}
			case "scope-change":
				scope.PrincipalID = "another-user"
			}
			result, err := search()
			if mode == "hit" || mode == "generation-change" {
				if err != nil || len(result.Chunks) != 1 || result.Chunks[0].Text != "canonical recovery procedure" || result.Generation.ID != generation.ID || result.CacheHit != (mode == "hit") {
					t.Fatal("cache result/version mismatch", err, result)
				}
				// Returned data must not mutate a later cache hit.
				result.Chunks[0].Text = "caller mutation"
				again, err := search()
				if err != nil || !again.CacheHit || again.Chunks[0].Text != "canonical recovery procedure" {
					t.Fatal("cache body was shared with caller", err)
				}
			} else {
				if err == nil || len(result.Chunks) != 0 {
					t.Fatal("cache disclosed rejected content", mode, err)
				}
				if mode == "body-corrupt" && !errors.Is(err, ErrInvalidProjection) {
					t.Fatal("fresh body integrity was not checked", err)
				}
			}
		})
	}
}
