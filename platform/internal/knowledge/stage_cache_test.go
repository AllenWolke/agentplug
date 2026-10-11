package knowledge

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestStageCacheConcurrentLoadsAndDetachedValues(t *testing.T) {
	c := NewStageCache(8, 128, time.Minute)
	var calls atomic.Int32
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			value, _, err := c.Do(context.Background(), "same", func(context.Context) ([]byte, error) { calls.Add(1); return []byte("original"), nil })
			if err != nil || string(value) != "original" {
				t.Error("concurrent result changed", err)
				return
			}
			value[0] = 'X'
		}()
	}
	close(start)
	workers.Wait()
	if calls.Load() != 1 {
		t.Fatal("duplicate model load", calls.Load())
	}
	value, hit, err := c.Do(context.Background(), "same", nil)
	if err != nil || !hit || string(value) != "original" {
		t.Fatal("caller mutated cache", err)
	}
}

func TestStageCacheExpiryEvictionAndFailure(t *testing.T) {
	c := NewStageCache(2, 4, time.Minute)
	now := time.Unix(100, 0)
	c.now = func() time.Time { return now }
	loads := 0
	load := func(context.Context) ([]byte, error) { loads++; return []byte("ab"), nil }
	c.Do(context.Background(), "a", load)
	c.Do(context.Background(), "b", load)
	c.Do(context.Background(), "a", load) // a is most recently used.
	c.Do(context.Background(), "c", load)
	_, hit, _ := c.Do(context.Background(), "b", load)
	if hit || loads != 4 {
		t.Fatal("LRU entry/byte budget failed", loads)
	}
	now = now.Add(time.Minute) // Exact expiry is a miss.
	_, hit, _ = c.Do(context.Background(), "b", load)
	if hit || loads != 5 {
		t.Fatal("expired result reused")
	}
	failure := errors.New("upstream unavailable")
	_, _, err := c.Do(context.Background(), "error", func(context.Context) ([]byte, error) { return nil, failure })
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	_, hit, err = c.Do(context.Background(), "error", load)
	if err != nil || hit {
		t.Fatal("failure was cached", err)
	}
	oversizedLoads := 0
	large := func(context.Context) ([]byte, error) { oversizedLoads++; return []byte("oversized"), nil }
	c.Do(context.Background(), "large", large)
	c.Do(context.Background(), "large", large)
	if oversizedLoads != 2 {
		t.Fatal("oversized entry cached")
	}
}

func TestStageCacheCancellationDoesNotPoisonWaiters(t *testing.T) {
	c := NewStageCache(8, 128, time.Minute)
	leader, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	started := make(chan struct{})
	leaderDone := make(chan error, 1)
	go func() {
		_, _, err := c.Do(leader, "same", func(ctx context.Context) ([]byte, error) { close(started); <-ctx.Done(); return nil, ctx.Err() })
		leaderDone <- err
	}()
	<-started
	waiter, cancelWaiter := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelWaiter()
	waiterDone := make(chan error, 1)
	go func() {
		value, _, err := c.Do(waiter, "same", func(context.Context) ([]byte, error) { return []byte("retry"), nil })
		if err == nil && string(value) != "retry" {
			err = errors.New("wrong retry value")
		}
		waiterDone <- err
	}()
	cancelLeader()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := <-waiterDone; err != nil {
		t.Fatal("live waiter canceled with leader", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := c.Do(canceled, "same", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled hit returned a value", err)
	}
}

func cacheFixtureScope() sharedkernel.Scope {
	return sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", AgentInstanceID: "i", InstallationID: "i", AgentID: "agent", AgentVersionID: "v", SessionID: "s", RunID: "r", TraceID: "trace", AuthorizationEpoch: 1}
}

func TestCachedQueryModelsCurrentPermissionAndVersionBoundaries(t *testing.T) {
	scope := cacheFixtureScope()
	models := &pipelineModelFixture{}
	checks := 0
	denied := false
	m := CachedQueryModels{Models: models, Cache: NewStageCache(32, 1<<20, time.Minute), Boundary: CacheBoundary{Scope: scope, PolicyFingerprint: "policy", CorpusFingerprint: "corpus", PipelineVersion: "pipeline-v1"}, Check: func(context.Context, sharedkernel.Scope, string) error {
		checks++
		if denied {
			return ErrKnowledgeAuthorityChanged
		}
		return nil
	}}
	for i := 0; i < 2; i++ {
		rewrite, err := m.Rewrite(context.Background(), scope, "recovery question")
		if err != nil || rewrite.CacheHit != (i == 1) {
			t.Fatal("rewrite cache", err)
		}
		embed, err := m.EmbedQuery(context.Background(), scope, rewrite.Text)
		if err != nil || embed.CacheHit != (i == 1) || embed.Vector[0] != 1 {
			t.Fatal("embedding cache", err)
		}
		embed.Vector[0] = 99 // No vector alias can contaminate the stored value.
		rank, err := m.Rerank(context.Background(), scope, rewrite.Text, []HybridChunk{{Chunk: Chunk{ID: "preferred", DocumentID: "visible", Text: "canonical"}}})
		if err != nil || rank.CacheHit != (i == 1) {
			t.Fatal("reranking cache", err)
		}
	}
	if models.calls != 3 || checks != 12 {
		t.Fatal("cache skipped per-caller authority or failed to avoid model calls", models.calls, checks)
	}
	denied = true
	if value, err := m.Rewrite(context.Background(), scope, "recovery question"); err == nil || value.Text != "" {
		t.Fatal("revoked cached rewrite disclosed", err)
	}
	if models.calls != 3 {
		t.Fatal("denied cache lookup invoked model")
	}
	denied = false
	for _, field := range []string{"principal", "epoch", "session", "installation", "agent-version", "policy", "corpus", "pipeline"} {
		t.Run(field, func(t *testing.T) {
			copy := m
			switch field {
			case "principal":
				copy.Boundary.Scope.PrincipalID = "other"
			case "epoch":
				copy.Boundary.Scope.AuthorizationEpoch++
			case "session":
				copy.Boundary.Scope.SessionID = "other"
			case "installation":
				copy.Boundary.Scope.InstallationID = "other"
			case "agent-version":
				copy.Boundary.Scope.AgentVersionID = "other"
			case "policy":
				copy.Boundary.PolicyFingerprint = "new-policy"
			case "corpus":
				copy.Boundary.CorpusFingerprint = "new-corpus"
			case "pipeline":
				copy.Boundary.PipelineVersion = "pipeline-v2"
			}
			result, err := copy.Rewrite(context.Background(), copy.Boundary.Scope, "recovery question")
			if err != nil || result.CacheHit {
				t.Fatal("version/identity boundary reused old cache", err)
			}
		})
	}
	postDenied := m
	postDenied.Check = func(context.Context, sharedkernel.Scope, string) error {
		checks++
		if checks%2 == 0 {
			return ErrKnowledgeAuthorityChanged
		}
		return nil
	}
	checks = 0
	if value, err := postDenied.Rewrite(context.Background(), scope, "recovery question"); err == nil || value.Text != "" {
		t.Fatal("revocation during cache read disclosed result", err)
	}
}

func TestCachedQueryModelsAcrossRunsChecksCurrentExecution(t *testing.T) {
	scope := cacheFixtureScope()
	models := &pipelineModelFixture{}
	current := scope
	checks := 0
	denied := false
	m := CachedQueryModels{Models: models, Cache: NewStageCache(32, 1<<20, time.Minute), Boundary: CacheBoundary{Scope: scope, PolicyFingerprint: "policy", CorpusFingerprint: "corpus", PipelineVersion: "pipeline"}, Check: func(_ context.Context, actual sharedkernel.Scope, _ string) error {
		checks++
		if actual != current || denied {
			return ErrKnowledgeAuthorityChanged
		}
		return nil
	}}
	for i := 0; i < 2; i++ {
		if i == 1 {
			current.RunID, current.TraceID, current.ParentRunID = "next-run", "next-trace", "parent"
			m.Boundary.Scope = current
		}
		r, err := m.Rewrite(context.Background(), current, "same query")
		if err != nil || r.CacheHit != (i == 1) {
			t.Fatal("cross-run rewrite", err)
		}
		e, err := m.EmbedQuery(context.Background(), current, r.Text)
		if err != nil || e.CacheHit != (i == 1) {
			t.Fatal("cross-run embedding", err)
		}
		x, err := m.Rerank(context.Background(), current, r.Text, []HybridChunk{{Chunk: Chunk{ID: "preferred", DocumentID: "visible", Text: "canonical"}}})
		if err != nil || x.CacheHit != (i == 1) {
			t.Fatal("cross-run reranking", err)
		}
	}
	if models.calls != 3 || checks != 12 {
		t.Fatal("new run bypassed live checks or called models", models.calls, checks)
	}
	denied = true
	if r, err := m.Rewrite(context.Background(), current, "same query"); err == nil || r.Text != "" {
		t.Fatal("revoked next run read cache")
	}
	if _, err := m.Rewrite(context.Background(), scope, "same query"); err == nil {
		t.Fatal("old execution scope accepted")
	}
}

func TestCachedQueryModelsInvalidRerankingIsNeverCached(t *testing.T) {
	scope := cacheFixtureScope()
	models := &pipelineModelFixture{invalid: "unknown"}
	m := CachedQueryModels{Models: models, Cache: NewStageCache(8, 1<<20, time.Minute), Boundary: CacheBoundary{Scope: scope, PolicyFingerprint: "policy", CorpusFingerprint: "corpus", PipelineVersion: "pipeline"}, Check: func(context.Context, sharedkernel.Scope, string) error { return nil }}
	chunks := []HybridChunk{{Chunk: Chunk{ID: "preferred", DocumentID: "visible", Text: "canonical"}}}
	for i := 0; i < 2; i++ {
		if result, err := m.Rerank(context.Background(), scope, "recovery procedure", chunks); err == nil || len(result.Scores) != 0 {
			t.Fatal("invalid reranking admitted", err)
		}
	}
	if models.calls != 2 {
		t.Fatal("invalid reranking cached")
	}
	models.invalid = ""
	result, err := m.Rerank(context.Background(), scope, "recovery procedure", chunks)
	if err != nil || result.CacheHit || models.calls != 3 || chunks[0].Text != "canonical" {
		t.Fatal("corrected ranking failed or model mutated canonical input", err)
	}
}
