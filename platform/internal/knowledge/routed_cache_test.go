package knowledge

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestValidatedCacheOnlyRefreshesKnownIneligibleHits(t *testing.T) {
	for _, mode := range []string{"hit-refresh", "fresh-rejected", "execution-denied", "still-rejected"} {
		t.Run(mode, func(t *testing.T) {
			cache := NewStageCache(8, 1024, time.Minute)
			ctx := context.Background()
			loads := 0
			if mode != "fresh-rejected" {
				_, _, _ = cache.Do(ctx, "key", func(context.Context) ([]byte, error) { return []byte("old"), nil })
			}
			denied := errors.New("execution revoked")
			value, hit, err := cache.DoValidated(ctx, "key", func(context.Context) ([]byte, error) {
				loads++
				if mode == "fresh-rejected" || mode == "still-rejected" {
					return []byte("old"), nil
				}
				return []byte("new"), nil
			}, func(_ context.Context, value []byte) error {
				if mode == "execution-denied" {
					return denied
				}
				if string(value) == "old" {
					return ErrCachedReceiptUnusable
				}
				return nil
			})
			if mode == "hit-refresh" {
				if err != nil || hit || string(value) != "new" || loads != 1 {
					t.Fatal("known value not refreshed once", err, loads)
				}
			} else {
				if err == nil || value != nil {
					t.Fatal("unverified value disclosed")
				}
				want := 1
				if mode == "execution-denied" {
					want = 0
				}
				if loads != want {
					t.Fatal("authority failure retried a model attempt", loads)
				}
			}
		})
	}
}

func TestQueryCachePartitionsRoutedTasksButSharesPinnedEmbedding(t *testing.T) {
	scope := cacheFixtureScope()
	models := &pipelineModelFixture{}
	m := CachedQueryModels{Models: models, Cache: NewStageCache(16, 1<<20, time.Minute), Boundary: CacheBoundary{Scope: scope, PolicyFingerprint: "p", CorpusFingerprint: "c", PipelineVersion: "v", SelectionFingerprint: "task-a"}, Check: func(context.Context, sharedkernel.Scope, string) error { return nil }}
	for i := 0; i < 2; i++ {
		if i == 1 {
			m.Boundary.SelectionFingerprint = "task-b"
		}
		r, err := m.Rewrite(context.Background(), scope, "same-stage-query")
		if err != nil || r.CacheHit {
			t.Fatal("chat reused another original task", err)
		}
		e, err := m.EmbedQuery(context.Background(), scope, "same-index-query")
		if err != nil || e.CacheHit != (i == 1) {
			t.Fatal("fixed embedding did not retain safe reuse", err)
		}
	}
}
