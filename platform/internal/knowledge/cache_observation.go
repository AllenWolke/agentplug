package knowledge

import (
	"context"
	"sync"
)

type cacheObservationKey struct{}

// CacheObservation counts actual logical StageCache calls for one query,
// including answer generation. It never holds keys, queries or cached values.
// A coalesced waiter is a hit; nil/bypassed caches do not perform a lookup.
type CacheObservation struct {
	mu                      sync.Mutex
	lookups, hits, failures int64
}

func WithCacheObservation(ctx context.Context) (context.Context, *CacheObservation) {
	o := &CacheObservation{}
	return context.WithValue(ctx, cacheObservationKey{}, o), o
}

func (o *CacheObservation) Snapshot() (lookups, hits, failures int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lookups, o.hits, o.failures
}

func observeCacheCall(ctx context.Context, hit bool, err error) {
	o, _ := ctx.Value(cacheObservationKey{}).(*CacheObservation)
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lookups++
	if hit {
		o.hits++
	}
	if err != nil {
		o.failures++
	}
}
