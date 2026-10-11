package knowledge

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// StageCache is an optional, bounded process cache. Values are detached on both
// insertion and return. It does not contain or replace authorization decisions.
// Restarting a process simply makes its cache cold; no schema or DDL is needed.
type StageCache struct {
	mu                   sync.Mutex
	entries              map[string]*list.Element
	lru                  list.List
	flights              map[string]*cacheFlight
	bytes                int
	maxEntries, maxBytes int
	ttl                  time.Duration
	now                  func() time.Time
}

type cacheEntry struct {
	key     string
	value   []byte
	expires time.Time
}
type cacheFlight struct {
	done  chan struct{}
	value []byte
	err   error
}

func NewStageCache(maxEntries, maxBytes int, ttl time.Duration) *StageCache {
	if maxEntries < 1 || maxBytes < 1 || ttl <= 0 {
		return nil
	}
	return &StageCache{entries: map[string]*list.Element{}, flights: map[string]*cacheFlight{}, maxEntries: maxEntries, maxBytes: maxBytes, ttl: ttl, now: time.Now}
}

// CacheKey avoids retaining raw queries or body text in keys or telemetry.
func CacheKey(encoded []byte) string {
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (c *StageCache) remove(e *list.Element) {
	entry := e.Value.(cacheEntry)
	delete(c.entries, entry.key)
	c.bytes -= len(entry.value)
	c.lru.Remove(e)
}

// Do coalesces concurrent loads. A canceled leader must not cancel a live
// waiter; that waiter can become the next loader. Failures are never cached.
// Authorization must be checked by EVERY caller before and after Do, including
// waiters. The cache has no authority to make that decision itself.
func (c *StageCache) Do(ctx context.Context, key string, load func(context.Context) ([]byte, error)) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if c == nil || key == "" {
		value, err := load(ctx)
		return value, false, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		c.mu.Lock()
		if e := c.entries[key]; e != nil {
			entry := e.Value.(cacheEntry)
			if c.now().Before(entry.expires) {
				c.lru.MoveToFront(e)
				value := append([]byte(nil), entry.value...)
				c.mu.Unlock()
				return value, true, nil
			}
			c.remove(e)
		}
		if flight := c.flights[key]; flight != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-flight.done:
				if errors.Is(flight.err, context.Canceled) || errors.Is(flight.err, context.DeadlineExceeded) {
					continue
				}
				if flight.err != nil {
					return nil, false, flight.err
				}
				return append([]byte(nil), flight.value...), true, nil
			}
		}
		// Keep bookkeeping bounded too. Model capacity and budget still govern
		// an uncached load when the cache is saturated by distinct requests.
		if len(c.flights) >= c.maxEntries {
			c.mu.Unlock()
			value, err := load(ctx)
			return value, false, err
		}
		flight := &cacheFlight{done: make(chan struct{})}
		c.flights[key] = flight
		c.mu.Unlock()
		value, err := load(ctx)
		if err == nil {
			err = ctx.Err()
		}
		c.mu.Lock()
		flight.err = err
		if err == nil {
			flight.value = append([]byte(nil), value...)
			if len(value) <= c.maxBytes {
				for c.lru.Len() >= c.maxEntries || c.bytes+len(value) > c.maxBytes {
					c.remove(c.lru.Back())
				}
				entry := cacheEntry{key: key, value: append([]byte(nil), value...), expires: c.now().Add(c.ttl)}
				c.entries[key] = c.lru.PushFront(entry)
				c.bytes += len(value)
			}
		}
		delete(c.flights, key)
		close(flight.done)
		c.mu.Unlock()
		if err != nil {
			return nil, false, err
		}
		return append([]byte(nil), value...), false, nil
	}
}
