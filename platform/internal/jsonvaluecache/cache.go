// Package jsonvaluecache reuses pure decoding of immutable byte values.
// It never caches authorization, expiry checks, or the freshness of a DB read.
package jsonvaluecache

import (
	"container/list"
	"crypto/sha256"
	"sync"
)

type entry[V any] struct {
	key         [32]byte
	value       V
	sourceBytes int
}

type Cache[V any] struct {
	mu                          sync.Mutex
	order                       *list.List
	items                       map[[32]byte]*list.Element
	maxEntries, maxBytes, bytes int
	decode                      func([]byte) (V, error)
	clone                       func(V) V
}

// New bounds entry count and retained source-byte weight. clone must detach
// mutable slices and pointers; immutable scalar values may use an identity copy.
func New[V any](entries, bytes int, decode func([]byte) (V, error), clone func(V) V) *Cache[V] {
	if entries < 1 || bytes < 1 || decode == nil || clone == nil {
		panic("invalid bounded decode cache")
	}
	return &Cache[V]{order: list.New(), items: make(map[[32]byte]*list.Element), maxEntries: entries, maxBytes: bytes, decode: decode, clone: clone}
}

func (c *Cache[V]) Decode(raw []byte) (V, error) {
	if len(raw) > c.maxBytes {
		return c.decode(raw)
	}
	key := sha256.Sum256(raw)
	c.mu.Lock()
	if element := c.items[key]; element != nil {
		c.order.MoveToFront(element)
		value := element.Value.(entry[V]).value
		c.mu.Unlock()
		return c.clone(value), nil
	}
	c.mu.Unlock()
	value, err := c.decode(raw)
	if err != nil {
		return value, err
	} // corrupt bytes never become a cached success
	owned := c.clone(value)
	c.mu.Lock()
	if existing := c.items[key]; existing != nil {
		c.order.MoveToFront(existing)
	} else {
		element := c.order.PushFront(entry[V]{key: key, value: owned, sourceBytes: len(raw)})
		c.items[key] = element
		c.bytes += len(raw)
		for len(c.items) > c.maxEntries || c.bytes > c.maxBytes {
			last := c.order.Back()
			old := last.Value.(entry[V])
			delete(c.items, old.key)
			c.bytes -= old.sourceBytes
			c.order.Remove(last)
		}
	}
	c.mu.Unlock()
	return value, nil
}
