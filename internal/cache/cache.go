// Package cache is smoker's optional CDN-style content cache. It stores whole
// backend responses (typically static assets like images) in a bounded in-memory
// LRU with a per-entry TTL, so smoker can serve them directly without asking the
// backend again until they expire.
//
// The cache is deliberately simple and correctness-first: it only ever stores
// what the caller decides is safe to store (see the proxy's storable checks —
// 200 responses, no Set-Cookie, no no-store/private Cache-Control), keys on the
// full host+URI, and never serves an expired entry.
package cache

import (
	"net/http"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Entry is a cached backend response.
type Entry struct {
	Status  int
	Header  http.Header // sanitized response headers (no hop-by-hop / Set-Cookie)
	Body    []byte
	Stored  time.Time
	Expires time.Time
}

// Cache is a bounded, TTL-aware, concurrency-safe response cache.
type Cache struct {
	lru *lru.Cache[string, *Entry]
	now func() time.Time
}

// New builds a cache holding up to maxEntries objects (LRU eviction).
func New(maxEntries int) (*Cache, error) {
	if maxEntries <= 0 {
		maxEntries = 1024
	}
	l, err := lru.New[string, *Entry](maxEntries)
	if err != nil {
		return nil, err
	}
	return &Cache{lru: l, now: time.Now}, nil
}

// Get returns a fresh entry for key, or ok=false on a miss or an expired entry
// (which it evicts).
func (c *Cache) Get(key string) (*Entry, bool) {
	e, ok := c.lru.Get(key)
	if !ok {
		return nil, false
	}
	if c.now().After(e.Expires) {
		c.lru.Remove(key)
		return nil, false
	}
	return e, true
}

// Put stores (or replaces) the entry for key.
func (c *Cache) Put(key string, e *Entry) { c.lru.Add(key, e) }

// Age returns how long ago the entry was stored, in whole seconds (>= 0).
func (c *Cache) Age(e *Entry) int {
	d := c.now().Sub(e.Stored)
	if d < 0 {
		return 0
	}
	return int(d.Seconds())
}

// Now returns the cache clock (the moment used for TTL decisions). Callers use it
// to stamp Entry.Stored/Expires consistently with Get's expiry check.
func (c *Cache) Now() time.Time { return c.now() }

// Len reports the number of cached objects (for metrics/tests).
func (c *Cache) Len() int { return c.lru.Len() }

// Purge empties the cache.
func (c *Cache) Purge() { c.lru.Purge() }
