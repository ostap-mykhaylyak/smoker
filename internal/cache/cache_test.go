package cache

import (
	"net/http"
	"testing"
	"time"
)

func entry(body string, stored, exp time.Time) *Entry {
	return &Entry{
		Status:  200,
		Header:  http.Header{"Content-Type": {"image/png"}},
		Body:    []byte(body),
		Stored:  stored,
		Expires: exp,
	}
}

func TestPutGet(t *testing.T) {
	c, err := New(8)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }

	if _, ok := c.Get("k"); ok {
		t.Fatal("empty cache must miss")
	}
	// Stored 60s ago, expires in an hour -> Age is 60.
	c.Put("k", entry("hello", base.Add(-time.Minute), base.Add(time.Hour)))
	e, ok := c.Get("k")
	if !ok {
		t.Fatal("expected a hit")
	}
	if string(e.Body) != "hello" {
		t.Errorf("body = %q", e.Body)
	}
	if c.Age(e) != 60 {
		t.Errorf("age = %d, want 60", c.Age(e))
	}
}

func TestExpiryEvicts(t *testing.T) {
	c, _ := New(8)
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }
	c.Put("k", entry("x", base, base.Add(30*time.Second)))

	c.now = func() time.Time { return base.Add(31 * time.Second) }
	if _, ok := c.Get("k"); ok {
		t.Error("expired entry must miss")
	}
	if c.Len() != 0 {
		t.Errorf("expired entry must be evicted, len = %d", c.Len())
	}
}

func TestLRUCapacity(t *testing.T) {
	c, _ := New(2)
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }
	exp := base.Add(time.Hour)
	c.Put("a", entry("a", base, exp))
	c.Put("b", entry("b", base, exp))
	c.Put("c", entry("c", base, exp)) // evicts the least-recently-used ("a")
	if _, ok := c.Get("a"); ok {
		t.Error("a should have been evicted at capacity")
	}
	if _, ok := c.Get("c"); !ok {
		t.Error("c should be present")
	}
}
