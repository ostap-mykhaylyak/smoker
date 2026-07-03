package reputation

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestMgr(t *testing.T, cfg Config) *Manager {
	t.Helper()
	dir := t.TempDir()
	m, err := Open(filepath.Join(dir, "reputation.db"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestGreylistThenBlock(t *testing.T) {
	m := newTestMgr(t, Config{
		BlockThreshold: 3,
		Window:         10 * time.Minute,
		GreylistTTL:    time.Minute,
		BlockTTL:       time.Hour,
		CleanTTL:       time.Minute,
	})

	ip := "203.0.113.7"
	if got := m.RegisterViolation(ip, "t1"); got.To != StateGreylisted {
		t.Fatalf("1st violation -> %q, want greylisted", got.To)
	}
	if got := m.RegisterViolation(ip, "t2"); got.To != StateGreylisted {
		t.Fatalf("2nd violation -> %q, want greylisted", got.To)
	}
	if got := m.RegisterViolation(ip, "t3"); got.To != StateBlocked {
		t.Fatalf("3rd violation -> %q, want blocked", got.To)
	}
	if m.Lookup(ip) != StateBlocked {
		t.Fatal("ip should be blocked")
	}
}

func TestBlockTTLExpiry(t *testing.T) {
	m := newTestMgr(t, Config{
		BlockThreshold: 1,
		Window:         10 * time.Minute,
		BlockTTL:       time.Hour,
		GreylistTTL:    time.Minute,
		CleanTTL:       time.Minute,
	})
	base := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return base }

	ip := "203.0.113.9"
	if m.RegisterViolation(ip, "x").To != StateBlocked {
		t.Fatal("threshold=1 should block immediately")
	}
	if m.Lookup(ip) != StateBlocked {
		t.Fatal("should be blocked before TTL")
	}
	// Advance past BlockTTL.
	m.now = func() time.Time { return base.Add(2 * time.Hour) }
	if got := m.Lookup(ip); got != StateClean {
		t.Fatalf("after TTL Lookup = %q, want clean", got)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reputation.db")
	cfg := Config{BlockThreshold: 1, Window: time.Minute, BlockTTL: time.Hour, GreylistTTL: time.Minute, CleanTTL: time.Minute}

	m1, err := Open(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	m1.RegisterViolation("198.51.100.5", "boom")
	_ = m1.Close()

	m2, err := Open(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	if m2.Lookup("198.51.100.5") != StateBlocked {
		t.Fatal("blocked state should survive restart (BoltDB)")
	}
}

func TestForceBlock(t *testing.T) {
	// High threshold so only an explicit Block() can blacklist the IP.
	m := newTestMgr(t, Config{BlockThreshold: 100, Window: time.Minute, BlockTTL: time.Hour, GreylistTTL: time.Minute, CleanTTL: time.Minute})
	ip := "203.0.113.50"
	if got := m.Block(ip, "admin-ajax flood"); got.To != StateBlocked || !got.Changed {
		t.Fatalf("Block -> %+v, want blocked/changed", got)
	}
	if m.Lookup(ip) != StateBlocked {
		t.Fatal("ip should be blocked after Block()")
	}
}

func TestMarkCleanEmitsTransition(t *testing.T) {
	m := newTestMgr(t, Config{BlockThreshold: 1, Window: time.Minute, BlockTTL: time.Hour, GreylistTTL: time.Minute, CleanTTL: time.Minute})
	var got Transition
	m.OnTransition = func(tr Transition) { got = tr }

	m.RegisterViolation("192.0.2.1", "v")
	m.MarkClean("192.0.2.1", "challenge passed")
	if got.To != StateClean || got.Reason != "challenge passed" {
		t.Fatalf("transition = %+v", got)
	}
}
