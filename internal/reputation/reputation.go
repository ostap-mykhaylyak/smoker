// Package reputation implements the IP Reputation Manager: an in-memory store
// (fast O(1) lookup on every request) backed by BoltDB for persistence across
// restarts. It consumes incidents published by the Detection Engine and decides
// whether an IP should be greylisted (challenged) or blocked outright after N
// violations within a sliding window.
//
// State file lives at /var/log/smoker/reputation.db (runtime data, not config).
// Every transition is emitted via OnTransition so the caller can write it to
// reputation.log.
package reputation

import (
	"encoding/json"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// State is an IP's reputation state.
type State string

const (
	StateClean      State = "clean"
	StateGreylisted State = "greylisted"
	StateBlocked    State = "blocked"
)

// Transition describes a state change for reputation.log.
type Transition struct {
	IP      string
	From    State
	To      State
	Reason  string
	Changed bool
	Expiry  time.Time
}

// Store is the mockable interface used by the proxy hot path.
type Store interface {
	// Lookup returns the current state, applying TTL expiry. Called first on
	// every request to fail-fast on already-blocked IPs.
	Lookup(ip string) State
	// RegisterViolation records an incident for ip and returns the resulting
	// transition (greylist or block depending on threshold).
	RegisterViolation(ip, reason string) Transition
	// MarkClean resets an IP to clean (e.g. after passing a challenge).
	MarkClean(ip, reason string) Transition
	// Block forces an IP into the blocked state for BlockTTL, regardless of the
	// prior violation count (used by rules that decide to ban outright).
	Block(ip, reason string) Transition
	// Close flushes and closes the backing store.
	Close() error
}

// Config controls thresholds and TTLs.
type Config struct {
	BlockThreshold int
	Window         time.Duration
	GreylistTTL    time.Duration
	BlockTTL       time.Duration
	CleanTTL       time.Duration
}

type entry struct {
	State      State       `json:"state"`
	Since      time.Time   `json:"since"`
	Expiry     time.Time   `json:"expiry"`
	Violations []time.Time `json:"violations"`
}

// Manager is the concrete Store.
type Manager struct {
	cfg Config
	db  *bolt.DB
	now func() time.Time

	mu      sync.RWMutex
	entries map[string]*entry

	OnTransition func(Transition)
}

var bucketName = []byte("reputation")

// Open loads persisted state from dbPath (creating it if absent) into memory.
func Open(dbPath string, cfg Config) (*Manager, error) {
	db, err := bolt.Open(dbPath, 0o640, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	m := &Manager{
		cfg:     cfg,
		db:      db,
		now:     time.Now,
		entries: make(map[string]*entry),
	}
	if err := m.load(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return m, nil
}

func (m *Manager) load() error {
	return m.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketName)
		if err != nil {
			return err
		}
		now := m.now()
		return b.ForEach(func(k, v []byte) error {
			var e entry
			if err := json.Unmarshal(v, &e); err != nil {
				return nil // skip corrupt entry
			}
			// Drop entries that have already expired to clean.
			if !e.Expiry.IsZero() && now.After(e.Expiry) {
				return nil
			}
			m.entries[string(k)] = &e
			return nil
		})
	})
}

func (m *Manager) persist(ip string, e *entry) {
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	_ = m.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return nil
		}
		return b.Put([]byte(ip), data)
	})
}

func (m *Manager) delete(ip string) {
	_ = m.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(ip))
	})
}

func (m *Manager) Lookup(ip string) State {
	m.mu.RLock()
	e, ok := m.entries[ip]
	m.mu.RUnlock()
	if !ok {
		return StateClean
	}
	if !e.Expiry.IsZero() && m.now().After(e.Expiry) {
		// Expired: transition back to clean.
		m.mu.Lock()
		delete(m.entries, ip)
		m.mu.Unlock()
		m.delete(ip)
		m.emit(Transition{IP: ip, From: e.State, To: StateClean, Reason: "ttl expired", Changed: true})
		return StateClean
	}
	return e.State
}

func (m *Manager) RegisterViolation(ip, reason string) Transition {
	now := m.now()
	m.mu.Lock()
	e, ok := m.entries[ip]
	if !ok {
		e = &entry{State: StateClean, Since: now}
		m.entries[ip] = e
	}
	from := e.State

	// If already blocked, just refresh — no downgrade.
	if e.State == StateBlocked {
		m.mu.Unlock()
		return Transition{IP: ip, From: from, To: StateBlocked, Reason: reason, Changed: false, Expiry: e.Expiry}
	}

	// Record violation and prune outside the window.
	e.Violations = append(e.Violations, now)
	cutoff := now.Add(-m.cfg.Window)
	pruned := e.Violations[:0]
	for _, ts := range e.Violations {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}
	e.Violations = pruned

	var to State
	if len(e.Violations) >= m.cfg.BlockThreshold {
		to = StateBlocked
		e.State = StateBlocked
		e.Since = now
		e.Expiry = now.Add(m.cfg.BlockTTL)
	} else {
		to = StateGreylisted
		e.State = StateGreylisted
		e.Since = now
		e.Expiry = now.Add(m.cfg.GreylistTTL)
	}
	snapshot := *e
	m.mu.Unlock()

	m.persist(ip, &snapshot)
	tr := Transition{IP: ip, From: from, To: to, Reason: reason, Changed: from != to, Expiry: snapshot.Expiry}
	m.emit(tr)
	return tr
}

func (m *Manager) MarkClean(ip, reason string) Transition {
	m.mu.Lock()
	e, ok := m.entries[ip]
	var from State = StateClean
	if ok {
		from = e.State
	}
	now := m.now()
	ne := &entry{State: StateClean, Since: now, Expiry: now.Add(m.cfg.CleanTTL)}
	m.entries[ip] = ne
	m.mu.Unlock()

	m.persist(ip, ne)
	tr := Transition{IP: ip, From: from, To: StateClean, Reason: reason, Changed: from != StateClean, Expiry: ne.Expiry}
	m.emit(tr)
	return tr
}

// Block forces ip into the blocked state for BlockTTL immediately.
func (m *Manager) Block(ip, reason string) Transition {
	m.mu.Lock()
	from := StateClean
	if e, ok := m.entries[ip]; ok {
		from = e.State
	}
	now := m.now()
	ne := &entry{State: StateBlocked, Since: now, Expiry: now.Add(m.cfg.BlockTTL)}
	m.entries[ip] = ne
	m.mu.Unlock()

	m.persist(ip, ne)
	tr := Transition{IP: ip, From: from, To: StateBlocked, Reason: reason, Changed: from != StateBlocked, Expiry: ne.Expiry}
	m.emit(tr)
	return tr
}

func (m *Manager) emit(tr Transition) {
	if m.OnTransition != nil && tr.Changed {
		m.OnTransition(tr)
	}
}

func (m *Manager) Close() error {
	return m.db.Close()
}
