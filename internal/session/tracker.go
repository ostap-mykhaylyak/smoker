// Package session implements the Session/Behavior Tracker. For every clean
// request that traverses the proxy it records lightweight per-session state
// (first seen, pageview count + timestamps, last path, challenge status) in an
// LRU cache with TTL. The Detection Engine's session-matchers checks are
// evaluated against this store.
//
// The tracker satisfies detect.SessionEvaluator so it plugs directly into the
// unified rule evaluation pipeline.
package session

import (
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/ostap-mykhaylyak/smoker/internal/detect"
)

// hit is one recorded request: when it happened and which path it hit. Storing
// the path lets us answer per-endpoint rate limits (e.g. only admin-ajax.php).
type hit struct {
	ts   time.Time
	path string
}

// record is the per-session state. Access is guarded by the tracker mutex held
// for the duration of a single record/evaluate op (records are tiny).
type record struct {
	firstSeen       time.Time
	lastSeen        time.Time
	lastPath        string
	challengePassed bool
	// pageviews holds recent request hits, bounded to maxPageviewStamps, enough
	// to answer min-prior-pageviews / rate-limit / endpoint-rate-limit.
	pageviews []hit
}

const maxPageviewStamps = 64

// Tracker is the concrete Session/Behavior Tracker.
type Tracker interface {
	detect.SessionEvaluator
	// Record updates session state for a clean request forwarded to backend.
	Record(key string, view *detect.RequestView)
	// MarkChallengePassed flags a session as having solved a challenge.
	MarkChallengePassed(key string)
	// ChallengePassed reports whether the (still-live) session has solved a
	// challenge. Used to grant a grace period so a visitor who already passed is
	// not re-challenged in a loop.
	ChallengePassed(key string) bool
	// Len reports tracked sessions (for tests/metrics).
	Len() int
}

type tracker struct {
	mu    sync.Mutex
	cache *lru.Cache[string, *record]
	ttl   time.Duration
	now   func() time.Time // injectable clock for tests
}

// New builds a Tracker holding up to maxEntries sessions for ttl.
func New(maxEntries int, ttl time.Duration) (Tracker, error) {
	if maxEntries <= 0 {
		maxEntries = 100000
	}
	c, err := lru.New[string, *record](maxEntries)
	if err != nil {
		return nil, err
	}
	return &tracker{cache: c, ttl: ttl, now: time.Now}, nil
}

func (t *tracker) Len() int { return t.cache.Len() }

func (t *tracker) get(key string) (*record, bool) {
	r, ok := t.cache.Get(key)
	if !ok {
		return nil, false
	}
	if t.now().Sub(r.lastSeen) > t.ttl {
		t.cache.Remove(key)
		return nil, false
	}
	return r, true
}

func (t *tracker) Record(key string, view *detect.RequestView) {
	if key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	r, ok := t.get(key)
	if !ok {
		r = &record{firstSeen: now}
	}
	r.lastSeen = now
	r.lastPath = view.Path
	r.pageviews = append(r.pageviews, hit{ts: now, path: view.Path})
	if len(r.pageviews) > maxPageviewStamps {
		r.pageviews = r.pageviews[len(r.pageviews)-maxPageviewStamps:]
	}
	t.cache.Add(key, r)
}

func (t *tracker) MarkChallengePassed(key string) {
	if key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.get(key)
	if !ok {
		r = &record{firstSeen: t.now()}
	}
	r.challengePassed = true
	r.lastSeen = t.now()
	t.cache.Add(key, r)
}

func (t *tracker) ChallengePassed(key string) bool {
	if key == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.get(key)
	return ok && r.challengePassed
}

// Evaluate reports whether the session-matchers condition holds — i.e. whether
// the behavioral attack pattern is present for this session.
func (t *tracker) Evaluate(sm *detect.SessionMatchers, key string, view *detect.RequestView) bool {
	if sm == nil || len(sm.Checks) == 0 {
		return false
	}
	t.mu.Lock()
	r, seen := t.get(key)
	// Snapshot the values we need, then release the lock before evaluating.
	var (
		firstSeen       time.Time
		challengePassed bool
		lastPath        string
		hits            []hit
	)
	if seen {
		firstSeen = r.firstSeen
		challengePassed = r.challengePassed
		lastPath = r.lastPath
		hits = append(hits, r.pageviews...)
	}
	t.mu.Unlock()

	and := sm.Condition == "" || sm.Condition == "and"
	now := t.now()
	result := and // AND starts true, OR starts false
	for i := range sm.Checks {
		got := t.evalCheck(&sm.Checks[i], seen, firstSeen, challengePassed, lastPath, hits, view, now)
		if sm.Checks[i].Negate {
			got = !got
		}
		if and {
			if !got {
				return false
			}
		} else {
			if got {
				return true
			}
		}
	}
	return result
}

func (t *tracker) evalCheck(c *detect.SessionCheck, seen bool, firstSeen time.Time, challengePassed bool, lastPath string, hits []hit, view *detect.RequestView, now time.Time) bool {
	switch c.Type {
	case "session-seen-before":
		return seen
	case "challenge-passed":
		return challengePassed
	case "min-prior-pageviews":
		return countWithin(hits, "", c.Window.Std(), now) >= c.Value
	case "rate-limit":
		// True when the session is OVER the configured limit in the window
		// (all endpoints combined).
		return countWithin(hits, "", c.Window.Std(), now) > c.Value
	case "endpoint-rate-limit":
		// Per-endpoint: count prior requests to THIS request's path and add 1
		// for the current one, firing when the total reaches value. Combined
		// with the template's http match, this counts hits to that endpoint
		// only (e.g. only /wp-admin/admin-ajax.php).
		path := ""
		if view != nil {
			path = view.Path
		}
		if c.Match != "" {
			path = c.Match // optional explicit path override (exact)
		}
		return countWithin(hits, path, c.Window.Std(), now)+1 >= c.Value
	case "last-path-matches":
		return lastPath != "" && matchGlob(c.Match, lastPath)
	default:
		// Unknown check type: treat as not-satisfied (fail-safe: does not fire
		// an action on an unrecognized behavioral predicate).
		return false
	}
}

// countWithin counts recorded hits within window. If path is non-empty, only
// hits to that exact path are counted (per-endpoint); empty path counts all.
func countWithin(hits []hit, path string, window time.Duration, now time.Time) int {
	cutoff := now.Add(-window)
	n := 0
	for _, h := range hits {
		if path != "" && h.path != path {
			continue
		}
		if window <= 0 || h.ts.After(cutoff) {
			n++
		}
	}
	return n
}

// matchGlob is a minimal prefix/suffix/contains glob for last-path-matches.
func matchGlob(pattern, s string) bool {
	if pattern == "" {
		return false
	}
	if pattern == s {
		return true
	}
	// Support a trailing '*' prefix match, leading '*' suffix match.
	switch {
	case pattern[0] == '*' && pattern[len(pattern)-1] == '*':
		inner := pattern[1 : len(pattern)-1]
		return inner != "" && containsStr(s, inner)
	case pattern[len(pattern)-1] == '*':
		return hasPrefix(s, pattern[:len(pattern)-1])
	case pattern[0] == '*':
		return hasSuffix(s, pattern[1:])
	}
	return false
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
func hasSuffix(s, p string) bool { return len(s) >= len(p) && s[len(s)-len(p):] == p }
