package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/smoker/internal/cache"
	"github.com/ostap-mykhaylyak/smoker/internal/challenge"
	"github.com/ostap-mykhaylyak/smoker/internal/config"
	"github.com/ostap-mykhaylyak/smoker/internal/detect"
	"github.com/ostap-mykhaylyak/smoker/internal/logging"
	"github.com/ostap-mykhaylyak/smoker/internal/protect"
	"github.com/ostap-mykhaylyak/smoker/internal/reputation"
	"github.com/ostap-mykhaylyak/smoker/internal/session"
)

const sqli = `
id: itest-sqli
info:
  name: itest SQLi
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-admin/admin-ajax.php?action=x&order_by={{p}}"
    matchers:
      - type: regex
        part: request
        regex:
          - "(?i)union\\s+select"
`

// gateChallenge is a stateless challenge rule used to reproduce the challenge
// loop: it matches a normal navigable path, so without a post-challenge grace a
// verified visitor would be re-challenged forever.
const gateChallenge = `
id: itest-gate
info:
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/gate"
action: challenge
`

// xmlrpcRate is a cookieless behavioral rate-limit (the real-world xmlrpc flood
// rule): 2nd+ hit to /xmlrpc.php within the window is throttled. It must fire on
// IP alone, even when the client rotates its User-Agent and sends no cookie.
const xmlrpcRate = `
id: itest-xmlrpc-rl
info:
  severity: medium
http:
  - path:
      - "{{BaseURL}}/xmlrpc.php"
session-matchers:
  checks:
    - type: endpoint-rate-limit
      value: 2
      window: 1h
action: rate-limit
action-response-code: 429
`

type testEnv struct {
	px      *Proxy
	backend *httptest.Server
	rep     *reputation.Manager
	tracker session.Tracker
	imgHits *int64 // backend hits for /cacheimg.png (to prove cache serving)
	dir     string // config + log dir (read backend.log/access.log here)
}

func setup(t *testing.T, extra ...string) *testEnv {
	t.Helper()
	dir := t.TempDir()

	var imgHits, noStoreHits int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /boom lets a test drive a backend-origin 5xx (recorded in backend.log).
		if r.URL.Path == "/boom" {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "boom")
			return
		}
		// /echo-len reports how many body bytes actually reached the backend, so
		// a test can prove large bodies are forwarded whole (never truncated).
		if r.URL.Path == "/echo-len" {
			n, _ := io.Copy(io.Discard, r.Body)
			fmt.Fprintf(w, "len=%d", n)
			return
		}
		// /cacheimg.png counts backend hits so a test can prove a cached response
		// is served without re-hitting the backend. The count is baked into the
		// body, so a cache HIT keeps returning the first-fetch value.
		if r.URL.Path == "/cacheimg.png" {
			n := atomic.AddInt64(&imgHits, 1)
			w.Header().Set("Content-Type", "image/png")
			fmt.Fprintf(w, "IMG-%d", n)
			return
		}
		// /nostore.png is a cacheable extension but forbids caching via
		// Cache-Control; each call must reach the backend (distinct body).
		if r.URL.Path == "/nostore.png" {
			n := atomic.AddInt64(&noStoreHits, 1)
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "no-store")
			fmt.Fprintf(w, "NS-%d", n)
			return
		}
		fmt.Fprintf(w, "backend-ok xff=%s", r.Header.Get("X-Forwarded-For"))
	}))
	t.Cleanup(backend.Close)
	backendHost := strings.TrimPrefix(backend.URL, "http://")

	cfgPath := filepath.Join(dir, "config.yaml")
	cfgYAML := fmt.Sprintf(`
listen:
  http: "127.0.0.1:0"
backend:
  http: %q
templates:
  dir: %q
reputation:
  db_path: %q
challenge:
  enabled: true
  assets_dir: %q
  secret: "test-secret"
logging:
  dir: %q
`, backendHost, dir, filepath.Join(dir, "rep.db"), dir, dir)
	cfgYAML += "\n" + strings.Join(extra, "\n") + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	cfgMgr, err := config.NewManager(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cfgMgr.Get()

	logs, err := logging.Open(cfg.Logging.Dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logs.Close() })

	rep, err := reputation.Open(cfg.Reputation.DBPath, reputation.Config{
		BlockThreshold: cfg.Reputation.BlockThreshold,
		Window:         cfg.Reputation.Window.Std(),
		GreylistTTL:    cfg.Reputation.GreylistTTL.Std(),
		BlockTTL:       cfg.Reputation.BlockTTL.Std(),
		CleanTTL:       cfg.Reputation.CleanTTL.Std(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rep.Close() })

	tr, err := session.New(1000, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	engine := detect.NewEngine(tr)
	var sigs []*detect.CompiledSignature
	for _, y := range []string{sqli, gateChallenge, xmlrpcRate} {
		tmpl, err := detect.ParseTemplate([]byte(y))
		if err != nil {
			t.Fatal(err)
		}
		sig, err := detect.Compile(tmpl)
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, sig)
	}
	engine.Reload(sigs)

	cl := &cleaner{rep: rep, tr: tr}
	ch := challenge.New(cfg.Challenge.AssetsDir, cfg.Challenge.Secret, cfg.Challenge.TTL.Std(), 0, nil, cl)

	cc, err := cache.New(cfg.Cache.MaxEntries)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := protect.New(cfg.Protection.MaxTrackedIPs)
	if err != nil {
		t.Fatal(err)
	}

	px := New(Deps{Config: cfgMgr, Engine: engine, Rep: rep, Tracker: tr, Challenge: ch, Logs: logs, Cache: cc, Guard: guard})
	return &testEnv{px: px, backend: backend, rep: rep, tracker: tr, imgHits: &imgHits, dir: dir}
}

type cleaner struct {
	rep reputation.Store
	tr  session.Tracker
}

func (c *cleaner) MarkIPClean(ip, reason string) { c.rep.MarkClean(ip, reason) }
func (c *cleaner) MarkSessionPassed(key string)  { c.tr.MarkChallengePassed(key) }

func do(px *Proxy, method, target, ip string) *httptest.ResponseRecorder {
	return doH(px, method, target, ip, nil)
}

// doH is do() with extra request headers (e.g. a CDN's CF-Connecting-IP).
func doH(px *Proxy, method, target, ip string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = ip + ":54321"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	px.ServeHTTP(rr, req)
	return rr
}

func TestCleanRequestReachesBackend(t *testing.T) {
	env := setup(t)
	rr := do(env.px, "GET", "http://shop.example/products", "203.0.113.10")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "backend-ok") {
		t.Fatalf("backend not reached: %q", body)
	}
	// The real client IP must be forwarded to the backend.
	if !strings.Contains(body, "203.0.113.10") {
		t.Errorf("X-Forwarded-For not set to real IP: %q", body)
	}
}

func TestSQLiRequestBlocked(t *testing.T) {
	env := setup(t)
	rr := do(env.px, "GET",
		"http://shop.example/wp-admin/admin-ajax.php?action=x&order_by=1%20union%20select%20pass",
		"203.0.113.11")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	// The offending IP should now carry a reputation violation.
	if env.rep.Lookup("203.0.113.11") == reputation.StateClean {
		t.Error("expected the SQLi source to be greylisted/blocked")
	}
}

func TestBlockedIPFailFast(t *testing.T) {
	env := setup(t)
	ip := "203.0.113.12"
	// Force block via repeated violations (default threshold 5).
	for i := 0; i < 5; i++ {
		env.rep.RegisterViolation(ip, "seed")
	}
	rr := do(env.px, "GET", "http://shop.example/", ip)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("blocked IP status = %d, want 403", rr.Code)
	}
}

func TestWhitelistBypassesFiltering(t *testing.T) {
	// A whitelisted IP must reach the backend even with a SQLi payload.
	env := setup(t, "whitelist:\n  dir: \"\"\n  ips: [\"203.0.113.99\"]")
	rr := do(env.px, "GET",
		"http://shop.example/wp-admin/admin-ajax.php?action=x&order_by=1%20union%20select%20pass",
		"203.0.113.99")
	if rr.Code != http.StatusOK {
		t.Fatalf("whitelisted IP status = %d, want 200 (bypassed)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "backend-ok") {
		t.Fatalf("whitelisted request did not reach backend: %q", rr.Body.String())
	}
}

func TestBlocklistDeniesStatically(t *testing.T) {
	env := setup(t, "blocklist:\n  dir: \"\"\n  ips: [\"203.0.113.44/32\"]")
	rr := do(env.px, "GET", "http://shop.example/", "203.0.113.44")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("blocklisted IP status = %d, want 403", rr.Code)
	}
}

func TestGreylistedIPGetsChallenge(t *testing.T) {
	env := setup(t)
	ip := "203.0.113.13"
	env.rep.RegisterViolation(ip, "seed") // 1 violation -> greylisted
	rr := do(env.px, "GET", "http://shop.example/", ip)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("greylisted status = %d, want 503 (challenge)", rr.Code)
	}
	if !strings.Contains(strings.ToLower(rr.Body.String()), "verifica") {
		t.Errorf("expected challenge page, got: %q", rr.Body.String())
	}
	// The challenge page must show the visitor's IP so it can be quoted for tracing.
	if !strings.Contains(rr.Body.String(), ip) {
		t.Errorf("challenge page should display the client IP %s, got: %q", ip, rr.Body.String())
	}
}

func TestRequestIDHeaderAndPage(t *testing.T) {
	env := setup(t)
	// Clean request: every response carries an X-Request-Id header.
	rr := do(env.px, "GET", "http://shop.example/products", "203.0.113.14")
	if rr.Header().Get("X-Request-Id") == "" {
		t.Error("clean response missing X-Request-Id header")
	}
	// Blocked request: the block page shows the IP and the same id is logged.
	ip := "203.0.113.15"
	for i := 0; i < 5; i++ {
		env.rep.RegisterViolation(ip, "seed")
	}
	rr = do(env.px, "GET", "http://shop.example/", ip)
	reqID := rr.Header().Get("X-Request-Id")
	if reqID == "" {
		t.Fatal("blocked response missing X-Request-Id header")
	}
	if !strings.Contains(rr.Body.String(), ip) {
		t.Errorf("block page should display the client IP %s, got: %q", ip, rr.Body.String())
	}
	data, err := os.ReadFile(filepath.Join(env.dir, "blocked.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), reqID) {
		t.Errorf("blocked.log should contain req_id %s, got: %q", reqID, string(data))
	}
}

func TestTrustedProxyRecoversRealIP(t *testing.T) {
	// The CDN's IP is trusted, so its CF-Connecting-IP header sets the real client.
	env := setup(t, "trusted_proxies:\n  dir: \"\"\n  ips: [\"203.0.113.7\"]")
	rr := doH(env.px, "GET", "http://shop.example/products", "203.0.113.7",
		map[string]string{"CF-Connecting-IP": "198.51.100.9"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	// The backend echoes X-Forwarded-For; it must be the real visitor, not the CDN.
	body := rr.Body.String()
	if !strings.Contains(body, "198.51.100.9") {
		t.Errorf("backend should see the real client IP, got: %q", body)
	}
	if strings.Contains(body, "203.0.113.7") {
		t.Errorf("the CDN IP must not be forwarded as the client: %q", body)
	}
}

func TestUntrustedPeerIgnoresForwardedHeader(t *testing.T) {
	// No trusted proxies configured: a forwarding header from an arbitrary client
	// must be ignored and the connection IP used (no spoofing).
	env := setup(t)
	rr := doH(env.px, "GET", "http://shop.example/products", "203.0.113.8",
		map[string]string{"CF-Connecting-IP": "198.51.100.9"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "203.0.113.8") {
		t.Errorf("connection IP must be used when peer is untrusted, got: %q", body)
	}
	if strings.Contains(body, "198.51.100.9") {
		t.Errorf("a spoofed CF-Connecting-IP must be ignored: %q", body)
	}
}

func TestBackend5xxLoggedToBackendLog(t *testing.T) {
	env := setup(t)
	rr := do(env.px, "GET", "http://shop.example/boom", "203.0.113.20")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 passed through", rr.Code)
	}
	data, err := os.ReadFile(filepath.Join(env.dir, "backend.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "backend 5xx response") {
		t.Errorf("backend.log missing 5xx entry: %q", string(data))
	}
	if !strings.Contains(string(data), "203.0.113.20") {
		t.Errorf("backend.log 5xx entry missing client ip: %q", string(data))
	}
}

func TestBackendUnreachableLoggedToBackendLog(t *testing.T) {
	env := setup(t)
	env.backend.Close() // backend down -> transport failure -> 502
	rr := do(env.px, "GET", "http://shop.example/", "203.0.113.21")
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rr.Code)
	}
	data, err := os.ReadFile(filepath.Join(env.dir, "backend.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "backend unreachable") {
		t.Errorf("backend.log missing unreachable entry: %q", string(data))
	}
}

// sessionCookie returns the value of the smoker session cookie the response set,
// or "" if none.
func sessionCookie(rr *httptest.ResponseRecorder) string {
	for _, c := range rr.Result().Cookies() {
		if c.Name == "smoker_sid" {
			return c.Value
		}
	}
	return ""
}

func TestChallengePassedBreaksLoop(t *testing.T) {
	env := setup(t)
	ip := "203.0.113.40"

	// First visit to the challenge-gated path: greylisted and challenged. The
	// response also establishes a stable session cookie.
	rr := do(env.px, "GET", "http://shop.example/gate", ip)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("first hit should be challenged (503), got %d", rr.Code)
	}
	cookie := sessionCookie(rr)
	if cookie == "" {
		t.Fatal("challenge response must set a session cookie for a stable identity")
	}
	id := cookie
	if i := strings.IndexByte(cookie, '.'); i > 0 {
		id = cookie[:i]
	}

	// Simulate the visitor solving the challenge: IP cleaned, session marked.
	env.rep.MarkClean(ip, "test challenge passed")
	env.tracker.MarkChallengePassed("sid:" + id)

	// Re-requesting the same gated path with the same cookie must NOT re-challenge
	// (the loop is broken) and must reach the backend.
	rr2 := doH(env.px, "GET", "http://shop.example/gate", ip,
		map[string]string{"Cookie": "smoker_sid=" + cookie})
	if rr2.Code != http.StatusOK {
		t.Fatalf("a session that passed a challenge must not be re-challenged; got %d", rr2.Code)
	}
	if !strings.Contains(rr2.Body.String(), "backend-ok") {
		t.Errorf("passed session should reach the backend, got: %q", rr2.Body.String())
	}
	if env.rep.Lookup(ip) != reputation.StateClean {
		t.Error("a passed session must not be re-greylisted (challenge loop)")
	}
}

func TestLargeBodyForwardedWhole(t *testing.T) {
	env := setup(t)
	// 3 MiB > maxInspectBody (1 MiB): the inspected prefix plus the remainder must
	// still reach the backend intact — no silent truncation.
	const size = 3 << 20
	body := strings.Repeat("A", size)
	req := httptest.NewRequest("POST", "http://shop.example/echo-len", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.50:1234"
	rr := httptest.NewRecorder()
	env.px.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	want := fmt.Sprintf("len=%d", size)
	if !strings.Contains(rr.Body.String(), want) {
		t.Errorf("backend received a truncated body: got %q, want %q", rr.Body.String(), want)
	}
}

// A buffered request must stay rewindable (GetBody set, ContentLength correct) so
// the backend Transport can retry it after a benign HTTP/2 GOAWAY instead of
// surfacing a 502 to the client. Regression test for that production bug.
func TestBufferedRequestIsRewindable(t *testing.T) {
	env := setup(t)

	// Empty body (typical static GET): ContentLength 0 lets the reverse proxy drop
	// the body and keep the request retryable.
	g := httptest.NewRequest("GET", "http://shop.example/wp-content/uploads/x.png", nil)
	_ = env.px.buildView(g)
	if g.ContentLength != 0 {
		t.Errorf("empty GET must have ContentLength 0, got %d", g.ContentLength)
	}
	if g.GetBody == nil {
		t.Error("empty GET must be rewindable (GetBody set) so a GOAWAY can be retried")
	}

	// Small POST body: rewindable and re-readable to the exact same bytes.
	p := httptest.NewRequest("POST", "http://shop.example/submit", strings.NewReader("hello"))
	view := env.px.buildView(p)
	if string(view.Body) != "hello" {
		t.Errorf("inspected body = %q, want hello", view.Body)
	}
	if p.ContentLength != 5 {
		t.Errorf("ContentLength = %d, want 5", p.ContentLength)
	}
	if p.GetBody == nil {
		t.Fatal("buffered POST must be rewindable (GetBody set)")
	}
	rc, err := p.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	if string(b) != "hello" {
		t.Errorf("GetBody replay = %q, want hello", b)
	}
}

func TestContentCacheServesFromCache(t *testing.T) {
	env := setup(t, "cache:\n  enabled: true\n  ttl: \"1h\"")

	// First request: MISS, fetched from the backend and stored.
	rr1 := do(env.px, "GET", "http://shop.example/cacheimg.png", "203.0.113.60")
	if rr1.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", rr1.Code)
	}
	if got := rr1.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("first X-Cache = %q, want MISS", got)
	}
	if rr1.Body.String() != "IMG-1" {
		t.Fatalf("first body = %q, want IMG-1", rr1.Body.String())
	}

	// Second request: HIT, served from cache without touching the backend.
	rr2 := do(env.px, "GET", "http://shop.example/cacheimg.png", "203.0.113.61")
	if rr2.Code != http.StatusOK {
		t.Fatalf("second status = %d, want 200", rr2.Code)
	}
	if got := rr2.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("second X-Cache = %q, want HIT", got)
	}
	if rr2.Body.String() != "IMG-1" {
		t.Errorf("second body = %q, want cached IMG-1", rr2.Body.String())
	}
	if n := atomic.LoadInt64(env.imgHits); n != 1 {
		t.Errorf("backend was hit %d times, want 1 (second served from cache)", n)
	}
}

func TestContentCacheRespectsNoStore(t *testing.T) {
	env := setup(t, "cache:\n  enabled: true\n  ttl: \"1h\"")
	rr1 := do(env.px, "GET", "http://shop.example/nostore.png", "203.0.113.62")
	rr2 := do(env.px, "GET", "http://shop.example/nostore.png", "203.0.113.62")
	// A no-store response must never be cached: each call reaches the backend and
	// gets a fresh (different) body.
	if rr1.Body.String() == rr2.Body.String() {
		t.Errorf("no-store response was cached: both bodies = %q", rr1.Body.String())
	}
	if got := rr2.Header().Get("X-Cache"); got == "HIT" {
		t.Errorf("no-store response must not be a cache HIT")
	}
}

func TestNonCacheablePathNotCached(t *testing.T) {
	env := setup(t, "cache:\n  enabled: true\n  ttl: \"1h\"")
	// A dynamic path (no cacheable extension) must not be cached or tagged.
	rr := do(env.px, "GET", "http://shop.example/api/data", "203.0.113.63")
	if got := rr.Header().Get("X-Cache"); got != "" {
		t.Errorf("non-cacheable path must have no X-Cache header, got %q", got)
	}
}

func TestProactiveFloodGovernor(t *testing.T) {
	// Rule-free flood protection: a per-IP weighted budget throttles a sensitive
	// endpoint with no hand-written rule. Small burst + weight so 2 pass, 3rd trips.
	env := setup(t, "protection:\n  enabled: true\n  rate_limit:\n    burst: 40\n    sensitive_weight: 20\n    sensitive_paths: [\"/flood\"]")
	ip := "203.0.113.80"
	hdr := map[string]string{"User-Agent": "Mozilla/5.0"}
	for i := 0; i < 2; i++ {
		rr := doH(env.px, "POST", "http://shop.example/flood", ip, hdr)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d should pass the governor, got %d", i, rr.Code)
		}
	}
	rr := doH(env.px, "POST", "http://shop.example/flood", ip, hdr)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd request over the per-IP budget must be throttled (429), got %d", rr.Code)
	}
}

func TestProactiveAnomalyChallengesScanner(t *testing.T) {
	// Rule-free bot protection: an offensive-tool User-Agent scores over the
	// anomaly threshold and is challenged (browsers pass, the scanner cannot).
	env := setup(t, "protection:\n  enabled: true")
	rr := doH(env.px, "GET", "http://shop.example/", "203.0.113.81",
		map[string]string{"User-Agent": "sqlmap/1.7", "Accept": "*/*", "Accept-Language": "en"})
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("scanner UA should be challenged (503), got %d", rr.Code)
	}
}

func TestProtectionDisabledByDefault(t *testing.T) {
	// With protection off (default), a scanner UA is NOT proactively challenged
	// (only signature rules apply), so existing behavior is unchanged.
	env := setup(t)
	rr := doH(env.px, "GET", "http://shop.example/", "203.0.113.82",
		map[string]string{"User-Agent": "sqlmap/1.7"})
	if rr.Code == http.StatusServiceUnavailable {
		t.Error("protection is opt-in; a scanner UA must not be challenged when disabled")
	}
}

// Regression: a cookieless flood that rotates its User-Agent every request must
// still be rate-limited, because behavioral tracking keys a cookieless client on
// the IP alone (not a per-request cookie or an IP+UA fingerprint). Reproduces the
// real-world xmlrpc.php flood that was slipping through.
func TestBehavioralRateLimitByIPIgnoresUARotation(t *testing.T) {
	env := setup(t)
	ip := "203.0.113.70"
	uas := []string{
		"Jetpack by WordPress.com",
		"Jetpack/12.0; WordPress/6.3; http://site63925488.com",
		"Jetpack/13.0; WordPress/6.3; http://site24195772.com",
	}

	// 1st hit (no cookie): allowed.
	rr := doH(env.px, "POST", "http://shop.example/xmlrpc.php", ip,
		map[string]string{"User-Agent": uas[0]})
	if rr.Code != http.StatusOK {
		t.Fatalf("1st xmlrpc hit should pass, got %d", rr.Code)
	}

	// 2nd hit, different UA, still no cookie: must be throttled (429) despite the
	// rotated User-Agent, proving the key is the IP.
	rr = doH(env.px, "POST", "http://shop.example/xmlrpc.php", ip,
		map[string]string{"User-Agent": uas[1]})
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("2nd xmlrpc hit from same IP (rotated UA, no cookie) must be rate-limited, got %d", rr.Code)
	}
}
