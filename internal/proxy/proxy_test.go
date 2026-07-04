package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/smoker/internal/challenge"
	"github.com/ostap-mykhaylyak/smoker/internal/config"
	"github.com/ostap-mykhaylyak/smoker/internal/detect"
	"github.com/ostap-mykhaylyak/smoker/internal/logging"
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

type testEnv struct {
	px      *Proxy
	backend *httptest.Server
	rep     *reputation.Manager
	dir     string // config + log dir (read backend.log/access.log here)
}

func setup(t *testing.T, extra ...string) *testEnv {
	t.Helper()
	dir := t.TempDir()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /boom lets a test drive a backend-origin 5xx (recorded in backend.log).
		if r.URL.Path == "/boom" {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "boom")
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
	tmpl, err := detect.ParseTemplate([]byte(sqli))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := detect.Compile(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	engine.Reload([]*detect.CompiledSignature{sig})

	cl := &cleaner{rep: rep, tr: tr}
	ch := challenge.New(cfg.Challenge.AssetsDir, cfg.Challenge.Secret, cfg.Challenge.TTL.Std(), 0, nil, cl)

	px := New(Deps{Config: cfgMgr, Engine: engine, Rep: rep, Tracker: tr, Challenge: ch, Logs: logs})
	return &testEnv{px: px, backend: backend, rep: rep, dir: dir}
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
