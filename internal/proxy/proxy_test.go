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
}

func setup(t *testing.T, extra ...string) *testEnv {
	t.Helper()
	dir := t.TempDir()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	return &testEnv{px: px, backend: backend, rep: rep}
}

type cleaner struct {
	rep reputation.Store
	tr  session.Tracker
}

func (c *cleaner) MarkIPClean(ip, reason string) { c.rep.MarkClean(ip, reason) }
func (c *cleaner) MarkSessionPassed(key string)  { c.tr.MarkChallengePassed(key) }

func do(px *Proxy, method, target, ip string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = ip + ":54321"
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
}
