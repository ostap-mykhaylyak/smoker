// Package protect is smoker's PROACTIVE protection layer. Unlike the signature
// engine (which needs a template per attack), these protections are generic and
// rule-free — they defend every site out of the box, in the spirit of a
// commercial WAF's automatic bot/flood mitigation:
//
//   - Rate governor: a per-IP token bucket (sliding budget) that throttles
//     floods, weighting abuse-prone endpoints (xmlrpc.php, wp-login.php, …) more.
//     It catches high-volume abuse without a hand-written rule per endpoint.
//   - Anomaly scoring: each request accrues a score from generic bot/scanner
//     signals (offensive User-Agents, missing browser headers, scanner paths,
//     traversal/injection markers, anomalous methods). Over a threshold it acts.
//
// A verdict is returned as a detect.Decision so the proxy applies it through the
// SAME action machinery (challenge / rate-limit / ban / block / log-only) and
// logging as signature matches. Nothing here inspects a response or the body;
// it is a cheap, early, request-shape gate keyed on the real client IP.
package protect

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/ostap-mykhaylyak/smoker/internal/detect"
)

// RateOptions configures the per-IP flood governor.
type RateOptions struct {
	Enabled         bool
	Window          time.Duration
	Burst           int      // max weighted requests per window per IP
	SensitiveWeight int      // cost multiplier for a sensitive path (>=1)
	SensitivePaths  []string // path prefixes that cost SensitiveWeight
	Action          detect.Action
	RespCode        int
}

// AnomalyOptions configures the request-anomaly scorer.
type AnomalyOptions struct {
	Enabled   bool
	Threshold int
	Action    detect.Action
	RespCode  int
}

// Options is the full proactive configuration for one assessment. The proxy
// builds it from the hot-reloadable config each request (cheap: a value struct,
// slices passed by reference).
type Options struct {
	Rate    RateOptions
	Anomaly AnomalyOptions
}

// Guard holds the per-IP rate state. It is safe for concurrent use.
type Guard struct {
	mu      sync.Mutex
	buckets *lru.Cache[string, *bucket]
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New builds a Guard tracking up to maxIPs distinct client IPs (LRU eviction).
func New(maxIPs int) (*Guard, error) {
	if maxIPs <= 0 {
		maxIPs = 65536
	}
	c, err := lru.New[string, *bucket](maxIPs)
	if err != nil {
		return nil, err
	}
	return &Guard{buckets: c, now: time.Now}, nil
}

// Assess runs the enabled proactive checks and returns a decision plus ok=true
// when the request should be acted on. The anomaly scorer runs first (it does
// not consume rate budget); the rate governor runs second so every counted
// request drains the bucket exactly once.
func (g *Guard) Assess(r *http.Request, ip string, opt Options) (detect.Decision, bool) {
	if opt.Anomaly.Enabled {
		if score, reason := anomalyScore(r); score >= opt.Anomaly.Threshold {
			return decision("protect:anomaly", reason, opt.Anomaly.Action, opt.Anomaly.RespCode), true
		}
	}
	if opt.Rate.Enabled {
		if !g.allow(ip, r.URL.Path, opt.Rate) {
			return decision("protect:rate-governor",
				"per-IP request budget exceeded", opt.Rate.Action, opt.Rate.RespCode), true
		}
	}
	return detect.Decision{}, false
}

// allow applies the token bucket for ip, charging weight for the path. It
// returns false when the IP is over budget.
func (g *Guard) allow(ip, path string, opt RateOptions) bool {
	burst := float64(opt.Burst)
	if burst <= 0 {
		return true // misconfigured -> do not throttle
	}
	win := opt.Window.Seconds()
	if win <= 0 {
		win = 60
	}
	refillPerSec := burst / win

	cost := 1.0
	if opt.SensitiveWeight > 1 && matchPrefix(path, opt.SensitivePaths) {
		cost = float64(opt.SensitiveWeight)
	}

	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	b, ok := g.buckets.Get(ip)
	if !ok {
		b = &bucket{tokens: burst, last: now}
		g.buckets.Add(ip, b)
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * refillPerSec
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}
	if b.tokens >= cost {
		b.tokens -= cost
		return true
	}
	return false
}

// Len reports the number of tracked IPs (for metrics/tests).
func (g *Guard) Len() int { return g.buckets.Len() }

func matchPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func decision(id, reason string, act detect.Action, code int) detect.Decision {
	if act == "" {
		act = detect.ActionChallenge
	}
	if code == 0 {
		code = 403
	}
	return detect.Decision{
		Matched:  true,
		Action:   act,
		RespCode: code,
		Incident: &detect.Incident{
			TemplateID: id,
			Severity:   detect.SevMedium,
			Action:     act,
			RespCode:   code,
			Source:     "protection",
			Reason:     reason,
		},
	}
}

// --- anomaly scoring (stateless, request-shape only) ---

// Signal weights. A single unmistakable signal (offensive tool UA, an abusive
// method) is worth the default threshold on its own; softer signals must combine.
const (
	scoreOffensiveUA = 100
	scoreBadMethod   = 100
	scoreScannerPath = 55
	scoreInjection   = 55
	scoreEmptyUA     = 35
	scoreScriptUA    = 25
	scoreNoAccept    = 20
	scoreNoAccLang   = 10
	scoreOverlong    = 20
)

var (
	offensiveUA = []string{
		"sqlmap", "nikto", "nessus", "masscan", "nmap", "zgrab", "wpscan",
		"dirbuster", "gobuster", "feroxbuster", "ffuf", "hydra", "nuclei",
		"acunetix", "netsparker", "arachni", "w3af", "openvas", "havij",
		"whatweb", "wfuzz", "commix", "xsstrike",
	}
	scriptUA = []string{
		"python-requests", "python-urllib", "go-http-client", "curl/", "wget/",
		"libwww-perl", "java/", "okhttp", "scrapy", "httpclient", "aiohttp",
		"guzzlehttp", "node-fetch", "axios/",
	}
	scannerPaths = []string{
		"/.env", "/.git/", "/.svn/", "/.hg/", "/.aws/", "/.ssh/",
		"/phpmyadmin", "/pma/", "/adminer", "/dbadmin", "/mysql",
		"/server-status", "/server-info", "/actuator", "/.docker",
		"/vendor/phpunit", "/cgi-bin/", "/wp-config.php.", "/config.php.",
		"/.well-known/../", "/backup", "/.vscode", "/.idea",
	}
	injectionMarkers = []string{
		"../", "..%2f", "..\\", "%2e%2e", "/etc/passwd", "/proc/self/",
		"<script", "union select", "union%20select", "${jndi:", "${env:",
		"/bin/sh", "; rm ", "|| ", "&&curl", "phpinfo(",
	}
	badMethods = map[string]bool{
		"TRACE": true, "TRACK": true, "DEBUG": true, "CONNECT": true,
	}
)

// anomalyScore returns the accumulated suspicion score and a short reason naming
// the dominant signal(s).
func anomalyScore(r *http.Request) (int, string) {
	score := 0
	var reasons []string
	add := func(pts int, why string) {
		score += pts
		reasons = append(reasons, why)
	}

	if badMethods[strings.ToUpper(r.Method)] {
		add(scoreBadMethod, "method:"+r.Method)
	}

	ua := strings.ToLower(r.UserAgent())
	switch {
	case ua == "":
		add(scoreEmptyUA, "empty-ua")
	case containsAny(ua, offensiveUA):
		add(scoreOffensiveUA, "offensive-ua")
	case containsAny(ua, scriptUA):
		add(scoreScriptUA, "script-ua")
	}

	// Headers a real browser almost always sends (only meaningful for navigations).
	if r.Method == http.MethodGet {
		if r.Header.Get("Accept") == "" {
			add(scoreNoAccept, "no-accept")
		}
		if r.Header.Get("Accept-Language") == "" {
			add(scoreNoAccLang, "no-accept-language")
		}
	}

	pathLower := strings.ToLower(r.URL.Path)
	if containsAny(pathLower, scannerPaths) {
		add(scoreScannerPath, "scanner-path")
	}

	decodedQuery := r.URL.RawQuery
	if dq, err := url.QueryUnescape(r.URL.RawQuery); err == nil {
		decodedQuery = dq
	}
	full := strings.ToLower(pathLower + "?" + decodedQuery)
	if containsAny(full, injectionMarkers) {
		add(scoreInjection, "injection-marker")
	}

	if len(r.URL.RawQuery) > 1024 || len(r.URL.Path) > 512 {
		add(scoreOverlong, "overlong-uri")
	}

	return score, strings.Join(reasons, ",")
}

func containsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}
