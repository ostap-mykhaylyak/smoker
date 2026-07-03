// Package proxy is the reverse-proxy core. It receives DNAT-redirected traffic
// on the internal ports, runs the unified inspection pipeline, and forwards
// clean requests to the real backend with correct X-Forwarded-For / X-Real-IP.
//
// Per-request pipeline (spec order):
//  1. IP Reputation check (fail-fast: drop already-blocked IPs cheaply)
//  2. Challenge verify endpoint handling
//  3. Greylist -> serve challenge page
//  4. Detection Engine inspection (CVE + behavioral, one pass)
//  5. Apply action (block / challenge / log-only / rate-limit)
//  6. Clean -> record session, set forwarded headers, proxy to backend, log
//
// The hot path avoids allocations where practical: request bodies are read into
// pooled buffers, and all regex/signature compilation happens at load time.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"time"

	"github.com/ostap-mykhaylyak/smoker/internal/challenge"
	"github.com/ostap-mykhaylyak/smoker/internal/config"
	"github.com/ostap-mykhaylyak/smoker/internal/detect"
	"github.com/ostap-mykhaylyak/smoker/internal/logging"
	"github.com/ostap-mykhaylyak/smoker/internal/reputation"
	"github.com/ostap-mykhaylyak/smoker/internal/session"
)

// ErrNoOriginalDst is returned by OriginalDst when no conntrack entry exists.
var ErrNoOriginalDst = errors.New("no SO_ORIGINAL_DST available")

// maxInspectBody bounds how much request body is buffered for inspection and
// replay. Bodies larger than this are inspected up to the limit then streamed.
const maxInspectBody = 1 << 20 // 1 MiB

type ctxKey int

const (
	ctxOrigDst ctxKey = iota
	ctxSetCookie
	ctxBackend
	ctxClientTLS // bool: was the inbound client connection TLS?
)

// backendTarget is the per-request upstream chosen from the inbound listener:
// the scheme drives whether the Transport does TLS, addr is the physical dial.
type backendTarget struct {
	scheme string // "http" | "https"
	addr   string // host:port to dial (e.g. 127.0.0.1:443)
}

// chooseBackend routes by inbound listener so nginx's own vhost logic is kept:
//   - plaintext :80 in  -> backend.http (nginx :80 keeps its 301->https etc.)
//   - TLS :443 in       -> backend.https over TLS (use_tls) or backend.http
func chooseBackend(r *http.Request, cfg *config.Config) backendTarget {
	if r.TLS != nil && cfg.Backend.UseTLS {
		return backendTarget{scheme: "https", addr: cfg.Backend.HTTPS}
	}
	return backendTarget{scheme: "http", addr: cfg.Backend.HTTP}
}

// Proxy is the HTTP handler shared by the plaintext and TLS listeners.
type Proxy struct {
	cfg       *config.Manager
	engine    detect.Engine
	rep       reputation.Store
	tracker   session.Tracker
	challenge *challenge.Manager
	logs      *logging.Loggers
	secret    []byte // HMAC key for signing the session cookie

	rp *httputil.ReverseProxy
}

// Deps bundles the collaborators (all interfaces -> mockable in tests).
type Deps struct {
	Config    *config.Manager
	Engine    detect.Engine
	Rep       reputation.Store
	Tracker   session.Tracker
	Challenge *challenge.Manager
	Logs      *logging.Loggers
	// Secret signs the session cookie so it cannot be forged/rotated to evade
	// behavioral rate limits.
	Secret string
}

// New builds a Proxy and its underlying ReverseProxy.
func New(d Deps) *Proxy {
	p := &Proxy{
		cfg:       d.Config,
		engine:    d.Engine,
		rep:       d.Rep,
		tracker:   d.Tracker,
		challenge: d.Challenge,
		logs:      d.Logs,
		secret:    []byte(d.Secret),
	}

	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.backendError,
	}

	// Custom transport: the outbound request keeps the client's Host as its URL
	// host (so TLS SNI, cert verification and backend vhost selection all use
	// the real domain), while DialContext redirects the physical TCP connection
	// to the configured backend address (e.g. 127.0.0.1:443). This is the
	// host-preserving re-encryption pattern for a local backend.
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		// Physical dial goes to the backend chosen per-request (stashed in the
		// request context), ignoring the host-preserving URL used for SNI.
		var addr string
		if bt, ok := ctx.Value(ctxBackend).(backendTarget); ok && bt.addr != "" {
			addr = bt.addr
		} else {
			cfg := p.cfg.Get()
			addr = cfg.Backend.HTTP
			if cfg.Backend.UseTLS {
				addr = cfg.Backend.HTTPS
			}
		}
		dl := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		return dl.DialContext(ctx, "tcp", addr)
	}
	base.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: d.Config.Get().Backend.InsecureSkipVerify, //nolint:gosec // trusted local backend, opt-in
	}
	p.rp.Transport = base
	return p
}

// ConnContext is installed on the http.Server so each connection's original
// destination (SO_ORIGINAL_DST) is captured once and stashed in the context.
func (p *Proxy) ConnContext(ctx context.Context, c net.Conn) context.Context {
	if dst, err := OriginalDst(c); err == nil {
		return context.WithValue(ctx, ctxOrigDst, dst)
	}
	return ctx
}

// ServeHTTP is the entrypoint for every request.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	cfg := p.cfg.Get()
	clientIP := realClientIP(r)

	// Capture the response status/size for the logs (so access.log records
	// 200/301/404/... — key for spotting scanner 404 storms).
	sw := &statusWriter{ResponseWriter: w}
	w = sw

	// Fail-open guard: if the inspection stack panics and fail-open is enabled,
	// forward the request rather than dropping it.
	defer func() {
		if rec := recover(); rec != nil {
			// A client that disconnects mid-response makes the reverse proxy
			// panic with http.ErrAbortHandler. That is normal, not a pipeline
			// failure: re-panic so the http.Server aborts the connection
			// silently instead of logging a spurious error.
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			p.logs.Service.Error("panic in pipeline", "err", rec, "ip", clientIP, "path", r.URL.Path)
			if cfg.FailOpen {
				p.forward(w, r, clientIP, nil, cfg, start)
				return
			}
			p.block(w, r, clientIP, http.StatusServiceUnavailable, "internal error", nil, cfg)
		}
	}()

	// (0) Static access lists (operator-controlled, hot-reloadable).
	if cfg.Whitelisted(clientIP) {
		// Trusted IP: bypass all filtering, stream straight to the backend.
		p.forward(w, r, clientIP, nil, cfg, start)
		return
	}
	if cfg.Blocklisted(clientIP) {
		p.challenge.ServeBlocked(w, r, http.StatusForbidden, "your address is blocked")
		p.logBlocked(clientIP, r, "", "static-blocklist", "block", "high", http.StatusForbidden)
		return
	}

	// (1) IP reputation fail-fast.
	switch p.rep.Lookup(clientIP) {
	case reputation.StateBlocked:
		p.challenge.ServeBlocked(w, r, http.StatusForbidden, "your address is temporarily blocked")
		p.logBlocked(clientIP, r, "", "reputation:blocked", "block", string(reputation.StateBlocked), http.StatusForbidden)
		return
	case reputation.StateGreylisted:
		// (2) allow the verify endpoint through even while greylisted.
		sessionKey := p.sessionKey(r, clientIP)
		if p.challenge.HandleVerify(w, r, clientIP, sessionKey) {
			return
		}
		// (3) serve challenge for everything else.
		if cfg.Challenge.Enabled {
			p.challenge.ServeChallenge(w, r, clientIP)
			return
		}
	default:
		// clean: verify endpoint should also short-circuit if hit.
		if r.URL.Path == challenge.VerifyPath {
			if p.challenge.HandleVerify(w, r, clientIP, p.sessionKey(r, clientIP)) {
				return
			}
		}
	}

	// (4) Build the request view (bounded body copy for inspection + replay).
	view := p.buildView(r)
	sessionKey := p.sessionKey(r, clientIP)

	dec := p.engine.Inspect(view, sessionKey)

	// (5) Apply action.
	if dec.Matched {
		p.applyAction(w, r, clientIP, sessionKey, dec, cfg, view, start)
		return
	}

	// (6) Clean passthrough.
	p.forward(w, r, clientIP, view.Body, cfg, start)
	// Record the clean pageview for behavioral tracking (post-decision so a
	// cold request has no self-generated prior pageview).
	p.tracker.Record(sessionKey, view)
}

func (p *Proxy) applyAction(w http.ResponseWriter, r *http.Request, ip, sessionKey string, dec detect.Decision, cfg *config.Config, view *detect.RequestView, start time.Time) {
	inc := dec.Incident
	switch dec.Action {
	case detect.ActionLogOnly:
		// Tuning mode: pass through to the backend and record what WOULD be
		// blocked. The logged status is the ACTUAL status served to the client
		// (not the would-be block code), so log-only entries don't look like
		// enforced blocks.
		p.forward(w, r, ip, view.Body, cfg, start)
		status, _ := statusInfo(w)
		p.logBlocked(ip, r, inc.TemplateID, inc.Reason, "log-only", string(inc.Severity), status)
		return
	case detect.ActionChallenge:
		p.rep.RegisterViolation(ip, "detect:"+inc.TemplateID)
		p.challenge.ServeChallenge(w, r, ip)
		p.logBlocked(ip, r, inc.TemplateID, inc.Reason, "challenge", string(inc.Severity), http.StatusServiceUnavailable)
		return
	case detect.ActionRateLimit:
		p.rep.RegisterViolation(ip, "detect:"+inc.TemplateID)
		w.Header().Set("Retry-After", "10")
		p.challenge.ServeBlocked(w, r, http.StatusTooManyRequests, "rate limited")
		p.logBlocked(ip, r, inc.TemplateID, inc.Reason, "rate-limit", string(inc.Severity), http.StatusTooManyRequests)
		return
	case detect.ActionBan:
		// Blacklist the IP outright: every subsequent request fails fast at the
		// reputation check for block_ttl.
		p.rep.Block(ip, "detect:"+inc.TemplateID)
		p.block(w, r, ip, dec.RespCode, inc.Reason, inc, cfg)
		p.logBlocked(ip, r, inc.TemplateID, inc.Reason, "ban", string(inc.Severity), dec.RespCode)
		return
	default: // ActionBlock
		p.rep.RegisterViolation(ip, "detect:"+inc.TemplateID)
		p.block(w, r, ip, dec.RespCode, inc.Reason, inc, cfg)
		p.logBlocked(ip, r, inc.TemplateID, inc.Reason, "block", string(inc.Severity), dec.RespCode)
		return
	}
}

func (p *Proxy) block(w http.ResponseWriter, r *http.Request, ip string, code int, reason string, inc *detect.Incident, cfg *config.Config) {
	p.challenge.ServeBlocked(w, r, code, reason)
}

// forward proxies a clean (or fail-open) request to the backend.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, ip string, body []byte, cfg *config.Config, start time.Time) {
	// Replay the buffered body to the backend.
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}
	// Stash real IP (for forwarded headers) and the per-request backend target
	// (used by rewrite for the scheme and by the Transport's DialContext).
	ctx := context.WithValue(r.Context(), ctxSetCookie, ip)
	ctx = context.WithValue(ctx, ctxBackend, chooseBackend(r, cfg))
	ctx = context.WithValue(ctx, ctxClientTLS, r.TLS != nil)
	p.rp.ServeHTTP(w, r.WithContext(ctx))
	status, n := statusInfo(w)
	p.logAccess(ip, r, status, n, time.Since(start))
}

// rewrite targets the backend and sets forwarding headers with the real IP.
// It is host-preserving: the URL host stays the client's Host so the backend
// serves the right vhost and (for TLS) SNI/cert verification use the real
// domain. The Transport's DialContext sends the connection to the real backend.
func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	scheme := "http"
	if bt, ok := pr.In.Context().Value(ctxBackend).(backendTarget); ok && bt.scheme != "" {
		scheme = bt.scheme
	}
	pr.Out.URL.Scheme = scheme
	pr.Out.URL.Host = pr.In.Host
	pr.Out.Host = pr.In.Host

	// X-Forwarded-* using the true pre-proxy client IP.
	pr.SetXForwarded()
	if ip, ok := pr.In.Context().Value(ctxSetCookie).(string); ok && ip != "" {
		pr.Out.Header.Set("X-Real-IP", ip)
		pr.Out.Header.Set("X-Forwarded-For", ip)
	}
}

func (p *Proxy) modifyResponse(resp *http.Response) error {
	// Attach a signed session cookie when the client has none, or replace a
	// forged/invalid one, so behavioral tracking has a stable, unforgeable key.
	req := resp.Request
	if req == nil {
		return nil
	}
	cfg := p.cfg.Get()
	needSet := true
	if c, err := req.Cookie(cfg.Session.CookieName); err == nil {
		if _, ok := verifySID(p.secret, c.Value); ok {
			needSet = false // client already has a valid cookie
		}
	}
	if needSet {
		if val := newSignedSID(p.secret); val != "" {
			secure, _ := req.Context().Value(ctxClientTLS).(bool)
			cookie := &http.Cookie{
				Name:     cfg.Session.CookieName,
				Value:    val,
				Path:     "/",
				HttpOnly: true,
				Secure:   secure,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int(cfg.Session.TTL.Std().Seconds()),
			}
			resp.Header.Add("Set-Cookie", cookie.String())
		}
	}

	// Optional zstd response compression for clients that advertise it.
	if cfg.Compression.Zstd && shouldCompress(req, resp, cfg.Compression.MinSize) {
		resp.Body = zstdReader(resp.Body)
		resp.Header.Set("Content-Encoding", "zstd")
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
		resp.Header.Add("Vary", "Accept-Encoding")
	}
	return nil
}

func (p *Proxy) backendError(w http.ResponseWriter, r *http.Request, err error) {
	// The client went away before the backend responded (request context
	// canceled): nothing to serve and nothing worth logging.
	if errors.Is(err, context.Canceled) || errors.Is(r.Context().Err(), context.Canceled) {
		return
	}
	p.logs.Service.Error("backend error", "err", err, "path", r.URL.Path)
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write([]byte("502 Bad Gateway"))
}

// buildView reads a bounded copy of the body and assembles a RequestView. The
// body is freshly allocated (not pooled): the copy backs the reader replayed to
// the backend, so pooling it risks corruption if the Transport is still reading
// it when the buffer is reused.
func (p *Proxy) buildView(r *http.Request) *detect.RequestView {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(r.Body, maxInspectBody))
		_ = r.Body.Close()
	}

	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		headers[k] = joinValues(v)
	}

	// Inspect URL-decoded content: attackers routinely percent-encode payloads
	// (e.g. %20 for spaces). Signatures are written against decoded text, so we
	// decode the query once before matching. Path is already decoded by net/url.
	decodedQuery := r.URL.RawQuery
	if dq, err := url.QueryUnescape(r.URL.RawQuery); err == nil {
		decodedQuery = dq
	}
	pathNorm := detect.NormalizePath(r.URL.Path)
	full, fullNorm := r.URL.Path, pathNorm
	if decodedQuery != "" {
		full += "?" + decodedQuery
		fullNorm += "?" + decodedQuery
	}

	return &detect.RequestView{
		Method:      r.Method,
		Path:        r.URL.Path,
		PathNorm:    pathNorm,
		RawQuery:    r.URL.RawQuery,
		FullURI:     full,
		FullURINorm: fullNorm,
		Headers:     headers,
		Body:        body,
	}
}

// sessionKey returns the id from a valid (HMAC-signed) session cookie, or an
// IP+UA fingerprint fallback. A missing, forged or rotated cookie falls back to
// the fingerprint — which is bound to the connection IP and therefore cannot be
// rotated to spawn fresh sessions and evade behavioral rate limits.
func (p *Proxy) sessionKey(r *http.Request, ip string) string {
	cfg := p.cfg.Get()
	if c, err := r.Cookie(cfg.Session.CookieName); err == nil && c.Value != "" {
		if id, ok := verifySID(p.secret, c.Value); ok {
			return "sid:" + id
		}
	}
	return "fp:" + sidFor(ip, r.UserAgent())
}

// --- logging helpers ---

func (p *Proxy) logAccess(ip string, r *http.Request, status int, bytes int64, dur time.Duration) {
	p.logs.Access.Info("request",
		slog.String("ip", ip),
		slog.String("method", r.Method),
		slog.String("host", r.Host),
		slog.String("path", r.URL.Path),
		slog.String("query", r.URL.RawQuery),
		slog.Int("status", status),
		slog.Int64("bytes", bytes),
		slog.String("ua", r.UserAgent()),
		slog.Int64("dur_us", dur.Microseconds()),
	)
}

func (p *Proxy) logBlocked(ip string, r *http.Request, templateID, reason, action, severity string, status int) {
	p.logs.Blocked.Warn("blocked",
		slog.String("ip", ip),
		slog.String("method", r.Method),
		slog.String("host", r.Host),
		slog.String("path", r.URL.Path),
		slog.Int("status", status),
		slog.String("template_id", templateID),
		slog.String("severity", severity),
		slog.String("action", action),
		slog.String("reason", reason),
	)
}

// --- pure helpers ---

// realClientIP returns the source IP of the connection. With nftables REDIRECT
// the client source is NOT rewritten, so RemoteAddr is the true client IP. We
// deliberately do NOT trust inbound X-Forwarded-For (smoker is the edge).
func realClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if ap, err := netip.ParseAddr(host); err == nil {
		return ap.String()
	}
	return host
}

func joinValues(v []string) string {
	switch len(v) {
	case 0:
		return ""
	case 1:
		return v[0]
	default:
		out := v[0]
		for _, s := range v[1:] {
			out += "," + s
		}
		return out
	}
}
