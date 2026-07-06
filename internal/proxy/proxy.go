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
	"strconv"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/smoker/internal/cache"
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
	ctxClientTLS  // bool: was the inbound client connection TLS?
	ctxReqID      // string: per-request id shown to the visitor and logged
	ctxCookieSet  // bool: the session cookie was already set earlier in the pipeline
	ctxCacheStore // string: cache key to store this (cache-miss) response under
	ctxCacheState // string: "HIT" | "MISS" for access.log
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
	cache     *cache.Cache // optional CDN-style content cache (nil = disabled)
	secret    []byte       // HMAC key for signing the session cookie

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
	// Cache is the optional content cache. nil disables caching entirely.
	Cache *cache.Cache
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
		cache:     d.Cache,
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
	clientIP := realClientIP(r, cfg)

	// Capture the response status/size for the logs (so access.log records
	// 200/301/404/... — key for spotting scanner 404 storms).
	sw := &statusWriter{ResponseWriter: w}
	w = sw

	// Assign a per-request id: exposed as X-Request-Id, shown on any block/
	// challenge page served to the visitor, and written to every log line for
	// this request, so a user report can be traced to the exact log entry.
	reqID := newRequestID()
	w.Header().Set("X-Request-Id", reqID)
	r = r.WithContext(context.WithValue(r.Context(), ctxReqID, reqID))

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
				p.forward(w, r, clientIP, cfg, start)
				return
			}
			p.block(w, r, clientIP, http.StatusServiceUnavailable, "internal error", nil, cfg)
		}
	}()

	// (0) Static access lists (operator-controlled, hot-reloadable).
	if cfg.Whitelisted(clientIP) {
		// Trusted IP: bypass all filtering, stream straight to the backend.
		p.forward(w, r, clientIP, cfg, start)
		return
	}
	if cfg.Blocklisted(clientIP) {
		p.challenge.ServeBlocked(w, r, clientIP, reqID, http.StatusForbidden, "your address is blocked")
		p.logBlocked(clientIP, r, "", "static-blocklist", "block", "high", http.StatusForbidden)
		return
	}

	// Establish a stable, signed session identity up front: if the client has no
	// valid session cookie, mint one and set it now (even on a block/challenge
	// response). This keeps the session key constant across the whole challenge
	// flow — instead of switching from an IP+UA fingerprint to a cookie id only
	// after the first backend response — so a passed challenge is remembered and
	// behavioral history is not reset mid-visit.
	sessionKey, cookieSet := p.ensureSession(w, r, clientIP)
	if cookieSet {
		r = r.WithContext(context.WithValue(r.Context(), ctxCookieSet, true))
	}

	// (1) IP reputation fail-fast.
	switch p.rep.Lookup(clientIP) {
	case reputation.StateBlocked:
		p.challenge.ServeBlocked(w, r, clientIP, reqID, http.StatusForbidden, "your address is temporarily blocked")
		p.logBlocked(clientIP, r, "", "reputation:blocked", "block", string(reputation.StateBlocked), http.StatusForbidden)
		return
	case reputation.StateGreylisted:
		// (2) allow the verify endpoint through even while greylisted.
		if p.challenge.HandleVerify(w, r, clientIP, reqID, sessionKey) {
			return
		}
		// (3) serve a challenge — unless this session already solved one, in
		// which case fall through (grace period, so a passed visitor is not
		// re-challenged in a loop).
		if cfg.Challenge.Enabled && !p.tracker.ChallengePassed(sessionKey) {
			p.challenge.ServeChallenge(w, r, clientIP, reqID)
			return
		}
	default:
		// clean: verify endpoint should also short-circuit if hit.
		if r.URL.Path == challenge.VerifyPath {
			if p.challenge.HandleVerify(w, r, clientIP, reqID, sessionKey) {
				return
			}
		}
	}

	// (4) Build the request view (bounded body copy for inspection; the full
	// body is preserved for the backend, never truncated).
	view := p.buildView(r)

	dec := p.engine.Inspect(view, sessionKey)

	// (5) Apply action.
	if dec.Matched {
		p.applyAction(w, r, clientIP, sessionKey, dec, cfg, view, start)
		return
	}

	// (6) Clean passthrough — served from the content cache when possible.
	if p.cacheable(r, cfg) {
		key := cacheKey(r)
		if e, ok := p.cache.Get(key); ok {
			p.serveCacheHit(w, r, clientIP, e, start)
			p.tracker.Record(sessionKey, view)
			return
		}
		// Miss: tag the request so modifyResponse stores the backend response, and
		// record the miss for access.log.
		ctx := context.WithValue(r.Context(), ctxCacheStore, key)
		ctx = context.WithValue(ctx, ctxCacheState, "MISS")
		r = r.WithContext(ctx)
	}
	p.forward(w, r, clientIP, cfg, start)
	// Record the clean pageview for behavioral tracking (post-decision so a
	// cold request has no self-generated prior pageview).
	p.tracker.Record(sessionKey, view)
}

// cacheable reports whether a request is eligible for the content cache: caching
// on, a GET without a Range, and a path extension in the configured set.
func (p *Proxy) cacheable(r *http.Request, cfg *config.Config) bool {
	return p.cache != nil &&
		r.Method == http.MethodGet &&
		r.Header.Get("Range") == "" &&
		cfg.CacheableExt(r.URL.Path)
}

// serveCacheHit writes a cached response directly to the client, bypassing the
// backend entirely.
func (p *Proxy) serveCacheHit(w http.ResponseWriter, r *http.Request, ip string, e *cache.Entry, start time.Time) {
	h := w.Header()
	for k, vv := range e.Header {
		h[k] = vv
	}
	h.Set("X-Cache", "HIT")
	h.Set("Age", strconv.Itoa(p.cache.Age(e)))
	w.WriteHeader(e.Status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(e.Body)
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxCacheState, "HIT"))
	p.logAccess(ip, r, e.Status, int64(len(e.Body)), time.Since(start))
}

func (p *Proxy) applyAction(w http.ResponseWriter, r *http.Request, ip, sessionKey string, dec detect.Decision, cfg *config.Config, view *detect.RequestView, start time.Time) {
	inc := dec.Incident
	reqID := reqIDFrom(r)
	switch dec.Action {
	case detect.ActionLogOnly:
		// Tuning mode: pass through to the backend and record what WOULD be
		// blocked. The logged status is the ACTUAL status served to the client
		// (not the would-be block code), so log-only entries don't look like
		// enforced blocks.
		p.forward(w, r, ip, cfg, start)
		status, _ := statusInfo(w)
		p.logBlocked(ip, r, inc.TemplateID, inc.Reason, "log-only", string(inc.Severity), status)
		return
	case detect.ActionChallenge:
		// Grace: a session that already solved a challenge is not challenged
		// again, so a challenge rule matching normal navigation cannot trap a
		// verified visitor in a challenge -> pass -> challenge loop. Abuse rules
		// (block / ban / rate-limit) below still enforce regardless.
		if p.tracker.ChallengePassed(sessionKey) {
			p.forward(w, r, ip, cfg, start)
			p.tracker.Record(sessionKey, view)
			return
		}
		p.rep.RegisterViolation(ip, "detect:"+inc.TemplateID)
		p.challenge.ServeChallenge(w, r, ip, reqID)
		p.logBlocked(ip, r, inc.TemplateID, inc.Reason, "challenge", string(inc.Severity), http.StatusServiceUnavailable)
		return
	case detect.ActionRateLimit:
		p.rep.RegisterViolation(ip, "detect:"+inc.TemplateID)
		w.Header().Set("Retry-After", "10")
		p.challenge.ServeBlocked(w, r, ip, reqID, http.StatusTooManyRequests, "rate limited")
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
	p.challenge.ServeBlocked(w, r, ip, reqIDFrom(r), code, reason)
}

// reqIDFrom returns the per-request id stashed in the context by ServeHTTP.
func reqIDFrom(r *http.Request) string {
	if v, ok := r.Context().Value(ctxReqID).(string); ok {
		return v
	}
	return ""
}

// forward proxies a clean (or fail-open) request to the backend. The request
// body is whatever r.Body currently is: for an inspected request buildView has
// already rebuilt it into the full original body (inspected prefix + untouched
// remainder), so the backend receives the complete body; for a bypass path
// (whitelist / fail-open before inspection) it is the original stream.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, ip string, cfg *config.Config, start time.Time) {
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

	// Record backend-origin errors (nginx/app 5xx) in the dedicated backend.log.
	// This is the actual response from the backend; transport failures (backend
	// unreachable) are handled separately in backendError.
	if resp.StatusCode >= 500 {
		p.logBackend(req, resp.StatusCode, "backend 5xx response", nil)
	}

	// Attach a signed session cookie when the client has none — unless one was
	// already set earlier in the pipeline by ensureSession (avoids a duplicate
	// Set-Cookie with a different id). This branch now only fires for paths that
	// skip ensureSession, e.g. whitelisted requests.
	if already, _ := req.Context().Value(ctxCookieSet).(bool); !already {
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
	}

	// Content cache: if this was a cacheable miss and the response is safe to
	// store, tee the body into the cache as it streams to the client (committed
	// on a clean EOF). A stored response is served raw, so it is NOT also
	// zstd-compressed here.
	stored := false
	if key, ok := req.Context().Value(ctxCacheStore).(string); ok && key != "" && p.cache != nil {
		if storable(resp, cfg.Cache.MaxObjectSize) {
			resp.Body = &cachingBody{
				src:     resp.Body,
				buf:     new(bytes.Buffer),
				key:     key,
				status:  resp.StatusCode,
				header:  cacheHeaders(resp.Header),
				maxSize: cfg.Cache.MaxObjectSize,
				ttl:     cfg.Cache.TTL.Std(),
				cache:   p.cache,
			}
			resp.Header.Set("X-Cache", "MISS")
			stored = true
		}
	}

	// Optional zstd response compression for clients that advertise it (skipped
	// when we are caching this response raw).
	if !stored && cfg.Compression.Zstd && shouldCompress(req, resp, cfg.Compression.MinSize) {
		resp.Body = zstdReader(resp.Body)
		resp.Header.Set("Content-Encoding", "zstd")
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
		resp.Header.Add("Vary", "Accept-Encoding")
	}
	return nil
}

// storable reports whether a backend response may be cached: a 200 with no
// per-user Set-Cookie, no no-store/private/no-cache directive, no content-varying
// Vary, and (if the length is known) within the size cap.
func storable(resp *http.Response, maxSize int) bool {
	if resp.StatusCode != http.StatusOK {
		return false
	}
	if resp.Header.Get("Set-Cookie") != "" {
		return false
	}
	cc := strings.ToLower(resp.Header.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") || strings.Contains(cc, "no-cache") {
		return false
	}
	if v := strings.TrimSpace(resp.Header.Get("Vary")); v != "" && !strings.EqualFold(v, "accept-encoding") {
		return false
	}
	if maxSize > 0 && resp.ContentLength > int64(maxSize) {
		return false
	}
	return true
}

// cacheHeaders clones the response headers for storage, dropping hop-by-hop and
// per-request headers that must not be replayed from cache.
func cacheHeaders(h http.Header) http.Header {
	out := h.Clone()
	for _, k := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade", "Set-Cookie", "X-Cache", "Age",
	} {
		out.Del(k)
	}
	return out
}

// cachingBody tees the backend body into a buffer while it streams to the client
// and, on a clean EOF within the size cap, commits the complete object to the
// cache. A client disconnect (Close before EOF) or an over-size body leaves
// nothing cached, so only whole, successfully delivered responses are stored.
type cachingBody struct {
	src     io.ReadCloser
	buf     *bytes.Buffer
	key     string
	status  int
	header  http.Header
	maxSize int
	ttl     time.Duration
	cache   *cache.Cache

	tooBig    bool
	committed bool
}

func (b *cachingBody) Read(p []byte) (int, error) {
	n, err := b.src.Read(p)
	if n > 0 && !b.tooBig {
		if b.maxSize > 0 && b.buf.Len()+n > b.maxSize {
			b.tooBig = true // give up: object exceeds the cap
			b.buf.Reset()
		} else {
			b.buf.Write(p[:n])
		}
	}
	if err == io.EOF && !b.tooBig && !b.committed {
		b.committed = true
		now := b.cache.Now()
		body := make([]byte, b.buf.Len())
		copy(body, b.buf.Bytes())
		b.cache.Put(b.key, &cache.Entry{
			Status:  b.status,
			Header:  b.header,
			Body:    body,
			Stored:  now,
			Expires: now.Add(b.ttl),
		})
	}
	return n, err
}

func (b *cachingBody) Close() error { return b.src.Close() }

func (p *Proxy) backendError(w http.ResponseWriter, r *http.Request, err error) {
	// The client went away before the backend responded (request context
	// canceled): nothing to serve and nothing worth logging.
	if errors.Is(err, context.Canceled) || errors.Is(r.Context().Err(), context.Canceled) {
		return
	}
	// Transport-level failure (backend down, refused, timeout): record it in the
	// dedicated backend.log and serve a 502.
	p.logBackend(r, http.StatusBadGateway, "backend unreachable", err)
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write([]byte("502 Bad Gateway"))
}

// logBackend writes a backend error (5xx response or transport failure) to
// backend.log, tagged with the same req_id/ip shown on any page and in
// access.log, so a single request can be traced across streams.
func (p *Proxy) logBackend(r *http.Request, status int, reason string, err error) {
	attrs := []any{
		slog.String("req_id", reqIDFrom(r)),
		slog.String("ip", clientIPFrom(r)),
		slog.String("method", r.Method),
		slog.String("host", r.Host),
		slog.String("path", r.URL.Path),
		slog.Int("status", status),
		slog.String("reason", reason),
	}
	if err != nil {
		attrs = append(attrs, slog.String("err", err.Error()))
	}
	p.logs.Backend.Error("backend error", attrs...)
}

// clientIPFrom returns the real client IP stashed in the context by forward.
func clientIPFrom(r *http.Request) string {
	if v, ok := r.Context().Value(ctxSetCookie).(string); ok {
		return v
	}
	return ""
}

// buildView reads a bounded prefix of the body for inspection and assembles a
// RequestView. Crucially it does NOT truncate the request: it rebuilds r.Body as
// the inspected prefix followed by the untouched remainder, so the backend still
// receives the FULL body even when it exceeds maxInspectBody (large uploads must
// never be silently corrupted). The prefix is freshly allocated (not pooled)
// because it backs the reader the Transport replays to the backend.
func (p *Proxy) buildView(r *http.Request) *detect.RequestView {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(r.Body, maxInspectBody))
		if len(body) < maxInspectBody {
			// Whole body consumed and buffered. Replace it with a REWINDABLE reader:
			// resetting ContentLength and setting GetBody is essential so the backend
			// Transport can retry the request after a benign connection loss — most
			// importantly an HTTP/2 GOAWAY when the backend recycles a connection.
			// Without it, a recycled backend connection surfaces to clients as a 502;
			// and for empty (e.g. GET) requests ContentLength==0 lets the proxy drop
			// the body entirely instead of sending a malformed chunked GET.
			_ = r.Body.Close()
			buf := body
			r.Body = io.NopCloser(bytes.NewReader(buf))
			r.ContentLength = int64(len(buf))
			r.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(buf)), nil
			}
		} else {
			// Body exceeds the inspection buffer: forward the inspected prefix plus
			// the untouched remainder so nothing is dropped. The remainder is a live
			// stream that cannot be rewound, so these (large upload) requests are not
			// retryable — acceptable, as they are non-idempotent POST/PUT bodies.
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
			r.GetBody = nil
		}
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

// ensureSession returns a stable session key for the request and, when the
// client presents no valid session cookie, mints a signed one and sets it on the
// response (set=true). Establishing the cookie up front — rather than only on
// the first backend response — keeps the session identity constant across the
// whole challenge flow, so a passed challenge and behavioral history survive
// instead of resetting when the id switches from fingerprint to cookie.
//
// A valid existing cookie yields "sid:<id>". A newly minted cookie also yields
// "sid:<id>" for the id just issued. Only if minting fails does it fall back to
// the IP+UA fingerprint ("fp:<h>"), which is bound to the connection IP and so
// cannot be rotated to spawn fresh sessions and evade behavioral rate limits.
func (p *Proxy) ensureSession(w http.ResponseWriter, r *http.Request, ip string) (key string, set bool) {
	cfg := p.cfg.Get()
	if c, err := r.Cookie(cfg.Session.CookieName); err == nil && c.Value != "" {
		if id, ok := verifySID(p.secret, c.Value); ok {
			return "sid:" + id, false
		}
	}
	val := newSignedSID(p.secret)
	dot := strings.IndexByte(val, '.')
	if val == "" || dot <= 0 {
		return "fp:" + sidFor(ip, r.UserAgent()), false
	}
	cookie := &http.Cookie{
		Name:     cfg.Session.CookieName,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(cfg.Session.TTL.Std().Seconds()),
	}
	w.Header().Add("Set-Cookie", cookie.String())
	return "sid:" + val[:dot], true
}

// --- logging helpers ---

func (p *Proxy) logAccess(ip string, r *http.Request, status int, bytes int64, dur time.Duration) {
	cacheState, _ := r.Context().Value(ctxCacheState).(string)
	p.logs.Access.Info("request",
		slog.String("req_id", reqIDFrom(r)),
		slog.String("ip", ip),
		slog.String("method", r.Method),
		slog.String("host", r.Host),
		slog.String("path", r.URL.Path),
		slog.String("query", r.URL.RawQuery),
		slog.Int("status", status),
		slog.Int64("bytes", bytes),
		slog.String("ua", r.UserAgent()),
		slog.String("cache", cacheState),
		slog.Int64("dur_us", dur.Microseconds()),
	)
}

// cacheKey identifies a cached object by method + host + full request URI, so
// different vhosts and query strings are cached separately.
func cacheKey(r *http.Request) string {
	return r.Method + " " + r.Host + " " + r.URL.RequestURI()
}

func (p *Proxy) logBlocked(ip string, r *http.Request, templateID, reason, action, severity string, status int) {
	p.logs.Blocked.Warn("blocked",
		slog.String("req_id", reqIDFrom(r)),
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

// realClientIP returns the true client IP. By default it is the source IP of
// the connection (with nftables REDIRECT the client source is NOT rewritten, so
// RemoteAddr is the real client) and inbound forwarding headers are deliberately
// ignored — smoker is the edge. But when the direct connection comes from a
// configured trusted proxy (e.g. Cloudflare), the real visitor IP is taken from
// that proxy's forwarding header instead, so reputation, access lists and logs
// track the visitor rather than the CDN.
func realClientIP(r *http.Request, cfg *config.Config) string {
	host := hostOnly(r.RemoteAddr)
	if cfg.TrustedProxy(host) {
		if fwd := forwardedClientIP(r); fwd != "" {
			return fwd
		}
	}
	return host
}

// hostOnly strips the port from RemoteAddr and normalizes the address.
func hostOnly(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if ap, err := netip.ParseAddr(host); err == nil {
		return ap.String()
	}
	return host
}

// forwardedClientIP extracts the originating client IP from the headers a
// trusted front proxy sets: Cloudflare's CF-Connecting-IP first, then the
// leftmost X-Forwarded-For entry, then X-Real-IP. Returns "" if none holds a
// valid IP. Only called after the direct peer is confirmed to be a trusted
// proxy, so these headers cannot be spoofed by an arbitrary client.
func forwardedClientIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" {
		if ap, err := netip.ParseAddr(v); err == nil {
			return ap.String()
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := xff
		if i := strings.IndexByte(xff, ','); i >= 0 {
			first = xff[:i]
		}
		if ap, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil {
			return ap.String()
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		if ap, err := netip.ParseAddr(v); err == nil {
			return ap.String()
		}
	}
	return ""
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
