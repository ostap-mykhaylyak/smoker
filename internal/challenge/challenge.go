// Package challenge serves the interstitial verification pages for greylisted
// IPs. Pages are plain static assets under /var/www/smoker (challenge.html,
// captcha.html, blocked.html) so operators can restyle them without recompiling
// the binary. A minimal HMAC-signed token proves a client solved the challenge;
// on success the IP is marked clean and the session flagged challenge-passed.
package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// VerifyPath is the internal endpoint clients POST/GET to prove a solved
// challenge. It is intercepted by the proxy before backend forwarding.
const VerifyPath = "/_smoker/verify"

// Cleaner is satisfied by the reputation manager + session tracker so the
// challenge module can clear an IP/session on success without importing them.
type Cleaner interface {
	MarkIPClean(ip, reason string)
	MarkSessionPassed(sessionKey string)
}

// Manager renders challenge assets and validates verification tokens.
type Manager struct {
	assetsDir string
	secret    []byte
	ttl       time.Duration
	powBits   int // proof-of-work difficulty (leading zero bits); 0 disables
	log       *slog.Logger
	cleaner   Cleaner
	now       func() time.Time
}

// New builds a challenge Manager. powBits sets the JS proof-of-work difficulty
// (leading zero bits the client must find); ~16 is sub-second in a browser but
// costly for a naive bot. 0 disables the PoW (token echo only). log may be nil.
func New(assetsDir, secret string, ttl time.Duration, powBits int, log *slog.Logger, cleaner Cleaner) *Manager {
	if powBits < 0 {
		powBits = 0
	}
	return &Manager{
		assetsDir: assetsDir,
		secret:    []byte(secret),
		ttl:       ttl,
		powBits:   powBits,
		log:       log,
		cleaner:   cleaner,
		now:       time.Now,
	}
}

// logf records a challenge-lifecycle event (nil-safe).
func (m *Manager) logf(msg string, args ...any) {
	if m.log != nil {
		m.log.Info(msg, args...)
	}
}

// ServeChallenge writes the interstitial challenge page for a greylisted client.
func (m *Manager) ServeChallenge(w http.ResponseWriter, r *http.Request, ip string) {
	// crypto.subtle (used to solve the PoW) is only available in a secure
	// context; over plain HTTP fall back to a no-PoW token so the client is not
	// dead-ended. The site's HTTPS challenges still carry the full difficulty.
	bits := m.powBits
	if r.TLS == nil {
		bits = 0
	}
	// Preserve the intended destination: the "return" field on re-serve, else
	// the current request URI on the first challenge.
	ret := r.FormValue("return")
	if ret == "" {
		ret = r.URL.RequestURI()
	}
	token := m.issueToken(bits)
	vars := map[string]string{
		"TOKEN":      token,
		"VERIFY_URL": VerifyPath,
		"RETURN_URL": safeReturn(ret),
		"POW_BITS":   strconv.Itoa(bits),
	}
	page := m.render("challenge.html", vars)
	// Safety net: if the on-disk asset predates the PoW protocol (no nonce
	// field) while PoW is required, it would submit token-only and loop
	// forever. Fall back to the embedded, protocol-correct page.
	if bits > 0 && !strings.Contains(page, `name="nonce"`) {
		page = fallbackPage("challenge.html", vars)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable) // 503 while unverified
	_, _ = w.Write([]byte(page))
	m.logf("challenge served", "ip", ip, "bits", bits, "secure", r.TLS != nil, "path", r.URL.Path)
}

// ServeBlocked writes the hard-block page (used for blocked IPs / block action).
func (m *Manager) ServeBlocked(w http.ResponseWriter, r *http.Request, code int, reason string) {
	page := m.render("blocked.html", map[string]string{"REASON": reason})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(page))
}

// HandleVerify validates a token; on success clears the IP + session and
// redirects back. Returns true if it handled the request (caller must stop).
func (m *Manager) HandleVerify(w http.ResponseWriter, r *http.Request, ip, sessionKey string) bool {
	if r.URL.Path != VerifyPath {
		return false
	}
	token := r.FormValue("token")
	bits, ok := m.validateToken(token)
	if !ok {
		m.logf("challenge verify failed", "ip", ip, "reason", "invalid-or-expired-token")
		m.ServeChallenge(w, r, ip)
		return true
	}
	if !verifyPoW(token, r.FormValue("nonce"), bits) {
		m.logf("challenge verify failed", "ip", ip, "reason", "pow-failed", "bits", bits)
		// Don't dead-end the client: re-issue a fresh, solvable challenge.
		m.ServeChallenge(w, r, ip)
		return true
	}
	if m.cleaner != nil {
		m.cleaner.MarkIPClean(ip, "challenge passed")
		if sessionKey != "" {
			m.cleaner.MarkSessionPassed(sessionKey)
		}
	}
	m.logf("challenge passed", "ip", ip)
	http.Redirect(w, r, safeReturn(r.FormValue("return")), http.StatusFound)
	return true
}

// safeReturn sanitizes the post-challenge redirect target to a same-origin,
// path-only URL. It rejects protocol-relative ("//host", "/\host") and absolute
// URLs to prevent an open redirect after verification.
func safeReturn(ret string) string {
	if ret == "" || ret[0] != '/' {
		return "/"
	}
	// "//" and "/\" are treated as protocol-relative by browsers -> off-site.
	if len(ret) > 1 && (ret[1] == '/' || ret[1] == '\\') {
		return "/"
	}
	return ret
}

// render loads an asset from disk and substitutes {{KEY}} placeholders. Reading
// per request keeps operator edits live; assets are tiny.
func (m *Manager) render(name string, vars map[string]string) string {
	data, err := os.ReadFile(filepath.Join(m.assetsDir, name))
	if err != nil {
		return fallbackPage(name, vars)
	}
	out := string(data)
	for k, v := range vars {
		out = strings.ReplaceAll(out, "{{"+k+"}}", htmlEscape(v))
	}
	return out
}

// issueToken returns "<exp>.<bits>.<mac>", where mac = HMAC(exp|bits). The
// required PoW difficulty is embedded and signed, so verification knows exactly
// what was demanded (an HTTP challenge is issued with bits=0 and cannot be
// upgraded to a harder one by a client).
//
// The token is deliberately NOT bound to the client IP: a single client can
// present different source IPs across HTTP/2 (TCP) and HTTP/3 (UDP/QUIC), or on
// mobile networks, which would otherwise make verification fail in a loop.
// Unforgeability comes from the HMAC; the PoW proves work; expiry bounds reuse.
func (m *Manager) issueToken(bits int) string {
	expStr := strconv.FormatInt(m.now().Add(m.ttl).Unix(), 10)
	bitsStr := strconv.Itoa(bits)
	mac := m.sign(expStr + "|" + bitsStr)
	return expStr + "." + bitsStr + "." + mac
}

// validateToken checks the token's HMAC and expiry and returns the embedded PoW
// difficulty. ok is false for a forged, malformed or expired token.
func (m *Manager) validateToken(token string) (bits int, ok bool) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return 0, false
	}
	expStr, bitsStr, mac := parts[0], parts[1], parts[2]
	exp, err1 := strconv.ParseInt(expStr, 10, 64)
	b, err2 := strconv.Atoi(bitsStr)
	if err1 != nil || err2 != nil || m.now().Unix() > exp {
		return 0, false
	}
	want := m.sign(expStr + "|" + bitsStr)
	if !hmac.Equal([]byte(mac), []byte(want)) {
		return 0, false
	}
	return b, true
}

func (m *Manager) sign(msg string) string {
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// verifyPoW checks that SHA-256(token ":" nonce) has at least `bits` leading
// zero bits — the proof-of-work the browser solved. bits<=0 disables the check.
func verifyPoW(token, nonce string, bits int) bool {
	if bits <= 0 {
		return true
	}
	if nonce == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token + ":" + nonce))
	return leadingZeroBits(sum[:]) >= bits
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		for m := byte(0x80); m > 0; m >>= 1 {
			if x&m != 0 {
				return n
			}
			n++
		}
		return n
	}
	return n
}

// ClientIP extracts the host portion of an address (helper for callers).
func ClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

// fallbackPage is a built-in minimal page used only if the asset file is
// missing, so the proxy never fails to render a challenge/block screen.
func fallbackPage(name string, vars map[string]string) string {
	switch name {
	case "blocked.html":
		return `<!doctype html><meta charset="utf-8"><title>Blocked</title>` +
			`<h1>403 — Request blocked</h1><p>` + htmlEscape(vars["REASON"]) + `</p>`
	default:
		return `<!doctype html><meta charset="utf-8"><title>Verifica</title>` +
			`<h1>Verifica in corso…</h1>` +
			`<form id="f" method="POST" action="` + htmlEscape(vars["VERIFY_URL"]) + `">` +
			`<input type="hidden" name="token" value="` + htmlEscape(vars["TOKEN"]) + `">` +
			`<input type="hidden" name="nonce" value="">` +
			`<input type="hidden" name="bits" value="` + htmlEscape(vars["POW_BITS"]) + `">` +
			`<input type="hidden" name="return" value="` + htmlEscape(vars["RETURN_URL"]) + `"></form>` +
			`<script>` + powSolverJS + `</script>`
	}
}

// powSolverJS finds a nonce so SHA-256("<token>:<nonce>") has >= bits leading
// zero bits, then submits the form. Requires a secure context (HTTPS) for
// crypto.subtle — smoker serves challenges over TLS.
const powSolverJS = `
(async function(){
  var f=document.getElementById('f');
  var token=f.token.value, bits=parseInt(f.bits.value,10)||0, enc=new TextEncoder();
  function lz(u){var n=0;for(var i=0;i<u.length;i++){var x=u[i];if(x===0){n+=8;continue;}
    for(var m=128;m>0;m>>=1){if(x&m)return n;n++;}return n;}return n;}
  var nonce=0;
  if(bits>0 && crypto && crypto.subtle){
    for(;;){var h=new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(token+':'+nonce)));
      if(lz(h)>=bits)break; nonce++;}
  }
  f.nonce.value=nonce; f.submit();
})();`
