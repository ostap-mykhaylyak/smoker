package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// newRequestID returns a short random identifier for a single request. It is
// exposed to the visitor (X-Request-Id header + shown on block/challenge pages)
// and written to access.log/blocked.log, so an operator can correlate a user
// report ("I was blocked, request id abc123") with the exact log line.
func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b) // 16 hex chars
}

// newSignedSID mints a fresh random session id and returns "<id>.<mac>", where
// mac is HMAC(id, secret). This is the value of the smoker session cookie.
func newSignedSID(secret []byte) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand should never fail; degrade to a still-unique-ish value.
		return ""
	}
	id := base64.RawURLEncoding.EncodeToString(b)
	return id + "." + macSID(secret, id)
}

// verifySID validates a cookie value and returns the embedded id if the HMAC
// checks out. An attacker-supplied or rotated cookie fails verification, so the
// caller falls back to keying on the connection IP (which cannot be rotated away).
func verifySID(secret []byte, cookie string) (string, bool) {
	dot := strings.LastIndexByte(cookie, '.')
	if dot <= 0 || dot == len(cookie)-1 {
		return "", false
	}
	id, mac := cookie[:dot], cookie[dot+1:]
	if hmac.Equal([]byte(mac), []byte(macSID(secret, id))) {
		return id, true
	}
	return "", false
}

func macSID(secret []byte, id string) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(id))
	sum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}
