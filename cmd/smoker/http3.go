package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// newHTTP3 builds an HTTP/3 (QUIC over UDP) server sharing smoker's handler and
// certificate store. advertisePort is the PUBLIC UDP port announced in Alt-Svc
// (may differ from the listen port when an L4 firewall redirects UDP — the
// client must be told the public port, e.g. 443, not the internal 18443).
//
// Optimizations:
//   - QUIC mandates TLS 1.3 (faster handshake, 1-RTT).
//   - Generous concurrent-stream limits for multiplexed browsers.
//   - Connection keep-alive to hold QUIC connections open across requests.
//   - 0-RTT is deliberately DISABLED: early-data is replayable, which is unsafe
//     to let past a WAF (an attacker could replay a captured request).
func newHTTP3(addr string, advertisePort int, handler http.Handler, tlsConf *tls.Config) *http3.Server {
	return &http3.Server{
		Addr:      addr,
		Port:      advertisePort,
		Handler:   handler,
		TLSConfig: tlsConf,
		QUICConfig: &quic.Config{
			MaxIncomingStreams:    256,
			MaxIncomingUniStreams: 256,
			KeepAlivePeriod:       30 * time.Second,
			Allow0RTT:             false,
		},
	}
}

// portOf extracts the numeric port from a listen address ("0.0.0.0:443" -> 443),
// returning fallback if it cannot be parsed.
func portOf(addr string, fallback int) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return fallback
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return fallback
	}
	return n
}

// altSvcHandler wraps the TCP (h1/h2) handler to advertise HTTP/3 availability
// via the Alt-Svc header, so compliant browsers upgrade to QUIC on the next
// request.
func altSvcHandler(next http.Handler, h3 *http3.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = h3.SetQUICHeaders(w.Header())
		next.ServeHTTP(w, r)
	})
}
