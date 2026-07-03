package proxy

import (
	"bufio"
	"errors"
	"net"
	"net/http"
)

// statusWriter wraps http.ResponseWriter to capture the response status code and
// byte count so they can be recorded in access.log — essential for spotting
// scanners (bursts of 404s hunting for vulnerable plugins). It transparently
// forwards Flush and Hijack so streaming responses and WebSocket upgrades
// through the reverse proxy keep working.
type statusWriter struct {
	http.ResponseWriter
	status  int
	written int64
	wrote   bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status = http.StatusOK // implicit 200 on first write
		s.wrote = true
	}
	n, err := s.ResponseWriter.Write(b)
	s.written += int64(n)
	return n, err
}

// Flush forwards to the underlying writer when it supports streaming.
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards to the underlying writer (WebSocket / Upgrade); errors if the
// underlying writer (e.g. HTTP/2) does not support hijacking.
func (s *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("smoker: underlying ResponseWriter does not support hijacking")
}

// statusInfo returns the captured status (defaulting to 200) and bytes written.
func statusInfo(w http.ResponseWriter) (int, int64) {
	if s, ok := w.(*statusWriter); ok {
		st := s.status
		if st == 0 {
			st = http.StatusOK
		}
		return st, s.written
	}
	return http.StatusOK, 0
}
