// Package tlsterm handles TLS termination for the HTTPS proxy. The certificate
// loader discovers cert/key pairs already present on the server by parsing
// nginx and Apache vhost configs, then builds a dynamic SNI-based
// tls.Config.GetCertificate. An optional ACME/autocert fallback issues certs
// for domains not found on disk.
//
// After TLS is terminated the decrypted request flows through the SAME
// Detection Engine as plaintext HTTP, then is re-forwarded to the backend
// (plaintext on localhost, or re-encrypted if the backend requires internal
// TLS).
package tlsterm

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/crypto/acme/autocert"
)

// CertStore holds the SNI -> certificate map and answers GetCertificate. It is
// safe for concurrent use and swappable on hot-reload.
type CertStore struct {
	mu       sync.RWMutex
	byName   map[string]*tls.Certificate
	fallback func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// NewCertStore returns an empty store.
func NewCertStore() *CertStore {
	return &CertStore{byName: map[string]*tls.Certificate{}}
}

// SetAutocert installs an autocert.Manager as the fallback for unknown SNI.
func (s *CertStore) SetAutocert(m *autocert.Manager) {
	s.mu.Lock()
	s.fallback = m.GetCertificate
	s.mu.Unlock()
}

// GetCertificate implements tls.Config.GetCertificate (SNI dispatch).
func (s *CertStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	s.mu.RLock()
	cert, ok := s.byName[name]
	if !ok {
		cert, ok = s.matchWildcard(name)
	}
	fb := s.fallback
	s.mu.RUnlock()
	if ok {
		return cert, nil
	}
	if fb != nil {
		return fb(hello)
	}
	return nil, fmt.Errorf("no certificate for SNI %q", hello.ServerName)
}

// matchWildcard looks for a *.example.com entry matching host.example.com.
// Caller holds RLock.
func (s *CertStore) matchWildcard(name string) (*tls.Certificate, bool) {
	dot := strings.IndexByte(name, '.')
	if dot < 0 {
		return nil, false
	}
	wc := "*" + name[dot:]
	c, ok := s.byName[wc]
	return c, ok
}

// TLSConfig produces a *tls.Config wired to this store.
//
// CurvePreferences is left nil on purpose: on Go 1.24+ the default TLS 1.3
// curve preferences include the post-quantum hybrid X25519MLKEM768, so the
// server negotiates PQC key exchange automatically with capable clients. (This
// is why the module requires Go 1.24 — see go.mod.)
func (s *CertStore) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: s.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

// pair is a discovered cert/key pair with the domains it serves.
type pair struct {
	certFile string
	keyFile  string
	domains  []string
}

// Reload rescans the configured vhost globs and atomically replaces the SNI map.
// Missing/unreadable pairs are skipped; a per-domain error list is returned.
func (s *CertStore) Reload(nginxGlobs, apacheGlobs []string) (int, []error) {
	var pairs []pair
	var errs []error

	for _, g := range nginxGlobs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			pairs = append(pairs, parseNginx(f)...)
		}
	}
	for _, g := range apacheGlobs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			pairs = append(pairs, parseApache(f)...)
		}
	}

	next := map[string]*tls.Certificate{}
	for _, p := range pairs {
		if p.certFile == "" || p.keyFile == "" || len(p.domains) == 0 {
			continue
		}
		cert, err := tls.LoadX509KeyPair(p.certFile, p.keyFile)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.certFile, err))
			continue
		}
		c := cert
		for _, d := range p.domains {
			next[strings.ToLower(d)] = &c
		}
	}

	s.mu.Lock()
	s.byName = next
	s.mu.Unlock()
	return len(next), errs
}

var (
	reNginxServerName = regexp.MustCompile(`(?m)^\s*server_name\s+([^;]+);`)
	reNginxCert       = regexp.MustCompile(`(?m)^\s*ssl_certificate\s+([^;]+);`)
	reNginxKey        = regexp.MustCompile(`(?m)^\s*ssl_certificate_key\s+([^;]+);`)

	reApacheServerName  = regexp.MustCompile(`(?mi)^\s*ServerName\s+(\S+)`)
	reApacheServerAlias = regexp.MustCompile(`(?mi)^\s*ServerAlias\s+(.+)$`)
	reApacheCert        = regexp.MustCompile(`(?mi)^\s*SSLCertificateFile\s+(\S+)`)
	reApacheKey         = regexp.MustCompile(`(?mi)^\s*SSLCertificateKeyFile\s+(\S+)`)
)

// parseNginx extracts (very pragmatically) the domains + cert/key from a vhost.
// It treats the whole file as one context; sites-enabled files typically hold a
// single TLS server block, which is the common case this loader targets.
func parseNginx(path string) []pair {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	text := string(data)
	cert := firstSubmatch(reNginxCert, text)
	key := firstSubmatch(reNginxKey, text)
	if cert == "" || key == "" {
		return nil
	}
	var domains []string
	for _, m := range reNginxServerName.FindAllStringSubmatch(text, -1) {
		for _, d := range strings.Fields(m[1]) {
			if d != "_" {
				domains = append(domains, d)
			}
		}
	}
	return []pair{{certFile: cert, keyFile: key, domains: dedup(domains)}}
}

func parseApache(path string) []pair {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	text := string(data)
	cert := firstSubmatch(reApacheCert, text)
	key := firstSubmatch(reApacheKey, text)
	if cert == "" || key == "" {
		return nil
	}
	var domains []string
	if sn := firstSubmatch(reApacheServerName, text); sn != "" {
		domains = append(domains, sn)
	}
	for _, m := range reApacheServerAlias.FindAllStringSubmatch(text, -1) {
		domains = append(domains, strings.Fields(m[1])...)
	}
	return []pair{{certFile: cert, keyFile: key, domains: dedup(domains)}}
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// NewAutocert builds an autocert.Manager for the given domains/cache dir.
func NewAutocert(cacheDir, email string, domains []string) *autocert.Manager {
	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		Email:      email,
		HostPolicy: autocert.HostWhitelist(domains...),
	}
}
