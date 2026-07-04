// Package config loads and hot-reloads /etc/smoker/config.yaml.
//
// The reload strategy is read-only: fsnotify watches the file and, on change,
// the file is re-parsed and swapped atomically. Configuration files are never
// written back, which is why /etc/smoker can be mounted read-only at runtime.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/ostap-mykhaylyak/smoker/internal/paths"
	"gopkg.in/yaml.v3"
)

// Duration is a yaml-friendly wrapper around time.Duration accepting values
// like "30m", "24h", "5s".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

// AccessList is an IP/CIDR allow- or deny-list. Its entries are the union of
// every *.ips file under Dir (a git-synced repo mirrored into Dir) plus any
// inline IPs. Git, if set, syncs the repo into Dir on the sync schedule.
type AccessList struct {
	Dir          string   `yaml:"dir"`           // directory of *.ips files
	IPs          []string `yaml:"ips"`           // inline entries
	SyncInterval Duration `yaml:"sync_interval"` // how often to pull Git into Dir
	Git          struct {
		URL    string `yaml:"url"`
		Branch string `yaml:"branch"`
	} `yaml:"git"`
}

// Config is the full runtime configuration. It is treated as immutable once
// loaded; hot-reload produces a new *Config that is swapped into Manager.
type Config struct {
	Listen struct {
		// Internal high ports the proxy binds; nftables DNATs 80/443 here.
		HTTP  string `yaml:"http"`  // e.g. "0.0.0.0:18080"
		HTTPS string `yaml:"https"` // e.g. "0.0.0.0:18443"
		// HTTP3 enables an HTTP/3 (QUIC/UDP) listener on the HTTPS address and
		// advertises it via Alt-Svc on the TCP responses. Requires the same
		// UDP port open in the firewall.
		HTTP3 bool `yaml:"http3"`
	} `yaml:"listen"`

	Backend struct {
		HTTP   string `yaml:"http"`    // real backend, e.g. "127.0.0.1:80"
		HTTPS  string `yaml:"https"`   // used when UseTLS is true
		UseTLS bool   `yaml:"use_tls"` // re-encrypt to backend over TLS
		// InsecureSkipVerify skips backend TLS cert verification. Safe for a
		// trusted local backend (loopback) whose cert is issued for the public
		// domain, not for 127.0.0.1. smoker preserves the original Host as SNI
		// so verification usually succeeds without this; enable it only if the
		// backend cert's SANs don't cover the served hostnames.
		InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	} `yaml:"backend"`

	Firewall struct {
		Enabled           bool `yaml:"enabled"`
		PublicHTTPPort    int  `yaml:"public_http_port"`    // 80
		PublicHTTPSPort   int  `yaml:"public_https_port"`   // 443
		InternalHTTPPort  int  `yaml:"internal_http_port"`  // 18080
		InternalHTTPSPort int  `yaml:"internal_https_port"` // 18443
		// FailOpen: if the proxy dies, remove DNAT so traffic reaches the
		// backend directly (availability over security).
		FailOpen bool `yaml:"fail_open"`
	} `yaml:"firewall"`

	TLS struct {
		NginxSitesGlob  []string `yaml:"nginx_sites_glob"`
		ApacheSitesGlob []string `yaml:"apache_sites_glob"`
		Autocert        struct {
			Enabled  bool     `yaml:"enabled"`
			CacheDir string   `yaml:"cache_dir"`
			Email    string   `yaml:"email"`
			Domains  []string `yaml:"domains"`
		} `yaml:"autocert"`
	} `yaml:"tls"`

	Templates struct {
		Dir          string   `yaml:"dir"`
		SyncInterval Duration `yaml:"sync_interval"`
		// Git repo mirrored directly into Dir (its content becomes the template
		// tree — no subdirectory). Set url: "" to disable syncing.
		Git struct {
			URL    string `yaml:"url"`
			Branch string `yaml:"branch"`
		} `yaml:"git"`
	} `yaml:"templates"`

	Reputation struct {
		DBPath         string   `yaml:"db_path"`
		BlockThreshold int      `yaml:"block_threshold"` // violations before block
		Window         Duration `yaml:"window"`          // sliding window for counting
		GreylistTTL    Duration `yaml:"greylist_ttl"`
		BlockTTL       Duration `yaml:"block_ttl"`
		CleanTTL       Duration `yaml:"clean_ttl"`
	} `yaml:"reputation"`

	Challenge struct {
		Enabled   bool     `yaml:"enabled"`
		AssetsDir string   `yaml:"assets_dir"`
		TTL       Duration `yaml:"ttl"`
		Secret    string   `yaml:"secret"`   // HMAC secret for challenge tokens + cookies
		POWBits   int      `yaml:"pow_bits"` // JS proof-of-work difficulty (leading zero bits)
	} `yaml:"challenge"`

	Session struct {
		CookieName string   `yaml:"cookie_name"`
		TTL        Duration `yaml:"ttl"`
		MaxEntries int      `yaml:"max_entries"`
	} `yaml:"session"`

	Compression struct {
		// Zstd enables zstd response compression for clients that advertise it
		// (Accept-Encoding: zstd) when the backend response is uncompressed and
		// of a compressible content type.
		Zstd    bool `yaml:"zstd"`
		MinSize int  `yaml:"min_size"` // skip responses smaller than this (bytes)
	} `yaml:"compression"`

	// Whitelist IPs/CIDRs bypass ALL filtering (reputation, detection,
	// challenge) and are forwarded straight to the backend. Blocklist IPs/CIDRs
	// are always denied, before any inspection. Each list merges: a static File,
	// every file under Dir (e.g. a git-synced repo), and inline IPs.
	Whitelist AccessList `yaml:"whitelist"`
	Blocklist AccessList `yaml:"blocklist"`

	// TrustedProxies are the IPs/CIDRs of front proxies (e.g. Cloudflare) whose
	// forwarding headers smoker honors to recover the real client IP. Same
	// dir/ips/git/sync_interval structure as the access lists. Empty (default)
	// means smoker is the edge and inbound forwarding headers are NOT trusted.
	TrustedProxies AccessList `yaml:"trusted_proxies"`

	Logging struct {
		Dir string `yaml:"dir"`
	} `yaml:"logging"`

	// FailOpen governs the Detection Engine / Reputation Manager: on internal
	// failure, allow traffic (true) or block it (false).
	FailOpen bool `yaml:"fail_open"`

	// Parsed access lists (populated by Load; not from YAML).
	whitelistNets    []netip.Prefix
	blocklistNets    []netip.Prefix
	trustedProxyNets []netip.Prefix
	accessWarns      []string // entries skipped as invalid (for logging)
}

// AccessListWarnings returns entries that were skipped as invalid IPs/CIDRs
// while loading the access lists (e.g. a stray line in a synced repo file).
func (c *Config) AccessListWarnings() []string { return c.accessWarns }

// compileAccessLists parses the whitelist/blocklist entries into prefixes.
// Invalid entries are skipped (recorded in accessWarns), never fatal: a stray
// line in a synced repo must not prevent the proxy from (re)loading its config.
func (c *Config) compileAccessLists() error {
	c.accessWarns = nil
	c.whitelistNets = c.parsePrefixes("whitelist", c.Whitelist.IPs)
	c.blocklistNets = c.parsePrefixes("blocklist", c.Blocklist.IPs)
	c.trustedProxyNets = c.parsePrefixes("trusted_proxies", c.TrustedProxies.IPs)
	return nil
}

// parsePrefixes accepts individual IPs ("1.2.3.4", "2001:db8::1") and CIDRs
// ("10.0.0.0/8"). Invalid entries are skipped and appended to accessWarns.
func (c *Config) parsePrefixes(list string, entries []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range entries {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				c.accessWarns = append(c.accessWarns, list+": "+s)
				continue
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			c.accessWarns = append(c.accessWarns, list+": "+s)
			continue
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out
}

// Whitelisted reports whether ip is in the whitelist (bypasses all filtering).
func (c *Config) Whitelisted(ip string) bool { return matchAny(c.whitelistNets, ip) }

// Blocklisted reports whether ip is in the static blocklist (always denied).
func (c *Config) Blocklisted(ip string) bool { return matchAny(c.blocklistNets, ip) }

// TrustedProxy reports whether ip is a configured trusted front proxy (e.g.
// Cloudflare) whose forwarding header may be honored to recover the real client
// IP. With none configured this is always false and forwarding headers are
// ignored (smoker is the edge).
func (c *Config) TrustedProxy(ip string) bool { return matchAny(c.trustedProxyNets, ip) }

func matchAny(nets []netip.Prefix, ip string) bool {
	if len(nets) == 0 {
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap() // normalize IPv4-in-IPv6
	for _, p := range nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Default returns a Config populated with production defaults so an operator's
// config.yaml can be sparse.
func Default() *Config {
	c := &Config{}
	c.Listen.HTTP = "0.0.0.0:18080"
	c.Listen.HTTPS = "0.0.0.0:18443"
	c.Backend.HTTP = "127.0.0.1:80"
	c.Backend.HTTPS = "127.0.0.1:443"
	c.Firewall.Enabled = true
	c.Firewall.PublicHTTPPort = 80
	c.Firewall.PublicHTTPSPort = 443
	c.Firewall.InternalHTTPPort = 18080
	c.Firewall.InternalHTTPSPort = 18443
	c.Firewall.FailOpen = true
	c.TLS.NginxSitesGlob = []string{"/etc/nginx/sites-enabled/*"}
	c.TLS.ApacheSitesGlob = []string{"/etc/apache2/sites-enabled/*"}
	c.Templates.Dir = paths.TemplatesDir
	c.Templates.SyncInterval = Duration(6 * time.Hour)
	c.Templates.Git.URL = "https://codeberg.org/ostap-mykhaylyak/templates"
	c.Templates.Git.Branch = "main"
	c.Reputation.DBPath = paths.ReputationDB
	c.Reputation.BlockThreshold = 5
	c.Reputation.Window = Duration(10 * time.Minute)
	c.Reputation.GreylistTTL = Duration(30 * time.Minute)
	c.Reputation.BlockTTL = Duration(24 * time.Hour)
	c.Reputation.CleanTTL = Duration(1 * time.Hour)
	c.Challenge.Enabled = true
	c.Challenge.AssetsDir = paths.AssetsDir
	c.Challenge.TTL = Duration(1 * time.Hour)
	c.Challenge.POWBits = 16
	c.Session.CookieName = "smoker_sid"
	c.Session.TTL = Duration(30 * time.Minute)
	c.Session.MaxEntries = 100000
	c.Compression.MinSize = 1024
	c.Whitelist.Dir = paths.WhitelistDir
	c.Whitelist.SyncInterval = Duration(1 * time.Hour)
	c.Whitelist.Git.URL = "https://codeberg.org/ostap-mykhaylyak/whitelist"
	c.Whitelist.Git.Branch = "main"
	c.Blocklist.Dir = paths.BlocklistDir
	c.Blocklist.SyncInterval = Duration(1 * time.Hour)
	c.Blocklist.Git.URL = "https://codeberg.org/ostap-mykhaylyak/blocklist"
	c.Blocklist.Git.Branch = "main"
	// Trusted proxies: dir created empty, no default remote. Manual *.ips files
	// are loaded at startup; git sync only runs if an operator sets git.url.
	c.TrustedProxies.Dir = paths.TrustedProxiesDir
	c.TrustedProxies.SyncInterval = Duration(12 * time.Hour)
	c.TrustedProxies.Git.Branch = "main"
	c.Logging.Dir = paths.LogDir
	c.FailOpen = false
	return c
}

// Load reads and parses the config file, layering it over Default().
func Load(path string) (*Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if err := c.loadAccessListFiles(); err != nil {
		return nil, err
	}
	if err := c.compileAccessLists(); err != nil {
		return nil, err
	}
	return c, nil
}

// loadAccessListFiles merges entries from each list's Dir into its inline IPs.
// A missing dir is treated as empty (not an error).
func (c *Config) loadAccessListFiles() error {
	wl, err := readListDir(c.Whitelist.Dir)
	if err != nil {
		return fmt.Errorf("whitelist: %w", err)
	}
	c.Whitelist.IPs = append(c.Whitelist.IPs, wl...)
	bl, err := readListDir(c.Blocklist.Dir)
	if err != nil {
		return fmt.Errorf("blocklist: %w", err)
	}
	c.Blocklist.IPs = append(c.Blocklist.IPs, bl...)
	tp, err := readListDir(c.TrustedProxies.Dir)
	if err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
	}
	c.TrustedProxies.IPs = append(c.TrustedProxies.IPs, tp...)
	return nil
}

// readListFile reads one IP/CIDR per line, ignoring blanks and '#' comments
// (whole-line or trailing). A non-existent path yields an empty list.
func readListFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

// readListDir reads every *.ips file under dir (recursively), skipping the .git
// directory and non-.ips files (README, LICENSE, …). A non-existent dir yields
// an empty list. Unreadable files are skipped, not fatal.
func readListDir(dir string) ([]string, error) {
	if dir == "" {
		return nil, nil
	}
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(p), ".ips") {
			return nil
		}
		if entries, e := readListFile(p); e == nil {
			out = append(out, entries...)
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return out, err
	}
	return out, nil
}

func (c *Config) validate() error {
	if c.Listen.HTTP == "" && c.Listen.HTTPS == "" {
		return fmt.Errorf("at least one of listen.http / listen.https must be set")
	}
	if c.Backend.HTTP == "" {
		return fmt.Errorf("backend.http is required")
	}
	if c.Reputation.BlockThreshold <= 0 {
		return fmt.Errorf("reputation.block_threshold must be > 0")
	}
	return nil
}

// Manager holds the current *Config behind an atomic pointer and drives
// fsnotify-based hot reload. Get() is safe for the hot path.
type Manager struct {
	path    string
	current atomic.Pointer[Config]
	watcher *fsnotify.Watcher

	mu        sync.Mutex
	listeners []func(*Config)
}

// NewManager loads the initial config and starts watching for changes.
func NewManager(path string) (*Manager, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	m := &Manager{path: path}
	m.current.Store(cfg)
	return m, nil
}

// Get returns the current config snapshot. Cheap; call it per request.
func (m *Manager) Get() *Config { return m.current.Load() }

// Reload re-reads config.yaml and the access-list files/dirs, swaps in the new
// snapshot and runs the registered listeners. Used after a git sync updates the
// access-list repos on disk.
func (m *Manager) Reload() error {
	cfg, err := Load(m.path)
	if err != nil {
		return err
	}
	m.current.Store(cfg)
	m.mu.Lock()
	ls := append([]func(*Config){}, m.listeners...)
	m.mu.Unlock()
	for _, fn := range ls {
		fn(cfg)
	}
	return nil
}

// OnReload registers a callback invoked with the new config after a successful
// reload. Callbacks run synchronously in the watch goroutine; keep them fast.
func (m *Manager) OnReload(fn func(*Config)) {
	m.mu.Lock()
	m.listeners = append(m.listeners, fn)
	m.mu.Unlock()
}

// Watch reloads the config on changes to config.yaml OR the whitelist/blocklist
// files. It watches the containing directories (robust to editor atomic saves
// and files created after startup) and filters events to the tracked paths.
// onError is called for reload failures (the old config is retained).
func (m *Manager) Watch(stop <-chan struct{}, onError func(error), onReload func()) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	m.watcher = w

	// Watch the config file's directory (robust to editor atomic saves) and
	// filter to config.yaml. The git-synced access-list dirs are reloaded by the
	// sync loop, not here.
	tracked := map[string]struct{}{m.path: {}}
	if err := w.Add(filepath.Dir(m.path)); err != nil {
		_ = w.Close()
		return err
	}

	go func() {
		defer w.Close()
		for {
			select {
			case <-stop:
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if _, isTracked := tracked[ev.Name]; !isTracked {
					continue
				}
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
					continue
				}
				cfg, err := Load(m.path)
				if err != nil {
					if onError != nil {
						onError(err)
					}
					continue
				}
				m.current.Store(cfg)
				m.mu.Lock()
				ls := append([]func(*Config){}, m.listeners...)
				m.mu.Unlock()
				for _, fn := range ls {
					fn(cfg)
				}
				if onReload != nil {
					onReload()
				}
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				if onError != nil {
					onError(err)
				}
			}
		}
	}()
	return nil
}
