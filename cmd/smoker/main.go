// Command smoker is the reverse-proxy WAF entrypoint. It wires the firewall
// redirect layer, TLS termination, the Nuclei-template Detection Engine, the IP
// Reputation Manager, the Session/Behavior Tracker, the Challenge module and
// structured logging into a single static binary.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/ostap-mykhaylyak/smoker/internal/bootstrap"
	"github.com/ostap-mykhaylyak/smoker/internal/cache"
	"github.com/ostap-mykhaylyak/smoker/internal/challenge"
	"github.com/ostap-mykhaylyak/smoker/internal/config"
	"github.com/ostap-mykhaylyak/smoker/internal/detect"
	"github.com/ostap-mykhaylyak/smoker/internal/firewall"
	"github.com/ostap-mykhaylyak/smoker/internal/logging"
	"github.com/ostap-mykhaylyak/smoker/internal/paths"
	"github.com/ostap-mykhaylyak/smoker/internal/protect"
	"github.com/ostap-mykhaylyak/smoker/internal/proxy"
	"github.com/ostap-mykhaylyak/smoker/internal/reputation"
	"github.com/ostap-mykhaylyak/smoker/internal/session"
	"github.com/ostap-mykhaylyak/smoker/internal/tlsterm"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// Overrides exist ONLY for testing; production relies on hardcoded paths.
	cfgPath := flag.String("config", paths.ConfigFile, "config file (testing override)")
	noFirewall := flag.Bool("no-firewall", false, "skip nftables redirect (testing)")
	showVersion := flag.Bool("version", false, "print version and exit")
	initOnly := flag.Bool("init", false, "create the default filesystem layout and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("smoker", version)
		return
	}

	if *initOnly {
		if err := doInit(*cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, "smoker:", err)
			os.Exit(1)
		}
		return
	}

	if err := run(*cfgPath, *noFirewall); err != nil {
		fmt.Fprintln(os.Stderr, "smoker:", err)
		os.Exit(1)
	}
}

// resolveSecret returns a strong HMAC secret. If the configured value is empty
// or the shipped placeholder (public in the repo, hence forgeable), it generates
// a random ephemeral secret and warns the operator. Ephemeral is acceptable:
// challenge tokens and session cookies are short-lived; a restart just
// re-issues them.
func resolveSecret(configured string, logs *logging.Loggers) string {
	const placeholder = "CHANGE-ME-to-a-long-random-string"
	if configured != "" && configured != placeholder && len(configured) >= 16 {
		return configured
	}
	// No usable configured secret: load-or-create a persistent random one under
	// the writable runtime dir, so challenge tokens and session cookies survive
	// restarts (an ephemeral secret would invalidate them on every restart,
	// causing "verification failed" loops).
	path := filepath.Join(paths.LogDir, ".secret")
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); len(s) >= 32 {
			return s
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		logs.Service.Error("failed to generate random secret", "err", err)
	}
	s := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		logs.Service.Warn("could not persist generated secret (will change on restart)", "path", path, "err", err)
	}
	logs.Service.Warn("challenge.secret is empty/placeholder — generated and persisted a random secret; "+
		"set a strong challenge.secret in config.yaml to control it explicitly", "path", path)
	return s
}

// doInit runs the full turnkey installer (`smoker --init`): data layout, binary
// into /sbin, and the systemd unit.
func doInit(cfgPath string) error {
	r, err := bootstrap.Install(cfgPath)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	if len(r.Files) > 0 {
		fmt.Printf("smoker: created %d data file(s):\n", len(r.Files))
		for _, f := range r.Files {
			fmt.Println("  ", f)
		}
	}
	if r.Binary != "" {
		fmt.Println("smoker: installed binary ->", r.Binary)
	}
	if r.UnitWritten {
		fmt.Println("smoker: installed systemd unit ->", r.Unit)
	} else {
		fmt.Println("smoker: systemd unit already present ->", r.Unit)
	}
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  1) edit %s and set challenge.secret\n", cfgPath)
	fmt.Println("  2) systemctl daemon-reload")
	fmt.Println("  3) systemctl enable --now smoker")
	return nil
}

func run(cfgPath string, noFirewall bool) error {
	// First run: if the config is missing, provision the full default layout
	// (config, templates, challenge assets, log dir) from the embedded skel.
	if bootstrap.NeedsInit(cfgPath) {
		created, berr := bootstrap.Ensure(cfgPath)
		if berr != nil {
			return fmt.Errorf("bootstrap (need root to write /etc and /var?): %w", berr)
		}
		fmt.Fprintf(os.Stderr,
			"smoker: first run — provisioned %d default file(s) under /etc/smoker, /var/log/smoker, /var/www/smoker.\n"+
				"smoker: review %s and set challenge.secret.\n"+
				"smoker: to run as a service instead, stop this and run: sudo smoker --init && systemctl enable --now smoker\n",
			len(created), cfgPath)
	}

	cfgMgr, err := config.NewManager(cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	cfg := cfgMgr.Get()

	// Ensure the log directory exists even if the config predates a wiped
	// /var/log (bootstrap only runs when the config file itself is missing).
	if err := os.MkdirAll(cfg.Logging.Dir, 0o750); err != nil {
		return fmt.Errorf("log dir: %w", err)
	}

	// --- Logging ---
	logs, err := logging.Open(cfg.Logging.Dir)
	if err != nil {
		return fmt.Errorf("logging: %w", err)
	}
	defer logs.Close()
	logs.Service.Info("starting smoker", "version", version, "config", cfgPath, "pid", os.Getpid())

	// Report the access lists loaded from disk at startup so an operator can
	// immediately confirm their entries were picked up (trusted-proxies has no
	// git-sync log of its own). A count of 0 despite files present usually means
	// the files are not named *.ips (e.g. Cloudflare's ips-v4 / ips-v6).
	logs.Service.Info("access lists loaded",
		"whitelist", len(cfg.Whitelist.IPs),
		"blocklist", len(cfg.Blocklist.IPs),
		"trusted_proxies", len(cfg.TrustedProxies.IPs))
	for _, wmsg := range cfg.AccessListWarnings() {
		logs.Service.Warn("access list: skipped invalid entry", "entry", wmsg)
	}

	// --- Reputation Manager (BoltDB) ---
	rep, err := reputation.Open(cfg.Reputation.DBPath, reputation.Config{
		BlockThreshold: cfg.Reputation.BlockThreshold,
		Window:         cfg.Reputation.Window.Std(),
		GreylistTTL:    cfg.Reputation.GreylistTTL.Std(),
		BlockTTL:       cfg.Reputation.BlockTTL.Std(),
		CleanTTL:       cfg.Reputation.CleanTTL.Std(),
	})
	if err != nil {
		return fmt.Errorf("reputation: %w", err)
	}
	defer rep.Close()
	rep.OnTransition = func(tr reputation.Transition) {
		logs.Reputation.Info("transition",
			slog.String("ip", tr.IP),
			slog.String("from", string(tr.From)),
			slog.String("to", string(tr.To)),
			slog.String("reason", tr.Reason),
			slog.Time("expiry", tr.Expiry),
		)
	}

	// --- Session/Behavior Tracker ---
	tracker, err := session.New(cfg.Session.MaxEntries, cfg.Session.TTL.Std())
	if err != nil {
		return fmt.Errorf("session tracker: %w", err)
	}

	// --- Detection Engine + template load ---
	engine := detect.NewEngine(tracker)
	loadTemplates(engine, cfg.Templates.Dir, logs)

	// --- Secret for challenge tokens + signed session cookies ---
	secret := resolveSecret(cfg.Challenge.Secret, logs)

	// --- Challenge module ---
	cleaner := &cleanerAdapter{rep: rep, tracker: tracker}
	chMgr := challenge.New(cfg.Challenge.AssetsDir, secret, cfg.Challenge.TTL.Std(), cfg.Challenge.POWBits, logs.Blocked, cleaner)

	// --- Content cache (CDN-style) ---
	// Always built (enable/disable and TTL/extensions are hot-reloadable); only
	// the LRU capacity is fixed at startup.
	contentCache, err := cache.New(cfg.Cache.MaxEntries)
	if err != nil {
		return fmt.Errorf("cache: %w", err)
	}
	logs.Service.Info("content cache ready",
		"enabled", cfg.Cache.Enabled, "ttl", cfg.Cache.TTL.Std().String(),
		"max_entries", cfg.Cache.MaxEntries, "extensions", len(cfg.Cache.Extensions))

	// --- Proactive protection (rule-free flood governor + anomaly scoring) ---
	guard, err := protect.New(cfg.Protection.MaxTrackedIPs)
	if err != nil {
		return fmt.Errorf("protection: %w", err)
	}
	logs.Service.Info("proactive protection ready",
		"enabled", cfg.Protection.Enabled,
		"rate_limit", cfg.Protection.RateLimit.Enabled,
		"anomaly", cfg.Protection.Anomaly.Enabled)

	// --- Proxy core ---
	px := proxy.New(proxy.Deps{
		Config:    cfgMgr,
		Engine:    engine,
		Rep:       rep,
		Tracker:   tracker,
		Challenge: chMgr,
		Logs:      logs,
		Cache:     contentCache,
		Guard:     guard,
		Secret:    secret,
	})

	// --- TLS cert store ---
	certStore := tlsterm.NewCertStore()
	n, cerrs := certStore.Reload(cfg.TLS.NginxSitesGlob, cfg.TLS.ApacheSitesGlob)
	logs.Service.Info("loaded certificates", "count", n, "errors", len(cerrs))
	if cfg.TLS.Autocert.Enabled {
		am := tlsterm.NewAutocert(cfg.TLS.Autocert.CacheDir, cfg.TLS.Autocert.Email, cfg.TLS.Autocert.Domains)
		certStore.SetAutocert(am)
	}

	// --- HTTP + HTTPS servers ---
	httpSrv := &http.Server{
		Addr:              cfg.Listen.HTTP,
		Handler:           px,
		ConnContext:       px.ConnContext,
		ReadHeaderTimeout: 10 * time.Second,
	}
	httpsSrv := &http.Server{
		Addr:              cfg.Listen.HTTPS,
		Handler:           px,
		ConnContext:       px.ConnContext,
		TLSConfig:         certStore.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// --- Optional HTTP/3 (QUIC) listener ---
	var h3 *http3.Server
	if cfg.Listen.HTTP3 && cfg.Listen.HTTPS != "" {
		// Advertise the PUBLIC UDP port in Alt-Svc: the listen port in edge mode,
		// or the firewall's public HTTPS port when behind a redirect.
		advertise := portOf(cfg.Listen.HTTPS, 443)
		if cfg.Firewall.Enabled && cfg.Firewall.PublicHTTPSPort != 0 {
			advertise = cfg.Firewall.PublicHTTPSPort
		}
		h3 = newHTTP3(cfg.Listen.HTTPS, advertise, px, certStore.TLSConfig())
		// Advertise h3 via Alt-Svc on the TCP TLS responses.
		httpsSrv.Handler = altSvcHandler(px, h3)
	}

	// --- Firewall redirect ---
	var fw firewall.Controller
	if cfg.Firewall.Enabled && !noFirewall {
		opts := firewall.DefaultOptions()
		opts.PublicHTTP = cfg.Firewall.PublicHTTPPort
		opts.PublicHTTPS = cfg.Firewall.PublicHTTPSPort
		opts.InternalHTTP = cfg.Firewall.InternalHTTPPort
		opts.InternalHTTPS = cfg.Firewall.InternalHTTPSPort
		opts.RedirectHTTPSUDP = cfg.Listen.HTTP3 // DNAT UDP too, for QUIC
		fw, err = firewall.New(opts)
		if err != nil {
			logs.Service.Error("firewall init failed", "err", err)
		} else if err := fw.EnableRedirect(); err != nil {
			logs.Service.Error("enable redirect failed", "err", err)
		} else {
			logs.Service.Info("nftables redirect enabled",
				"http", opts.PublicHTTP, "https", opts.PublicHTTPS)
		}
	}

	// --- Background: config hot-reload ---
	stop := make(chan struct{})
	_ = cfgMgr.Watch(stop,
		func(err error) { logs.Service.Error("config reload failed", "err", err) },
		func() {
			nc := cfgMgr.Get()
			logs.Service.Info("config reloaded",
				"whitelist_dir", nc.Whitelist.Dir, "whitelist", len(nc.Whitelist.IPs),
				"blocklist_dir", nc.Blocklist.Dir, "blocklist", len(nc.Blocklist.IPs),
				"trusted_proxies", len(nc.TrustedProxies.IPs))
			loadTemplates(engine, nc.Templates.Dir, logs)
			n, _ := certStore.Reload(nc.TLS.NginxSitesGlob, nc.TLS.ApacheSitesGlob)
			logs.Service.Info("certificates reloaded", "count", n)
			for _, wmsg := range nc.AccessListWarnings() {
				logs.Service.Warn("access list: skipped invalid entry", "entry", wmsg)
			}
		})

	// --- Background: independent git-sync loops (templates + access lists) ---
	startSyncLoops(stop, cfgMgr, engine, logs)

	// --- Background: hot-reload access lists on manual file changes (fsnotify) ---
	// Picks up added/edited *.ips files (whitelist, blocklist, trusted-proxies)
	// without a restart or a git sync — important for trusted-proxies, which
	// typically has no git remote.
	if err := cfgMgr.WatchAccessLists(stop,
		func() {
			nc := cfgMgr.Get()
			logs.Service.Info("access lists reloaded (file change)",
				"whitelist", len(nc.Whitelist.IPs),
				"blocklist", len(nc.Blocklist.IPs),
				"trusted_proxies", len(nc.TrustedProxies.IPs))
			for _, wmsg := range nc.AccessListWarnings() {
				logs.Service.Warn("access list: skipped invalid entry", "entry", wmsg)
			}
		},
		func(err error) { logs.Service.Error("access-list watch", "err", err) },
	); err != nil {
		logs.Service.Error("access-list watch init failed", "err", err)
	} else {
		logs.Service.Info("watching access lists for changes",
			"whitelist_dir", cfg.Whitelist.Dir, "blocklist_dir", cfg.Blocklist.Dir,
			"trusted_proxies_dir", cfg.TrustedProxies.Dir)
	}

	// --- Background: hot-reload templates on file changes (fsnotify) ---
	if err := detect.WatchTemplates(cfg.Templates.Dir, stop,
		func() {
			loadTemplates(engine, cfgMgr.Get().Templates.Dir, logs)
		},
		func(err error) { logs.Service.Error("template watch", "err", err) },
	); err != nil {
		logs.Service.Error("template watch init failed", "dir", cfg.Templates.Dir, "err", err)
	} else {
		logs.Service.Info("watching templates for changes", "dir", cfg.Templates.Dir)
	}

	// --- Start servers ---
	go func() {
		logs.Service.Info("http listener", "addr", cfg.Listen.HTTP)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logs.Service.Error("http server", "err", err)
		}
	}()
	go func() {
		logs.Service.Info("https listener", "addr", cfg.Listen.HTTPS)
		if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logs.Service.Error("https server", "err", err)
		}
	}()
	if h3 != nil {
		go func() {
			logs.Service.Info("http3 (quic) listener", "addr", cfg.Listen.HTTPS)
			if err := h3.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logs.Service.Error("http3 server", "err", err)
			}
		}()
	}

	// --- Signals ---
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	for {
		s := <-sig
		switch s {
		case syscall.SIGHUP:
			// logrotate hook: reopen log files.
			if err := logs.Reopen(); err != nil {
				logs.Service.Error("log reopen failed", "err", err)
			} else {
				logs.Service.Info("log files reopened (SIGHUP)")
			}
		default:
			logs.Service.Info("shutting down", "signal", s.String())
			close(stop)
			return shutdown(httpSrv, httpsSrv, h3, fw, cfg, logs)
		}
	}
}

// shutdown performs graceful termination: drain connections, then decide the
// firewall end-state based on fail-open configuration.
func shutdown(httpSrv, httpsSrv *http.Server, h3 *http3.Server, fw firewall.Controller, cfg *config.Config, logs *logging.Loggers) error {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	_ = httpsSrv.Shutdown(ctx)
	if h3 != nil {
		_ = h3.Close()
	}

	if fw != nil {
		if cfg.Firewall.FailOpen {
			// Remove redirect so traffic reaches the backend directly.
			if err := fw.DisableRedirect(); err != nil {
				logs.Service.Error("disable redirect failed", "err", err)
			} else {
				logs.Service.Info("redirect removed (fail-open bypass)")
			}
		} else {
			logs.Service.Info("redirect left in place (fail-closed)")
		}
		_ = fw.Close()
	}
	logs.Service.Info("shutdown complete")
	return nil
}

// loadTemplates loads + compiles templates from dir and hot-swaps the engine.
func loadTemplates(engine detect.Engine, dir string, logs *logging.Loggers) {
	res, err := detect.LoadDir(dir)
	if err != nil {
		logs.Service.Error("template load failed", "dir", dir, "err", err)
		return
	}
	engine.Reload(res.Signatures)
	logs.Service.Info("templates loaded",
		"dir", dir, "loaded", res.Loaded, "skipped", res.Skipped, "errors", len(res.Errors))
	for _, e := range res.Errors {
		logs.Service.Warn("template error", "err", e.Error())
	}
}

// startSyncLoops launches independent git-sync loops for the templates, the
// whitelist and the blocklist, each on its own interval, each with an initial
// sync at startup. An interval <= 0 disables that loop.
func startSyncLoops(stop <-chan struct{}, cfgMgr *config.Manager, engine detect.Engine, logs *logging.Loggers) {
	go syncLoop(stop, cfgMgr.Get().Templates.SyncInterval.Std(), func() {
		cfg := cfgMgr.Get()
		if err := detect.SyncRepo(cfg.Templates.Dir, cfg.Templates.Git.URL, cfg.Templates.Git.Branch); err != nil {
			logs.Service.Warn("template sync", "err", err.Error())
		}
		loadTemplates(engine, cfg.Templates.Dir, logs)
	})
	go syncLoop(stop, cfgMgr.Get().Whitelist.SyncInterval.Std(), func() {
		syncAccessList(cfgMgr, logs, "whitelist")
	})
	go syncLoop(stop, cfgMgr.Get().Blocklist.SyncInterval.Std(), func() {
		syncAccessList(cfgMgr, logs, "blocklist")
	})
	// Trusted proxies have no default remote: only run a git-sync loop if the
	// operator configured one (e.g. mirroring Cloudflare's published ranges).
	// Manual *.ips files in the dir are still loaded at startup and config reload.
	if cfgMgr.Get().TrustedProxies.Git.URL != "" {
		go syncLoop(stop, cfgMgr.Get().TrustedProxies.SyncInterval.Std(), func() {
			syncAccessList(cfgMgr, logs, "trusted_proxies")
		})
	}
}

// syncLoop runs sync() immediately and then every interval until stop closes.
func syncLoop(stop <-chan struct{}, interval time.Duration, sync func()) {
	if interval <= 0 {
		return // disabled
	}
	sync()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			sync()
		}
	}
}

// syncAccessList pulls one access-list repo into its dir and reloads the config
// so the new prefixes take effect. label is "whitelist" or "blocklist".
func syncAccessList(cfgMgr *config.Manager, logs *logging.Loggers, label string) {
	al := cfgMgr.Get().Whitelist
	switch label {
	case "blocklist":
		al = cfgMgr.Get().Blocklist
	case "trusted_proxies":
		al = cfgMgr.Get().TrustedProxies
	}
	if err := detect.SyncRepo(al.Dir, al.Git.URL, al.Git.Branch); err != nil {
		logs.Service.Warn(label+" sync", "err", err.Error())
	}
	if err := cfgMgr.Reload(); err != nil {
		logs.Service.Error("config reload after "+label+" sync failed", "err", err.Error())
		return
	}
	nc := cfgMgr.Get()
	list := nc.Whitelist
	switch label {
	case "blocklist":
		list = nc.Blocklist
	case "trusted_proxies":
		list = nc.TrustedProxies
	}
	logs.Service.Info(label+" reloaded", "dir", list.Dir, "entries", len(list.IPs))
	for _, wmsg := range nc.AccessListWarnings() {
		logs.Service.Warn("access list: skipped invalid entry", "entry", wmsg)
	}
}

// cleanerAdapter satisfies challenge.Cleaner by delegating to the reputation
// manager and session tracker.
type cleanerAdapter struct {
	rep     reputation.Store
	tracker session.Tracker
}

func (c *cleanerAdapter) MarkIPClean(ip, reason string) { c.rep.MarkClean(ip, reason) }
func (c *cleanerAdapter) MarkSessionPassed(key string)  { c.tracker.MarkChallengePassed(key) }
