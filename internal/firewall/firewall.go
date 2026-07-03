// Package firewall is the redirect layer. It programs nftables DNAT/redirect
// rules so public traffic on ports 80/443 is steered to the proxy's internal
// high ports (e.g. 18080/18443). It can enable/disable the redirect at runtime
// to implement configurable fail-open (bypass) when the proxy is unhealthy.
//
// The nftables implementation lives in firewall_linux.go (build tag linux);
// other platforms get a no-op stub so the project builds and unit-tests
// everywhere. The real controller requires CAP_NET_ADMIN.
package firewall

// Options configures the redirect layer.
type Options struct {
	// TableName / ChainName let multiple instances / tests coexist.
	TableName string
	ChainName string

	PublicHTTP    int // 80
	PublicHTTPS   int // 443
	InternalHTTP  int // 18080
	InternalHTTPS int // 18443

	// RedirectHTTPSUDP also DNATs UDP on the public HTTPS port to the internal
	// HTTPS port, so HTTP/3 (QUIC) reaches the proxy when running behind the
	// redirect. Ignored in edge mode (no redirect).
	RedirectHTTPSUDP bool
}

// DefaultOptions returns production defaults.
func DefaultOptions() Options {
	return Options{
		TableName:     "smoker",
		ChainName:     "prerouting",
		PublicHTTP:    80,
		PublicHTTPS:   443,
		InternalHTTP:  18080,
		InternalHTTPS: 18443,
	}
}

// Controller installs and removes the redirect rules.
type Controller interface {
	// EnableRedirect installs the DNAT/redirect rules (idempotent).
	EnableRedirect() error
	// DisableRedirect removes them, restoring direct backend access
	// (fail-open / bypass mode).
	DisableRedirect() error
	// Active reports whether the redirect is currently installed.
	Active() bool
	// Close releases the netlink connection.
	Close() error
}
