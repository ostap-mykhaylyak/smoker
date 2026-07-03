//go:build !linux

package firewall

import "errors"

// stubController is a no-op used on non-Linux dev machines. It records desired
// state so tests can assert on Active() without needing nftables.
type stubController struct {
	opts   Options
	active bool
}

// New returns a stub Controller on non-Linux platforms.
func New(opts Options) (Controller, error) {
	return &stubController{opts: opts}, nil
}

// ErrUnsupported indicates real redirect is unavailable on this platform.
var ErrUnsupported = errors.New("firewall redirect requires linux/nftables")

func (c *stubController) EnableRedirect() error  { c.active = true; return nil }
func (c *stubController) DisableRedirect() error { c.active = false; return nil }
func (c *stubController) Active() bool           { return c.active }
func (c *stubController) Close() error           { return nil }
