//go:build !linux

package proxy

import (
	"net"
	"net/netip"
)

// OriginalDst is unavailable off Linux; callers fall back to conn.LocalAddr.
func OriginalDst(conn net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, ErrNoOriginalDst
}
