//go:build linux

package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// soOriginalDst is the getsockopt option (IP level) that returns the pre-DNAT
// destination recorded by conntrack. It is a stable Linux value (80) and is
// defined locally because it is not exported on every architecture of
// x/sys/unix.
const soOriginalDst = 80

// OriginalDst recovers the pre-DNAT destination (the address the client
// originally connected to) via getsockopt(SO_ORIGINAL_DST). With nftables
// redirect the kernel rewrites the destination to the local proxy, so the real
// intended host:port must be read from the connection-tracking entry.
//
// This is needed to preserve the true destination for logging and vhost
// selection on plaintext HTTP; the real *client* IP is conn.RemoteAddr.
func OriginalDst(conn net.Conn) (netip.AddrPort, error) {
	// Unwrap *tls.Conn (HTTPS) to reach the underlying TCP connection.
	if u, ok := conn.(interface{ NetConn() net.Conn }); ok {
		conn = u.NetConn()
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("not a TCP connection")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}

	var (
		addr netip.AddrPort
		serr error
	)
	cerr := raw.Control(func(fd uintptr) {
		// SO_ORIGINAL_DST is read at IP level; IPPROTO_IP == SOL_IP == 0.
		mreq, gerr := unix.GetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IP, soOriginalDst)
		if gerr != nil {
			serr = gerr
			return
		}
		// mreq.Multiaddr mirrors sockaddr_in:
		//   [0:2] family, [2:4] port (big-endian), [4:8] IPv4 address.
		b := mreq.Multiaddr
		port := uint16(b[2])<<8 | uint16(b[3])
		ip := netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]})
		addr = netip.AddrPortFrom(ip, port)
	})
	if cerr != nil {
		return netip.AddrPort{}, cerr
	}
	if serr != nil {
		// No conntrack original dst (direct connection, not redirected).
		if errors.Is(serr, unix.ENOENT) || errors.Is(serr, unix.ENOPROTOOPT) {
			return netip.AddrPort{}, ErrNoOriginalDst
		}
		return netip.AddrPort{}, serr
	}
	return addr, nil
}
