//go:build linux

package firewall

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// nftController implements Controller using google/nftables (netlink).
type nftController struct {
	opts Options

	mu     sync.Mutex
	conn   *nftables.Conn
	table  *nftables.Table
	chain  *nftables.Chain
	active bool
}

// New returns an nftables-backed Controller. Requires CAP_NET_ADMIN.
func New(opts Options) (Controller, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("open nftables netlink: %w", err)
	}
	return &nftController{opts: opts, conn: conn}, nil
}

func (c *nftController) EnableRedirect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// ip nat table + prerouting chain (nat hook, dstnat priority).
	c.table = c.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   c.opts.TableName,
	})
	polAccept := nftables.ChainPolicyAccept
	c.chain = c.conn.AddChain(&nftables.Chain{
		Name:     c.opts.ChainName,
		Table:    c.table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Policy:   &polAccept,
	})
	// Rebuild rules from scratch: flush the chain first.
	c.conn.FlushChain(c.chain)

	c.addRedirect(unix.IPPROTO_TCP, c.opts.PublicHTTP, c.opts.InternalHTTP)
	c.addRedirect(unix.IPPROTO_TCP, c.opts.PublicHTTPS, c.opts.InternalHTTPS)
	if c.opts.RedirectHTTPSUDP {
		// HTTP/3 (QUIC) is UDP on the HTTPS port.
		c.addRedirect(unix.IPPROTO_UDP, c.opts.PublicHTTPS, c.opts.InternalHTTPS)
	}

	if err := c.conn.Flush(); err != nil {
		return fmt.Errorf("apply redirect rules: %w", err)
	}
	c.active = true
	return nil
}

// rtnLocal is RTN_LOCAL: the FIB address type for addresses that belong to this
// host. We redirect ONLY traffic destined to a local address so that, when the
// box also routes/forwards for other hosts, transit traffic (e.g. a downstream
// machine's apt-get to archive.ubuntu.com:80) is NOT hijacked into the proxy.
const rtnLocal = 2

// addRedirect appends
//
//	<proto> dport <pub> fib daddr . iif type local  redirect to :<internal>
//
// REDIRECT keeps the connection local while SO_ORIGINAL_DST still exposes the
// pre-NAT destination to the proxy. The `fib daddr type local` guard is the
// equivalent of iptables `-m addrtype --dst-type LOCAL` and is what prevents the
// prerouting hook from capturing forwarded/transit traffic. proto is
// unix.IPPROTO_TCP or unix.IPPROTO_UDP (UDP for HTTP/3/QUIC); both carry the
// destination port at transport-header offset 2.
func (c *nftController) addRedirect(proto, pubPort, internalPort int) {
	portBE := make([]byte, 2)
	binary.BigEndian.PutUint16(portBE, uint16(pubPort))
	toBE := make([]byte, 2)
	binary.BigEndian.PutUint16(toBE, uint16(internalPort))
	localType := make([]byte, 4)
	binary.NativeEndian.PutUint32(localType, rtnLocal)

	c.conn.AddRule(&nftables.Rule{
		Table: c.table,
		Chain: c.chain,
		Exprs: []expr.Any{
			// meta l4proto == <proto>
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{byte(proto)},
			},
			// dport == pubPort  (transport header offset 2, len 2)
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: portBE},
			// Only redirect if the destination address is LOCAL to this host,
			// i.e. actually addressed to us — never forwarded/transit traffic.
			&expr.Fib{
				Register:       1,
				FlagDADDR:      true,
				FlagIIF:        true,
				ResultADDRTYPE: true,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: localType},
			// load target port into reg1 and redirect
			&expr.Immediate{Register: 1, Data: toBE},
			&expr.Redir{RegisterProtoMin: 1, RegisterProtoMax: 1},
		},
	})
}

func (c *nftController) DisableRedirect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.table == nil {
		// Nothing installed; try to delete by name in case of prior run.
		c.table = &nftables.Table{Family: nftables.TableFamilyIPv4, Name: c.opts.TableName}
	}
	c.conn.DelTable(c.table)
	if err := c.conn.Flush(); err != nil {
		return fmt.Errorf("remove redirect rules: %w", err)
	}
	c.active = false
	c.table = nil
	c.chain = nil
	return nil
}

func (c *nftController) Active() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

func (c *nftController) Close() error {
	// google/nftables uses a per-call netlink socket; nothing to close.
	return nil
}
