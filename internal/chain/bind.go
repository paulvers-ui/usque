package chain

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// netstackBind is a wireguard-go conn.Bind whose UDP sockets live inside
// another tunnel's userspace network stack instead of the host network.
// This is what lets wg0 ride inside WARP1.
//
// A netstack only routes *connected* UDP: an unconnected socket's
// WriteTo(addr) fails with "network is unreachable" (see UnderlayOf). So the
// bind dials one connected conn per peer endpoint and feeds every conn's
// reads into a single receive queue. wg0 is a client here; it only ever
// talks to the endpoints it sends to, so it needs no listening socket.
type netstackBind struct {
	under *netstack.Net

	mu    sync.Mutex
	conns map[netip.AddrPort]*gonet.UDPConn
	recv  chan nsPacket
	done  chan struct{} // nil while closed
}

type nsPacket struct {
	b    []byte
	from netip.AddrPort
}

func newNetstackBind(under *netstack.Net) *netstackBind {
	return &netstackBind{under: under}
}

type nsEndpoint struct{ dst netip.AddrPort }

func (e *nsEndpoint) ClearSrc()           {}
func (e *nsEndpoint) SrcToString() string { return "" }
func (e *nsEndpoint) DstToString() string { return e.dst.String() }
func (e *nsEndpoint) DstToBytes() []byte  { b, _ := e.dst.MarshalBinary(); return b }
func (e *nsEndpoint) DstIP() netip.Addr   { return e.dst.Addr() }
func (e *nsEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func (b *netstackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	recv, done := make(chan nsPacket, 256), make(chan struct{})
	b.recv, b.done = recv, done
	b.conns = make(map[netip.AddrPort]*gonet.UDPConn)
	fn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case p := <-recv:
			sizes[0] = copy(bufs[0], p.b)
			eps[0] = &nsEndpoint{dst: p.from}
			return 1, nil
		case <-done:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{fn}, port, nil
}

// connFor returns the connected conn to dst, dialing it on first use.
func (b *netstackBind) connFor(dst netip.AddrPort) (*gonet.UDPConn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done == nil {
		return nil, net.ErrClosed
	}
	if c := b.conns[dst]; c != nil {
		return c, nil
	}
	c, err := b.under.DialUDPAddrPort(netip.AddrPort{}, dst)
	if err != nil {
		return nil, err
	}
	b.conns[dst] = c
	go b.readLoop(c, dst, b.recv, b.done)
	return c, nil
}

func (b *netstackBind) readLoop(c *gonet.UDPConn, from netip.AddrPort, recv chan<- nsPacket, done <-chan struct{}) {
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			// Drop the conn; the next Send to this endpoint redials it.
			b.drop(from, c)
			return
		}
		select {
		case recv <- nsPacket{b: append([]byte(nil), buf[:n]...), from: from}:
		case <-done:
			return
		}
	}
}

func (b *netstackBind) drop(dst netip.AddrPort, c *gonet.UDPConn) {
	b.mu.Lock()
	if b.conns[dst] == c {
		delete(b.conns, dst)
	}
	b.mu.Unlock()
	_ = c.Close()
}

func (b *netstackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done != nil {
		close(b.done)
		b.done = nil
	}
	for _, c := range b.conns {
		_ = c.Close()
	}
	b.conns = nil
	return nil
}

func (b *netstackBind) SetMark(uint32) error { return nil }

func (b *netstackBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*nsEndpoint)
	if !ok {
		return errWrongEndpoint
	}
	c, err := b.connFor(e.dst)
	if err != nil {
		return err
	}
	for _, buf := range bufs {
		if _, err := c.Write(buf); err != nil {
			b.drop(e.dst, c)
			return err
		}
	}
	return nil
}

func (b *netstackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &nsEndpoint{dst: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}, nil
}

func (b *netstackBind) BatchSize() int { return 1 }

var _ conn.Bind = (*netstackBind)(nil)

var errWrongEndpoint = errors.New("chain: wrong endpoint type")

// NewNetstackBind exposes the bind for the end-to-end simulations.
func NewNetstackBind(under *netstack.Net) conn.Bind { return newNetstackBind(under) }
