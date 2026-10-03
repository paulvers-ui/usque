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

// sendQueueLen bounds the packets queued per peer endpoint while the stack
// below cannot take them (its tunnel is reconnecting). WireGuard retransmits
// handshakes and its inner TCP retransmits data, so dropping beyond this is safe.
const sendQueueLen = 256

// netstackBind is a wireguard-go conn.Bind whose UDP sockets live inside
// another tunnel's userspace network stack instead of the host network.
// This is what lets wg0 ride inside WARP1.
//
// A netstack only routes *connected* UDP: an unconnected socket's
// WriteTo(addr) fails with "network is unreachable" (see UnderlayOf). So the
// bind dials one connected conn per peer endpoint and feeds every conn's
// reads into a single receive queue. wg0 is a client here; it only ever
// talks to the endpoints it sends to, so it needs no listening socket.
//
// Writes are asynchronous: a wireguard-go netstack hands outbound packets to
// its reader over an unbuffered channel, so a write into WARP1's stack blocks
// until WARP1 is connected and pumping. Done inline, that blocked dev.Up() (the
// first handshake) and with it the whole chain start, until WARP1 connected.
type netstackBind struct {
	under *netstack.Net

	mu    sync.Mutex
	conns map[netip.AddrPort]*nsConn
	recv  chan nsPacket
	done  chan struct{} // nil while closed
}

// nsConn is one connected conn plus its write queue and writer.
type nsConn struct {
	c    *gonet.UDPConn
	out  chan []byte
	quit chan struct{} // closed once, when the conn is dropped
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
	b.conns = make(map[netip.AddrPort]*nsConn)
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
func (b *netstackBind) connFor(dst netip.AddrPort) (*nsConn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done == nil {
		return nil, net.ErrClosed
	}
	if nc := b.conns[dst]; nc != nil {
		return nc, nil
	}
	c, err := b.under.DialUDPAddrPort(netip.AddrPort{}, dst)
	if err != nil {
		return nil, err
	}
	nc := &nsConn{c: c, out: make(chan []byte, sendQueueLen), quit: make(chan struct{})}
	b.conns[dst] = nc
	go b.readLoop(nc, dst, b.recv, b.done)
	go b.writeLoop(nc, dst)
	return nc, nil
}

func (b *netstackBind) readLoop(nc *nsConn, from netip.AddrPort, recv chan<- nsPacket, done <-chan struct{}) {
	buf := make([]byte, 65535)
	for {
		n, err := nc.c.Read(buf)
		if err != nil {
			// Drop the conn; the next Send to this endpoint redials it.
			b.drop(from, nc)
			return
		}
		select {
		case recv <- nsPacket{b: append([]byte(nil), buf[:n]...), from: from}:
		case <-done:
			return
		}
	}
}

// writeLoop owns all writes to nc. A write may block for as long as the stack
// below is reconnecting; Send keeps queueing (and then dropping) meanwhile.
func (b *netstackBind) writeLoop(nc *nsConn, dst netip.AddrPort) {
	for {
		select {
		case p := <-nc.out:
			if _, err := nc.c.Write(p); err != nil {
				b.drop(dst, nc)
				return
			}
		case <-nc.quit:
			return
		}
	}
}

// drop forgets nc (if it is still the conn for dst) and closes it, which also
// ends its read and write loops.
func (b *netstackBind) drop(dst netip.AddrPort, nc *nsConn) {
	b.mu.Lock()
	if b.conns[dst] == nc {
		delete(b.conns, dst)
		close(nc.quit)
	}
	b.mu.Unlock()
	_ = nc.c.Close()
}

func (b *netstackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done != nil {
		close(b.done)
		b.done = nil
	}
	for _, nc := range b.conns {
		close(nc.quit)
		_ = nc.c.Close()
	}
	b.conns = nil
	return nil
}

func (b *netstackBind) SetMark(uint32) error { return nil }

// Send queues copies of bufs (wireguard-go reuses them once Send returns) and
// never blocks; see netstackBind.
func (b *netstackBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*nsEndpoint)
	if !ok {
		return errWrongEndpoint
	}
	nc, err := b.connFor(e.dst)
	if err != nil {
		return err
	}
	for _, buf := range bufs {
		select {
		case nc.out <- append([]byte(nil), buf...):
		case <-nc.quit:
			return net.ErrClosed
		default:
			// Queue full: the stack below is not draining (reconnecting).
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
