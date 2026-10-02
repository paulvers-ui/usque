package chain

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// netstackBind is a wireguard-go conn.Bind whose UDP sockets live inside
// another tunnel's userspace network stack instead of the host network.
// This is what lets wg0 ride inside WARP1.
type netstackBind struct {
	under *netstack.Net

	mu     sync.Mutex
	pc4    net.PacketConn
	pc6    net.PacketConn
	closed bool
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
	if b.pc4 != nil || b.pc6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.closed = false
	var fns []conn.ReceiveFunc
	var errs []error
	if pc, err := b.under.ListenUDPAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), port)); err == nil {
		b.pc4 = pc
		fns = append(fns, b.receive(pc))
	} else {
		errs = append(errs, err)
	}
	if pc, err := b.under.ListenUDPAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), port)); err == nil {
		b.pc6 = pc
		fns = append(fns, b.receive(pc))
	} else {
		errs = append(errs, err)
	}
	if len(fns) == 0 {
		return nil, 0, errors.Join(errs...)
	}
	return fns, port, nil
}

func (b *netstackBind) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

func (b *netstackBind) receive(pc net.PacketConn) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, addr, err := pc.ReadFrom(bufs[0])
			if err != nil {
				if b.isClosed() {
					return 0, net.ErrClosed
				}
				// wireguard-go stops a receive loop for good on a non-temporary
				// error, so ride out transient netstack errors here.
				time.Sleep(50 * time.Millisecond)
				continue
			}
			ua, ok := addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			ap := ua.AddrPort()
			sizes[0] = n
			eps[0] = &nsEndpoint{dst: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}
			return 1, nil
		}
	}
}

func (b *netstackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	if b.pc4 != nil {
		_ = b.pc4.Close()
		b.pc4 = nil
	}
	if b.pc6 != nil {
		_ = b.pc6.Close()
		b.pc6 = nil
	}
	return nil
}

func (b *netstackBind) SetMark(uint32) error { return nil }

func (b *netstackBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*nsEndpoint)
	if !ok {
		return errWrongEndpoint
	}
	b.mu.Lock()
	pc := b.pc4
	if e.dst.Addr().Is6() {
		pc = b.pc6
	}
	b.mu.Unlock()
	if pc == nil {
		return net.ErrClosed
	}
	ua := net.UDPAddrFromAddrPort(e.dst)
	for _, buf := range bufs {
		if _, err := pc.WriteTo(buf, ua); err != nil {
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
